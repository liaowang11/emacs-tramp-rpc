// SPDX-License-Identifier: GPL-3.0-or-later

//! Run programs in the user's GUI login session.
//!
//! sshd starts each command in its own security (audit) session.  On macOS
//! the login keychain is unavailable there, so anything the RPC server runs
//! (git credential helpers, `gh`, agents that keep an OAuth login in the
//! keychain) behaves as if the user were logged out.
//!
//! `tramp-rpc-server daemon`, started by a per-user launchd agent, lives in
//! the GUI session.  A client in the ssh session hands the daemon its argv,
//! working directory, environment and stdio file descriptors over a Unix
//! socket; the daemon starts the program on those descriptors, so data never
//! passes through the client or the daemon.  Interactive clients (stdin is a
//! terminal) get a fresh pseudo-terminal from the daemon instead, because a
//! process cannot take over a terminal that is already another session's
//! controlling terminal, and relay between it and their own terminal.
//!
//! Every client path falls back to running in place when no daemon answers,
//! so one command line works on Linux, on a Mac nobody is logged into, and
//! when the agent is not installed.  Nothing here writes to stderr except the
//! daemon: for the RPC server stderr shares the ssh channel with the binary
//! protocol, and for agents it reaches the ACP client as agent errors.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

/// Handle the command line before the RPC runtime starts.
///
/// Returns `None` when this process should serve RPC on its own stdio, as it
/// always did, and `Some(code)` when a subcommand ran instead.
pub(crate) fn dispatch(args: Vec<OsString>) -> Option<ExitCode> {
    match args.first().and_then(|a| a.to_str()) {
        // Started by the daemon: serve here, never hand off again.
        Some("--serve") => None,
        Some("run") => Some(run(args[1..].to_vec())),
        Some("daemon") => Some(daemon_command(&args[1..])),
        _ => handoff_server(),
    }
}

/// `tramp-rpc-server run [--] PROGRAM ARGS...`
fn run(mut argv: Vec<OsString>) -> ExitCode {
    if argv.first().is_some_and(|a| a == "--") {
        argv.remove(0);
    }
    if argv.is_empty() {
        return ExitCode::from(2);
    }
    #[cfg(target_os = "macos")]
    if let Some(code) = imp::run_in_gui_session(&argv) {
        return code;
    }
    exec_in_place(&argv)
}

/// Replace this process with ARGV, the behavior without a daemon.
fn exec_in_place(argv: &[OsString]) -> ExitCode {
    let err = Command::new(&argv[0]).args(&argv[1..]).exec();
    ExitCode::from(if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}

fn handoff_server() -> Option<ExitCode> {
    #[cfg(target_os = "macos")]
    {
        imp::handoff_server()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

fn daemon_command(args: &[OsString]) -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        let path = match args {
            [flag, path] if flag == "--socket" => Some(std::path::PathBuf::from(path)),
            [] => imp::socket_path(),
            _ => None,
        };
        match path {
            Some(path) => imp::daemon(&path),
            None => {
                eprintln!("usage: tramp-rpc-server daemon [--socket PATH]");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        eprintln!("tramp-rpc-server daemon is only needed on macOS");
        ExitCode::from(1)
    }
}

/// Return PROGRAM as found on SEARCH_PATH, or PROGRAM unchanged.
///
/// The client resolves the program against its own PATH: the daemon runs with
/// launchd's minimal environment, and the child's PATH only applies after exec.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn resolve_program(program: &OsString, search_path: Option<&std::ffi::OsStr>) -> OsString {
    use std::os::unix::fs::PermissionsExt;

    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(program.as_os_str());
    if bytes.contains(&b'/') {
        return program.clone();
    }
    let Some(search_path) = search_path else {
        return program.clone();
    };
    for dir in std::env::split_paths(search_path) {
        let candidate = dir.join(program);
        if let Ok(meta) = std::fs::metadata(&candidate)
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            return candidate.into_os_string();
        }
    }
    program.clone()
}

#[cfg(target_os = "macos")]
mod imp {
    use super::resolve_program;
    use nix::cmsg_space;
    use nix::errno::Errno;
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use nix::pty::{Winsize, openpty};
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, killpg, sigaction};
    use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
    use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};
    use nix::unistd::{Pid, geteuid, getpeereid};
    use serde::{Deserialize, Serialize};
    use serde_bytes::ByteBuf;
    use std::ffi::{OsStr, OsString};
    use std::io::{IoSlice, IoSliceMut, Read, Write};
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    /// Daemon reply: the program runs on the passed descriptors.
    const STARTED: u8 = b'S';
    /// Daemon reply: the program runs on a new terminal; its master follows.
    const PTY_STARTED: u8 = b'M';
    /// Daemon reply: the program could not be started; run it in place.
    const FAILED: u8 = b'E';
    /// How long the daemon waits for a connected client's request.
    const REQUEST_TIMEOUT_MS: u16 = 5000;
    /// Largest request the daemon reads.
    const MAX_REQUEST: u32 = 4 << 20;
    /// How long a hung-up child may take to exit before it is killed.
    pub(super) const KILL_GRACE: Duration = Duration::from_secs(3);

    /// What to start, sent as MessagePack after a 4-byte length.
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub(super) struct Launch {
        pub argv: Vec<ByteBuf>,
        pub cwd: ByteBuf,
        pub env: Vec<(ByteBuf, ByteBuf)>,
        /// Terminal size (rows, columns) for a PTY launch.
        pub pty: Option<(u16, u16)>,
    }

    impl Launch {
        /// Describe ARGV run from this process's directory and environment.
        pub(super) fn here(argv: &[OsString], pty: Option<(u16, u16)>) -> Option<Self> {
            let cwd = std::env::current_dir().ok()?;
            Some(Launch {
                argv: argv
                    .iter()
                    .map(|a| ByteBuf::from(a.as_bytes().to_vec()))
                    .collect(),
                cwd: ByteBuf::from(cwd.into_os_string().into_vec()),
                env: std::env::vars_os()
                    .map(|(k, v)| (ByteBuf::from(k.into_vec()), ByteBuf::from(v.into_vec())))
                    .collect(),
                pty,
            })
        }
    }

    /// A program the daemon started for this client.
    pub(super) enum Started {
        /// Running on the descriptors the client passed.
        Pipe(UnixStream),
        /// Running on a terminal whose master the daemon handed back.
        Pty(UnixStream, OwnedFd),
    }

    /// The daemon socket: under the account's home directory, found through
    /// the password database so ssh, launchd and `sudo -H` agree on it.
    /// Application Support, not Caches, so the system never purges it.
    pub(super) fn socket_path() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("TRAMP_RPC_GUI_SOCKET") {
            return Some(path.into());
        }
        let user = nix::unistd::User::from_uid(geteuid()).ok()??;
        Some(
            user.dir
                .join("Library/Application Support/tramp-rpc/gui.sock"),
        )
    }

    fn same_user(stream: &UnixStream) -> bool {
        getpeereid(stream).is_ok_and(|(uid, _)| uid == geteuid())
    }

    fn set_cloexec(fd: RawFd) {
        let _ = fcntl(
            unsafe { BorrowedFd::borrow_raw(fd) },
            FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
        );
    }

    fn dup_cloexec(fd: BorrowedFd<'_>) -> nix::Result<OwnedFd> {
        let raw = fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(3))?;
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    /// Send one byte with optional descriptors attached.
    fn send_with_fds(stream: &UnixStream, bytes: &[u8], fds: &[RawFd]) -> nix::Result<()> {
        let cmsgs: Vec<ControlMessage<'_>> = if fds.is_empty() {
            Vec::new()
        } else {
            vec![ControlMessage::ScmRights(fds)]
        };
        let sent = sendmsg::<()>(
            stream.as_raw_fd(),
            &[IoSlice::new(bytes)],
            &cmsgs,
            MsgFlags::empty(),
            None,
        )?;
        if sent == bytes.len() {
            Ok(())
        } else {
            Err(Errno::EIO)
        }
    }

    /// Receive up to BUF.len() bytes and any descriptors sent with them.
    /// Descriptors are marked close-on-exec at once.
    fn recv_with_fds(stream: &UnixStream, buf: &mut [u8]) -> nix::Result<(usize, Vec<OwnedFd>)> {
        let mut space = cmsg_space!([RawFd; 3]);
        let mut iov = [IoSliceMut::new(buf)];
        let msg = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut space),
            MsgFlags::empty(),
        )?;
        let mut fds = Vec::new();
        for cmsg in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(raw) = cmsg {
                for fd in raw {
                    set_cloexec(fd);
                    fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }
        Ok((msg.bytes, fds))
    }

    /// Ask the daemon at PATH to start LAUNCH.
    ///
    /// STDIO is the descriptors a pipe launch runs on; a PTY launch passes
    /// none.  `None` means nothing was started and the caller should run the
    /// program itself.
    pub(super) fn launch(
        path: &Path,
        launch: &Launch,
        stdio: Option<[BorrowedFd<'_>; 3]>,
    ) -> Option<Started> {
        let mut stream = UnixStream::connect(path).ok()?;
        if !same_user(&stream) {
            return None;
        }
        let payload = rmp_serde::to_vec_named(launch).ok()?;
        let len = u32::try_from(payload.len()).ok()?.to_be_bytes();
        let raw: Vec<RawFd> = stdio
            .map(|fds| fds.iter().map(|fd| fd.as_raw_fd()).collect())
            .unwrap_or_default();
        send_with_fds(&stream, &len, &raw).ok()?;
        stream.write_all(&payload).ok()?;

        let mut reply = [0u8; 1];
        let (n, mut fds) = recv_with_fds(&stream, &mut reply).ok()?;
        match (n, reply[0]) {
            (1, STARTED) => Some(Started::Pipe(stream)),
            (1, PTY_STARTED) if fds.len() == 1 => Some(Started::Pty(stream, fds.remove(0))),
            _ => None,
        }
    }

    /// Wait for the started program's exit code: its status, or 128+signal.
    pub(super) fn wait_status(mut stream: UnixStream) -> u8 {
        let mut code = [0u8; 4];
        match stream.read_exact(&mut code) {
            Ok(()) => i32::from_be_bytes(code).clamp(0, 255) as u8,
            Err(_) => 255,
        }
    }

    /// Point this process's stdio at /dev/null.  The child holds the ssh
    /// pipes now; the client must not keep them open after the child exits.
    fn detach_stdio() {
        if let Ok(null) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
        {
            for fd in 0..3 {
                unsafe { libc::dup2(null.as_raw_fd(), fd) };
            }
        }
    }

    fn stdio_fds() -> [BorrowedFd<'static>; 3] {
        unsafe {
            [
                BorrowedFd::borrow_raw(0),
                BorrowedFd::borrow_raw(1),
                BorrowedFd::borrow_raw(2),
            ]
        }
    }

    /// Plain `tramp-rpc-server`: hand this connection to a server the daemon
    /// starts in the GUI session.  `None` serves it here instead.
    pub(super) fn handoff_server() -> Option<ExitCode> {
        let path = socket_path()?;
        let exe = std::env::current_exe().ok()?;
        let argv = [exe.into_os_string(), OsString::from("--serve")];
        let started = launch(&path, &Launch::here(&argv, None)?, Some(stdio_fds()))?;
        match started {
            Started::Pipe(stream) => {
                detach_stdio();
                Some(ExitCode::from(wait_status(stream)))
            }
            Started::Pty(..) => None,
        }
    }

    fn terminal_size(fd: RawFd) -> Option<(u16, u16)> {
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        (unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == 0)
            .then_some((size.ws_row, size.ws_col))
    }

    /// `run`: start ARGV in the GUI session.  `None` runs it in place.
    pub(super) fn run_in_gui_session(argv: &[OsString]) -> Option<ExitCode> {
        let path = socket_path()?;
        let mut argv = argv.to_vec();
        argv[0] = resolve_program(&argv[0], std::env::var_os("PATH").as_deref());
        let tty = nix::unistd::isatty(std::io::stdin()).unwrap_or(false);
        let pty = if tty { terminal_size(0) } else { None };
        let launch_req = Launch::here(&argv, pty)?;
        match launch(&path, &launch_req, pty.is_none().then(stdio_fds))? {
            Started::Pipe(stream) => {
                detach_stdio();
                Some(ExitCode::from(wait_status(stream)))
            }
            Started::Pty(stream, master) => Some(ExitCode::from(relay(stream, master))),
        }
    }

    static WINCH: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_winch(_: libc::c_int) {
        WINCH.store(true, Ordering::Relaxed);
    }

    fn write_all_fd(fd: BorrowedFd<'_>, mut data: &[u8]) -> bool {
        while !data.is_empty() {
            match nix::unistd::write(fd, data) {
                Ok(0) => return false,
                Ok(n) => data = &data[n..],
                Err(Errno::EINTR | Errno::EAGAIN) => continue,
                Err(_) => return false,
            }
        }
        true
    }

    /// Copy between this process's terminal and the child's until the child
    /// exits, then return its exit code.
    fn relay(stream: UnixStream, master: OwnedFd) -> u8 {
        let stdin = unsafe { BorrowedFd::borrow_raw(0) };
        let stdout = unsafe { BorrowedFd::borrow_raw(1) };
        let saved = tcgetattr(stdin).ok();
        if let Some(saved) = &saved {
            let mut raw = saved.clone();
            cfmakeraw(&mut raw);
            let _ = tcsetattr(stdin, SetArg::TCSANOW, &raw);
        }
        let _ = unsafe {
            sigaction(
                Signal::SIGWINCH,
                &SigAction::new(
                    SigHandler::Handler(on_winch),
                    SaFlags::empty(),
                    SigSet::empty(),
                ),
            )
        };

        let mut buf = vec![0u8; 16 * 1024];
        let mut stdin_open = true;
        loop {
            if WINCH.swap(false, Ordering::Relaxed)
                && let Some((rows, cols)) = terminal_size(0)
            {
                let size = libc::winsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &size) };
            }
            let mut fds = vec![
                PollFd::new(master.as_fd(), PollFlags::POLLIN),
                PollFd::new(stream.as_fd(), PollFlags::POLLIN),
            ];
            if stdin_open {
                fds.push(PollFd::new(stdin, PollFlags::POLLIN));
            }
            match poll(&mut fds, PollTimeout::NONE) {
                Err(Errno::EINTR) => continue,
                Err(_) => break,
                Ok(_) => {}
            }
            let ready = |fd: &PollFd<'_>| {
                fd.revents()
                    .is_some_and(|r| r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP))
            };
            let (master_ready, child_done) = (ready(&fds[0]), ready(&fds[1]));
            let stdin_ready = stdin_open && ready(&fds[2]);
            drop(fds);
            if stdin_ready {
                match nix::unistd::read(stdin, &mut buf) {
                    Ok(0) | Err(_) => stdin_open = false,
                    Ok(n) => {
                        let _ = write_all_fd(master.as_fd(), &buf[..n]);
                    }
                }
            }
            if master_ready {
                match nix::unistd::read(master.as_fd(), &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if !write_all_fd(stdout, &buf[..n]) {
                            break;
                        }
                    }
                }
            }
            if child_done && !master_ready {
                break;
            }
        }
        if let Some(saved) = &saved {
            let _ = tcsetattr(stdin, SetArg::TCSADRAIN, saved);
        }
        drop(master);
        wait_status(stream)
    }

    // ------------------------------------------------------------------
    // Daemon
    // ------------------------------------------------------------------

    /// Serialises descriptor creation and process spawns, so a descriptor
    /// received or created without close-on-exec never leaks into a child
    /// another connection is starting.  A leaked pipe writer would keep an
    /// ssh session open forever.
    static SPAWN: Mutex<()> = Mutex::new(());

    /// A close-on-exec pipe, created under `SPAWN` so a concurrent spawn in
    /// this process cannot inherit it.  Tests run clients and the daemon in
    /// one process; real clients are separate processes.
    #[cfg(test)]
    pub(super) fn cloexec_pipe() -> (OwnedFd, OwnedFd) {
        let _guard = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
        let (r, w) = nix::unistd::pipe().unwrap();
        set_cloexec(r.as_raw_fd());
        set_cloexec(w.as_raw_fd());
        (r, w)
    }

    pub(super) fn daemon(path: &Path) -> ExitCode {
        match bind(path) {
            Ok(listener) => {
                serve(listener);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("tramp-rpc-server daemon: {}: {e}", path.display());
                ExitCode::from(1)
            }
        }
    }

    /// Bind PATH in a directory only this user can enter.
    pub(super) fn bind(path: &Path) -> std::io::Result<UnixListener> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if let Some(dir) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    pub(super) fn serve(listener: UnixListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || {
                if same_user(&stream) {
                    serve_one(stream);
                }
            });
        }
    }

    /// Read a request: the 4-byte length carries the descriptors.
    fn read_request(stream: &mut UnixStream) -> Option<(Launch, Vec<OwnedFd>)> {
        // Wait for the request outside `SPAWN`: a client that connects and
        // sends nothing must not stall every other launch.
        let mut ready = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
        match poll(&mut ready, PollTimeout::from(REQUEST_TIMEOUT_MS)) {
            Ok(1) => {}
            _ => return None,
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(REQUEST_TIMEOUT_MS.into())))
            .ok()?;
        let mut len = [0u8; 4];
        let (n, fds) = {
            let _guard = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
            recv_with_fds(stream, &mut len).ok()?
        };
        if n == 0 {
            return None;
        }
        stream.read_exact(&mut len[n..]).ok()?;
        let len = u32::from_be_bytes(len);
        if len > MAX_REQUEST {
            return None;
        }
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).ok()?;
        stream.set_read_timeout(None).ok()?;
        Some((rmp_serde::from_slice(&payload).ok()?, fds))
    }

    struct Child {
        child: std::process::Child,
        /// A second writer on the child's stdout, watched for the reader
        /// hanging up.  Closed the moment the child exits: as a writer on
        /// the ssh pipe it would otherwise hold the session open.
        stdout_watch: Option<OwnedFd>,
        /// The PTY master to hand back.
        master: Option<OwnedFd>,
    }

    fn spawn(launch: &Launch, fds: Vec<OwnedFd>) -> Option<Child> {
        let program = launch.argv.first()?;
        let mut cmd = Command::new(OsStr::from_bytes(program));
        cmd.args(launch.argv[1..].iter().map(|a| OsStr::from_bytes(a)))
            .env_clear()
            .envs(
                launch
                    .env
                    .iter()
                    .map(|(k, v)| (OsStr::from_bytes(k), OsStr::from_bytes(v))),
            )
            .current_dir(OsStr::from_bytes(&launch.cwd));

        let _guard = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
        let (stdout_watch, master, pty) = match launch.pty {
            None => {
                let [stdin, stdout, stderr]: [OwnedFd; 3] = fds.try_into().ok()?;
                let watch = dup_cloexec(stdout.as_fd()).ok()?;
                cmd.stdin(Stdio::from(stdin))
                    .stdout(Stdio::from(stdout))
                    .stderr(Stdio::from(stderr));
                (Some(watch), None, false)
            }
            Some((rows, cols)) => {
                let size = Winsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                let pair = openpty(&size, None).ok()?;
                set_cloexec(pair.master.as_raw_fd());
                set_cloexec(pair.slave.as_raw_fd());
                cmd.stdin(Stdio::from(pair.slave.try_clone().ok()?))
                    .stdout(Stdio::from(pair.slave.try_clone().ok()?))
                    .stderr(Stdio::from(pair.slave));
                (None, Some(pair.master), true)
            }
        };
        // A session of its own: hanging up one client signals only its
        // child's process group, and the child outlives a daemon restart.
        unsafe {
            cmd.pre_exec(move || {
                nix::unistd::setsid()?;
                if pty && libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().ok()?;
        Some(Child {
            child,
            stdout_watch,
            master,
        })
    }

    fn serve_one(mut stream: UnixStream) {
        let Some((launch, fds)) = read_request(&mut stream) else {
            return;
        };
        let Some(mut child) = spawn(&launch, fds) else {
            let _ = stream.write_all(&[FAILED]);
            return;
        };
        let pid = Pid::from_raw(child.child.id() as i32);
        let replied = match child.master.take() {
            Some(master) => send_with_fds(&stream, &[PTY_STARTED], &[master.as_raw_fd()]),
            None => send_with_fds(&stream, &[STARTED], &[]),
        };
        if replied.is_err() {
            let _ = killpg(pid, Signal::SIGHUP);
        }
        supervise(&stream, pid, child.stdout_watch.as_ref());
        // Close the stdout watch before reporting, so the ssh side sees EOF
        // as soon as the child is gone.
        drop(child.stdout_watch.take());
        let code = match child.child.wait() {
            Ok(status) => status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
            Err(_) => 255,
        };
        let _ = stream.write_all(&code.to_be_bytes());
    }

    /// Wait until PID exits.  When the client disconnects or the reader of
    /// the child's stdout goes away, hang up the child's process group, and
    /// kill it if it is still there after `KILL_GRACE`.
    fn supervise(stream: &UnixStream, pid: Pid, stdout_watch: Option<&OwnedFd>) {
        let Ok(kq) = Kqueue::new() else { return };
        let mut changes = vec![
            KEvent::new(
                pid.as_raw() as usize,
                EventFilter::EVFILT_PROC,
                EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
                FilterFlag::NOTE_EXIT,
                0,
                0,
            ),
            KEvent::new(
                stream.as_raw_fd() as usize,
                EventFilter::EVFILT_READ,
                EvFlags::EV_ADD | EvFlags::EV_CLEAR,
                FilterFlag::empty(),
                0,
                0,
            ),
        ];
        if let Some(fd) = stdout_watch {
            // A low-water mark beyond any buffer keeps the filter quiet
            // while the pipe has room; it still reports EV_EOF.
            changes.push(KEvent::new(
                fd.as_raw_fd() as usize,
                EventFilter::EVFILT_WRITE,
                EvFlags::EV_ADD | EvFlags::EV_CLEAR,
                FilterFlag::NOTE_LOWAT,
                i32::MAX as isize,
                0,
            ));
        }
        let mut events = vec![
            KEvent::new(
                0,
                EventFilter::EVFILT_READ,
                EvFlags::empty(),
                FilterFlag::empty(),
                0,
                0
            );
            4
        ];
        let mut deadline: Option<Instant> = None;
        let mut killed = false;
        loop {
            let timeout = deadline.map(|d| {
                let left = d.saturating_duration_since(Instant::now());
                libc::timespec {
                    tv_sec: left.as_secs() as libc::time_t,
                    tv_nsec: left.subsec_nanos() as libc::c_long,
                }
            });
            let n = match kq.kevent(&changes, &mut events, timeout) {
                Ok(n) => n,
                Err(Errno::EINTR) => continue,
                Err(_) => return,
            };
            changes.clear();
            if n == 0 {
                if !killed {
                    let _ = killpg(pid, Signal::SIGKILL);
                    killed = true;
                }
                deadline = None;
                continue;
            }
            let mut hang_up = false;
            for ev in &events[..n] {
                match ev.filter() {
                    Ok(EventFilter::EVFILT_PROC) => return,
                    Ok(EventFilter::EVFILT_READ) => {
                        if ev.flags().contains(EvFlags::EV_EOF) {
                            hang_up = true;
                            changes.push(KEvent::new(
                                ev.ident(),
                                EventFilter::EVFILT_READ,
                                EvFlags::EV_DELETE,
                                FilterFlag::empty(),
                                0,
                                0,
                            ));
                        } else {
                            let mut sink = [0u8; 64];
                            let _ = (&*stream).read(&mut sink);
                        }
                    }
                    Ok(EventFilter::EVFILT_WRITE) if ev.flags().contains(EvFlags::EV_EOF) => {
                        hang_up = true;
                        changes.push(KEvent::new(
                            ev.ident(),
                            EventFilter::EVFILT_WRITE,
                            EvFlags::EV_DELETE,
                            FilterFlag::empty(),
                            0,
                            0,
                        ));
                    }
                    _ => {}
                }
            }
            if hang_up && deadline.is_none() && !killed {
                let _ = killpg(pid, Signal::SIGHUP);
                deadline = Some(Instant::now() + KILL_GRACE);
            }
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::imp::*;
    use super::resolve_program;
    use serde_bytes::ByteBuf;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    struct Daemon {
        _dir: tempfile::TempDir,
        socket: PathBuf,
    }

    fn start_daemon() -> Daemon {
        // Short path: Unix socket paths are limited to 104 bytes.
        let dir = tempfile::Builder::new()
            .prefix("trg")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("s");
        let listener = bind(&socket).unwrap();
        std::thread::spawn(move || serve(listener));
        Daemon { _dir: dir, socket }
    }

    fn request(argv: &[&str], cwd: &Path, env: &[(&str, &str)], pty: Option<(u16, u16)>) -> Launch {
        Launch {
            argv: argv
                .iter()
                .map(|a| ByteBuf::from(a.as_bytes().to_vec()))
                .collect(),
            cwd: ByteBuf::from(cwd.to_str().unwrap().as_bytes().to_vec()),
            env: env
                .iter()
                .map(|(k, v)| {
                    (
                        ByteBuf::from(k.as_bytes().to_vec()),
                        ByteBuf::from(v.as_bytes().to_vec()),
                    )
                })
                .collect(),
            pty,
        }
    }

    const PATH: (&str, &str) = ("PATH", "/usr/bin:/bin");

    /// Read FD to EOF on a thread; fail the test if EOF does not arrive.
    fn read_to_eof(fd: OwnedFd, within: Duration) -> String {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut file = std::fs::File::from(fd);
            let mut out = Vec::new();
            let _ = file.read_to_end(&mut out);
            let _ = tx.send(out);
        });
        String::from_utf8(rx.recv_timeout(within).expect("EOF did not arrive")).unwrap()
    }

    fn status_within(started: Started, within: Duration) -> u8 {
        let Started::Pipe(stream) = started else {
            panic!("expected a pipe launch")
        };
        // macOS rejects the option once the daemon has closed its end; the
        // status is then already buffered.
        let _ = stream.set_read_timeout(Some(within));
        wait_status(stream)
    }

    fn pipe_launch(daemon: &Daemon, req: &Launch) -> (Started, OwnedFd, OwnedFd) {
        let (in_r, in_w) = cloexec_pipe();
        let (out_r, out_w) = cloexec_pipe();
        let started = launch(
            &daemon.socket,
            req,
            Some([in_r.as_fd(), out_w.as_fd(), out_w.as_fd()]),
        )
        .expect("daemon started the program");
        (started, in_w, out_r)
    }

    fn pid_from(file: &Path) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(text) = std::fs::read_to_string(file)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            assert!(Instant::now() < deadline, "child never wrote its pid");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn gone_within(pid: i32, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if unsafe { libc::kill(pid, 0) } == -1 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn pipe_launch_passes_stdio_cwd_env_and_exit_code() {
        let daemon = start_daemon();
        let cwd = tempfile::tempdir().unwrap();
        let req = request(
            &[
                "/bin/sh",
                "-c",
                "read x; echo \"got:$x:$(pwd -P):$FOO\"; exit 7",
            ],
            cwd.path(),
            &[("FOO", "bar"), PATH],
            None,
        );
        let (started, mut stdin, stdout) = pipe_launch(&daemon, &req);
        {
            let mut w = std::fs::File::from(stdin.try_clone().unwrap());
            w.write_all(b"hi\n").unwrap();
        }
        drop(std::mem::replace(&mut stdin, cloexec_pipe().1));
        // EOF must arrive once the child exits: the daemon may not keep a
        // writer on the client's stdout.
        let out = read_to_eof(stdout, Duration::from_secs(5));
        let real = std::fs::canonicalize(cwd.path()).unwrap();
        assert_eq!(out.trim(), format!("got:hi:{}:bar", real.display()));
        assert_eq!(status_within(started, Duration::from_secs(5)), 7);
    }

    #[test]
    fn signal_exit_maps_to_128_plus_signal() {
        let daemon = start_daemon();
        let req = request(
            &["/bin/sh", "-c", "kill -TERM $$"],
            Path::new("/"),
            &[PATH],
            None,
        );
        let (started, _stdin, _stdout) = pipe_launch(&daemon, &req);
        assert_eq!(status_within(started, Duration::from_secs(5)), 143);
    }

    #[test]
    fn closing_the_stdout_reader_hangs_up_the_child() {
        let daemon = start_daemon();
        let req = request(&["/bin/sleep", "30"], Path::new("/"), &[PATH], None);
        let (started, _stdin, stdout) = pipe_launch(&daemon, &req);
        drop(stdout);
        assert_eq!(
            status_within(started, Duration::from_secs(5)),
            128 + libc::SIGHUP as u8
        );
    }

    #[test]
    fn client_disconnect_hangs_up_the_child() {
        let daemon = start_daemon();
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("echo $$ > '{}'; exec /bin/sleep 30", pid_file.display());
        let req = request(&["/bin/sh", "-c", &script], Path::new("/"), &[PATH], None);
        let (started, _stdin, _stdout) = pipe_launch(&daemon, &req);
        let pid = pid_from(&pid_file);
        drop(started);
        assert!(
            gone_within(pid, Duration::from_secs(5)),
            "child survived the client"
        );
    }

    #[test]
    fn a_child_ignoring_hangup_is_killed_after_the_grace_period() {
        let daemon = start_daemon();
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        // Report the pid only after the trap is in place, so the hangup
        // cannot arrive first.
        let script = format!(
            "trap '' HUP; echo $$ > '{}'; /bin/sleep 30",
            pid_file.display()
        );
        let req = request(&["/bin/sh", "-c", &script], Path::new("/"), &[PATH], None);
        let (started, _stdin, stdout) = pipe_launch(&daemon, &req);
        pid_from(&pid_file);
        drop(stdout);
        let grace = KILL_GRACE + Duration::from_secs(5);
        assert_eq!(status_within(started, grace), 128 + libc::SIGKILL as u8);
    }

    #[test]
    fn a_program_that_cannot_start_is_left_to_the_client() {
        let daemon = start_daemon();
        let req = request(&["/nonexistent/program"], Path::new("/"), &[PATH], None);
        let (in_r, _in_w) = cloexec_pipe();
        let (_out_r, out_w) = cloexec_pipe();
        assert!(
            launch(
                &daemon.socket,
                &req,
                Some([in_r.as_fd(), out_w.as_fd(), out_w.as_fd()])
            )
            .is_none()
        );
    }

    #[test]
    fn a_silent_client_does_not_block_other_launches() {
        let daemon = start_daemon();
        // Connects and never sends a request.
        let _silent = std::os::unix::net::UnixStream::connect(&daemon.socket).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let req = request(&["/bin/sh", "-c", "exit 5"], Path::new("/"), &[PATH], None);
        let (tx, rx) = mpsc::channel();
        let socket = daemon.socket.clone();
        std::thread::spawn(move || {
            let (in_r, _in_w) = cloexec_pipe();
            let (_out_r, out_w) = cloexec_pipe();
            let started = launch(
                &socket,
                &req,
                Some([in_r.as_fd(), out_w.as_fd(), out_w.as_fd()]),
            );
            let _ = tx.send(started.map(|s| status_within(s, Duration::from_secs(5))));
        });
        let status = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a silent client blocked another launch");
        assert_eq!(status, Some(5));
    }

    #[test]
    fn no_daemon_means_run_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let req = request(&["/usr/bin/true"], Path::new("/"), &[PATH], None);
        let (in_r, _in_w) = cloexec_pipe();
        let (_out_r, out_w) = cloexec_pipe();
        assert!(
            launch(
                &dir.path().join("missing"),
                &req,
                Some([in_r.as_fd(), out_w.as_fd(), out_w.as_fd()])
            )
            .is_none()
        );
    }

    fn pty_launch(
        daemon: &Daemon,
        script: &str,
    ) -> (std::os::unix::net::UnixStream, std::fs::File) {
        let req = request(
            &["/bin/sh", "-c", script],
            Path::new("/"),
            &[PATH, ("TERM", "dumb")],
            Some((24, 80)),
        );
        match launch(&daemon.socket, &req, None).expect("daemon started the program") {
            Started::Pty(stream, master) => (stream, std::fs::File::from(master)),
            Started::Pipe(_) => panic!("expected a PTY launch"),
        }
    }

    /// Read MASTER until it contains NEEDLE.
    fn read_until(master: &mut std::fs::File, needle: &str) -> String {
        let (tx, rx) = mpsc::channel();
        let mut reader = master.try_clone().unwrap();
        let needle = needle.to_string();
        std::thread::spawn(move || {
            let mut seen = String::new();
            let mut buf = [0u8; 1024];
            while !seen.contains(&needle) {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
            let _ = tx.send(seen);
        });
        rx.recv_timeout(Duration::from_secs(5))
            .expect("terminal output did not arrive")
    }

    #[test]
    fn pty_launch_gives_the_child_a_terminal_of_the_requested_size() {
        let daemon = start_daemon();
        let (stream, mut master) = pty_launch(&daemon, "[ -t 0 ] && echo TTY; stty size; exit 3");
        let out = read_until(&mut master, "24 80");
        assert!(out.contains("TTY"), "{out:?}");
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        assert_eq!(wait_status(stream), 3);
    }

    #[test]
    fn pty_interrupt_reaches_the_child() {
        let daemon = start_daemon();
        let (stream, mut master) = pty_launch(
            &daemon,
            "trap 'echo INTERRUPTED; exit 130' INT; echo ready; while :; do /bin/sleep 0.1; done",
        );
        read_until(&mut master, "ready");
        master.write_all(b"\x03").unwrap();
        assert!(read_until(&mut master, "INTERRUPTED").contains("INTERRUPTED"));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        assert_eq!(wait_status(stream), 130);
    }

    #[test]
    fn launch_request_round_trips() {
        let req = request(&["a", "b"], Path::new("/x"), &[("K", "V")], Some((1, 2)));
        let bytes = rmp_serde::to_vec_named(&req).unwrap();
        assert_eq!(rmp_serde::from_slice::<Launch>(&bytes).unwrap(), req);
    }

    #[test]
    fn programs_resolve_against_the_client_path() {
        let resolved = resolve_program(&OsString::from("sh"), Some("/nonexistent:/bin".as_ref()));
        assert_eq!(resolved, OsString::from("/bin/sh"));
        assert_eq!(
            resolve_program(&OsString::from("./x"), Some("/bin".as_ref())),
            OsString::from("./x")
        );
        assert_eq!(
            resolve_program(&OsString::from("no-such-tool"), Some("/bin".as_ref())),
            OsString::from("no-such-tool")
        );
    }
}
