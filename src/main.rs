#![feature(ptr_metadata)]

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::mem;
use std::num::NonZeroUsize;
use std::ops::Drop;
use std::os::fd::AsRawFd;
use std::process::{Command, ExitCode, Stdio};
use std::ptr::{self, NonNull};
use std::time::{Duration, Instant};

use clap::Parser;
use lazy_static::lazy_static;

use clip::ClipboardProvider;
use clipboard as clip;

use nix::libc::{c_int, c_void};
use nix::poll;
use nix::sys::mman;
use nix::sys::signal;
use nix::sys::stat;
use nix::unistd;
use nix::unistd::alarm;

struct ProtectedBox<T: ?Sized> {
    ptr: NonNull<T>,
    _marker: PhantomData<T>,
}

impl<T> ProtectedBox<T> {
    pub fn new(val: T) -> ProtectedBox<T> {
        let bx = unsafe { ProtectedBox::new_from_ref_copy(&val) };
        mem::forget(val);
        bx
    }
}

impl<T: ?Sized> ProtectedBox<T> {
    pub unsafe fn new_from_ref_copy(val: &T) -> ProtectedBox<T> {
        let t_size = mem::size_of_val(val);
        // TODO: Dynamic size
        assert!(t_size < 4096);

        let mmap_ptr: *mut c_void = match unsafe {
            mman::mmap(
                None,
                NonZeroUsize::new(4096).unwrap(),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_PRIVATE
                    | mman::MapFlags::MAP_ANONYMOUS
                    | mman::MapFlags::MAP_LOCKED,
                -1,
                0,
            )
        } {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to allocate memory for ProtectedBox: {e:?}"),
        };

        unsafe {
            ptr::copy_nonoverlapping(val as *const T as *const u8, mmap_ptr as *mut u8, t_size)
        }

        let fattened_ptr = unsafe {
            // let slice: *mut [()] = core::slice::from_raw_parts_mut(mmap_ptr as *mut (), t_size);
            // let metadata = ptr::metadata(slice);
            ptr::from_raw_parts_mut(
                mmap_ptr as *mut (),
                mem::transmute_copy::<usize, _>(&t_size),
            )
        };

        ProtectedBox {
            ptr: NonNull::new(fattened_ptr).expect("null pointer"),
            _marker: PhantomData,
        }
    }
}

impl<T: ?Sized> Drop for ProtectedBox<T> {
    fn drop(&mut self) {
        unsafe {
            match mman::munmap(self.ptr.as_ptr() as *mut c_void, 4096) {
                Ok(_) => (),
                Err(_) => panic!("Failed to drop protected memory!"),
            }
        }
    }
}

/*impl<T> From<T> for ProtectedBox<T> {
    fn from(val: T) -> ProtectedBox<T> {
        ProtectedBox::new(val)
    }
}*/

impl<T: ?Sized> AsRef<T> for ProtectedBox<T> {
    fn as_ref(&self) -> &T {
        unsafe { &*(self.ptr.as_ptr() as *const T) }
    }
}

enum PublicPacketHeader {
    OpenWindow = 0,
}

impl PublicPacketHeader {
    pub fn packet_len(&self) -> usize {
        match self {
            PublicPacketHeader::OpenWindow => 1,
        }
    }
}

enum EntryMenu {
    CopyUsername,
    CopyPassword,
}

fn run_rofi(key_data: &mut MasterKeyData, last_entry: &mut Option<LastOpenEntry>) {
    fn open_entry_list_menu(
        key_data: &mut MasterKeyData,
        last_entry: &mut Option<LastOpenEntry>,
        passwd: &str,
    ) {
        let password_entry_name: String = match last_entry {
            Some(LastOpenEntry { time, name })
                if time.elapsed() < Duration::from_secs(ARGS.open_last_timeout) =>
            {
                *time = Instant::now();
                name.clone()
            }
            _ => {
                let mut keepassxc_entries_cmd = Command::new("/usr/bin/keepassxc-cli")
                    .arg("ls")
                    .arg(&*ARGS.database)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("failed to spawn child process");
                keepassxc_entries_cmd
                    .stdin
                    .as_mut()
                    .expect("couldn't write to stdin of child process")
                    .write_all(passwd.as_bytes())
                    .expect("couldn't write to stdin of child process");
                let keepassxc_entries_exit_code = keepassxc_entries_cmd
                    .wait()
                    .expect("failed to start keepasscx-cli")
                    .code()
                    .expect("failed to acquire exit code.");
                if keepassxc_entries_exit_code != 0 {
                    eprintln!(
                        "[ERR] keepassxc-cli exited with status code {keepassxc_entries_exit_code}"
                    );
                    return;
                }

                let mut keepassxc_entries_stdout = keepassxc_entries_cmd
                    .stdout
                    .expect("couldn't read stdout of child process");
                let mut keepassxc_entries = String::new();
                keepassxc_entries_stdout
                    .read_to_string(&mut keepassxc_entries)
                    .expect("couldn't read stdout of child process");

                let mut rofi_entries_proc = Command::new("/usr/bin/rofi")
                    .arg("-dmenu")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("failed to spawn child process");

                let rofi_entries_proc_stdin = rofi_entries_proc
                    .stdin
                    .as_mut()
                    .expect("couldn't write to stdin of child process");
                rofi_entries_proc_stdin
                    .write_all(keepassxc_entries.as_bytes())
                    .expect("couldn't write to stdin of child process");
                let rofi_entries_proc_exit_code = rofi_entries_proc
                    .wait()
                    .expect("failed to start child process")
                    .code()
                    .expect("failed to acquire exit code");
                if rofi_entries_proc_exit_code != 0 {
                    if rofi_entries_proc_exit_code != 1 {
                        eprintln!(
                            "[WARN] Rofi exited with status code {rofi_entries_proc_exit_code}"
                        );
                    }
                    return;
                }
                let mut rofi_entries_proc_stdout = rofi_entries_proc
                    .stdout
                    .expect("couldn't read stdout of child process");
                let mut password_entry_name = String::new();
                rofi_entries_proc_stdout
                    .read_to_string(&mut password_entry_name)
                    .expect("couldn't read stdout of child process");
                // Remove leading newline
                password_entry_name.pop();
                *last_entry = Some(LastOpenEntry {
                    name: password_entry_name.clone(),
                    time: Instant::now(),
                });
                password_entry_name
            }
        };

        open_entry_menu(key_data, last_entry, &password_entry_name, passwd);
    }

    fn open_entry_menu(
        key_data: &mut MasterKeyData,
        last_entry: &mut Option<LastOpenEntry>,
        entry_name: &str,
        passwd: &str,
    ) {
        let mut rofi_copy_mode_proc = Command::new("/usr/bin/rofi")
            .arg("-dmenu")
            .arg("-p")
            .arg(entry_name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn child process");
        let rofi_copy_mode_stdin = rofi_copy_mode_proc
            .stdin
            .as_mut()
            .expect("couldn't write to stdin of child process");
        rofi_copy_mode_stdin
            .write_all(b"Copy username\nCopy password\nGo back")
            .expect("couldn't write to stdin of child process");
        let rofi_copy_mode_exit_code = rofi_copy_mode_proc
            .wait()
            .expect("failed to spawn child process")
            .code()
            .expect("failed to acquire exit code");

        if rofi_copy_mode_exit_code != 0 {
            if rofi_copy_mode_exit_code != 1 {
                eprintln!("[WARN] Rofi exited with status code {rofi_copy_mode_exit_code}");
            }
            return;
        }

        let mut rofi_copy_mode_stdout = rofi_copy_mode_proc
            .stdout
            .expect("couldn't read stdout of child process");
        let mut rofi_copy_mode_str = String::new();
        rofi_copy_mode_stdout
            .read_to_string(&mut rofi_copy_mode_str)
            .expect("couldn't read stdout of child process");

        // Remove leading newline
        rofi_copy_mode_str.pop();
        let sel = match &*rofi_copy_mode_str {
            "Copy username" => EntryMenu::CopyUsername,
            "Copy password" => EntryMenu::CopyPassword,
            "Go back" => {
                let mut fake_last_open_entry: Option<LastOpenEntry> = None;
                open_entry_list_menu(key_data, &mut fake_last_open_entry, passwd);
                *last_entry = fake_last_open_entry;
                return;
            }
            _ => unreachable!(),
        };

        copy_menu_selection_to_clipboard(entry_name, passwd, sel);
    }

    fn copy_menu_selection_to_clipboard(entry_name: &str, passwd: &str, sel: EntryMenu) {
        let mut keepassxc_info_proc = Command::new("/usr/bin/keepassxc-cli")
            .arg("show")
            .arg("--show-protected")
            .arg(&*ARGS.database)
            .arg(entry_name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn child process");

        let keepassxc_info_stdin = keepassxc_info_proc
            .stdin
            .as_mut()
            .expect("couldn't write to stdin of child process");
        keepassxc_info_stdin
            .write_all(passwd.as_bytes())
            .expect("couldn't write to stdin of child process");
        let keepassxc_info_stdout = keepassxc_info_proc
            .stdout
            .as_mut()
            .expect("couldn't read stdout of child process");
        let mut keepassxc_entry_info = String::new();
        keepassxc_info_stdout
            .read_to_string(&mut keepassxc_entry_info)
            .expect("couldn't read stdout of child process");
        // Remove leading newline
        keepassxc_entry_info.pop();

        let map = match parse_entry_info(&keepassxc_entry_info) {
            Some(map) => map,
            None => {
                eprintln!("[ERR] Failed to parse entry keepassxc info.");
                return;
            }
        };

        let value_to_copy = match sel {
            EntryMenu::CopyUsername => map["UserName"],
            EntryMenu::CopyPassword => map["Password"],
        };

        let mut ctx: clip::ClipboardContext = clip::ClipboardProvider::new().unwrap();
        ctx.set_contents(value_to_copy.to_string()).unwrap();
        register_clear_clipboard_alarm();
    }

    fn open_passwd_input_menu(
        key_data: &mut MasterKeyData,
        last_entry: &mut Option<LastOpenEntry>,
    ) {
        let passwd = match &key_data.key {
            Some(passwd) => {
                key_data.last_use = Instant::now();
                String::from(passwd.as_ref())
            }
            None => {
                let rofi_enter_passwd = Command::new("/usr/bin/rofi")
                    .arg("-dmenu")
                    .arg("-password")
                    .args(["-p", "Password"])
                    .output()
                    .expect("failed to spawn child process");
                let exit_code = rofi_enter_passwd
                    .status
                    .code()
                    .expect("failed to acquire exit code.");

                if exit_code != 0 {
                    if exit_code != 1 {
                        eprintln!("[WARN] Rofi exited with status code {exit_code}");
                    }
                    return;
                }

                let str: &str = &String::from_utf8_lossy(rofi_enter_passwd.stdout.as_slice());
                key_data.last_use = Instant::now();
                unsafe {
                    key_data.key = Some(ProtectedBox::new_from_ref_copy(str));
                }
                String::from(str)
            }
        };

        open_entry_list_menu(key_data, last_entry, &passwd);
    }

    // TODO: Replace all panics with returns and log to stderr.
    open_passwd_input_menu(key_data, last_entry);
}

extern "C" fn handle_clear_clipboard_(_: c_int) {
    let mut ctx: clip::ClipboardContext = clip::ClipboardProvider::new().unwrap();
    ctx.set_contents("".to_string()).unwrap();
    eprintln!("[INFO] Cleared clipboard");
}

fn register_clear_clipboard_alarm() {
    alarm::set(ARGS.timeout as u32);
    let sa = signal::SigAction::new(
        signal::SigHandler::Handler(handle_clear_clipboard_),
        signal::SaFlags::SA_RESTART,
        signal::SigSet::empty(),
    );
    unsafe {
        match signal::sigaction(signal::Signal::SIGALRM, &sa) {
            Ok(_) => (),
            Err(e) => eprintln!("[ERR] Failed to register alarm to clear clipboard: {e:?}"),
        }
    }
}

fn parse_entry_info(input: &str) -> Option<HashMap<&str, &str>> {
    let mut map = HashMap::new();
    for line in input.lines() {
        let Some((key, value)) = line.split_once(": ") else {
            return None;
        };

        map.insert(key, value);
    }
    Some(map)
}

fn recv_fifo(
    buf: &mut Vec<u8>,
    key_data: &mut MasterKeyData,
    last_entry: &mut Option<LastOpenEntry>,
) {
    if buf[0] == PublicPacketHeader::OpenWindow as u8
        && buf.len() == PublicPacketHeader::OpenWindow.packet_len()
    {
        run_rofi(key_data, last_entry);
    } else if buf.len() > 32 {
        eprintln!("Received unknown data")
    } else {
        eprintln!("Received unknown data: {buf:?}");
    }

    buf.clear();
}

fn open_fifo() -> Option<File> {
    match OpenOptions::new()
        .write(false)
        .read(true)
        .create_new(false)
        .open(&*ARGS.path)
    {
        Ok(f) => Some(f),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            eprintln!("[WARN] FIFO was removed while waiting for sender.");
            None
        }
        Err(e) => panic!("Unknown error while opening FIFO: {e:?}"),
    }
}

extern "C" fn fifo_delete_handler_(_sig: c_int) {
    match fs::remove_file(&*ARGS.path) {
        Ok(_) => (),
        Err(e) => eprintln!("[ERR] Failed to delete FIFO: {e:?}"),
    }
}

fn register_fifo_delete_sigaction() {
    unsafe {
        match signal::sigaction(
            signal::Signal::SIGINT,
            &signal::SigAction::new(
                signal::SigHandler::Handler(fifo_delete_handler_),
                signal::SaFlags::empty(),
                signal::SigSet::empty(),
            ),
        ) {
            Ok(_) => (),
            Err(e) => eprintln!("[ERR] Failed to register signal handler: {e:?}"),
        }
    }
}

#[derive(Parser, Debug)]
struct Args {
    /// Path to place FIFO pipe
    #[arg(short, long, default_value_t = String::from("/tmp/passwd-daemon"))]
    path: String,
    /// Timeout in seconds before master password is discarded
    #[arg(short, long, default_value_t = 30)]
    timeout: u64,
    /// Timeout in seconds where the last opened entry will be automatically opened
    #[arg(short, long, default_value_t = 20)]
    open_last_timeout: u64,
    /// Password database path
    #[arg(short, long)]
    database: String,
}

lazy_static! {
    static ref ARGS: Args = Args::parse();
}

struct MasterKeyData {
    key: Option<ProtectedBox<str>>,
    last_use: Instant,
}

#[derive(Clone)]
struct LastOpenEntry {
    name: String,
    time: Instant,
}

fn main() -> ExitCode {
    match unistd::mkfifo(&*ARGS.path, stat::Mode::S_IRUSR.union(stat::Mode::S_IWUSR)) {
        Ok(_) => eprintln!("[INFO] Created FIFO at {}", ARGS.path),
        Err(e) => {
            eprintln!("[ERR] Failed to create FIFO at {}: {:?}", ARGS.path, e);
            return ExitCode::from(1);
        }
    }

    // Register sigaction to delete the FIFO pipe when the program exits.
    register_fifo_delete_sigaction();

    let mut key_data = MasterKeyData {
        key: None,
        last_use: Instant::now(),
    };
    let mut last_entry: Option<LastOpenEntry> = None;

    let mut fifo = match open_fifo() {
        Some(f) => f,
        None => return ExitCode::from(1),
    };

    let mut fifo_packets = Vec::new();
    loop {
        let mut pollfds = [poll::PollFd::new(fifo.as_raw_fd(), poll::PollFlags::POLLIN)];
        let mut buf = [0; 128];

        // Leave some room for inaccuracy in poll and Instant::elapsed
        const TIMEOUT_EPSILON: u64 = 1;

        let timeout = ARGS.timeout * 1000;
        assert!(timeout + TIMEOUT_EPSILON < c_int::max_value() as u64);

        // Poll blocks for all file descriptors while waiting for the POLLIN event, or an error.

        // TODO:
        // The timeout likely wont ever occur because most of the time is spent waiting on open(), not on read().
        // This is OK though, because it will reset it next time it it accessed, just not exactly when the timeout ends.
        match poll::poll(&mut pollfds, (TIMEOUT_EPSILON + timeout) as c_int) {
            Err(e) => eprintln!("Error in poll: {e:?}"),
            Ok(n_events) => {
                if key_data.last_use.elapsed() >= Duration::from_millis(timeout) {
                    key_data.key = None;
                }

                let mut current_event_count = 0;

                // Check for events in each PollFd
                for pollfd in &mut pollfds {
                    let revents = match pollfd.revents() {
                        Some(revents) => revents,
                        None => {
                            eprintln!(
                                "[ERR] Incompatible kernel version. (unrecognized revent in poll)"
                            );
                            return ExitCode::from(1);
                        }
                    };

                    if revents != poll::PollFlags::empty() {
                        current_event_count += 1;
                    }

                    // Can we read from this file descriptor?
                    if revents.intersects(poll::PollFlags::POLLIN) {
                        match fifo.read(&mut buf) {
                            Err(e) => eprintln!("Error reading pipe: {e:?}"),
                            Ok(0) => unreachable!("No data to read but poll emitted POLLIN?"),
                            Ok(n) => {
                                // If this is the FIFO pipe, the recv_fifo function will handle it.
                                if pollfd.as_raw_fd() == fifo.as_raw_fd() {
                                    fifo_packets.extend_from_slice(&buf[0..n]);
                                    recv_fifo(&mut fifo_packets, &mut key_data, &mut last_entry);
                                } else {
                                    unreachable!()
                                }
                            }
                        }
                    }

                    // When hang-up is received we close the pipe and wait for another sender.
                    if revents.intersects(poll::PollFlags::POLLHUP) {
                        // FIXME: Should you do it this way?
                        drop(fifo);
                        fifo = match open_fifo() {
                            Some(f) => f,
                            None => return ExitCode::from(1),
                        };
                        *pollfd = poll::PollFd::new(fifo.as_raw_fd(), poll::PollFlags::POLLIN);
                    }

                    // There are no more events left.
                    if current_event_count == n_events {
                        break;
                    }
                }
            }
        }
    }
}
