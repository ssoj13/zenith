/*!
 * Copyright 2019-2026, Benjamin Vaisvil and the zenith contributors
 */

use crate::metrics::ProcessTableSortBy;

#[cfg(target_os = "macos")]
use libc::{c_int, c_void, pid_t};
#[cfg(unix)]
use libc::{getpriority, id_t, setpriority};

#[cfg(target_os = "linux")]
use linux_taskstats::Client;
#[cfg(target_os = "linux")]
use procfs;

use std::cmp::Ordering;
#[cfg(target_os = "linux")]
use std::cmp::Ordering::Equal;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::Process;
use sysinfo::ProcessStatus;

use chrono::prelude::DateTime;
use chrono::Duration as CDuration;
use chrono::Local;



#[cfg(target_os = "macos")]
const PROC_PIDTASKINFO: c_int = 4;

#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcTaskInfo {
    pti_virtual_size: u64,
    pti_resident_size: u64,
    pti_total_user: u64,
    pti_total_system: u64,
    pti_threads_user: u64,
    pti_threads_system: u64,
    pti_policy: i32,
    pti_faults: i32,
    pti_pageins: i32,
    pti_cow_faults: i32,
    pti_messages_sent: i32,
    pti_messages_received: i32,
    pti_syscalls_mach: i32,
    pti_syscalls_unix: i32,
    pti_csw: i32,
    pti_threadnum: i32,
    pti_numrunning: i32,
    pti_priority: i32,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn proc_pidinfo(
        pid: pid_t,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

/*
 * Sysinfo doesn't get number of threads, priority or nice
 * this function makes a syscall to get that info
 */
#[cfg(target_os = "macos")]
fn get_macos_process_info(pid: i32) -> Option<ProcTaskInfo> {
    use std::mem;

    // Get thread count and priority using proc_pidinfo
    let mut task_info: ProcTaskInfo = unsafe { mem::zeroed() };
    let size = mem::size_of::<ProcTaskInfo>() as c_int;

    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTASKINFO,
            0,
            &mut task_info as *mut _ as *mut c_void,
            size,
        )
    };
    if ret > 0 {
        Some(task_info)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn get_priority(pid: u32) -> i32 {
    // have to reset errno before calling getpriority
    unsafe { *libc::__error() = 0 };
    let nice = unsafe { getpriority(0, pid) };
    if nice == -1 && unsafe { *libc::__error() } != 0 {
        0 // Error occurred, use default
    } else {
        nice
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct ZProcess {
    pub pid: u32,
    pub uid: u32,
    pub user_name: String,
    pub memory: u64,
    pub cpu_usage: f32,
    pub cum_cpu_usage: f64,
    pub command: Vec<String>,
    pub exe: String,
    pub status: ProcessStatus,
    pub name: String,
    pub priority: i32,
    pub nice: i32,
    pub virtual_memory: u64,
    pub threads_total: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub prev_read_bytes: u64,
    pub prev_write_bytes: u64,
    pub last_updated: SystemTime,
    pub end_time: Option<u64>,
    pub start_time: u64,
    pub gpu_usage: u64,
    pub fb_utilization: u64,
    pub enc_utilization: u64,
    pub dec_utilization: u64,
    pub sm_utilization: u64,
    pub io_delay: Duration,
    pub swap_delay: Duration,
    pub prev_io_delay: Duration,
    pub prev_swap_delay: Duration,
}

#[cfg(target_os = "macos")]
pub fn set_addl_task_info(zprocess: &mut ZProcess) {
    let pid_i32 = zprocess.pid.try_into();
    if let Ok(pid) = pid_i32 {
        let task_info = get_macos_process_info(pid);
        if let Some(ti) = task_info {
            zprocess.priority = ti.pti_priority;
            zprocess.nice = get_priority(zprocess.pid);
            zprocess.threads_total = ti.pti_threadnum as u64;
        }
    }
}

#[cfg(target_os = "linux")]
pub fn set_addl_task_info(zprocess: &mut ZProcess) {
    let pid_i32 = zprocess.pid.try_into();
    if let Ok(pid) = pid_i32 {
        if let Ok(proc) = procfs::process::Process::new(pid) {
            if let Ok(stat) = proc.stat() {
                zprocess.priority = stat.priority as i32;
                zprocess.nice = stat.nice as i32;
                zprocess.threads_total = stat.num_threads as u64;
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub fn set_addl_task_info(_zprocess: &mut ZProcess) {
    // Thread count and priority info not yet implemented for Windows
}

impl ZProcess {
    pub fn from_user_and_process(user_name: String, process: &Process) -> Self {
        let disk_usage = process.disk_usage();

        let mut zp = ZProcess {
            uid: {
                #[cfg(unix)]
                { process.user_id().map(|uid| **uid).unwrap_or(0) }
                #[cfg(not(unix))]
                { 0 }
            },
            user_name,
            pid: process.pid().as_u32(),
            memory: process.memory(),
            cpu_usage: process.cpu_usage(),
            command: process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect(),
            status: process.status(),
            exe: process
                .exe()
                .map(|p| format!("{}", p.display()))
                .unwrap_or_default(),
            name: process.name().to_string_lossy().to_string(),
            cum_cpu_usage: process.cpu_usage() as f64,
            priority: 0, // process.priority,
            nice: 0,     // process.nice,
            virtual_memory: process.virtual_memory(),
            threads_total: 0, // process.threads_total,
            read_bytes: disk_usage.total_read_bytes,
            write_bytes: disk_usage.total_written_bytes,
            prev_read_bytes: disk_usage.total_read_bytes,
            prev_write_bytes: disk_usage.total_written_bytes,
            last_updated: SystemTime::now(),
            end_time: None,
            start_time: process.start_time(),
            gpu_usage: 0,
            fb_utilization: 0,
            enc_utilization: 0,
            dec_utilization: 0,
            sm_utilization: 0,
            io_delay: Duration::from_nanos(0),
            swap_delay: Duration::from_nanos(0),
            prev_io_delay: Duration::from_nanos(0),
            prev_swap_delay: Duration::from_nanos(0),
        };
        set_addl_task_info(&mut zp);

        zp
    }
    pub fn get_read_bytes_sec(&self, tick_rate: &Duration) -> f64 {
        debug!(
            "Pid {:?} Read {:?} Prev {:?}",
            self.pid, self.read_bytes, self.prev_read_bytes
        );
        (self.read_bytes - self.prev_read_bytes) as f64 / tick_rate.as_secs_f64()
    }
    pub fn get_write_bytes_sec(&self, tick_rate: &Duration) -> f64 {
        debug!(
            "Pid {:?} Write {:?} Prev {:?}",
            self.pid, self.write_bytes, self.prev_write_bytes
        );
        (self.write_bytes - self.prev_write_bytes) as f64 / tick_rate.as_secs_f64()
    }

    #[cfg(unix)]
    pub async fn suspend(&self) -> String {
        let result = unsafe { libc::kill(self.pid as i32, libc::SIGSTOP) };
        if result == 0 { "Signal Sent.".into() } else { "Failed to suspend process.".into() }
    }

    #[cfg(target_os = "windows")]
    pub async fn suspend(&self) -> String {
        "Suspend not supported on Windows.".into()
    }

    #[cfg(unix)]
    pub async fn resume(&self) -> String {
        let result = unsafe { libc::kill(self.pid as i32, libc::SIGCONT) };
        if result == 0 { "Signal Sent.".into() } else { "Failed to resume process.".into() }
    }

    #[cfg(target_os = "windows")]
    pub async fn resume(&self) -> String {
        "Resume not supported on Windows.".into()
    }

    #[cfg(unix)]
    pub async fn kill(&self) -> String {
        let result = unsafe { libc::kill(self.pid as i32, libc::SIGKILL) };
        if result == 0 { "Signal Sent.".into() } else { "Failed to kill process.".into() }
    }

    #[cfg(target_os = "windows")]
    pub async fn kill(&self) -> String {
        win_terminate_process(self.pid)
    }

    #[cfg(unix)]
    pub async fn terminate(&self) -> String {
        let result = unsafe { libc::kill(self.pid as i32, libc::SIGTERM) };
        if result == 0 { "Signal Sent.".into() } else { "Failed to terminate process.".into() }
    }

    #[cfg(target_os = "windows")]
    pub async fn terminate(&self) -> String {
        win_terminate_process(self.pid)
    }

    pub fn nice(&mut self) -> String {
        self.set_priority(19)
    }

    pub fn get_run_duration(&self) -> CDuration {
        let start_time = DateTime::<Local>::from(UNIX_EPOCH + Duration::from_secs(self.start_time));
        let et = match self.end_time {
            Some(t) => DateTime::<Local>::from(UNIX_EPOCH + Duration::from_secs(t)),
            None => Local::now(),
        };
        et - start_time
    }

    #[cfg(target_os = "linux")]
    pub fn get_io_wait(&self, tick_rate: &Duration) -> f64 {
        ((self.io_delay.as_secs_f64() - self.prev_io_delay.as_secs_f64()) / tick_rate.as_secs_f64())
            * 100.0
    }

    #[cfg(target_os = "linux")]
    pub fn get_total_io_wait(&self) -> f64 {
        let process_duration = self
            .get_run_duration()
            .to_std()
            .expect("Duration out of expected range!");
        (self.io_delay.as_secs_f64() / process_duration.as_secs_f64()) * 100.0
    }

    #[cfg(target_os = "linux")]
    pub fn get_swap_wait(&self, tick_rate: &Duration) -> f64 {
        ((self.swap_delay.as_secs_f64() - self.prev_swap_delay.as_secs_f64())
            / tick_rate.as_secs_f64())
            * 100.0
    }

    #[cfg(target_os = "linux")]
    pub fn get_total_swap_wait(&self) -> f64 {
        let process_duration = self
            .get_run_duration()
            .to_std()
            .expect("Duration out of expected range!");
        (self.swap_delay.as_secs_f64() / process_duration.as_secs_f64()) * 100.0
    }

    #[cfg(target_os = "linux")]
    pub fn update_delay(&mut self, client: &Option<Client>) {
        debug!("Getting Task Stats for {}", self.pid);
        if let Some(c) = client {
            let stats_result = c.pid_stats(self.pid as u32);
            match stats_result {
                Ok(s) => {
                    self.prev_io_delay = self.io_delay;
                    self.prev_swap_delay = self.swap_delay;
                    self.io_delay = s.delays.blkio.delay_total;
                    self.swap_delay = s.delays.swapin.delay_total;
                    debug!(
                        "Pid: {} io_delay: {} swap_delay: {}",
                        self.pid,
                        self.io_delay.as_secs(),
                        self.swap_delay.as_secs()
                    );
                }
                Err(_) => debug!("Couldn't get stats for {}", self.pid),
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn set_priority(&mut self, priority: i32) -> String {
        let mut result = unsafe { setpriority(0, self.pid as id_t, priority) };

        if result < 0 {
            String::from("Couldn't set priority.")
        } else {
            unsafe {
                result = getpriority(0, self.pid as id_t);
            }
            self.priority = result + 20;
            self.nice = result;
            String::from("Priority Set.")
        }
    }

    #[cfg(target_os = "macos")]
    pub fn set_priority(&mut self, priority: i32) -> String {
        let result = unsafe { setpriority(0, self.pid as id_t, priority) };
        if result < 0 {
            String::from("Couldn't set priority.")
        } else {
            String::from("Priority Set.")
        }
    }

    #[cfg(target_os = "windows")]
    pub fn set_priority(&mut self, _priority: i32) -> String {
        String::from("Set priority not supported on Windows.")
    }

    pub fn set_end_time(&mut self) {
        if self.end_time.is_none() {
            self.end_time = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(t) => Some(t.as_secs()),
                Err(_) => panic!("System time before unix epoch??"),
            };
        }
    }

    #[cfg(all(not(feature = "nvidia"), not(target_os = "linux")))]
    /// returns a pointer to a comparator function, not a closure
    pub fn field_comparator(
        sortfield: ProcessTableSortBy,
    ) -> fn(&Self, &Self, &Duration) -> Ordering {
        match sortfield {
            ProcessTableSortBy::Cpu => |pa, pb, _tick| pa.cpu_usage.total_cmp(&pb.cpu_usage),
            ProcessTableSortBy::Mem => |pa, pb, _tick| pa.memory.cmp(&pb.memory),
            ProcessTableSortBy::MemPerc => |pa, pb, _tick| pa.memory.cmp(&pb.memory),
            ProcessTableSortBy::User => |pa, pb, _tick| pa.user_name.cmp(&pb.user_name),
            ProcessTableSortBy::Pid => |pa, pb, _tick| pa.pid.cmp(&pb.pid),
            ProcessTableSortBy::Status => {
                |pa, pb, _tick| pa.status.to_single_char().cmp(pb.status.to_single_char())
            }
            ProcessTableSortBy::Priority => |pa, pb, _tick| pa.priority.cmp(&pb.priority),
            ProcessTableSortBy::Nice => |pa, pb, _tick| pa.nice.cmp(&pb.nice),
            ProcessTableSortBy::Virt => |pa, pb, _tick| pa.virtual_memory.cmp(&pb.virtual_memory),
            ProcessTableSortBy::Cmd => |pa, pb, _tick| pa.name.cmp(&pb.name),
            ProcessTableSortBy::DiskRead => |pa, pb, tick| {
                pa.get_read_bytes_sec(tick)
                    .total_cmp(&pb.get_read_bytes_sec(tick))
            },
            ProcessTableSortBy::DiskWrite => |pa, pb, tick| {
                pa.get_write_bytes_sec(tick)
                    .total_cmp(&pb.get_write_bytes_sec(tick))
            },
        }
    }

    #[cfg(all(feature = "nvidia", not(target_os = "linux")))]
    /// returns a pointer to a comparator function, not a closure
    pub fn field_comparator(
        sortfield: ProcessTableSortBy,
    ) -> fn(&Self, &Self, &Duration) -> Ordering {
        match sortfield {
            ProcessTableSortBy::Cpu => {
                |pa, pb, _tick| pa.cpu_usage.partial_cmp(&pb.cpu_usage).unwrap_or(Equal)
            }
            ProcessTableSortBy::Mem => |pa, pb, _tick| pa.memory.cmp(&pb.memory),
            ProcessTableSortBy::MemPerc => |pa, pb, _tick| pa.memory.cmp(&pb.memory),
            ProcessTableSortBy::User => |pa, pb, _tick| pa.user_name.cmp(&pb.user_name),
            ProcessTableSortBy::Pid => |pa, pb, _tick| pa.pid.cmp(&pb.pid),
            ProcessTableSortBy::Status => {
                |pa, pb, _tick| pa.status.to_single_char().cmp(pb.status.to_single_char())
            }
            ProcessTableSortBy::Priority => |pa, pb, _tick| pa.priority.cmp(&pb.priority),
            ProcessTableSortBy::Nice => {
                |pa, pb, _tick| pa.priority.partial_cmp(&pb.nice).unwrap_or(Equal)
            }
            ProcessTableSortBy::Virt => |pa, pb, _tick| pa.virtual_memory.cmp(&pb.virtual_memory),
            ProcessTableSortBy::Cmd => |pa, pb, _tick| pa.name.cmp(&pb.name),
            ProcessTableSortBy::DiskRead => |pa, pb, tick| {
                pa.get_read_bytes_sec(tick)
                    .partial_cmp(&pb.get_read_bytes_sec(tick))
                    .unwrap_or(Equal)
            },
            ProcessTableSortBy::DiskWrite => |pa, pb, tick| {
                pa.get_write_bytes_sec(tick)
                    .partial_cmp(&pb.get_write_bytes_sec(tick))
                    .unwrap_or(Equal)
            },
            ProcessTableSortBy::Gpu => |pa, pb, _tick| pa.gpu_usage.cmp(&pb.gpu_usage),
            ProcessTableSortBy::FB => |pa, pb, _tick| pa.fb_utilization.cmp(&pb.fb_utilization),
        }
    }

    #[cfg(all(not(feature = "nvidia"), target_os = "linux"))]
    /// returns a pointer to a comparator function, not a closure
    pub fn field_comparator(
        sortfield: ProcessTableSortBy,
    ) -> fn(&Self, &Self, &Duration) -> Ordering {
        match sortfield {
            ProcessTableSortBy::Cpu => {
                |pa, pb, _tick| pa.cpu_usage.partial_cmp(&pb.cpu_usage).unwrap_or(Equal)
            }
            ProcessTableSortBy::Mem => |pa, pb, _tick| pa.memory.cmp(&pb.memory),
            ProcessTableSortBy::MemPerc => |pa, pb, _tick| pa.memory.cmp(&pb.memory),
            ProcessTableSortBy::User => |pa, pb, _tick| pa.user_name.cmp(&pb.user_name),
            ProcessTableSortBy::Pid => |pa, pb, _tick| pa.pid.cmp(&pb.pid),
            ProcessTableSortBy::Status => {
                |pa, pb, _tick| pa.status.to_single_char().cmp(pb.status.to_single_char())
            }
            ProcessTableSortBy::Priority => |pa, pb, _tick| pa.priority.cmp(&pb.priority),
            ProcessTableSortBy::Nice => {
                |pa, pb, _tick| pa.priority.partial_cmp(&pb.nice).unwrap_or(Equal)
            }
            ProcessTableSortBy::Virt => |pa, pb, _tick| pa.virtual_memory.cmp(&pb.virtual_memory),
            ProcessTableSortBy::Cmd => |pa, pb, _tick| pa.name.cmp(&pb.name),
            ProcessTableSortBy::DiskRead => |pa, pb, tick| {
                pa.get_read_bytes_sec(tick)
                    .partial_cmp(&pb.get_read_bytes_sec(tick))
                    .unwrap_or(Equal)
            },
            ProcessTableSortBy::DiskWrite => |pa, pb, tick| {
                pa.get_write_bytes_sec(tick)
                    .partial_cmp(&pb.get_write_bytes_sec(tick))
                    .unwrap_or(Equal)
            },
            ProcessTableSortBy::IOWait => |pa, pb, _tick| {
                (pa.io_delay - pa.prev_io_delay).cmp(&(pb.io_delay - pb.prev_io_delay))
            },
        }
    }

    #[cfg(all(feature = "nvidia", target_os = "linux"))]
    /// returns a pointer to a comparator function, not a closure
    pub fn field_comparator(
        sortfield: ProcessTableSortBy,
    ) -> fn(&Self, &Self, &Duration) -> Ordering {
        match sortfield {
            ProcessTableSortBy::Cpu => {
                |pa, pb, _tick| pa.cpu_usage.partial_cmp(&pb.cpu_usage).unwrap_or(Equal)
            }
            ProcessTableSortBy::Mem => |pa, pb, _tick| pa.memory.cmp(&pb.memory),
            ProcessTableSortBy::MemPerc => |pa, pb, _tick| pa.memory.cmp(&pb.memory),
            ProcessTableSortBy::User => |pa, pb, _tick| pa.user_name.cmp(&pb.user_name),
            ProcessTableSortBy::Pid => |pa, pb, _tick| pa.pid.cmp(&pb.pid),
            ProcessTableSortBy::Status => {
                |pa, pb, _tick| pa.status.to_single_char().cmp(pb.status.to_single_char())
            }
            ProcessTableSortBy::Priority => |pa, pb, _tick| pa.priority.cmp(&pb.priority),
            ProcessTableSortBy::Nice => {
                |pa, pb, _tick| pa.priority.partial_cmp(&pb.nice).unwrap_or(Equal)
            }
            ProcessTableSortBy::Virt => |pa, pb, _tick| pa.virtual_memory.cmp(&pb.virtual_memory),
            ProcessTableSortBy::Cmd => |pa, pb, _tick| pa.name.cmp(&pb.name),
            ProcessTableSortBy::DiskRead => |pa, pb, tick| {
                pa.get_read_bytes_sec(tick)
                    .partial_cmp(&pb.get_read_bytes_sec(tick))
                    .unwrap_or(Equal)
            },
            ProcessTableSortBy::DiskWrite => |pa, pb, tick| {
                pa.get_write_bytes_sec(tick)
                    .partial_cmp(&pb.get_write_bytes_sec(tick))
                    .unwrap_or(Equal)
            },
            ProcessTableSortBy::IOWait => |pa, pb, _tick| {
                (pa.io_delay - pa.prev_io_delay).cmp(&(pb.io_delay - pb.prev_io_delay))
            },
            ProcessTableSortBy::Gpu => |pa, pb, _tick| pa.gpu_usage.cmp(&pb.gpu_usage),
            ProcessTableSortBy::FB => |pa, pb, _tick| pa.fb_utilization.cmp(&pb.fb_utilization),
        }
    }
}

#[cfg(target_os = "windows")]
fn win_terminate_process(pid: u32) -> String {
    extern "system" {
        fn OpenProcess(desired_access: u32, inherit_handles: i32, process_id: u32) -> *mut std::ffi::c_void;
        fn TerminateProcess(process: *mut std::ffi::c_void, exit_code: u32) -> i32;
        fn CloseHandle(object: *mut std::ffi::c_void) -> i32;
    }
    const PROCESS_TERMINATE: u32 = 0x0001;
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return "Access Denied or No Such Process.".into();
        }
        let result = TerminateProcess(handle, 1);
        CloseHandle(handle);
        if result != 0 {
            "Process Terminated.".into()
        } else {
            "Failed to terminate process.".into()
        }
    }
}

pub trait ProcessStatusExt {
    fn to_single_char(&self) -> &str;
}

impl ProcessStatusExt for ProcessStatus {
    fn to_single_char(&self) -> &str {
        match *self {
            ProcessStatus::Idle => "I",
            ProcessStatus::Run => "R",
            ProcessStatus::Sleep => "S",
            ProcessStatus::Stop => "T",
            ProcessStatus::Zombie => "Z",
            ProcessStatus::Tracing => "t",
            ProcessStatus::Dead => "x",
            ProcessStatus::Wakekill => "K",
            ProcessStatus::Waking => "W",
            ProcessStatus::Parked => "P",
            ProcessStatus::UninterruptibleDiskSleep => "D",
            ProcessStatus::LockBlocked => "L",
            ProcessStatus::Suspended => "T",
            ProcessStatus::Unknown(_) => "U",
        }
    }
}
