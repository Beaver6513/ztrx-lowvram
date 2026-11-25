//! Who writes a title address: `VICTORY_WRITE_BREAK=<rva>` (an offset in
//! the title's image) arms a hardware data breakpoint on its four bytes on
//! every thread, again every quarter second so that new threads have it
//! too, and prints the instruction that wrote it and its stack (once per
//! instruction, at most 32). For finding what moves a title's state on, by
//! comparing runs where it moves with runs where it does not.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64, EXCEPTION_POINTERS,
    GetThreadContext, SetThreadContext,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, GetCurrentThreadStackLimits, OpenThread,
    ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

use crate::crash::{Aligned16, MAX_FRAMES, locate, unwind_into};

/// The watched address (0: none).
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
/// Instructions already reported.
static SEEN: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// `VICTORY_EXEC_BREAK=<rva>[,<rva>[,<rva>]]`: code addresses watched for
/// being run, in DR1 to DR3 (0: none), and how often each was reached.
static EXEC: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
static EXEC_HITS: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];

const SINGLE_STEP: i32 = 0x8000_0004_u32 as i32;
const CONTINUE_EXECUTION: i32 = -1;
const CONTINUE_SEARCH: i32 = 0;
/// DR7: local enable of DR0, break on writes, four bytes.
const DR7_WRITE_4: u64 = 1 | (0b01 << 16) | (0b11 << 18);

/// Reads `VICTORY_WRITE_BREAK` and, if set, watches that offset of the
/// image at `base`.
pub fn break_on_writes(base: usize) {
    let parse = |v: &str| usize::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok();
    if let Some(rva) = std::env::var("VICTORY_WRITE_BREAK").ok().as_deref().and_then(parse) {
        let address = (base + rva) & !3;
        ADDRESS.store(address, Ordering::Relaxed);
        eprintln!("VIctory: breaking on writes to title+{rva:#x} ({address:#x})");
    }
    if let Ok(list) = std::env::var("VICTORY_EXEC_BREAK") {
        for (slot, rva) in EXEC.iter().zip(list.split(',').filter_map(parse)) {
            slot.store(base + rva, Ordering::Relaxed);
            eprintln!("VIctory: breaking when title+{rva:#x} runs");
        }
    }
    let address = ADDRESS.load(Ordering::Relaxed);
    if address == 0 && EXEC[0].load(Ordering::Relaxed) == 0 {
        return;
    }
    // SAFETY: a handler of ours, called first.
    unsafe { AddVectoredExceptionHandler(1, Some(handler)) };
    std::thread::spawn(move || {
        let mut ticks = 0u32;
        loop {
            arm_all(address);
            std::thread::sleep(std::time::Duration::from_millis(250));
            ticks += 1;
            if ticks.is_multiple_of(40) {
                let line: Vec<String> = EXEC
                    .iter()
                    .zip(&EXEC_HITS)
                    .filter(|(at, _)| at.load(Ordering::Relaxed) != 0)
                    .map(|(at, n)| format!("{} {}", locate(at.load(Ordering::Relaxed)), n.load(Ordering::Relaxed)))
                    .collect();
                if !line.is_empty() {
                    eprintln!("VIctory: exec totals: {}", line.join(", "));
                }
            }
        }
    });
}

/// Sets DR0/DR7 on every other thread of the process that lacks them.
fn arm_all(address: usize) {
    // SAFETY: plain queries and a snapshot of this process's threads.
    let (me, process, snapshot) =
        unsafe { (GetCurrentThreadId(), GetCurrentProcessId(), CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) };
    if snapshot == INVALID_HANDLE_VALUE {
        return;
    }
    // SAFETY: zeroed is a valid THREADENTRY32; its size is set before use.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut ids = Vec::new();
    // SAFETY: `snapshot` is open; `entry` is sized.
    let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == process && entry.th32ThreadID != me {
            ids.push(entry.th32ThreadID);
        }
        // SAFETY: as above.
        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    // SAFETY: we opened it.
    unsafe { CloseHandle(snapshot) };
    for id in ids {
        // SAFETY: a thread of our own process; suspended only while its
        // debug registers are read and set.
        unsafe {
            let thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, id);
            if thread.is_null() {
                continue;
            }
            if SuspendThread(thread) != u32::MAX {
                let mut ctx = Aligned16(std::mem::zeroed());
                ctx.0.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
                let exec: [u64; 3] = std::array::from_fn(|i| EXEC[i].load(Ordering::Relaxed) as u64);
                let mut dr7 = 0u64;
                if address != 0 {
                    dr7 |= DR7_WRITE_4;
                }
                for (i, &at) in exec.iter().enumerate() {
                    if at != 0 {
                        // Local enable; RW 00 (execute) and LEN 00.
                        dr7 |= 1 << (2 * (i + 1));
                    }
                }
                if GetThreadContext(thread, &mut ctx.0) != 0
                    && (ctx.0.Dr0 != address as u64 || [ctx.0.Dr1, ctx.0.Dr2, ctx.0.Dr3] != exec || ctx.0.Dr7 != dr7)
                {
                    ctx.0.Dr0 = address as u64;
                    [ctx.0.Dr1, ctx.0.Dr2, ctx.0.Dr3] = exec;
                    ctx.0.Dr7 = dr7;
                    ctx.0.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
                    SetThreadContext(thread, &ctx.0);
                }
                ResumeThread(thread);
            }
            CloseHandle(thread);
        }
    }
}

/// A write to the watched address: the instruction after it and the stack,
/// once per instruction; execution goes on.
unsafe extern "system" fn handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    // SAFETY: the system passes valid pointers.
    let (record, context) = unsafe { (&*(*info).ExceptionRecord, &mut *(*info).ContextRecord) };
    if record.ExceptionCode != SINGLE_STEP || context.Dr6 & 0xf == 0 {
        return CONTINUE_SEARCH;
    }
    let dr6 = context.Dr6;
    context.Dr6 = 0;
    if dr6 & 1 == 0 {
        // A watched instruction is about to run: counted, the first three
        // times with the stack; RF lets it run on resuming.
        context.EFlags |= 0x1_0000;
        for i in 0..3 {
            if dr6 & (2 << i) != 0 {
                let n = EXEC_HITS[i].fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 3 || n.is_power_of_two() {
                    let (mut low, mut high) = (0, 0);
                    // SAFETY: writes the current thread's stack bounds.
                    unsafe { GetCurrentThreadStackLimits(&mut low, &mut high) };
                    let mut frames = Vec::with_capacity(MAX_FRAMES);
                    unwind_into(*context, low, high, &mut frames);
                    // SAFETY: a plain query.
                    let thread = unsafe { GetCurrentThreadId() };
                    // The first argument, its first word (a vtable, for a
                    // method) and that table's 18th slot (offset 0x88).
                    let rcx = context.Rcx as usize;
                    let read = |at: usize| -> usize {
                        let mut v = 0usize;
                        // SAFETY: a read the system checks; a bad address
                        // leaves 0.
                        unsafe {
                            windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                                at as *const _,
                                (&raw mut v).cast(),
                                8,
                                std::ptr::null_mut(),
                            )
                        };
                        v
                    };
                    let vtable = read(rcx);
                    let slot = if vtable != 0 { read(vtable + 0x88) } else { 0 };
                    eprintln!(
                        "VIctory: {} ran ({n} times) on thread {thread}; rcx {rcx:#x}, its vtable {}, slot 0x88 {}",
                        locate(context.Rip as usize),
                        locate(vtable),
                        locate(slot)
                    );
                    for (j, pc) in frames.into_iter().take(12).enumerate() {
                        eprintln!("    #{j:<2} {}", locate(pc as usize));
                    }
                }
            }
        }
        return CONTINUE_EXECUTION;
    }
    let rip = context.Rip;
    let first = {
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains(&rip) || seen.len() >= 32 {
            false
        } else {
            seen.push(rip);
            true
        }
    };
    if first {
        let address = ADDRESS.load(Ordering::Relaxed);
        // SAFETY: the address is in the title's image, readable.
        let value = unsafe { (address as *const u32).read_volatile() };
        let (mut low, mut high) = (0, 0);
        // SAFETY: writes the current thread's stack bounds.
        unsafe { GetCurrentThreadStackLimits(&mut low, &mut high) };
        let mut frames = Vec::with_capacity(MAX_FRAMES);
        let copy: CONTEXT = *context;
        unwind_into(copy, low, high, &mut frames);
        // SAFETY: a plain query.
        let thread = unsafe { GetCurrentThreadId() };
        eprintln!("VIctory: write to {address:#x} (now {value:#x}) by thread {thread}, after {}", locate(rip as usize));
        for (i, pc) in frames.into_iter().enumerate() {
            eprintln!("    #{i:<2} {}", locate(pc as usize));
        }
    }
    CONTINUE_EXECUTION
}
