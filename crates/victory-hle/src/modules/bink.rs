//! The title's movies: logged, and skipped on request (`VICTORY_SKIP_MOVIES`).
//!
//! The title plays its movies with the Bink 2 DLL it ships, which runs as
//! it is. Its imports of the playback calls are bound to the functions here,
//! which call the DLL's own. Every movie the title opens is logged (name,
//! size, length), so a run's log tells which movies it plays.
//!
//! `VICTORY_SKIP_MOVIES`:
//! - unset, `0`, `off`: movies play;
//! - `1`, `on`: every movie that does not loop ends on its first frame (logos,
//!   intro and cut-scene movies; a looping one, such as a menu background,
//!   plays);
//! - `all`: every movie, looping ones too;
//! - anything else: a `;`-separated list of parts of movie names (as the log
//!   shows them); only movies whose name contains one are skipped, looping
//!   or not.
//!
//! A skipped movie still opens, sizes and registers its frame buffers and
//! closes through the DLL; only its frames are not decoded: its frame
//! counter is set to the last frame, which is how the title sees a movie
//! end, and its waits return at once.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use victory_loader::{ImportResolver, Provenance, Resolution};
use victory_pe::ImportSymbol;

/// The start of Bink 2's public `BINK` structure.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Header {
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub frame_num: u32,
    pub last_frame_num: u32,
    pub frame_rate: u32,
    pub frame_rate_div: u32,
    pub read_error: u32,
    pub open_flags: u32,
}

/// `OpenFlags`: the movie will loop (`BINKWILLLOOP`, set by `BinkSetWillLoop`).
const WILL_LOOP: u32 = 0x80;
/// `BinkOpen` flags: the name is a file handle, not a path (`BINKFILEHANDLE`).
const FILE_HANDLE: u32 = 0x0080_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Off,
    NotLooping,
    All,
    Named(Vec<String>),
}

pub fn parse_mode(value: Option<&str>) -> Mode {
    let Some(v) = value.map(str::trim) else {
        return Mode::Off;
    };
    match v.to_ascii_lowercase().as_str() {
        "" | "0" | "off" | "false" | "no" => Mode::Off,
        "1" | "on" | "true" | "yes" => Mode::NotLooping,
        "all" => Mode::All,
        _ => Mode::Named(
            v.split(';')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        ),
    }
}

fn mode() -> &'static Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    MODE.get_or_init(|| {
        let m = parse_mode(std::env::var("VICTORY_SKIP_MOVIES").ok().as_deref());
        if m != Mode::Off {
            tracing::info!(mode = ?m, "movies are skipped (VICTORY_SKIP_MOVIES)");
        }
        m
    })
}

/// Whether a movie is skipped, by the mode, its name and its flags.
fn skipped(mode: &Mode, name: Option<&str>, open_flags: u32) -> bool {
    match mode {
        Mode::Off => false,
        Mode::All => true,
        Mode::NotLooping => open_flags & WILL_LOOP == 0,
        Mode::Named(parts) => name.is_some_and(|n| {
            let n = n.to_ascii_lowercase();
            parts.iter().any(|p| n.contains(p.as_str()))
        }),
    }
}

/// Names of the open movies, by handle.
static NAMES: Mutex<Option<HashMap<usize, Option<String>>>> = Mutex::new(None);
/// Movies already reported as skipped, by handle.
static REPORTED: Mutex<Option<HashMap<usize, ()>>> = Mutex::new(None);

fn name_of(bink: usize) -> Option<String> {
    NAMES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&bink).cloned())
        .flatten()
}

/// A NUL-terminated path the title passed, if it is one: readable memory,
/// printable, at most 512 bytes.
fn read_name(name: *const u8) -> Option<String> {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery,
    };
    if name.is_null() {
        return None;
    }
    let mut out = Vec::new();
    let mut at = name;
    while out.len() < 512 {
        // Check each page before reading from it.
        if out.is_empty() || (at as usize) & 0xfff == 0 {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: a query about an address; nothing is read.
            let got = unsafe { VirtualQuery(at.cast(), &mut info, size_of_val(&info)) };
            if got == 0
                || info.State != MEM_COMMIT
                || info.Protect & (PAGE_NOACCESS | PAGE_GUARD) != 0
                || info.Protect == 0
            {
                return None;
            }
        }
        // SAFETY: the page holding `at` is committed and readable.
        let byte = unsafe { at.read() };
        if byte == 0 {
            break;
        }
        if !(0x20..0x7f).contains(&byte) {
            return None;
        }
        out.push(byte);
        at = at.wrapping_add(1);
    }
    // A movie opened from memory passes its bytes, which begin with the
    // Bink signature: not a name.
    String::from_utf8(out)
        .ok()
        .filter(|s| !s.is_empty() && !s.starts_with("KB2"))
}

/// Ends the movie if it is to be skipped: its frame counters at the last
/// frame. True when it was skipped.
///
/// # Safety
/// `bink` is null or a movie the DLL opened.
unsafe fn end_if_skipped(bink: *mut Header) -> bool {
    let mode = mode();
    if *mode == Mode::Off || bink.is_null() {
        return false;
    }
    // SAFETY: a movie the DLL opened (the caller's contract).
    let h = unsafe { &mut *bink };
    if h.frames == 0 {
        return false;
    }
    let name = name_of(bink as usize);
    if !skipped(mode, name.as_deref(), h.open_flags) {
        return false;
    }
    let first = REPORTED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(bink as usize, ())
        .is_none();
    if first {
        tracing::info!(
            name = name.as_deref().unwrap_or("?"),
            seconds = format_args!("{:.1}", seconds(h)),
            "movie skipped"
        );
    }
    h.frame_num = h.frames;
    h.last_frame_num = h.frames;
    true
}

fn seconds(h: &Header) -> f64 {
    if h.frame_rate == 0 || h.frame_rate_div == 0 {
        return 0.0;
    }
    f64::from(h.frames) * f64::from(h.frame_rate_div) / f64::from(h.frame_rate)
}

macro_rules! real {
    ($slot:ident, $ty:ty) => {{
        let address = $slot.load(Ordering::Acquire);
        // SAFETY: stored from the DLL's export of this name, which has this
        // signature; never 0 once a hook is bound.
        (address != 0).then(|| unsafe { std::mem::transmute::<usize, $ty>(address) })
    }};
}

static OPEN_WITH_OPTIONS: AtomicUsize = AtomicUsize::new(0);
static CLOSE: AtomicUsize = AtomicUsize::new(0);
static WAIT: AtomicUsize = AtomicUsize::new(0);
static SHOULD_SKIP: AtomicUsize = AtomicUsize::new(0);
static NEXT_FRAME: AtomicUsize = AtomicUsize::new(0);
static DO_FRAME: AtomicUsize = AtomicUsize::new(0);
static DO_FRAME_ASYNC_MULTI: AtomicUsize = AtomicUsize::new(0);
static DO_FRAME_ASYNC_WAIT: AtomicUsize = AtomicUsize::new(0);
static GOTO: AtomicUsize = AtomicUsize::new(0);

type OpenWithOptions = unsafe extern "system" fn(*const u8, *const c_void, u32) -> *mut Header;
type Handle = unsafe extern "system" fn(*mut Header);
type HandleToInt = unsafe extern "system" fn(*mut Header) -> i32;
type DoFrameAsyncMulti = unsafe extern "system" fn(*mut Header, *const u32, i32) -> i32;
type DoFrameAsyncWait = unsafe extern "system" fn(*mut Header, i32) -> i32;
type Goto = unsafe extern "system" fn(*mut Header, u32, i32);

extern "system" fn BinkOpenWithOptions(name: *const u8, options: *const c_void, flags: u32) -> *mut Header {
    let Some(real) = real!(OPEN_WITH_OPTIONS, OpenWithOptions) else {
        return std::ptr::null_mut();
    };
    let path = if flags & FILE_HANDLE == 0 { read_name(name) } else { None };
    // SAFETY: what the title passed, to the DLL's own function.
    let bink = unsafe { real(name, options, flags) };
    // SAFETY: a movie the DLL opened, or null.
    match unsafe { bink.as_ref() } {
        Some(h) => {
            tracing::info!(
                name = path.as_deref().unwrap_or("?"),
                size = format_args!("{}x{}", h.width, h.height),
                frames = h.frames,
                seconds = format_args!("{:.1}", seconds(h)),
                flags = format_args!("{:#x}", h.open_flags),
                "movie opened"
            );
            NAMES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert_with(HashMap::new)
                .insert(bink as usize, path);
        }
        None => tracing::info!(name = path.as_deref().unwrap_or("?"), "movie did not open"),
    }
    bink
}

extern "system" fn BinkClose(bink: *mut Header) {
    // A later movie may get the same address.
    if let Some(m) = NAMES.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        m.remove(&(bink as usize));
    }
    if let Some(m) = REPORTED.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        m.remove(&(bink as usize));
    }
    if let Some(real) = real!(CLOSE, Handle) {
        // SAFETY: the title's movie, to the DLL's own function.
        unsafe { real(bink) }
    }
}

extern "system" fn BinkWait(bink: *mut Header) -> i32 {
    // SAFETY: the title passes a movie the DLL opened.
    if unsafe { end_if_skipped(bink) } {
        return 0; // the next frame is due now
    }
    // SAFETY: as above.
    real!(WAIT, HandleToInt).map_or(0, |real| unsafe { real(bink) })
}

extern "system" fn BinkShouldSkip(bink: *mut Header) -> i32 {
    // SAFETY: the title passes a movie the DLL opened.
    if unsafe { end_if_skipped(bink) } {
        return 0;
    }
    // SAFETY: as above.
    real!(SHOULD_SKIP, HandleToInt).map_or(0, |real| unsafe { real(bink) })
}

extern "system" fn BinkNextFrame(bink: *mut Header) {
    // SAFETY: the title passes a movie the DLL opened.
    if unsafe { end_if_skipped(bink) } {
        return;
    }
    if let Some(real) = real!(NEXT_FRAME, Handle) {
        // SAFETY: as above.
        unsafe { real(bink) }
    }
}

extern "system" fn BinkDoFrame(bink: *mut Header) -> i32 {
    // SAFETY: the title passes a movie the DLL opened.
    if unsafe { end_if_skipped(bink) } {
        return 0;
    }
    // SAFETY: as above.
    real!(DO_FRAME, HandleToInt).map_or(0, |real| unsafe { real(bink) })
}

extern "system" fn BinkDoFrameAsyncMulti(bink: *mut Header, threads: *const u32, count: i32) -> i32 {
    // SAFETY: the title passes a movie the DLL opened.
    if unsafe { end_if_skipped(bink) } {
        return 1;
    }
    // SAFETY: as above.
    real!(DO_FRAME_ASYNC_MULTI, DoFrameAsyncMulti).map_or(1, |real| unsafe { real(bink, threads, count) })
}

extern "system" fn BinkDoFrameAsyncWait(bink: *mut Header, us: i32) -> i32 {
    // SAFETY: the title passes a movie the DLL opened.
    if unsafe { end_if_skipped(bink) } {
        return 1; // done
    }
    // SAFETY: as above.
    real!(DO_FRAME_ASYNC_WAIT, DoFrameAsyncWait).map_or(1, |real| unsafe { real(bink, us) })
}

extern "system" fn BinkGoto(bink: *mut Header, frame: u32, flags: i32) {
    // SAFETY: the title passes a movie the DLL opened.
    if unsafe { end_if_skipped(bink) } {
        return;
    }
    if let Some(real) = real!(GOTO, Goto) {
        // SAFETY: as above.
        unsafe { real(bink, frame, flags) }
    }
}

/// Our function for a Bink export, and where to keep the DLL's own. Only
/// the opening is wrapped when movies are not skipped (for the log).
fn hook(name: &str, skipping: bool) -> Option<(usize, &'static AtomicUsize)> {
    Some(match name {
        "BinkOpenWithOptions" => (BinkOpenWithOptions as OpenWithOptions as usize, &OPEN_WITH_OPTIONS),
        "BinkClose" => (BinkClose as Handle as usize, &CLOSE),
        _ if !skipping => return None,
        "BinkWait" => (BinkWait as HandleToInt as usize, &WAIT),
        "BinkShouldSkip" => (BinkShouldSkip as HandleToInt as usize, &SHOULD_SKIP),
        "BinkNextFrame" => (BinkNextFrame as Handle as usize, &NEXT_FRAME),
        "BinkDoFrame" => (BinkDoFrame as HandleToInt as usize, &DO_FRAME),
        "BinkDoFrameAsyncMulti" => (BinkDoFrameAsyncMulti as DoFrameAsyncMulti as usize, &DO_FRAME_ASYNC_MULTI),
        "BinkDoFrameAsyncWait" => (BinkDoFrameAsyncWait as DoFrameAsyncWait as usize, &DO_FRAME_ASYNC_WAIT),
        "BinkGoto" => (BinkGoto as Goto as usize, &GOTO),
        _ => return None,
    })
}

fn is_bink(dll: &str) -> bool {
    let dll = dll.to_ascii_lowercase();
    dll.starts_with("bink2") && dll.ends_with(".dll")
}

/// Resolves through `inner`, and puts our functions in front of the
/// title's Bink DLL.
pub struct Movies<'a> {
    pub inner: &'a dyn ImportResolver,
}

impl ImportResolver for Movies<'_> {
    fn resolve(&self, dll: &str, symbol: &ImportSymbol) -> Resolution {
        let found = self.inner.resolve(dll, symbol);
        let Resolution::Found {
            address,
            provenance: Provenance::Title,
        } = found
        else {
            return found;
        };
        let ImportSymbol::Name { name, .. } = symbol else {
            return found;
        };
        if !is_bink(dll) {
            return found;
        }
        let Some((ours, slot)) = hook(name, *mode() != Mode::Off) else {
            return found;
        };
        slot.store(address, Ordering::Release);
        Resolution::Found {
            address: ours,
            provenance: Provenance::Title,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        assert_eq!(std::mem::offset_of!(Header, frames), 0x08);
        assert_eq!(std::mem::offset_of!(Header, frame_num), 0x0c);
        assert_eq!(std::mem::offset_of!(Header, frame_rate), 0x14);
        assert_eq!(std::mem::offset_of!(Header, open_flags), 0x20);
    }

    #[test]
    fn modes() {
        assert_eq!(parse_mode(None), Mode::Off);
        assert_eq!(parse_mode(Some("0")), Mode::Off);
        assert_eq!(parse_mode(Some(" 1 ")), Mode::NotLooping);
        assert_eq!(parse_mode(Some("ALL")), Mode::All);
        assert_eq!(
            parse_mode(Some("Intro; logo;")),
            Mode::Named(vec!["intro".into(), "logo".into()])
        );
    }

    #[test]
    fn what_is_skipped() {
        assert!(!skipped(&Mode::Off, Some("intro"), 0));
        assert!(skipped(&Mode::NotLooping, None, 0));
        assert!(!skipped(&Mode::NotLooping, None, WILL_LOOP));
        assert!(skipped(&Mode::All, None, WILL_LOOP));
        let named = parse_mode(Some("intro"));
        assert!(skipped(&named, Some("movies/INTRO_01"), WILL_LOOP));
        assert!(!skipped(&named, Some("movies/tv_show"), 0));
        assert!(!skipped(&named, None, 0));
    }

    #[test]
    fn a_skipped_movie_ends() {
        let mut h = Header {
            frames: 300,
            frame_num: 1,
            ..Default::default()
        };
        // Only with the mode on; the test process has it off.
        if *mode() == Mode::Off {
            // SAFETY: a valid header.
            assert!(!unsafe { end_if_skipped(&mut h) });
            assert_eq!(h.frame_num, 1);
        }
    }

    #[test]
    fn names_are_read_only_from_text() {
        assert_eq!(read_name(c"movies/intro".as_ptr().cast()), Some("movies/intro".into()));
        assert_eq!(read_name(b"\x01\x02\0".as_ptr()), None);
        assert_eq!(read_name(std::ptr::null()), None);
        assert_eq!(read_name(c"KB2n".as_ptr().cast()), None);
        assert_eq!(read_name(16 as *const u8), None);
    }

    #[test]
    fn only_bink_dlls() {
        assert!(is_bink("Bink2Scarlett.dll"));
        assert!(!is_bink("xmem.dll"));
    }
}
