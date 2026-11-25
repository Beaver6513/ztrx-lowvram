//! The DirectX 12 Agility SDK, loaded at run time when the user supplies one.
//!
//! Windows 10's own `System32\D3D12Core.dll` stops at shader model 6.5,
//! even where the card and its driver go further (a GeForce GTX 16 series
//! card, for one). Translated shaders are SM 6.6, so on such a system no
//! pipeline could be made. Windows 10 22H2 (19045.3393+, KB5029331) and
//! Windows 11 have `ID3D12SDKConfiguration1::CreateDeviceFactory`, which
//! loads a `D3D12Core.dll` from a folder the application names, with no
//! developer mode and no `D3D12SDKVersion` export in the executable.
//!
//! The first folder holding an x64 `D3D12Core.dll` that exports
//! `D3D12SDKVersion` is used:
//! 1. `%VICTORY_D3D12_DIR%` (only that one when it is set),
//! 2. `<folder of victory.exe>\D3D12`,
//! 3. `<folder of victory.exe>`,
//! 4. `%LOCALAPPDATA%\victory\D3D12`.
//!
//! A folder may also be the unpacked NuGet package
//! (`Microsoft.Direct3D.D3D12.<version>`): its `build\native\bin\x64` is
//! looked in. Without an SDK, or on a Windows without the interface, devices
//! come from the system's D3D12 as before.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL;
use windows::Win32::Graphics::Direct3D12::*;
use windows::core::{GUID, HRESULT, IUnknown, Interface, PCSTR, Param};

/// The variable naming the SDK folder.
pub const ENV: &str = "VICTORY_D3D12_DIR";

/// What loading the SDK came to, once per process.
pub enum State {
    /// Devices come from the SDK's factory.
    Loaded {
        factory: ID3D12DeviceFactory,
        version: u32,
        dir: PathBuf,
    },
    /// No SDK in any folder looked in: the system's D3D12.
    NotFound,
    /// An SDK was found (or named) but could not be used: the system's D3D12.
    Unavailable(String),
}

static STATE: OnceLock<State> = OnceLock::new();

/// The folders to look in, in order.
fn candidates(env: Option<PathBuf>, exe_dir: Option<PathBuf>, local: Option<PathBuf>) -> Vec<PathBuf> {
    if let Some(d) = env {
        // Named by the user: a wrong path is reported, not passed over.
        return vec![d];
    }
    let mut dirs = Vec::new();
    if let Some(d) = exe_dir {
        dirs.push(d.join("D3D12"));
        dirs.push(d);
    }
    if let Some(d) = local {
        dirs.push(d.join("victory").join("D3D12"));
    }
    dirs
}

/// The folder in `dir` that holds `D3D12Core.dll`: `dir` itself, or the
/// x64 binaries of an unpacked NuGet package.
fn core_dir(dir: &Path) -> Option<PathBuf> {
    [dir.to_path_buf(), dir.join("build").join("native").join("bin").join("x64")]
        .into_iter()
        .find(|d| d.join("D3D12Core.dll").is_file())
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// The `u32` a DLL's `D3D12SDKVersion` export holds, read from the file's
/// bytes without loading it.
fn sdk_version(b: &[u8]) -> Result<u32, String> {
    if b.get(..2) != Some(b"MZ") {
        return Err("not a PE file".into());
    }
    let pe = u32_at(b, 0x3c).ok_or("truncated")? as usize;
    if b.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("not a PE file".into());
    }
    let coff = pe + 4;
    if u16_at(b, coff) != Some(0x8664) {
        return Err("not an x64 DLL".into());
    }
    if u16_at(b, coff + 18).ok_or("truncated")? & 0x2000 == 0 {
        return Err("not a DLL".into());
    }
    let sections = usize::from(u16_at(b, coff + 2).ok_or("truncated")?);
    let opt = coff + 20;
    let opt_size = usize::from(u16_at(b, coff + 16).ok_or("truncated")?);
    if u16_at(b, opt) != Some(0x20b) {
        return Err("not PE32+".into());
    }
    let section_table = opt + opt_size;
    let file_offset = |rva: u32| -> Option<usize> {
        (0..sections).find_map(|i| {
            let s = section_table + i * 40;
            let size = u32_at(b, s + 8)?.max(u32_at(b, s + 16)?);
            let start = u32_at(b, s + 12)?;
            let raw = u32_at(b, s + 20)?;
            let delta = rva.checked_sub(start)?;
            (delta < size).then(|| raw as usize + delta as usize)
        })
    };
    // Data directory 0: exports.
    let (dir_rva, dir_size) = (
        u32_at(b, opt + 112).ok_or("truncated")?,
        u32_at(b, opt + 116).ok_or("truncated")?,
    );
    if dir_rva == 0 {
        return Err("no export table".into());
    }
    let ed = file_offset(dir_rva).ok_or("export table outside the file")?;
    let names = u32_at(b, ed + 24).ok_or("truncated")? as usize;
    let functions = u32_at(b, ed + 28).ok_or("truncated")?;
    let name_table = u32_at(b, ed + 32).ok_or("truncated")?;
    let ordinal_table = u32_at(b, ed + 36).ok_or("truncated")?;
    let wanted = b"D3D12SDKVersion\0";
    for i in 0..names.min(0x10000) {
        let Some(name_rva) = file_offset(name_table + 4 * i as u32).and_then(|o| u32_at(b, o)) else {
            continue;
        };
        let Some(name) = file_offset(name_rva) else { continue };
        if b.get(name..name + wanted.len()) != Some(wanted) {
            continue;
        }
        let ordinal = file_offset(ordinal_table + 2 * i as u32)
            .and_then(|o| u16_at(b, o))
            .ok_or("bad ordinal table")?;
        let rva = file_offset(functions + 4 * u32::from(ordinal))
            .and_then(|o| u32_at(b, o))
            .ok_or("bad function table")?;
        if rva == 0 || (rva >= dir_rva && rva < dir_rva.saturating_add(dir_size)) {
            return Err("D3D12SDKVersion is forwarded".into());
        }
        let version = file_offset(rva).and_then(|o| u32_at(b, o)).ok_or("D3D12SDKVersion outside the file")?;
        return match version {
            0 => Err("D3D12SDKVersion is 0".into()),
            v => Ok(v),
        };
    }
    Err("no D3D12SDKVersion export".into())
}

/// The first usable folder and its SDK version.
fn find(env: Option<PathBuf>, exe_dir: Option<PathBuf>, local: Option<PathBuf>) -> Result<Option<(PathBuf, u32)>, String> {
    let named = env.is_some();
    let mut last = None;
    for dir in candidates(env, exe_dir, local) {
        let Some(dir) = core_dir(&dir) else {
            if named {
                return Err(format!("{ENV}={} has no D3D12Core.dll", dir.display()));
            }
            continue;
        };
        let dll = dir.join("D3D12Core.dll");
        match std::fs::read(&dll).map_err(|e| e.to_string()).and_then(|b| sdk_version(&b)) {
            Ok(version) => return Ok(Some((dir, version))),
            Err(e) => last = Some(format!("{}: {e}", dll.display())),
        }
    }
    last.map_or(Ok(None), Err)
}

fn env_path(name: &str) -> Option<PathBuf> {
    let v = std::env::var_os(name)?;
    match v.to_str() {
        Some(s) if s.trim().is_empty() => None,
        Some(s) => Some(PathBuf::from(s.trim().trim_matches('"'))),
        None => Some(PathBuf::from(v)),
    }
}

/// `dir` with a trailing backslash, in the ANSI code page, as
/// `CreateDeviceFactory` takes it.
fn ansi_path(dir: &Path) -> Result<CString, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Globalization::{CP_ACP, WC_NO_BEST_FIT_CHARS, WideCharToMultiByte};
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    if wide.last() != Some(&u16::from(b'\\')) {
        wide.push(u16::from(b'\\'));
    }
    let len = i32::try_from(wide.len()).map_err(|_| "path too long")?;
    let mut lossy = 0i32;
    // SAFETY: `wide` holds `len` units; a null output asks for the size.
    let needed = unsafe {
        WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wide.as_ptr(), len, std::ptr::null_mut(), 0, std::ptr::null(), &mut lossy)
    };
    if needed <= 0 || lossy != 0 {
        return Err(format!("{} cannot be written in the system code page; use a plain path", dir.display()));
    }
    let mut out = vec![0u8; needed as usize];
    // SAFETY: `out` has the size the call above asked for.
    let written = unsafe {
        WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wide.as_ptr(), len, out.as_mut_ptr(), needed, std::ptr::null(), &mut lossy)
    };
    if written <= 0 || lossy != 0 {
        return Err(format!("{} cannot be written in the system code page; use a plain path", dir.display()));
    }
    out.truncate(written as usize);
    CString::new(out).map_err(|_| "path contains NUL".into())
}

type GetInterface = unsafe extern "system" fn(*const GUID, *const GUID, *mut *mut std::ffi::c_void) -> HRESULT;

fn factory(version: u32, dir: &Path) -> Result<ID3D12DeviceFactory, String> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
    let path = ansi_path(dir)?;
    let name: Vec<u16> = "d3d12.dll".encode_utf16().chain([0]).collect();
    // SAFETY: a NUL-terminated name, System32 only; `D3D12GetInterface` is
    // looked up by name (older Windows lacks it) and has this signature; on
    // success it writes an owned interface pointer. `CreateDeviceFactory`
    // takes a NUL-terminated ANSI path ending in a backslash.
    unsafe {
        let module = LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if module.is_null() {
            return Err("no d3d12.dll".into());
        }
        let get = GetProcAddress(module, c"D3D12GetInterface".as_ptr().cast())
            .ok_or("no D3D12GetInterface (Windows 10 needs 22H2 with KB5029331 or later)")?;
        let get = std::mem::transmute::<unsafe extern "system" fn() -> isize, GetInterface>(get);
        let mut raw = std::ptr::null_mut();
        get(&CLSID_D3D12SDKConfiguration, &ID3D12SDKConfiguration1::IID, &mut raw)
            .ok()
            .map_err(|e| format!("no ID3D12SDKConfiguration1 (Windows 10 needs 22H2 with KB5029331 or later): {e}"))?;
        if raw.is_null() {
            return Err("D3D12GetInterface gave no ID3D12SDKConfiguration1".into());
        }
        let config = ID3D12SDKConfiguration1::from_raw(raw);
        let factory: ID3D12DeviceFactory = config
            .CreateDeviceFactory(version, PCSTR(path.as_ptr().cast()))
            .map_err(|e| format!("CreateDeviceFactory({version}, {}): {e}", dir.display()))?;
        // Several parts of the layer make devices on the same adapter; they
        // get the one device, as `D3D12CreateDevice` gives them.
        factory
            .SetFlags(D3D12_DEVICE_FACTORY_FLAG_ALLOW_RETURNING_EXISTING_DEVICE)
            .map_err(|e| format!("ID3D12DeviceFactory::SetFlags: {e}"))?;
        // The free functions (`D3D12SerializeVersionedRootSignature` and the
        // other `d3d12.dll` exports the layer and the title call) then go
        // to the SDK's runtime too: the system's would refuse SM 6.6 flags.
        factory
            .ApplyToGlobalState()
            .map_err(|e| format!("ID3D12DeviceFactory::ApplyToGlobalState: {e}"))?;
        Ok(factory)
    }
}

fn init() -> State {
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf));
    let state = match find(env_path(ENV), exe_dir, env_path("LOCALAPPDATA")) {
        Ok(None) => State::NotFound,
        Err(e) => State::Unavailable(e),
        Ok(Some((dir, version))) => {
            let dir = std::path::absolute(&dir).unwrap_or(dir);
            match factory(version, &dir) {
                Ok(factory) => State::Loaded { factory, version, dir },
                Err(e) => State::Unavailable(e),
            }
        }
    };
    match &state {
        State::Loaded { version, dir, .. } => {
            tracing::info!(version, dir = %dir.display(), "D3D12 Agility SDK loaded");
        }
        State::NotFound => tracing::debug!("no D3D12 Agility SDK; the system's D3D12"),
        State::Unavailable(e) => tracing::warn!(reason = %e, "D3D12 Agility SDK not used; the system's D3D12"),
    }
    state
}

/// Loads the SDK on first use. Call before the first D3D12 call of the
/// process, so every later one goes to the same runtime.
pub fn state() -> &'static State {
    STATE.get_or_init(init)
}

/// The loaded SDK's version and folder.
pub fn loaded() -> Option<(u32, &'static Path)> {
    match state() {
        State::Loaded { version, dir, .. } => Some((*version, dir.as_path())),
        _ => None,
    }
}

/// What to tell a user whose device stops below SM 6.6.
pub fn no_sm66_hint() -> String {
    match state() {
        State::Loaded { version, .. } => {
            format!("Agility SDK {version} is loaded: the card or its driver stops below SM 6.6")
        }
        State::Unavailable(e) => format!("the D3D12 Agility SDK could not be used: {e}"),
        State::NotFound => format!(
            "on Windows 10, set {ENV} to a D3D12 Agility SDK folder (the one holding D3D12Core.dll)"
        ),
    }
}

/// `D3D12CreateDevice`, through the SDK when it is loaded.
pub fn create_device<P: Param<IUnknown>>(
    adapter: P,
    level: D3D_FEATURE_LEVEL,
    device: &mut Option<ID3D12Device>,
) -> windows::core::Result<()> {
    // SAFETY: valid out pointer; the factory lives for the process.
    unsafe {
        match state() {
            State::Loaded { factory, .. } => factory.CreateDevice(adapter, level, device),
            _ => D3D12CreateDevice(adapter, level, device),
        }
    }
}

/// `D3D12GetDebugInterface` (`ID3D12Debug`, DRED settings), from the SDK
/// when it is loaded: the global call would configure the system's runtime,
/// not the one devices come from.
pub fn debug_interface<T: Interface>(clsid: &GUID, out: &mut Option<T>) -> windows::core::Result<()> {
    // SAFETY: valid out pointer; the factory lives for the process.
    unsafe {
        match state() {
            State::Loaded { factory, .. } => {
                *out = Some(factory.GetConfigurationInterface::<T>(clsid)?);
                Ok(())
            }
            _ => D3D12GetDebugInterface(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_folder_is_the_only_one() {
        let dirs = candidates(Some("X:\\sdk".into()), Some("C:\\app".into()), Some("C:\\local".into()));
        assert_eq!(dirs, vec![PathBuf::from("X:\\sdk")]);
    }

    #[test]
    fn default_order() {
        let dirs = candidates(None, Some("C:\\app".into()), Some("C:\\local".into()));
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("C:\\app\\D3D12"),
                PathBuf::from("C:\\app"),
                PathBuf::from("C:\\local\\victory\\D3D12"),
            ]
        );
    }

    #[test]
    fn missing_named_folder_is_reported() {
        let dir = tempfile_dir();
        let err = find(Some(dir.clone()), None, None).unwrap_err();
        assert!(err.contains("has no D3D12Core.dll"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_non_pe() {
        assert!(sdk_version(b"not a dll").is_err());
        assert!(sdk_version(&[]).is_err());
    }

    /// A minimal x64 DLL exporting `D3D12SDKVersion` = 620.
    fn dll(version: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x600];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        b[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        b[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        b[coff + 18..coff + 20].copy_from_slice(&0x2000u16.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[opt + 112..opt + 116].copy_from_slice(&0x1000u32.to_le_bytes());
        b[opt + 116..opt + 120].copy_from_slice(&0x100u32.to_le_bytes());
        let sec = opt + 240;
        b[sec + 8..sec + 12].copy_from_slice(&0x400u32.to_le_bytes());
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes());
        b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        // Export directory at file 0x200 (RVA 0x1000).
        let ed = 0x200;
        b[ed + 20..ed + 24].copy_from_slice(&1u32.to_le_bytes());
        b[ed + 24..ed + 28].copy_from_slice(&1u32.to_le_bytes());
        b[ed + 28..ed + 32].copy_from_slice(&0x1040u32.to_le_bytes());
        b[ed + 32..ed + 36].copy_from_slice(&0x1050u32.to_le_bytes());
        b[ed + 36..ed + 40].copy_from_slice(&0x1060u32.to_le_bytes());
        b[0x240..0x244].copy_from_slice(&0x1200u32.to_le_bytes());
        b[0x250..0x254].copy_from_slice(&0x10a0u32.to_le_bytes());
        b[0x2a0..0x2a0 + 16].copy_from_slice(b"D3D12SDKVersion\0");
        b[0x400..0x404].copy_from_slice(&version.to_le_bytes());
        b
    }

    #[test]
    fn reads_the_exported_version() {
        assert_eq!(sdk_version(&dll(620)), Ok(620));
        assert!(sdk_version(&dll(0)).is_err());
    }

    #[test]
    fn finds_a_nuget_package_folder() {
        let root = tempfile_dir();
        let bin = root.join("build").join("native").join("bin").join("x64");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("D3D12Core.dll"), dll(620)).unwrap();
        assert_eq!(find(Some(root.clone()), None, None), Ok(Some((bin, 620))));
        let _ = std::fs::remove_dir_all(root);
    }

    fn tempfile_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "victory-agility-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
