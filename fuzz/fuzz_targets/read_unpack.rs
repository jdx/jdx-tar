#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempfile::tempdir() else { return };
    let mut options = jdx_tar::UnpackOptions::default();
    let _ = jdx_tar::Archive::new(data).unpack(dir.path(), &mut options);
});
