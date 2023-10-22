use core::slice;

/// Zero a buffer
///
/// # Safety
///
/// `*ptr` must be valid for `len`
#[no_mangle]
pub unsafe extern "C" fn rc_zeroize(ptr: *mut u8, len: usize) {
    use zeroize::Zeroize;
    let buf = unsafe { slice::from_raw_parts_mut(ptr, len) };
    buf.iter_mut().zeroize();
}
