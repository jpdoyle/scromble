/// From https://docs.rs/subtle/2.3.0/src/subtle/lib.rs.html#138
/// This function is a best-effort attempt to prevent the compiler from
/// knowing anything about the value of the returned `u8`, other than its
/// type.
///
/// Because we want to support stable Rust, we don't have access to inline
/// assembly or test::black_box, so we use the fact that volatile values
/// will never be elided to register values.
///
/// Note: Rust's notion of "volatile" is subject to change over time. While
/// this code may break in a non-destructive way in the future,
/// “constant-time” code is a continually moving target, and this is better
/// than doing nothing.
#[inline(never)]
pub fn black_box(input: u8) -> u8 {
    unsafe {
        // Optimization barrier
        //
        // Unsafe is ok, because:
        //   - &input is not NULL;
        //   - size of input is not zero;
        //   - u8 is neither Sync, nor Send;
        //   - u8 is Copy, so input is always live;
        //   - u8 type is always properly aligned.
        core::ptr::read_volatile(&input as *const u8)
    }
}
