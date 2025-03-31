//@compile-flags: -Zmiri-genmc

#![no_main]

use std::sync::atomic::*;

const ORD: Ordering = Ordering::SeqCst;

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {

    let x = AtomicU64::new(0);
    x.store(0, ORD); // TODO GENMC: remove this test once this issue is fixed
    x.load(ORD); // "Read from uninitialized memory" without the line above

    0
}
