#![no_main]

use std::sync::atomic::*;

static FLAG: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    FLAG.store(1, Ordering::SeqCst);
    let val = FLAG.load(Ordering::SeqCst);
    if val != 1 {
        std::process::abort();
    }
    0
}
