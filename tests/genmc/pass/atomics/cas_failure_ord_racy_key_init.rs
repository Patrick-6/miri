//@compile-flags: -Zmiri-genmc -Zmiri-disable-stacked-borrows -Zmiri-ignore-leaks
// -Zmiri-genmc-print-exec-graphs=all

#![no_main]

#[path = "../../../utils/genmc.rs"]
mod genmc;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::*;

use crate::genmc::*;

const KEY_SENTVAL: usize = usize::MAX;

static KEY: AtomicUsize = AtomicUsize::new(KEY_SENTVAL);

static mut VALUES: [usize; 2] = [0, 0];

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    unsafe {
        let mut a = 0;
        let mut b = 0;
        let ids = [
            spawn_pthread_closure(|| {
                VALUES[0] = 42;
                let key = get_or_init(0);
                a = VALUES[key];
            }),
            spawn_pthread_closure(|| {
                VALUES[1] = 1234;
                let key = get_or_init(1);
                b = VALUES[key];
            }),
        ];
        join_pthreads(ids);
        if a != b {
            std::process::abort();
        }
    }
    0
}

fn get_or_init(key: usize) -> usize {
    // Adapted from: `impl LazyKey`, `fn lazy_init`: rust/library/std/src/sys/thread_local/key/racy.rs
    match KEY.compare_exchange(KEY_SENTVAL, key, Release, Acquire) {
        // The CAS succeeded, so we've created the actual key
        Ok(_) => key,
        // If someone beat us to the punch, use their key instead
        Err(n) => n,
    }
}
