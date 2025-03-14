//@compile-flags: -Zmiri-genmc -Zmiri-disable-stacked-borrows -Zmiri-genmc-verbose
//@normalize-stderr-test: "Verification took .*s" -> "Verification took [TIME]s"

#![no_main]

#[path = "../../../utils/genmc.rs"]
mod genmc;
#[path = "../../../utils/mod.rs"]
mod utils;

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::*;

use crate::genmc::*;
use crate::utils::*;

const UNINITIALIZED: u64 = 0;
const GETTING_INIT: u64 = 1;
const INITIALIZED: u64 = 2;

static mut X: u64 = 0;
static LOCK: AtomicU64 = AtomicU64::new(UNINITIALIZED);

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    unsafe {
        spawn_pthread_closure(|| {
            get_or_init(1);
        });
        spawn_pthread_closure(|| {
            get_or_init(2);
        });
    }
    0
}

fn get_or_init(value: u64) -> u64 {
    loop {
        match LOCK.load(Acquire) {
            INITIALIZED => unsafe { return X },
            GETTING_INIT => {
                unsafe { miri_genmc_assume(false) };
                continue;
            }
            UNINITIALIZED => {
                if LOCK
                    .compare_exchange_weak(UNINITIALIZED, GETTING_INIT, Relaxed, Relaxed)
                    .is_err()
                {
                    unsafe { miri_genmc_assume(false) };
                    continue;
                }
                unsafe { X = value };
                if LOCK.compare_exchange(GETTING_INIT, INITIALIZED, Release, Relaxed).is_err() {
                    unsafe { std::hint::unreachable_unchecked() };
                }
                return value;
            }
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }
}
