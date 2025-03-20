//@compile-flags: -Zmiri-genmc

#![no_main]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::{self, pthread_attr_t, pthread_t};

static X: AtomicU64 = AtomicU64::new(0);
static Y: AtomicU64 = AtomicU64::new(0);

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    let mut thread_id_1: pthread_t = 0;
    let mut thread_id_2: pthread_t = 0;

    let attr: *const pthread_attr_t = std::ptr::null();
    let value: *mut c_void = std::ptr::null_mut();

    // TODO GENMC: Hack (since Miri handles allocations lazily, and GenMC doesn't, we need to use them so they are `malloced` before the other thread starts)
    // unsafe { X.as_ptr().write(0) };
    // unsafe { Y.as_ptr().write(0) };
    // TODO GENMC: Make the initial writes atomic so GenMC sees them
    X.store(0, Ordering::Relaxed);
    Y.store(0, Ordering::Relaxed);

    assert_eq!(0, unsafe { libc::pthread_create(&raw mut thread_id_1, attr, thread_1, value) });
    assert_eq!(0, unsafe { libc::pthread_create(&raw mut thread_id_2, attr, thread_2, value) });

    0
}

extern "C" fn thread_1(_value: *mut c_void) -> *mut c_void {
    X.store(1, Ordering::SeqCst);
    Y.store(2, Ordering::SeqCst);
    std::ptr::null_mut()
}

extern "C" fn thread_2(_value: *mut c_void) -> *mut c_void {
    Y.store(1, Ordering::Relaxed);
    std::sync::atomic::fence(Ordering::SeqCst);
    X.store(2, Ordering::Relaxed);
    std::ptr::null_mut()
}
