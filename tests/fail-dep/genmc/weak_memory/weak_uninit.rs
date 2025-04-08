//@compile-flags: -Zmiri-ignore-leaks -Zmiri-genmc

// Tests showing weak memory behaviours are exhibited. All tests
// return true when the desired behaviour is seen.
// This is scheduler and pseudo-RNG dependent, so each test is
// run multiple times until one try returns true.
// Spurious failure is possible, if you are really unlucky with
// the RNG and always read the latest value from the store buffer.

#![no_main]

#[path = "../../../utils-dep/mod.rs"]
mod utils_dep;

use std::ffi::c_void;
use std::sync::atomic::*;

use libc::{self, pthread_attr_t, pthread_t};

use crate::utils_dep::*;

#[allow(dead_code)]
#[derive(Copy, Clone)]
struct EvilSend<T>(pub T);

unsafe impl<T> Send for EvilSend<T> {}
unsafe impl<T> Sync for EvilSend<T> {}

// We can't create static items because we need to run each test multiple times.
fn static_uninit_atomic() -> &'static AtomicUsize {
    unsafe { Box::leak(Box::new_uninit()).assume_init_ref() }
}

extern "C" fn thread_1(value: *mut c_void) -> *mut c_void {
    unsafe {
        let x_ptr_ptr: *const *const AtomicUsize = std::mem::transmute(value);
        let x: &AtomicUsize = &**x_ptr_ptr;
        x.store(1, Ordering::Relaxed);
        std::ptr::null_mut()
    }
}

extern "C" fn thread_2(value: *mut c_void) -> *mut c_void {
    unsafe {
        let x_ptr_ptr: *const *const AtomicUsize = std::mem::transmute(value);
        let x: &AtomicUsize = &**x_ptr_ptr;
        x.load(Ordering::Relaxed); //~ERROR: using uninitialized data
        std::ptr::null_mut()
    }
}

fn relaxed() {
    let x: &'static AtomicUsize = static_uninit_atomic();
    let mut x_ptr: *const AtomicUsize = core::ptr::from_ref(x);
    let param: *mut c_void = unsafe { std::mem::transmute(&raw mut x_ptr) };

    let mut ids: [pthread_t; 2] = [0, 0];

    let attr: *const pthread_attr_t = std::ptr::null();

    if 0 != unsafe { libc::pthread_create(&raw mut ids[1], attr, thread_1, param) } {
        std::process::abort();
    }
    if 0 != unsafe { libc::pthread_create(&raw mut ids[0], attr, thread_2, param) } {
        std::process::abort();
    }

    unsafe { join_pthreads(ids) };
}

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    // Unlike with the non-GenMC version of this test, we should only need 1 iteration to detect the bug:
    // for _ in 0..100 {
    relaxed();
    // }

    0
}
