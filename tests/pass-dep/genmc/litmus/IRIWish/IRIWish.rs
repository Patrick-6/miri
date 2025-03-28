//@compile-flags: -Zmiri-ignore-leaks -Zmiri-genmc

#![no_main]

#[path = "../../../../utils-dep/mod.rs"]
mod utils_dep;

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::utils_dep::*;

static X: AtomicU64 = AtomicU64::new(0);
static Y: AtomicU64 = AtomicU64::new(0);

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    // TODO GENMC: Hack (since Miri handles allocations lazily, and GenMC doesn't, we need to use them so they are `malloced` before any other thread uses them)
    X.store(0, std::sync::atomic::Ordering::SeqCst);
    Y.store(0, std::sync::atomic::Ordering::SeqCst);

    let thread_order = [thread_1, thread_2, thread_3, thread_4];
    let _ids = unsafe { create_pthreads_no_params(thread_order) };

    0
}

pub extern "C" fn thread_1(_value: *mut c_void) -> *mut c_void {
    X.store(1, Ordering::Relaxed);
    null_mut()
}

pub extern "C" fn thread_2(_value: *mut c_void) -> *mut c_void {
    let r1 = X.load(Ordering::Relaxed);
    Y.store(r1, Ordering::Release);
    null_mut()
}

pub extern "C" fn thread_3(_value: *mut c_void) -> *mut c_void {
    let _r1 = X.load(Ordering::Relaxed);
    std::sync::atomic::fence(Ordering::AcqRel);
    let _r2 = Y.load(Ordering::Relaxed);
    null_mut()
}

pub extern "C" fn thread_4(_value: *mut c_void) -> *mut c_void {
    let _r1 = Y.load(Ordering::Relaxed);
    std::sync::atomic::fence(Ordering::AcqRel);
    let _r2 = X.load(Ordering::Relaxed);
    null_mut()
}
