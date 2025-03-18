#![no_main]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::{self, pthread_attr_t, pthread_t};

static X: AtomicU64 = AtomicU64::new(0);
static Y: AtomicU64 = AtomicU64::new(0);

const LOAD_ORD: Ordering = Ordering::Relaxed;
const STORE_ORD: Ordering = Ordering::Relaxed;

// const LOAD_ORD: Ordering = Ordering::SeqCst;
// const STORE_ORD: Ordering = Ordering::SeqCst;

// const LOAD_ORD: Ordering = Ordering::Acquire;
// const STORE_ORD: Ordering = Ordering::Release;

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    let mut thread_id: pthread_t = 0;

    let attr: *const pthread_attr_t = std::ptr::null();
    let value: *mut c_void = std::ptr::null_mut();

    unsafe { X.as_ptr().write(0) }; // TODO GENMC: Hack
    unsafe { Y.as_ptr().write(0) };

    let ret_create = unsafe { libc::pthread_create(&raw mut thread_id, attr, thread_func, value) };
    assert!(ret_create == 0);

    X.store(1, STORE_ORD);
    Y.store(2, STORE_ORD);

    let ret_join = unsafe { libc::pthread_join(thread_id, std::ptr::null_mut()) };
    assert!(ret_join == 0);

    let x = X.load(LOAD_ORD);
    let y = Y.load(LOAD_ORD);
    if x == 1 && y == 1 {
        unsafe { std::hint::unreachable_unchecked() };
    }
    0
}

extern "C" fn thread_func(_value: *mut c_void) -> *mut c_void {
    Y.store(1, STORE_ORD);
    X.store(2, STORE_ORD);
    std::ptr::null_mut()
}
