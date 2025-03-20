#![no_main]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::{self, pthread_attr_t, pthread_t};

static X: AtomicU64 = AtomicU64::new(0);
static Y: AtomicU64 = AtomicU64::new(0);

const LOAD_ORD: Ordering = Ordering::Acquire;
const STORE_ORD: Ordering = Ordering::Release;


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
    X.store(0, STORE_ORD);
    Y.store(0, STORE_ORD);

    assert_eq!(0, libc::pthread_create(&raw mut thread_id_1, attr, thread_1, value));
    assert_eq!(0, libc::pthread_create(&raw mut thread_id_2, attr, thread_2, value));

    0
}

extern "C" fn thread_1(_value: *mut c_void) -> *mut c_void {
    Y.store(1, STORE_ORD);
    X.store(2, STORE_ORD);
    std::ptr::null_mut()
}

extern "C" fn thread_2(_value: *mut c_void) -> *mut c_void {
    Y.store(1, STORE_ORD);
    X.store(2, STORE_ORD);
    std::ptr::null_mut()
}
