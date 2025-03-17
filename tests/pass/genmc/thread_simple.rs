#![no_main]

use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::AtomicU64;
use std::ffi::c_void;

use libc::{self, pthread_attr_t, pthread_t};

static FLAG: AtomicU64 = AtomicU64::new(0);

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    let mut thread_id: pthread_t = 0;

    let attr: *const pthread_attr_t = std::ptr::null();
    let value: *mut c_void = std::ptr::null_mut();

    // FLAG.store(42, SeqCst); // TODO GENMC:  HACK
    unsafe { FLAG.as_ptr().write(42) }; // TODO GENMC:  HACK

    let ret_create = unsafe { libc::pthread_create(&raw mut thread_id, attr, thread_func, value) };
    assert!(ret_create == 0);

    FLAG.store(1, SeqCst);

    let ret_join = unsafe { libc::pthread_join(thread_id, std::ptr::null_mut()) };
    assert!(ret_join == 0);

    let flag = FLAG.load(SeqCst);
    assert!(flag == 1 || flag == 2);
    0
}

extern "C" fn thread_func(_value: *mut c_void) -> *mut c_void {
    FLAG.store(2, SeqCst);
    std::ptr::null_mut()
}
