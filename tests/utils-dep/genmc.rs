use std::ffi::c_void;

use libc::{self, pthread_attr_t, pthread_t};

pub unsafe fn create_pthreads_no_params<const N: usize>(
    functions: [extern "C" fn(*mut c_void) -> *mut c_void; N],
) -> [pthread_t; N] {
    functions.map(|func| {
        let mut thread_id: pthread_t = 0;

        let attr: *const pthread_attr_t = std::ptr::null();
        let value: *mut c_void = std::ptr::null_mut();

        let ret = unsafe { libc::pthread_create(&raw mut thread_id, attr, func, value) };
        if 0 != ret {
            std::process::abort();
        }
        thread_id
    })
}

pub unsafe fn join_pthreads<const N: usize>(thread_ids: [pthread_t; N]) {
    thread_ids.map(|id| {
        let ret = unsafe { libc::pthread_join(id, std::ptr::null_mut()) };
        if 0 != ret {
            std::process::abort();
        }
    });
}
