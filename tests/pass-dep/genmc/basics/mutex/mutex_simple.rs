//@only-target: windows # TODO GENMC (TESTS): "disabled" until Mutex support is implemented <==========================
//@compile-flags: -Zmiri-genmc
//@revisions: order12 order21

#![no_main]

#[path = "../../../../utils-dep/mod.rs"]
mod utils_dep;

use std::ffi::c_void;
use std::sync::Mutex;

use crate::utils_dep::*;

const REPS: u64 = 2;

static LOCK: Mutex<[u64; 32]> = Mutex::new([1234; 32]);

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    let mut guard = LOCK.lock().unwrap();
    for &v in guard.iter() {
        assert!(v == 1234); // Check that mutex values are initialized correctly
    }
    guard[0] = 0;
    guard[1] = 10;
    assert!(guard[0] == 0 && guard[1] == 10); // Check if changes are accepted

    assert!(LOCK.try_lock().is_err()); // Trying to lock should fail if the lock is already held

    drop(guard); // Dropping the guard should unlock the mutex correctly.
    {
        assert!(LOCK.try_lock().is_ok()); // Trying to lock now should *not* fail since the lock is not held.
    }

    // Thread spawning order should not matter for the result
    let thread_order = if cfg!(order21) { [thread_2, thread_1] } else { [thread_1, thread_2] };
    let ids = unsafe { create_pthreads_no_params(thread_order) };
    unsafe { join_pthreads(ids) };

    let guard = LOCK.lock().unwrap();
    assert!(guard[0] == REPS * 6); // Due to locking, no weird values should be here
    assert!(guard[1] == 10); // Rest should be unchanged
    for &v in guard.iter().skip(2) {
        assert!(v == 1234);
    }
    drop(guard);

    0
}

extern "C" fn thread_1(_value: *mut c_void) -> *mut c_void {
    for _ in 0..REPS {
        let mut guard = LOCK.lock().unwrap();
        guard[0] += 2;
    }
    std::ptr::null_mut()
}

extern "C" fn thread_2(_value: *mut c_void) -> *mut c_void {
    for _ in 0..REPS {
        let mut guard = LOCK.lock().unwrap();
        guard[0] += 4;
    }
    std::ptr::null_mut()
}
