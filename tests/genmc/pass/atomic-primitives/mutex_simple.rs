//@revisions: reps1 reps2 reps3
//@compile-flags: -Zmiri-genmc -Zmiri-disable-stacked-borrows -Zmiri-genmc-verbose
//@normalize-stderr-test: "Verification took .*s" -> "Verification took [TIME]s"

// Test various features of the `std::sync::Mutex` API with GenMC.
// The test variants use a different number of iterations for the part that increments the counter protected by the mutex.
// More repetitions leads to more possible executions, representing all ways that the threads entering the critical sections can be ordered.
//
// The test has verbose output to test that there are no blocked executions due to the unblocking annotations Miri provides to GenMC.

#![no_main]
#![feature(abort_unwind)]

#[path = "../../../utils/genmc.rs"]
mod genmc;

use std::ffi::c_void;
use std::sync::Mutex;

use crate::genmc::*;

const REPS: u64 = if cfg!(reps3) {
    3
} else if cfg!(reps2) {
    2
} else {
    1
};

static LOCK: Mutex<[u64; 32]> = Mutex::new([1234; 32]);

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    std::panic::abort_unwind(main_);
    0
}

fn main_() {
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

    let ids = unsafe { spawn_pthreads_no_params([thread_1, thread_2]) };
    unsafe { join_pthreads(ids) };

    let guard = LOCK.lock().unwrap();
    assert!(guard[0] == REPS * 6); // Due to locking, no weird values should be here
    assert!(guard[1] == 10); // Rest should be unchanged
    for &v in guard.iter().skip(2) {
        assert!(v == 1234);
    }
    drop(guard);
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
