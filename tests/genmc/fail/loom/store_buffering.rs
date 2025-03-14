//@ revisions: non_genmc non_genmc_std genmc genmc_std
//@[genmc,genmc_std] compile-flags: -Zmiri-genmc -Zmiri-disable-stacked-borrows

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2019 Carl Lerche

// This is the test `store_buffering` from `loom/test/litmus.rs`, adapted for Miri-GenMC.
// https://github.com/tokio-rs/loom/blob/dbf32b04bae821c64be44405a0bb72ca08741558/tests/litmus.rs

// This test shows the comparison between running Miri with or without GenMC.
// Without GenMC, Miri requires multiple iterations of the loop to detect the error.
// This test also serves as a comparison between using std threads and pthreads, they should behave identically in this test.

#![no_main]

#[path = "../../../utils/genmc.rs"]
mod genmc;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::*;

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    // For normal Miri, we need multiple repetitions, but GenMC should find the bug with only 1.
    const REPS: usize = if cfg!(any(non_genmc, non_genmc_std)) { 128 } else { 1 };
    for _ in 0..REPS {
        // New atomics every iterations, so they don't influence each other.
        let x = AtomicUsize::new(0);
        let y = AtomicUsize::new(0);

        #[cfg(any(non_genmc_std, genmc_std))]
        let result = {
            // We lie about this being static to satisfy the type checker.
            // We join the threads immediately, so this is safe.
            // FIXME(genmc): once Miri-GenMC supports scoped threads, add a new test variant that uses them.
            let x: &'static AtomicUsize = unsafe { &*&raw const x };
            let y: &'static AtomicUsize = unsafe { &*&raw const y };

            let t1 = std::thread::spawn(|| {
                x.store(1, Relaxed);
                y.load(Relaxed)
            });
            let t2 = std::thread::spawn(|| {
                y.store(1, Relaxed);
                x.load(Relaxed)
            });

            let a = t1.join().unwrap();
            let b = t2.join().unwrap();
            (a, b)
        };

        #[cfg(not(any(non_genmc_std, genmc_std)))]
        let result = unsafe {
            use crate::genmc::*;

            let mut a: usize = 1234;
            let mut b: usize = 1234;

            let ids = [
                spawn_pthread_closure(|| {
                    x.store(1, Relaxed);
                    a = y.load(Relaxed)
                }),
                spawn_pthread_closure(|| {
                    y.store(1, Relaxed);
                    b = x.load(Relaxed)
                }),
            ];
            join_pthreads(ids);
            (a, b)
        };
        if result == (0, 0) {
            std::process::abort(); //~ ERROR: abnormal termination
        }
    }

    0
}
