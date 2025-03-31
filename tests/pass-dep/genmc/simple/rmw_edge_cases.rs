//@compile-flags: -Zmiri-genmc

#![no_main]

use std::sync::atomic::*;

const ORD: Ordering = Ordering::SeqCst;

fn assert_eq<T: Eq>(x: T, y: T) {
    if x != y {
        std::process::abort();
    }
}

#[unsafe(no_mangle)]
fn miri_start(_argc: isize, _argv: *const *const u8) -> isize {
    // Testing unsigned operations:
    let x = AtomicU64::new(0);
    x.store(0, ORD); // TODO GENMC (HACK): remove this test once initialization issue is fixed
    assert_eq(0, x.fetch_max(u64::MAX, ORD));
    assert_eq(u64::MAX, x.fetch_add(10, ORD));
    assert_eq(u64::MAX.wrapping_add(10), x.load(ORD)); // Add should be wrapping

    x.store(1234, ORD);
    assert_eq(1234, x.fetch_min(u64::MIN, ORD));
    assert_eq(u64::MIN, x.fetch_sub(10, ORD));
    assert_eq(u64::MIN.wrapping_sub(10), x.load(ORD)); // Sub should be wrapping

    // Testing signed operations:
    let x = AtomicI64::new(0);
    x.store(0, ORD); // TODO GENMC (HACK): remove this test once initialization issue is fixed
    assert_eq(0, x.fetch_max(i64::MAX, ORD));
    assert_eq(i64::MAX, x.fetch_add(10, ORD));
    assert_eq(i64::MAX.wrapping_add(10), x.load(ORD)); // Add should be wrapping

    x.store(1234, ORD);
    assert_eq(1234, x.fetch_min(i64::MIN, ORD));
    assert_eq(i64::MIN, x.fetch_sub(10, ORD));
    assert_eq(i64::MIN.wrapping_sub(10), x.load(ORD)); // Sub should be wrapping

    0
}
