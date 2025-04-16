#![feature(core_intrinsics)]
// Directly call intrinsic to avoid debug assertions in libstd
use std::intrinsics::float_to_int_unchecked;

fn main() {
    unsafe {
        float_to_int_unchecked::<f32, u32>(-1.000000001f32); //~ ERROR: cannot be represented in target type `u32`
    }
}
