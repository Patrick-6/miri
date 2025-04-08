use rustc_abi::Size;
use rustc_middle::ty::ScalarInt;

use crate::Scalar;

pub fn scalar_to_genmc_scalar(value: Scalar) -> u64 {
    // TODO GENMC: proper handling of `Scalar`
    match value {
        rustc_const_eval::interpret::Scalar::Int(scalar_int) =>
            scalar_int.to_uint(scalar_int.size()).try_into().unwrap(), // TODO GENMC: doesn't work for size != 8
        rustc_const_eval::interpret::Scalar::Ptr(_pointer, _size) => todo!(), // pointer.into_parts().1.bytes(),
    }
}

pub fn genmc_scalar_to_scalar(value: u64, size: Size) -> Scalar {
    // TODO GENMC: proper handling of large integers
    // TODO GENMC: proper handling of pointers (currently assumes all integers)

    // TODO GENMC (HACK): since we give dummy values to GenMC for NA accesses, we need to be able to convert it back:
    let value = if size.bytes() == 1 { value.min(u64::from(u8::MAX)) } else { value };
    let Some(value_scalar_int) = ScalarInt::try_from_uint(value, size) else {
        todo!(
            "GenMC: cannot currently convert GenMC value {value} (0x{value:x}), with size {size:?} into a Miri Scalar"
        );
    };
    Scalar::Int(value_scalar_int)
}

#[derive(Debug)]
pub struct Threads {
    // TODO
    // inner: &ThreadManager
}

#[allow(unused)] // TODO GENMC: remove
impl Threads {
    pub fn new() -> Self {
        Self {}
    }

    pub fn is_enabled(&self, thread_id: u32) -> bool {
        // eprintln!("Threads::is_enabled({thread_id})");
        true
    }

    pub fn set_next_thread(&mut self, thread_id: u32) {
        eprintln!("Threads::set_next_thread({thread_id})");
    }
}
