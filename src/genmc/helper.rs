use rustc_abi::Size;
use rustc_const_eval::interpret::{InterpResult, interp_ok};
use rustc_middle::ty::ScalarInt;

use super::ffi::GenmcScalar;
use crate::alloc_addresses::EvalContextExt as _;
use crate::{BorTag, MiriInterpCx, Pointer, Scalar, throw_unsup_format};

pub fn scalar_to_genmc_scalar<'tcx>(
    ecx: &MiriInterpCx<'tcx>,
    scalar: Scalar,
) -> InterpResult<'tcx, GenmcScalar> {
    // TODO GENMC: proper handling of `Scalar`
    interp_ok(match scalar {
        rustc_const_eval::interpret::Scalar::Int(scalar_int) => {
            // TODO GENMC: u128 support
            let value: u64 = scalar_int.to_uint(scalar_int.size()).try_into().unwrap(); // TODO GENMC: doesn't work for size != 8
            GenmcScalar { value, extra: 0 }
        }
        rustc_const_eval::interpret::Scalar::Ptr(pointer, size) => {
            let addr = Pointer::from(pointer).addr();
            let (alloc_id, _size, _prov_extra) =
                rustc_const_eval::interpret::Machine::ptr_get_alloc(ecx, pointer, size.into())
                    .unwrap();
            let base_addr = ecx.addr_from_alloc_id(alloc_id, None)?;
            GenmcScalar { value: addr.bytes(), extra: base_addr }
        }
    })
}

pub fn genmc_scalar_to_scalar<'tcx>(
    ecx: &MiriInterpCx<'tcx>,
    scalar: GenmcScalar,
    size: Size,
) -> InterpResult<'tcx, Scalar> {
    // TODO GENMC: proper handling of large integers
    // TODO GENMC: proper handling of pointers (currently assumes all integers)

    if scalar.extra != 0 {
        // We have a pointer!

        let addr = Size::from_bytes(scalar.value);
        let base_addr = scalar.extra;

        let alloc_size = 0; // TODO GENMC: what is the correct size here? Is 0 ok?
        let only_exposed_allocations = false;
        let Some(alloc_id) =
            ecx.alloc_id_from_addr(base_addr, alloc_size, only_exposed_allocations)
        else {
            // TODO GENMC: what is the correct error in this case?
            throw_unsup_format!(
                "Cannot get allocation id of pointer received from GenMC (base address: 0x{base_addr:x}, pointer address: 0x{:x})",
                addr.bytes()
            );
        };

        // TODO GENMC: is using `size: Size` ok here? Can we ever have `size != sizeof pointer`?

        // FIXME: Currently GenMC mode incompatible with aliasing model checking
        let tag = BorTag::default();
        let provenance = crate::machine::Provenance::Concrete { alloc_id, tag };
        let offset = addr;
        let ptr = rustc_middle::mir::interpret::Pointer::new(provenance, offset);

        let size = size.bytes().try_into().unwrap();
        return interp_ok(Scalar::Ptr(ptr, size));
    }

    // TODO GENMC (HACK): since we give dummy values to GenMC for NA accesses, we need to be able to convert it back:
    let trunc_value = if size.bits() >= 64 {
        scalar.value
    } else {
        let mask = (1u64 << size.bits()) - 1;
        // let trunc_value = value & mask;
        // eprintln!(
        //     "Masking {value} = 0x{value:x} to size {size:?}, with mask 0x{mask:x}, result: {trunc_value} = 0x{trunc_value:x}"
        // );
        // trunc_value
        scalar.value & mask
    };

    let Some(value_scalar_int) = ScalarInt::try_from_uint(trunc_value, size) else {
        todo!(
            "GenMC: cannot currently convert GenMC value {} (0x{:x}) (truncated {trunc_value} = 0x{trunc_value:x}), with size {size:?} into a Miri Scalar",
            scalar.value,
            scalar.value,
        );
    };
    interp_ok(Scalar::Int(value_scalar_int))
}

// TODO GENMC (CLEANUP): Remove this:
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
