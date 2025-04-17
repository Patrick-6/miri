use either::Either;
use rustc_abi::Size;
use rustc_const_eval::interpret::{InterpCx, InterpResult, interp_ok};
use rustc_middle::ty::ScalarInt;
use tracing::info;

use super::ffi::GenmcScalar;
use crate::alloc_addresses::EvalContextExt as _;
use crate::{
    BorTag, MiriInterpCx, MiriMachine, Pointer, Provenance, Scalar, ThreadId, ThreadManager,
    throw_unsup_format,
};

/// Like `scalar_to_genmc_scalar`, but returns an error if the scalar is not an integer
pub fn rhs_scalar_to_genmc_scalar<'tcx>(
    ecx: &MiriInterpCx<'tcx>,
    scalar: Scalar,
) -> InterpResult<'tcx, GenmcScalar> {
    if matches!(scalar, Scalar::Ptr(..)) {
        throw_unsup_format!("Right hand side of atomic operation cannot be a pointer");
    }
    scalar_to_genmc_scalar(ecx, scalar)
}

pub fn scalar_to_genmc_scalar<'tcx>(
    ecx: &MiriInterpCx<'tcx>,
    scalar: Scalar,
) -> InterpResult<'tcx, GenmcScalar> {
    interp_ok(match scalar {
        rustc_const_eval::interpret::Scalar::Int(scalar_int) => {
            // TODO GENMC: u128 support
            let value: u64 = scalar_int.to_uint(scalar_int.size()).try_into().unwrap(); // TODO GENMC: doesn't work for size != 8
            GenmcScalar { value, extra: 0 }
        }
        rustc_const_eval::interpret::Scalar::Ptr(pointer, size) => {
            let addr = Pointer::from(pointer).addr();
            if let Provenance::Wildcard = pointer.provenance {
                throw_unsup_format!("Pointers with wildcard provenance not allowed in GenMC mode");
            }
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

pub enum NextInstrInfo {
    None,
    Statement,
    NonAtomicTerminator,
    MaybeAtomicTerminator,
}

/// TODO GENMC: DOCUMENTATION
pub fn get_next_instr_info<'tcx>(
    _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    thread_manager: &ThreadManager<'tcx>,
    thread_id: ThreadId,
) -> NextInstrInfo {
    let stack = thread_manager.get_thread_stack(thread_id);
    let Some(frame) = stack.last() else {
        return NextInstrInfo::None;
    };
    let Either::Left(loc) = frame.current_loc() else {
        todo!("TODO GENMC: can we get here?");
        // // We are unwinding and this fn has no cleanup code.
        // // Just go on unwinding.
        // trace!("unwinding: skipping frame");
        // self.return_from_current_stack_frame(/* unwinding */ true)?;
        // return interp_ok(true);
    };
    let basic_block = &frame.body().basic_blocks[loc.block];

    if let Some(stmt) = basic_block.statements.get(loc.statement_index) {
        info!("GenMC: thread {thread_id:?}, next is a statement with kind: {:?}", stmt.kind);
        return NextInstrInfo::Statement;
    }

    let terminator = basic_block.terminator();
    info!("GenMC: thread {thread_id:?}, next is a terminator with kind: {:?}", terminator.kind);
    use rustc_middle::mir::TerminatorKind;
    match &terminator.kind {
        // All atomics are modeled as function calls to intrinsic functions
        TerminatorKind::Call { func, .. } | TerminatorKind::TailCall { func, .. } => {
            let _func = func;
            // TODO GENMC (Scheduler): change once the required function(s) are public in rustc:
            // match ecx.instantiate_from_current_frame_and_normalize_erasing_regions(func) {
            //     Ok(func) => todo!(),
            //     Err(err) => {
            //         info!("GenMC: error when checking terminator kind: {err:?}");
            //         return NextInstrInfo::MaybeAtomicTerminator; // TODO GENMC: currently careful, but could return NonAtomic maybe?
            //     },
            // }
            
            NextInstrInfo::MaybeAtomicTerminator 
        }
        _ => NextInstrInfo::NonAtomicTerminator,
    }
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
