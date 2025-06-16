use either::Either;
use rustc_abi::Size;
use rustc_const_eval::interpret::{InterpCx, InterpResult, interp_ok};
use rustc_middle::mir::Terminator;
use rustc_middle::ty::{self, ScalarInt};
use tracing::info;

use super::GenmcScalar;
use crate::alloc_addresses::EvalContextExt as _;
use crate::{
    BorTag, MiriInterpCx, MiriMachine, Pointer, Provenance, Scalar, ThreadId, ThreadManager,
    throw_unsup_format,
};

/// Convert an address selected by GenMC into Miri's type for addresses.
/// This function may panic on platforms with addresses larger than 64 bits
pub fn to_miri_size(genmc_address: usize) -> Size {
    Size::from_bytes(genmc_address)
}

/// Convert an address (originally selected by GenMC) back into form that GenMC expects
/// This function should never panic, since we received the address from GenMC (as a `usize`)
pub fn size_to_genmc(miri_address: Size) -> usize {
    miri_address.bytes().try_into().unwrap()
}

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

pub fn option_scalar_to_genmc_scalar<'tcx>(
    ecx: &MiriInterpCx<'tcx>,
    maybe_scalar: Option<Scalar>,
) -> InterpResult<'tcx, GenmcScalar> {
    if let Some(scalar) = maybe_scalar {
        scalar_to_genmc_scalar(ecx, scalar)
    } else {
        interp_ok(GenmcScalar::UNINIT)
    }
}

pub fn scalar_to_genmc_scalar<'tcx>(
    ecx: &MiriInterpCx<'tcx>,
    scalar: Scalar,
) -> InterpResult<'tcx, GenmcScalar> {
    interp_ok(match scalar {
        rustc_const_eval::interpret::Scalar::Int(scalar_int) => {
            // TODO GENMC: u128 support
            let value: u64 = scalar_int.to_uint(scalar_int.size()).try_into().unwrap(); // TODO GENMC: doesn't work for size != 8
            GenmcScalar { value, extra: 0, is_init: true }
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
            GenmcScalar { value: addr.bytes(), extra: base_addr, is_init: true }
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

#[derive(Debug)]
pub enum NextInstrInfo {
    None, // TODO GENMC: reduce this to 1 bool
    Statement,
    Terminator { is_atomic: bool },
}

/// TODO GENMC: DOCUMENTATION
pub fn get_next_instr_info<'tcx>(
    ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    thread_manager: &ThreadManager<'tcx>,
    thread_id: ThreadId,
) -> NextInstrInfo {
    let stack = thread_manager.get_thread_stack(thread_id);
    let Some(frame) = stack.last() else {
        return NextInstrInfo::None;
    };
    let Either::Left(loc) = frame.current_loc() else {
        // We are unwinding.
        return NextInstrInfo::None;
    };
    let basic_block = &frame.body().basic_blocks[loc.block];

    if let Some(stmt) = basic_block.statements.get(loc.statement_index) {
        info!("GenMC: thread {thread_id:?}, next is a statement with kind: {:?}", stmt.kind);
        return NextInstrInfo::Statement;
    }

    let terminator = basic_block.terminator();
    info!("GenMC: thread {thread_id:?}, next is a terminator with kind: {:?}", terminator.kind);
    NextInstrInfo::Terminator { is_atomic: is_terminator_atomic(ecx, terminator, thread_id) }
}

fn is_terminator_atomic<'tcx>(
    ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    terminator: &Terminator<'tcx>,
    thread_id: ThreadId,
) -> bool {
    // TODO GENMC (PERFORMANCE): this could become a bottleneck,
    // especially for multithreaded execution, since we need to lock the "symbol interner" to get the name of the intrinsic.
    // Maybe we could cache this somehow? (TODO: measure impact)
    use rustc_middle::mir::TerminatorKind;
    match &terminator.kind {
        // All atomics are modeled as function calls to intrinsic functions
        TerminatorKind::Call { func, .. } | TerminatorKind::TailCall { func, .. } => {
            // TODO GENMC (Scheduler): change once the required function(s) are public in rustc:
            info!("GenMC: terminator is a `Call` or `TailCall` with operand: {func:?}");
            let frame = ecx.machine.threads.get_thread_stack(thread_id).last().unwrap();
            let func_ty = func.ty(&frame.body().local_decls, *ecx.tcx);
            info!("GenMC:   Ty of operand: {func_ty:?}");
            match ecx.instantiate_from_frame_and_normalize_erasing_regions(frame, func_ty) {
                // match ecx.instantiate_from_current_frame_and_normalize_erasing_regions(func_ty) {
                Err(err) => {
                    info!("GenMC:   error when checking terminator kind: {err:?}");
                    // TODO GENMC: currently careful, but could return NonAtomic maybe?
                    true // possibly atomic?
                    // TODO GENMC: use ? here, make result interp_result
                }
                Ok(func_ty) => {
                    info!("GenMC:   terminator is a function with ty: {func_ty:?}");
                    match func_ty.kind() {
                        // Atomics are modeled as intrinsics and can only be called through a `FnDef` (not through `FnPtr`)
                        ty::FnDef(def_id, _args) => {
                            let item_name = ecx.tcx.item_name(*def_id);
                            info!(
                                "GenMC:     function DefId: {def_id:?}, item name: {item_name:?}"
                            );
                            if item_name.as_str().contains("join") {
                                // TODO GENMC: add thread creation
                                return true; // TODO GENMC: improve this code
                            }
                            let Some(intrinsic_def) = ecx.tcx.intrinsic(def_id) else {
                                return false;
                            };
                            // assert!(
                            //     !item_name.as_str().contains("join"),
                            //     "oh no: item name: {item_name:?}"
                            // );
                            info!("GenMC:     intrinsic name: \"{}\"", intrinsic_def.name.as_str());
                            // TODO GENMC: make this more precise (only loads)
                            intrinsic_def.name.as_str().starts_with("atomic_")
                            // || intrinsic_def.name.as_str().contains("join")
                        }
                        _ => false,
                    }
                }
            }
        }
        _ => false,
    }
}
