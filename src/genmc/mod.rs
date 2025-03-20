use std::cell::RefCell;
#[allow(unused_imports)] // TODO GENMC: false warning?
use std::pin::Pin;

use cxx::UniquePtr;
use rand::prelude::*;
use rand::rngs::StdRng;
use rustc_abi::{Align, Size};
use rustc_middle::ty::ScalarInt;
use tracing::warn;

use self::ffi::{MemoryOrdering, MiriGenMCShim, RmwBinOp, createGenmcHandle};
use crate::intrinsics::AtomicOp;
use crate::{
    AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd, MemoryKind, MiriMachine, ThreadId,
    ThreadManager,
};

mod cxx_extra;

// TODO GENMC: extract the ffi module if possible, to reduce number of required recompilation
#[cxx::bridge]
mod ffi {
    #[derive(Debug)]
    enum MemoryOrdering {
        NotAtomic = 0,
        Unordered = 1,
        Relaxed = 2,
        Acquire = 4,
        Release = 5,
        AcquireRelease = 6,
        SequentiallyConsistent = 7,
    }

    #[derive(Debug)]
    enum RmwBinOp {
        Min,
        Max,
        UMin,
        UMax,
        Add,
        Sub,
        And,
        Nand,
        Or,
        Xor,
    }

    extern "Rust" {
        type Threads;
        fn is_enabled(self: &Threads, thread_id: u32) -> bool;
        // fn set_next_thread(self: &mut Threads, thread_id: u32);
    }

    unsafe extern "C++" {
        include!("miri/genmc/src/Verification/MiriInterface.hpp");

        type MemoryOrdering;
        type RmwBinOp;
        // type GenmcConfig; // TODO GENMC
        // type OperatingMode; // Estimation(budget) or Verification
        type MiriGenMCShim;

        fn createGenmcHandle(/* GenmcConfig config */ /* OperatingMode */)
         -> UniquePtr<MiriGenMCShim>;

        fn handleExecutionStart(self: Pin<&mut MiriGenMCShim>);
        fn handleExecutionEnd(self: Pin<&mut MiriGenMCShim>);

        fn handleLoad(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            address: usize,
            size: usize,
            memory_ordering: MemoryOrdering,
        ) -> u64; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleReadModifyWrite(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            address: usize,
            size: usize,
            load_ordering: MemoryOrdering,
            store_ordering: MemoryOrdering,
            rmw_op: RmwBinOp,
            rhs_value: u64,
        ) -> u64; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleStore(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            address: usize,
            size: usize,
            value: u64,
            // value: u128, // TODO GENMC: handle this
            memory_ordering: MemoryOrdering,
            rmw: bool,
        );
        fn handleFence(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            memory_ordering: MemoryOrdering,
        );

        fn handleMalloc(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            size: usize,
            alignment: usize,
        ) -> usize;
        fn handleFree(self: Pin<&mut MiriGenMCShim>, thread_id: u32, address: usize, size: usize);

        // fn handleThreadKill(self: Pin<&mut MiriGenMCShim>, thread_id: u32, parent_id: u32);
        fn handleThreadCreate(self: Pin<&mut MiriGenMCShim>, thread_id: u32, parent_id: u32);
        fn handleThreadJoin(self: Pin<&mut MiriGenMCShim>, thread_id: u32, child_id: u32);
        fn handleThreadFinish(self: Pin<&mut MiriGenMCShim>, thread_id: u32, ret_val: u64);

        fn scheduleNext(self: Pin<&mut MiriGenMCShim>, threads: &mut Threads) -> bool;
        fn isHalting(self: &MiriGenMCShim) -> bool;
        fn isMoot(self: &MiriGenMCShim) -> bool;
        fn isExplorationDone(self: Pin<&mut MiriGenMCShim>) -> bool;

        fn printGraph(self: Pin<&mut MiriGenMCShim>);
    }
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

    fn is_enabled(&self, thread_id: u32) -> bool {
        // eprintln!("Threads::is_enabled({thread_id})");
        true
    }

    fn set_next_thread(&mut self, thread_id: u32) {
        eprintln!("Threads::set_next_thread({thread_id})");
    }
}

// #[allow(non_snake_case)]
// fn isEnabled(threads: &Threads, thread_id: u32) -> bool {
//     threads.is_enabled(thread_id)
// }

trait ToGenmcMemoryOrdering {
    fn convert(self) -> MemoryOrdering;
}

impl ToGenmcMemoryOrdering for AtomicReadOrd {
    fn convert(self) -> MemoryOrdering {
        match self {
            AtomicReadOrd::Relaxed => MemoryOrdering::Relaxed,
            AtomicReadOrd::Acquire => MemoryOrdering::Acquire,
            AtomicReadOrd::SeqCst => MemoryOrdering::SequentiallyConsistent,
        }
    }
}

impl ToGenmcMemoryOrdering for AtomicWriteOrd {
    fn convert(self) -> MemoryOrdering {
        match self {
            AtomicWriteOrd::Relaxed => MemoryOrdering::Relaxed,
            AtomicWriteOrd::Release => MemoryOrdering::Relaxed,
            AtomicWriteOrd::SeqCst => MemoryOrdering::SequentiallyConsistent,
        }
    }
}

impl ToGenmcMemoryOrdering for AtomicFenceOrd {
    fn convert(self) -> MemoryOrdering {
        match self {
            AtomicFenceOrd::Acquire => MemoryOrdering::Acquire,
            AtomicFenceOrd::Release => MemoryOrdering::Release,
            AtomicFenceOrd::AcqRel => MemoryOrdering::AcquireRelease,
            AtomicFenceOrd::SeqCst => MemoryOrdering::SequentiallyConsistent,
        }
    }
}

impl From<AtomicRwOrd> for (MemoryOrdering, MemoryOrdering) {
    fn from(value: AtomicRwOrd) -> Self {
        match value {
            // TODO GENMC: are these correct?
            AtomicRwOrd::Relaxed => (MemoryOrdering::Relaxed, MemoryOrdering::Relaxed),
            AtomicRwOrd::Acquire => (MemoryOrdering::Acquire, MemoryOrdering::Relaxed),
            AtomicRwOrd::Release => (MemoryOrdering::Relaxed, MemoryOrdering::Release),
            AtomicRwOrd::AcqRel => (MemoryOrdering::Acquire, MemoryOrdering::Release),
            AtomicRwOrd::SeqCst =>
                (MemoryOrdering::SequentiallyConsistent, MemoryOrdering::SequentiallyConsistent),
        }
    }
}

fn to_genmc_rmw_op(rmw_op: AtomicOp, is_unsigned: bool) -> RmwBinOp {
    match (rmw_op, is_unsigned) {
        (AtomicOp::Min, false) => RmwBinOp::Min, // TODO GENMC: is there a use for FMin? (Min, UMin, FMin)
        (AtomicOp::Max, false) => RmwBinOp::Max,
        (AtomicOp::Min, true) => RmwBinOp::UMin,
        (AtomicOp::Max, true) => RmwBinOp::UMax,
        (AtomicOp::MirOp(bin_op, negate), _) =>
            match bin_op {
                rustc_middle::mir::BinOp::Add => RmwBinOp::Add,
                rustc_middle::mir::BinOp::Sub => RmwBinOp::Sub,
                rustc_middle::mir::BinOp::BitOr if !negate => RmwBinOp::Or,
                rustc_middle::mir::BinOp::BitXor if !negate => RmwBinOp::Xor,
                rustc_middle::mir::BinOp::BitAnd if negate => RmwBinOp::Nand,
                rustc_middle::mir::BinOp::BitAnd => RmwBinOp::And,
                _ => {
                    panic!("unsupported atomic operation: bin_op: {bin_op:?}, negate: {negate}");
                }
            },
    }
}

// fn to_genmc_memory_ordering(atomic_ordering: Option<AtomicOrdering>) -> MemoryOrdering {
//     let Some(atomic_ordering) = atomic_ordering else {
//         return MemoryOrdering::NotAtomic;
//     };
//     match atomic_ordering {
//         AtomicOrdering::Unordered => MemoryOrdering::Unordered,
//         AtomicOrdering::Relaxed => MemoryOrdering::Relaxed,
//         AtomicOrdering::Acquire => MemoryOrdering::Acquire,
//         AtomicOrdering::Release => MemoryOrdering::Release,
//         AtomicOrdering::AcquireRelease => MemoryOrdering::AcquireRelease,
//         AtomicOrdering::SequentiallyConsistent => MemoryOrdering::SequentiallyConsistent,
//     }
// }

#[derive(Clone, Debug)]
pub struct GenmcConfig {
    // TODO
    #[allow(unused)]
    pub(crate) memory_model: Box<str>, // TODO: could potentially make this an enum
}

#[allow(clippy::derivable_impls)] // TODO: remove
impl Default for GenmcConfig {
    fn default() -> Self {
        Self { memory_model: "RC11".into() }
    }
}

pub struct GenmcCtx {
    // TODO GENMC: remove this Mutex if possible
    handle: RefCell<UniquePtr<MiriGenMCShim>>,
    // TODO
    // pub(crate) genmc_seed: u64; // OR: Option<u64>
    pub(crate) rng: RefCell<StdRng>, // TODO GENMC: temporary rng for handling scheduling
}

fn scalar_to_genmc_scalar(value: crate::Scalar) -> u64 {
    // TODO: proper handling of `Scalar`
    match value {
        rustc_const_eval::interpret::Scalar::Int(scalar_int) =>
            scalar_int.to_uint(scalar_int.size()).try_into().unwrap(), // TODO GENMC: doesn't work for size != 8
        rustc_const_eval::interpret::Scalar::Ptr(_pointer, _size) => todo!(), // pointer.into_parts().1.bytes(),
    }
}

/// Convert an address selected by GenMC into Miri's type for addresses.
/// This function may panic on platforms with addresses larger than 64 bits
fn to_miri_size(genmc_address: usize) -> Size {
    Size::from_bytes(genmc_address)
}

/// Convert an address (originally selected by GenMC) back into form that GenMC expects
/// This function should never panic, since we received the address from GenMC (as a `usize`)
fn size_to_genmc(miri_address: Size) -> usize {
    miri_address.bytes().try_into().unwrap()
}

impl GenmcCtx {
    pub fn new(config: &GenmcConfig) -> Self {
        tracing::trace!("GenMC: Creating new GenMC Context");

        /*
         * NOTE on integer sizes for storing addresses:
         * Miri requests addresses from GenMC, which internally uses `uintptr_t` for addresses.
         * Miri uses `u64` for addresses, so unless we run on a larger than 64-bit host, the addresses returned by GenMC will fit in a `u64`
         */
        if u64::try_from(usize::MAX).is_err() {
            warn!(
                "GenMC mode is unsupported on architectures with pointers larger than 64 bits, so results might be garbage!"
            );
        }

        let _config = config; // TODO GENMC: implement GenMC config

        let handle = createGenmcHandle();
        assert!(!handle.is_null());
        let handle = RefCell::new(handle);

        let rng = RefCell::new(StdRng::seed_from_u64(0));
        Self { handle, rng }
    }

    pub fn print_genmc_graph(&self) {
        tracing::trace!("GenMC: print the Execution graph");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.printGraph();
    }

    pub fn is_halting(&self) -> bool {
        // TODO GENMC: this probably shouldn't be exposed
        tracing::trace!("GenMC: ask if execution is halting");
        let mc = self.handle.borrow();
        mc.isHalting()
    }

    pub fn is_moot(&self) -> bool {
        // TODO GENMC: this probably shouldn't be exposed
        tracing::trace!("GenMC: ask if execution is moot");
        let mc = self.handle.borrow();
        mc.isMoot()
    }

    pub fn is_exploration_done(&self) -> bool {
        tracing::trace!("GenMC: ask if execution exploration is done");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.isExplorationDone()
    }

    /**** Memory access handling ****/

    pub(crate) fn handle_execution_start(&self) {
        tracing::trace!("GenMC: inform GenMC that new execution started");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleExecutionStart();
    }

    pub(crate) fn handle_execution_end(&self) {
        tracing::trace!("GenMC: inform GenMC that execution ended!");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleExecutionEnd();
        // TODO GENMC: could return as result here maybe?
    }

    //* might fails if there's a race, load might also not read anything (returns None) */
    pub(crate) fn atomic_load<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        ordering: AtomicReadOrd,
    ) -> Result<crate::Scalar, ()> {
        let ordering = ordering.convert();
        tracing::trace!(
            "GenMC: atomic_load with ordering {ordering:?}, address: {address:?}, size: {size:?}"
        );
        self.atomic_load_impl(machine, address, size, ordering)
    }

    pub(crate) fn atomic_store<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        value: crate::Scalar,
        ordering: AtomicWriteOrd,
    ) -> Result<(), ()> {
        let ordering = ordering.convert();
        tracing::trace!(
            "GenMC: atomic_store of value {value:?}, with ordering {ordering:?}, address: {address:?}, size: {size:?}"
        );
        self.atomic_store_impl(machine, address, size, value, ordering)
    }

    pub(crate) fn atomic_fence<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        ordering: AtomicFenceOrd,
    ) -> Result<(), ()> {
        tracing::trace!("GenMC: atomic_fence with ordering: {ordering:?}");

        let ordering = ordering.convert();
        let curr_thread = machine.threads.active_thread().to_u32();

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleFence(curr_thread, ordering);

        Ok(())
    }

    pub(crate) fn atomic_rmw_op<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        ordering: AtomicRwOrd,
        rmw_op: AtomicOp,
        rhs_scalar: crate::Scalar,
        is_unsigned: bool,
    ) -> Result<crate::Scalar, ()> {
        assert_ne!(0, size.bytes());
        let curr_thread = machine.threads.active_thread().to_u32();
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        let (load_ordering, store_ordering) = ordering.into();
        tracing::trace!(
            "GenMC: atomic_rmw_op, thread: {curr_thread}, address: {address:?}, size: {size:?}, orderings: ({load_ordering:?}, {store_ordering:?})",
        );

        let genmc_rmw_op = to_genmc_rmw_op(rmw_op, is_unsigned);
        let genmc_rhs = scalar_to_genmc_scalar(rhs_scalar);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let old_value = pinned_mc.handleReadModifyWrite(
            curr_thread,
            genmc_address,
            genmc_size,
            load_ordering,
            store_ordering,
            genmc_rmw_op,
            genmc_rhs,
        );

        let old_value_scalar_int = ScalarInt::try_from_uint(old_value, size).unwrap();
        let old_value_scalar = crate::Scalar::Int(old_value_scalar_int);

        Ok(old_value_scalar)
    }

    pub(crate) fn atomic_exchange<'tcx>(&self, _machine: &MiriMachine<'tcx>) -> Result<(), ()> {
        tracing::trace!("GenMC: atomic_exchange");
        // TODO GENMC
        todo!()
    }

    pub(crate) fn atomic_compare_exchange<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        can_fail_spuriously: bool,
    ) -> Result<(), ()> {
        // TODO GENMC
        tracing::trace!("GenMC: atomic_compare_exchange");
        dbg!(can_fail_spuriously);
        todo!()
    }

    pub(crate) fn memory_load<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
    ) -> Result<(), ()> {
        let curr_thread = machine.threads.active_thread().to_u32();
        tracing::trace!(
            "GenMC: TODO GENMC: SKIP! received memory_load (non-atomic): thread: {curr_thread}, address: {address:?}, size: {size:?}, thread_id: {:?}",
            machine.threads.active_thread(),
        );
        // GenMC doesn't like ZSTs, and they can't have any data races, so we skip them
        if size.bytes() == 0 {
            return Ok(());
        }
        // self.atomic_load_impl(address, size, MemoryOrdering::NotAtomic) // TODO GENMC
        Ok(())
    }

    pub(crate) fn memory_store<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        // value: crate::Scalar,
    ) -> Result<(), ()> {
        let curr_thread = machine.threads.active_thread().to_u32();
        tracing::trace!(
            "GenMC: TODO GENMC: SKIP! received memory_store (non-atomic): thread: {curr_thread}, address: {address:?}, size: {size:?}"
        );
        // GenMC doesn't like ZSTs, and they can't have any data races, so we skip them
        if size.bytes() == 0 {
            return Ok(());
        }
        // self.atomic_store_impl(address, size, value_genmc, MemoryOrdering::NotAtomic) // TODO GENMC
        Ok(())
    }

    /**** Memory (de)allocation ****/

    pub(crate) fn handle_alloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        size: Size,
        alignment: Align,
    ) -> Result<u64, ()> {
        let curr_thread = machine.threads.active_thread().to_u32();
        tracing::trace!(
            "GenMC: handle_alloc (thread: {curr_thread}, size: {size:?}, alignment: {alignment:?})"
        );
        // kind: MemoryKind, TODO GENMC: Does GenMC care about the kind of Memory?

        // GenMC doesn't support ZSTs, so we set the minimum size to 1 byte
        let genmc_size = size_to_genmc(size).max(1);

        let alignment = alignment.bytes_usize();

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let genmc_address = pinned_mc.handleMalloc(curr_thread, genmc_size, alignment);

        let chosen_address = to_miri_size(genmc_address);
        let chosen_address = chosen_address.bytes();
        Ok(chosen_address)
    }

    pub(crate) fn handle_dealloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        align: Align,
        kind: MemoryKind,
    ) -> Result<(), ()> {
        tracing::trace!(
            "GenMC: TODO GENMC: (SKIP) telling GenMC about memory deallocation (address: {address:?})"
        );
        return Ok(());

        let curr_thread = machine.threads.active_thread().to_u32();
        eprintln!(
            "TODO GENMC: inform GenMC about memory deallocation (thread: {curr_thread}, address: 0x{address:?}, size: {size:?}, align: {align:?}, memory_kind: {kind:?}"
        );

        let genmc_address = size_to_genmc(address);
        // GenMC doesn't support ZSTs, so we set the minimum size to 1 byte
        let genmc_size = size_to_genmc(size).max(1);

        let pinned_mc =
            self.handle.borrow_mut().as_mut().expect("model checker should not be null");
        pinned_mc.handleFree(curr_thread, genmc_address, genmc_size);

        Ok(())
    }

    /**** Thread management ****/

    pub(crate) fn handle_thread_create<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
        new_thread_id: ThreadId,
    ) -> Result<(), ()> {
        let new_thread_id = new_thread_id.to_u32();
        let parent_thread_id = threads.active_thread().to_u32();

        tracing::trace!(
            "GenMC: handling thread creation (thread {parent_thread_id} spawned thread {new_thread_id})"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleThreadCreate(new_thread_id, parent_thread_id);

        Ok(())
    }

    pub(crate) fn handle_thread_join(
        &self,
        // machine: &MiriMachine<'tcx>,
        // threads: &ThreadManager<'tcx>,
        active_thread_id: ThreadId,
        child_thread_id: ThreadId,
    ) -> Result<(), ()> {
        // let curr_thread_id = machine.threads.active_thread().to_u32();
        let curr_thread_id = active_thread_id.to_u32();
        let child_thread_id = child_thread_id.to_u32();

        tracing::trace!(
            "GenMC: handling thread joining (thread {curr_thread_id} joining thread {child_thread_id})"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleThreadJoin(curr_thread_id, child_thread_id);

        Ok(())
    }

    pub(crate) fn handle_thread_finish<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
    ) -> Result<(), ()> {
        let curr_thread_id = threads.active_thread().to_u32();
        let ret_val = 0; // TODO GENMC: do threads in Miri have a return value?

        tracing::trace!(
            "GenMC: handling thread finish (thread {curr_thread_id} returns with DUMMY value 0)"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleThreadFinish(curr_thread_id, ret_val);

        Ok(())
    }

    /**** Scheduling queries ****/

    pub(crate) fn should_preempt(&self) -> bool {
        true // TODO GENMC
    }

    pub(crate) fn schedule_thread<'tcx>(
        &self,
        thread_manager: &ThreadManager<'tcx>,
    ) -> Result<ThreadId, ()> {
        // TODO GENMC
        tracing::trace!("GenMC: TODO GENMC: ask who to schedule next");

        let mut threads = Threads::new();

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.scheduleNext(&mut threads);

        let enabled_thread_count = thread_manager.get_enabled_thread_count();
        let mut i = self.rng.borrow_mut().random_range(0..enabled_thread_count);
        for (thread_id, thread) in thread_manager.threads_ref().iter_enumerated() {
            if !thread.get_state().is_enabled() {
                continue;
            }
            if i != 0 {
                i -= 1;
                continue;
            }
            return Ok(thread_id);
        }
        unreachable!()
    }
}

impl GenmcCtx {
    //* might fails if there's a race, load might also not read anything (returns None) */
    fn atomic_load_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        memory_ordering: MemoryOrdering,
    ) -> Result<crate::Scalar, ()> {
        assert_ne!(0, size.bytes());
        let curr_thread = machine.threads.active_thread().to_u32();
        tracing::trace!(
            "GenMC: load, thread: {curr_thread}, address: {address:?}, size: {size:?}, {memory_ordering:?}"
        );
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let read_value =
            pinned_mc.handleLoad(curr_thread, genmc_address, genmc_size, memory_ordering);

        let scalar_int = ScalarInt::try_from_uint(read_value, size).unwrap();
        let read_scalar = crate::Scalar::Int(scalar_int);

        Ok(read_scalar)
    }

    fn atomic_store_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        value: crate::Scalar, // TODO GENMC: handle larger values
        memory_ordering: MemoryOrdering,
    ) -> Result<(), ()> {
        assert_ne!(0, size.bytes());
        let curr_thread = machine.threads.active_thread().to_u32();

        let genmc_value = scalar_to_genmc_scalar(value);
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        tracing::trace!(
            "GenMC: store, thread: {curr_thread}, address: {address:?}, size: {size:?}, ordering {memory_ordering:?}, value: {value:?}"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleStore(
            curr_thread,
            genmc_address,
            genmc_size,
            genmc_value,
            memory_ordering,
            false,
        );
        // TODO GENMC
        Ok(())
    }
}

impl std::fmt::Debug for GenmcCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenmcCtx")
            // .field("mc", &self.mc)
            .finish_non_exhaustive()
    }
}
