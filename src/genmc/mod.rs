use std::cell::{Cell, RefCell};
#[allow(unused_imports)] // TODO GENMC: false warning?
use std::pin::Pin;

use cxx::UniquePtr;
use rand::prelude::*;
use rand::rngs::StdRng;
use rustc_abi::{Align, Size};
use rustc_middle::ty::ScalarInt;
use tracing::{info, warn};

use self::ffi::{
    MemoryOrdering, MiriGenMCShim, RmwBinOp, StoreEventType, ThreadState, createGenmcHandle,
};
use crate::intrinsics::AtomicOp;
use crate::{
    AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd, MemoryKind, MiriMachine, Scalar,
    ThreadId, ThreadManager,
};

mod cxx_extra;

pub use self::ffi::GenmcParams;

// TODO GENMC: document this:
#[derive(Debug, Default, Clone)]
pub struct GenmcConfig {
    pub params: GenmcParams,
    pub print_graph: GenmcPrintGraphSetting,
}

// TODO GENMC: document this:
#[derive(Debug, Default, Clone, Copy)]
pub enum GenmcPrintGraphSetting {
    #[default]
    None,
    First,
    All,
}

impl Default for GenmcParams {
    fn default() -> Self {
        Self {
            memory_model: "RC11".into(),
            quiet: true,
            print_random_schedule_seed: false,
            disable_race_detection: false,
        }
    }
}

impl GenmcConfig {
    pub fn set_graph_printing(&mut self, param: &str) {
        self.print_graph = match param {
            "none" | "false" | "" => GenmcPrintGraphSetting::None,
            "first" | "true" => GenmcPrintGraphSetting::First,
            // TODO GENMC: are these graphs always the same? Would printing the last one make more sense?
            "all" => GenmcPrintGraphSetting::All,
            _ => todo!("Unsupported argument"),
        }
    }
}

// TODO GENMC: extract the ffi module if possible, to reduce number of required recompilation
#[cxx::bridge]
mod ffi {

    /// Parameters that will be given to GenMC for setting up the model checker.
    /// (The fields of this struct are visible to both Rust and C++)
    #[derive(Clone, Debug)]
    struct GenmcParams {
        #[allow(unused)]
        pub memory_model: String, // TODO GENMC: (is this even needed?) could potentially make this an enum

        pub quiet: bool, // TODO GENMC: maybe make log-level more fine grained
        // pub genmc_seed: u64; // OR: Option<u64>
        pub print_random_schedule_seed: bool,
        pub disable_race_detection: bool,
    }

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
        Xchg,
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

    #[derive(Debug)]
    enum StoreEventType {
        Normal,
        ReadModifyWrite,
        CompareExchange,
    }

    #[derive(Debug)]
    enum ThreadState {
        Enabled = 0,
        Blocked = 1,
        StackEmpty = 2,
        Terminated = 3, // TODO GENMC: check if any other states/info is needed
    }

    #[derive(Debug)]
    struct CompareExchangeResult {
        read_value: u64, // TODO GENMC: handle bigger values
        is_success: bool,
    }

    extern "Rust" {
        // TODO GENMC (CLEANUP): remove if not needed
        type Threads;
        fn is_enabled(self: &Threads, thread_id: u32) -> bool;
        fn set_next_thread(self: &mut Threads, thread_id: u32);
    }

    unsafe extern "C++" {
        include!("miri/genmc/src/Verification/MiriInterface.hpp");

        type MemoryOrdering;
        type RmwBinOp;
        type StoreEventType;
        type ThreadState;
        // type OperatingMode; // Estimation(budget) or Verification

        type CompareExchangeResult;

        type MiriGenMCShim;

        fn createGenmcHandle(config: &GenmcParams, /* OperatingMode */)
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
        fn handleCompareExchange(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            address: usize,
            size: usize,
            expected_value: u64,
            new_value: u64,
            success_load_ordering: MemoryOrdering,
            success_store_ordering: MemoryOrdering,
            fail_load_ordering: MemoryOrdering,
            can_fail_spuriously: bool,
        ) -> CompareExchangeResult;
        fn handleStore(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            address: usize,
            size: usize,
            value: u64,
            // value: u128, // TODO GENMC: handle this
            memory_ordering: MemoryOrdering,
            store_event_type: StoreEventType,
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

        fn scheduleNext(self: Pin<&mut MiriGenMCShim>, thread_states: &[ThreadState]) -> i64;
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
            AtomicWriteOrd::Release => MemoryOrdering::Release,
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

// TODO: add methods for this conversion:

impl From<AtomicRwOrd> for (MemoryOrdering, MemoryOrdering) {
    fn from(value: AtomicRwOrd) -> Self {
        match value {
            // TODO GENMC: check if we need to implement Release ==> (Release, Release)
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

pub struct GenmcCtx {
    // TODO GENMC: remove this Mutex if possible
    handle: RefCell<UniquePtr<MiriGenMCShim>>,

    #[allow(unused)] // TODO GENMC (CLEANUP)
    pub(crate) rng: RefCell<StdRng>, // TODO GENMC: temporary rng for handling scheduling

    max_thread_id: Cell<u32>,
}

fn scalar_to_genmc_scalar(value: Scalar) -> u64 {
    // TODO GENMC: proper handling of `Scalar`
    match value {
        rustc_const_eval::interpret::Scalar::Int(scalar_int) =>
            scalar_int.to_uint(scalar_int.size()).try_into().unwrap(), // TODO GENMC: doesn't work for size != 8
        rustc_const_eval::interpret::Scalar::Ptr(_pointer, _size) => todo!(), // pointer.into_parts().1.bytes(),
    }
}

fn genmc_scalar_to_scalar(value: u64, size: Size) -> Scalar {
    // TODO GENMC: proper handling of large integers
    // TODO GENMC: proper handling of pointers (currently assumes all integers)

    let value_scalar_int = ScalarInt::try_from_uint(value, size).unwrap();
    Scalar::Int(value_scalar_int)
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
        info!("GenMC: Creating new GenMC Context");

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

        let handle = createGenmcHandle(&config.params);
        assert!(!handle.is_null());
        let handle = RefCell::new(handle);

        let seed = 0;
        let rng = RefCell::new(StdRng::seed_from_u64(seed));
        let max_thread_id = Cell::new(0);
        Self { handle, rng, max_thread_id }
    }

    pub fn print_genmc_graph(&self) {
        info!("GenMC: print the Execution graph");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.printGraph();
    }

    pub fn is_halting(&self) -> bool {
        // TODO GENMC: this probably shouldn't be exposed
        info!("GenMC: ask if execution is halting");
        let mc = self.handle.borrow();
        mc.isHalting()
    }

    pub fn is_moot(&self) -> bool {
        // TODO GENMC: this probably shouldn't be exposed
        info!("GenMC: ask if execution is moot");
        let mc = self.handle.borrow();
        mc.isMoot()
    }

    pub fn is_exploration_done(&self) -> bool {
        info!("GenMC: ask if execution exploration is done");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.isExplorationDone()
    }

    /**** Memory access handling ****/

    pub(crate) fn handle_execution_start(&self) {
        info!("GenMC: inform GenMC that new execution started");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleExecutionStart();
    }

    pub(crate) fn handle_execution_end(&self) {
        info!("GenMC: inform GenMC that execution ended!");
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
    ) -> Result<Scalar, ()> {
        let ordering = ordering.convert();
        self.atomic_load_impl(machine, address, size, ordering)
    }

    pub(crate) fn atomic_store<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        value: Scalar,
        ordering: AtomicWriteOrd,
    ) -> Result<(), ()> {
        let ordering = ordering.convert();
        self.atomic_store_impl(machine, address, size, value, ordering)
    }

    pub(crate) fn atomic_fence<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        ordering: AtomicFenceOrd,
    ) -> Result<(), ()> {
        info!("GenMC: atomic_fence with ordering: {ordering:?}");

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
        rhs_scalar: Scalar,
        is_unsigned: bool,
    ) -> Result<Scalar, ()> {
        let (load_ordering, store_ordering) = ordering.into();
        let genmc_rmw_op = to_genmc_rmw_op(rmw_op, is_unsigned);
        tracing::info!(
            "GenMC: atomic_rmw_op (op: {genmc_rmw_op:?}): rhs value: {rhs_scalar:?}, is_unsigned: {is_unsigned}, orderings ({load_ordering:?}, {store_ordering:?})"
        );
        self.atomic_rmw_op_impl(
            machine,
            address,
            size,
            load_ordering,
            store_ordering,
            genmc_rmw_op,
            rhs_scalar,
        )
    }

    pub(crate) fn atomic_exchange<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        rhs_scalar: Scalar,
        ordering: AtomicRwOrd,
    ) -> Result<Scalar, ()> {
        // TODO GENMC: could maybe merge this with atomic_rmw?

        let (load_ordering, store_ordering) = ordering.into();
        let genmc_rmw_op = RmwBinOp::Xchg;
        tracing::info!(
            "GenMC: atomic_exchange (op: {genmc_rmw_op:?}): new value: {rhs_scalar:?}, orderings ({load_ordering:?}, {store_ordering:?})"
        );
        self.atomic_rmw_op_impl(
            machine,
            address,
            size,
            load_ordering,
            store_ordering,
            genmc_rmw_op,
            rhs_scalar,
        )
    }

    pub(crate) fn atomic_compare_exchange<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        expected_old_value: Scalar,
        new_value: Scalar,
        success: AtomicRwOrd,
        fail: AtomicReadOrd,
        can_fail_spuriously: bool,
    ) -> Result<(Scalar, bool), ()> {
        let (success_load_ordering, success_store_ordering) = success.into();
        let fail_load_ordering = fail.convert();

        info!(
            "GenMC: atomic_compare_exchange, address: {address:?}, size: {size:?} ({expected_old_value:?}, {new_value:?}, {success:?}, {fail:?}), can fail spuriously: {can_fail_spuriously}"
        );
        info!(
            "GenMC: atomic_compare_exchange orderings: success: ({success_load_ordering:?}, {success_store_ordering:?}), failure load ordering: {fail_load_ordering:?}"
        );

        if can_fail_spuriously {
            tracing::warn!(
                "GenMC: TODO GENMC: implement spurious failures for compare_exchange_weak"
            );
        }

        let curr_thread = machine.threads.active_thread().to_u32();
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        let genmc_expected_value = scalar_to_genmc_scalar(expected_old_value);
        let genmc_new_value = scalar_to_genmc_scalar(new_value);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let result = pinned_mc.handleCompareExchange(
            curr_thread,
            genmc_address,
            genmc_size,
            genmc_expected_value,
            genmc_new_value,
            success_load_ordering,
            success_store_ordering,
            fail_load_ordering,
            can_fail_spuriously,
        );

        let return_scalar = genmc_scalar_to_scalar(result.read_value, size);
        info!(
            "GenMC: atomic_compare_exchange: result: {result:?}, returning scalar: {return_scalar:?}"
        );
        Ok((return_scalar, result.is_success))
    }

    pub(crate) fn memory_load<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
    ) -> Result<(), ()> {
        let curr_thread = machine.threads.active_thread().to_u32();
        info!(
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
        info!(
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
        info!(
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
        let curr_thread = machine.threads.active_thread().to_u32();
        info!(
            "GenMC: memory deallocation, thread: {curr_thread}, address: {address:?}, size: {size:?}, align: {align:?}, memory_kind: {kind:?}"
        );

        let genmc_address = size_to_genmc(address);
        // GenMC doesn't support ZSTs, so we set the minimum size to 1 byte
        let genmc_size = size_to_genmc(size).max(1);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
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

        info!(
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
        let curr_thread_id = active_thread_id.to_u32();
        let child_thread_id = child_thread_id.to_u32();

        info!(
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

        // NOTE: Miri doesn't support return values for threads, but GenMC expects one, so we return 0
        let ret_val = 0;

        info!("GenMC: handling thread finish (thread {curr_thread_id} returns with dummy value 0)");

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
        let mut max_thread_id = self.max_thread_id.get();

        // TODO GENMC: improve performance, e.g., with SmallVec
        let mut threads_state: Vec<ThreadState> =
            Vec::with_capacity(max_thread_id.try_into().unwrap());

        let mut enabled_count = 0;
        for (thread_id, thread) in thread_manager.threads_ref().iter_enumerated() {
            max_thread_id = max_thread_id.max(thread_id.to_u32());
            let thread_id_usize = thread_id.to_u32().try_into().unwrap();
            assert!(threads_state.len() <= thread_id_usize);
            while threads_state.len() < thread_id_usize {
                threads_state.push(ThreadState::Terminated);
            }
            // If a thread is finished, there might still be something to do (see `src/concurrency/thread.rs`: `run_on_stack_empty`)
            // In that case, the thread is still enabled, but has an empty stack
            // We don't want to run this thread in GenMC mode (especially not the main thread, which terminates the program once it's done)
            // We tell GenMC that this thread is disabled
            let is_enabled = thread.get_state().is_enabled();
            let is_finished = thread.top_user_relevant_frame().is_none();
            threads_state.push(match (is_enabled, is_finished) {
                (true, false) => {
                    enabled_count += 1;
                    ThreadState::Enabled
                }
                (true, true) => ThreadState::StackEmpty,
                (false, true) => ThreadState::Terminated,
                (false, false) => ThreadState::Blocked,
            })
        }
        // Once there are no threads with non-empty stacks anymore, we allow scheduling threads with empty stacks:
        if enabled_count == 0 {
            for thread_state in threads_state.iter_mut().rev() {
                if ThreadState::StackEmpty == *thread_state {
                    *thread_state = ThreadState::Enabled;
                    enabled_count += 1;
                    break;
                }
            }
            assert_ne!(0, enabled_count);
        }
        // TODO GENMC (OPTIMIZATION): could possibly skip scheduling call if we only have 1 enabled thread

        // To make sure we are not missing any threads (and since GenMC will index into this vec), we add them as `blocked`
        let old_len = threads_state.len();
        threads_state.resize((max_thread_id + 1).try_into().unwrap(), ThreadState::Blocked);
        info!(
            "GenMC: schedule_thread: resizing threads_state: {old_len} --> {} (max_thread_id: {max_thread_id}, old: {}), threads_state: {threads_state:?}",
            threads_state.len(),
            self.max_thread_id.get()
        );
        assert!(old_len <= threads_state.len());
        assert!(self.max_thread_id.get() <= max_thread_id);
        self.max_thread_id.set(max_thread_id);
        assert_eq!(self.max_thread_id.get(), max_thread_id);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let result = pinned_mc.scheduleNext(&threads_state);
        if let Ok(next_thread) = u32::try_from(result) {
            // TODO GENMC: can we ensure this thread_id is valid?
            info!(
                "GenMC: next thread to run is {next_thread}, total {} threads (max thread id: {max_thread_id})",
                threads_state.len()
            );
            assert!(usize::try_from(next_thread).unwrap() < threads_state.len());
            assert!(threads_state[usize::try_from(next_thread).unwrap()] == ThreadState::Enabled);
            let next_thread = ThreadId::new_unchecked(next_thread);
            Ok(next_thread)
        } else {
            // Negative result means there is no next thread to schedule
            unimplemented!();
        }

        // let enabled_thread_count = thread_manager.get_enabled_thread_count();
        // let mut i = self.rng.borrow_mut().random_range(0..enabled_thread_count);
        // for (thread_id, thread) in thread_manager.threads_ref().iter_enumerated() {
        //     if !thread.get_state().is_enabled() {
        //         continue;
        //     }
        //     if i != 0 {
        //         i -= 1;
        //         continue;
        //     }
        //     return Ok(thread_id);
        // }
        // unreachable!()
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
    ) -> Result<Scalar, ()> {
        assert_ne!(0, size.bytes());
        let curr_thread = machine.threads.active_thread().to_u32();
        info!(
            "GenMC: load, thread: {curr_thread}, address: {address:?}, size: {size:?}, ordering: {memory_ordering:?}"
        );
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let read_value =
            pinned_mc.handleLoad(curr_thread, genmc_address, genmc_size, memory_ordering);

        let read_scalar = genmc_scalar_to_scalar(read_value, size);
        Ok(read_scalar)
    }

    fn atomic_store_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        value: Scalar, // TODO GENMC: handle larger values
        memory_ordering: MemoryOrdering,
    ) -> Result<(), ()> {
        assert_ne!(0, size.bytes());
        let curr_thread = machine.threads.active_thread().to_u32();

        let genmc_value = scalar_to_genmc_scalar(value);
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        info!(
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
            StoreEventType::Normal,
        );
        // TODO GENMC
        Ok(())
    }

    pub(crate) fn atomic_rmw_op_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        load_ordering: MemoryOrdering,
        store_ordering: MemoryOrdering,
        genmc_rmw_op: RmwBinOp,
        rhs_scalar: Scalar,
    ) -> Result<Scalar, ()> {
        assert_ne!(0, size.bytes());
        let curr_thread = machine.threads.active_thread().to_u32();
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        info!(
            "GenMC: atomic_rmw_op (op: {genmc_rmw_op:?}, rhs value: {rhs_scalar:?}), thread: {curr_thread}, address: {address:?}, size: {size:?}, orderings: ({load_ordering:?}, {store_ordering:?})",
        );

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

        let old_value_scalar = genmc_scalar_to_scalar(old_value, size);
        Ok(old_value_scalar)
    }
}

impl std::fmt::Debug for GenmcCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenmcCtx")
            // .field("mc", &self.mc)
            .finish_non_exhaustive()
    }
}
