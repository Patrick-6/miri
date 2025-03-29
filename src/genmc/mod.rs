use std::cell::RefCell;
#[allow(unused_imports)] // TODO GENMC: false warning?
use std::pin::Pin;

use cxx::UniquePtr;
use rand::prelude::*;
use rand::rngs::StdRng;
use rustc_abi::{Align, Size};
use tracing::{info, warn};

use self::ffi::{
    MemoryOrdering, MiriGenMCShim, RmwBinOp, StoreEventType, ThreadState, createGenmcHandle,
};
use self::helper::{Threads, genmc_scalar_to_scalar, scalar_to_genmc_scalar};
use self::mapping::ToGenmcMemoryOrdering;
use self::thread_info_manager::{GenmcThreadId, GenmcThreadIdInner, ThreadInfoManager};
use crate::intrinsics::AtomicOp;
use crate::{
    AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd, MemoryKind, MiriMachine, Scalar,
    ThreadId, ThreadManager,
};

mod config;
mod cxx_extra;
mod helper;
mod mapping;
mod thread_info_manager;

pub use self::config::{GenmcConfig, GenmcPrintGraphSetting};
pub use self::ffi::GenmcParams;

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
            thread_id: i32,
            address: usize,
            size: usize,
            memory_ordering: MemoryOrdering,
        ) -> u64; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleReadModifyWrite(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            load_ordering: MemoryOrdering,
            store_ordering: MemoryOrdering,
            rmw_op: RmwBinOp,
            rhs_value: u64,
        ) -> u64; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleCompareExchange(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
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
            thread_id: i32,
            address: usize,
            size: usize,
            value: u64,
            // value: u128, // TODO GENMC: handle this
            memory_ordering: MemoryOrdering,
            store_event_type: StoreEventType,
        );
        fn handleFence(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            memory_ordering: MemoryOrdering,
        );

        fn handleMalloc(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            size: usize,
            alignment: usize,
        ) -> usize;
        fn handleFree(self: Pin<&mut MiriGenMCShim>, thread_id: i32, address: usize, size: usize);

        fn handleThreadCreate(self: Pin<&mut MiriGenMCShim>, thread_id: i32, parent_id: i32);
        fn handleThreadJoin(self: Pin<&mut MiriGenMCShim>, thread_id: i32, child_id: i32);
        fn handleThreadFinish(self: Pin<&mut MiriGenMCShim>, thread_id: i32, ret_val: u64);

        fn scheduleNext(self: Pin<&mut MiriGenMCShim>, thread_states: &[ThreadState]) -> i64;
        fn isHalting(self: &MiriGenMCShim) -> bool;
        fn isMoot(self: &MiriGenMCShim) -> bool;
        fn isExplorationDone(self: Pin<&mut MiriGenMCShim>) -> bool;

        fn printGraph(self: Pin<&mut MiriGenMCShim>);
    }
}

pub struct GenmcCtx {
    // TODO GENMC: remove this Mutex if possible
    handle: RefCell<UniquePtr<MiriGenMCShim>>,

    #[allow(unused)] // TODO GENMC (CLEANUP)
    rng: RefCell<StdRng>, // TODO GENMC: temporary rng for handling scheduling

    // TODO GENMC (PERFORMANCE): could use one RefCell for all internals instead of multiple
    thread_infos: RefCell<ThreadInfoManager>,
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

        let thread_infos = RefCell::new(ThreadInfoManager::new());

        Self { handle, rng, thread_infos }
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
        self.thread_infos.borrow_mut().reset();

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

        let thread_infos = self.thread_infos.borrow();
        let curr_thread = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread).genmc_tid;

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleFence(genmc_tid.0, ordering);

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
        let (load_ordering, store_ordering) = ordering.to_genmc_memory_orderings();
        let genmc_rmw_op = rmw_op.to_genmc_rmw_op(is_unsigned);
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

        let (load_ordering, store_ordering) = ordering.to_genmc_memory_orderings();
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
        let (success_load_ordering, success_store_ordering) = success.to_genmc_memory_orderings();
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

        let thread_infos = self.thread_infos.borrow();
        let curr_thread = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread).genmc_tid;

        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        let genmc_expected_value = scalar_to_genmc_scalar(expected_old_value);
        let genmc_new_value = scalar_to_genmc_scalar(new_value);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let result = pinned_mc.handleCompareExchange(
            genmc_tid.0,
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
        info!(
            "GenMC: TODO GENMC: SKIP! received memory_load (non-atomic): address: {address:?}, size: {size:?}",
        );
        // GenMC doesn't like ZSTs, and they can't have any data races, so we skip them
        if size.bytes() == 0 {
            return Ok(());
        }
        let _ = machine;
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
        info!(
            "GenMC: TODO GENMC: SKIP! received memory_store (non-atomic): address: {address:?}, size: {size:?}"
        );
        // GenMC doesn't like ZSTs, and they can't have any data races, so we skip them
        if size.bytes() == 0 {
            return Ok(());
        }
        let _ = machine;
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
        let thread_infos = self.thread_infos.borrow();
        let curr_thread = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread).genmc_tid;
        info!(
            "GenMC: handle_alloc (thread: {curr_thread:?} ({genmc_tid:?}), size: {size:?}, alignment: {alignment:?})"
        );
        // kind: MemoryKind, TODO GENMC: Does GenMC care about the kind of Memory?

        // GenMC doesn't support ZSTs, so we set the minimum size to 1 byte
        let genmc_size = size_to_genmc(size).max(1);

        let alignment = alignment.bytes_usize();

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let genmc_address = pinned_mc.handleMalloc(genmc_tid.0, genmc_size, alignment);

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
        let thread_infos = self.thread_infos.borrow();
        let curr_thread = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread).genmc_tid;
        info!(
            "GenMC: memory deallocation, thread: {curr_thread:?} ({genmc_tid:?}), address: {address:?}, size: {size:?}, align: {align:?}, memory_kind: {kind:?}"
        );

        let genmc_address = size_to_genmc(address);
        // GenMC doesn't support ZSTs, so we set the minimum size to 1 byte
        let genmc_size = size_to_genmc(size).max(1);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleFree(genmc_tid.0, genmc_address, genmc_size);

        Ok(())
    }

    /**** Thread management ****/

    pub(crate) fn handle_thread_create<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
        new_thread_id: ThreadId,
    ) -> Result<(), ()> {
        let mut thread_infos = self.thread_infos.borrow_mut();

        let curr_thread_id = threads.active_thread();
        let genmc_parent_tid = thread_infos.get_info(curr_thread_id).genmc_tid;
        let genmc_new_tid = thread_infos.add_thread(new_thread_id);

        info!(
            "GenMC: handling thread creation (thread {curr_thread_id:?} ({genmc_parent_tid:?}) spawned thread {new_thread_id:?} ({genmc_new_tid:?}))"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleThreadCreate(genmc_new_tid.0, genmc_parent_tid.0);

        Ok(())
    }

    pub(crate) fn handle_thread_join(
        &self,
        // machine: &MiriMachine<'tcx>,
        // threads: &ThreadManager<'tcx>,
        active_thread_id: ThreadId,
        child_thread_id: ThreadId,
    ) -> Result<(), ()> {
        let thread_infos = self.thread_infos.borrow();

        let genmc_curr_tid = thread_infos.get_info(active_thread_id).genmc_tid;
        let genmc_child_tid = thread_infos.get_info(child_thread_id).genmc_tid;

        info!(
            "GenMC: handling thread joining (thread {active_thread_id:?} ({genmc_curr_tid:?}) joining thread {child_thread_id:?} ({genmc_child_tid:?}))"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleThreadJoin(genmc_curr_tid.0, genmc_child_tid.0);

        Ok(())
    }

    pub(crate) fn handle_thread_finish<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
    ) -> Result<(), ()> {
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        // NOTE: Miri doesn't support return values for threads, but GenMC expects one, so we return 0
        let ret_val = 0;

        info!(
            "GenMC: handling thread finish (thread {curr_thread_id:?} ({genmc_tid:?}) returns with dummy value 0)"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleThreadFinish(genmc_tid.0, ret_val);

        Ok(())
    }

    /**** Scheduling functionality ****/

    // TODO GENMC: what is the correct name here?
    // TODO GENMC: does this also need to happen on other threads?
    pub(crate) fn thread_stack_empty(&self, thread_id: ThreadId) {
        info!("GenMC: thread {thread_id:?} finished");
        let mut thread_infos = self.thread_infos.borrow_mut();
        thread_infos.get_info_mut(thread_id).user_code_finished = true;
    }

    pub(crate) fn should_preempt(&self) -> bool {
        true // TODO GENMC
    }

    pub(crate) fn schedule_thread<'tcx>(
        &self,
        thread_manager: &ThreadManager<'tcx>,
    ) -> Result<ThreadId, ()> {
        let thread_infos = self.thread_infos.borrow();
        let thread_count = thread_infos.thread_count();

        // TODO GENMC: improve performance, e.g., with SmallVec
        let mut threads_state: Vec<ThreadState> = vec![ThreadState::Terminated; thread_count];

        let mut enabled_count = 0;
        for (thread_id, thread) in thread_manager.threads_ref().iter_enumerated() {
            // If a thread is finished, there might still be something to do (see `src/concurrency/thread.rs`: `run_on_stack_empty`)
            // In that case, the thread is still enabled, but has an empty stack
            // We don't want to run this thread in GenMC mode (especially not the main thread, which terminates the program once it's done)
            // We tell GenMC that this thread is disabled
            let is_enabled = thread.get_state().is_enabled();
            // TODO GENMC:
            // let is_finished = thread.top_user_relevant_frame().is_none();
            // let user_code_finished = thread_infos.get_info(thread_id).user_code_finished;
            let thread_info = thread_infos.get_info(thread_id);
            let user_code_finished = thread_info.user_code_finished;
            let index = usize::try_from(thread_info.genmc_tid.0).unwrap();
            threads_state[index] = match (is_enabled, user_code_finished) {
                (true, false) => {
                    enabled_count += 1;
                    ThreadState::Enabled
                }
                (true, true) => ThreadState::StackEmpty,
                (false, true) => ThreadState::Terminated,
                (false, false) => ThreadState::Blocked,
            };
        }
        // Once there are no threads with non-empty stacks anymore, we allow scheduling threads with empty stacks:
        // TODO GENMC: decide if this can only happen for the main thread:
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
        // TODO GENMC (OPTIMIZATION): could possibly skip scheduling call to GenMC if we only have 1 enabled thread

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let result = pinned_mc.scheduleNext(&threads_state);
        if let Ok(genmc_next_thread_id) = GenmcThreadIdInner::try_from(result) {
            assert_eq!(
                threads_state.get(usize::try_from(genmc_next_thread_id).unwrap()),
                Some(&ThreadState::Enabled)
            );
            // TODO GENMC: can we ensure this thread_id is valid?
            let genmc_next_thread_id = GenmcThreadId(genmc_next_thread_id);
            let next_thread_id = thread_infos.get_info_genmc(genmc_next_thread_id).miri_tid;
            info!(
                "GenMC: next thread to run is {next_thread_id:?} ({genmc_next_thread_id:?}), total {} threads",
                threads_state.len()
            );
            Ok(next_thread_id)
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
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        info!(
            "GenMC: load, thread: {curr_thread_id:?} ({genmc_tid:?}), address: {address:?}, size: {size:?}, ordering: {memory_ordering:?}"
        );
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let read_value =
            pinned_mc.handleLoad(genmc_tid.0, genmc_address, genmc_size, memory_ordering);

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
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        let genmc_value = scalar_to_genmc_scalar(value);
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        info!(
            "GenMC: store, thread: {curr_thread_id:?} ({genmc_tid:?}), address: {address:?}, size: {size:?}, ordering {memory_ordering:?}, value: {value:?}"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleStore(
            genmc_tid.0,
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
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        info!(
            "GenMC: atomic_rmw_op, thread: {curr_thread_id:?} ({genmc_tid:?}) (op: {genmc_rmw_op:?}, rhs value: {rhs_scalar:?}), address: {address:?}, size: {size:?}, orderings: ({load_ordering:?}, {store_ordering:?})",
        );

        let genmc_rhs = scalar_to_genmc_scalar(rhs_scalar);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let old_value = pinned_mc.handleReadModifyWrite(
            genmc_tid.0,
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
            .field("thread_infos", &self.thread_infos)
            .finish_non_exhaustive()
    }
}
