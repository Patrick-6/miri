use std::cell::{Cell, RefCell};
#[allow(unused_imports)] // TODO GENMC: false warning?
use std::pin::Pin;

#[allow(unused_imports)] // TODO GENMC: false warning?
use cxx::{CxxString, UniquePtr};
use rand::prelude::*;
use rand::rngs::StdRng;
use rustc_abi::{Align, Size};
use rustc_const_eval::interpret::{InterpCx, InterpResult, interp_ok};
use rustc_middle::{throw_ub_format, throw_unsup_format};
use tracing::{info, warn};

use self::ffi::{
    GenmcScalar, MemoryOrdering, MiriGenMCShim, RmwBinOp, StoreEventType, ThreadState,
    createGenmcHandle,
};
use self::helper::{Threads, genmc_scalar_to_scalar, scalar_to_genmc_scalar};
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

/// TODO GENMC: remove this:
const IGNORE_NON_ATOMICS: bool = false;

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
    #[allow(unused)] // TODO GENMC: remove once struct is used
    struct ThreadStateInfo {
        state: ThreadState,
        is_next_instr_load: bool,
    }

    #[derive(Debug, Clone, Copy)]
    struct GenmcScalar {
        value: u64,
        extra: u64,
    }

    /**** \/ Result & Error types \/ ****/

    #[must_use]
    #[derive(Debug)]
    struct ReadModifyWriteResult {
        old_value: GenmcScalar,      // TODO GENMC: handle bigger values
        error: UniquePtr<CxxString>, // TODO GENMC: pass more error info here
        is_success: bool,
    }

    #[must_use]
    #[derive(Debug)]
    struct LoadResult {
        read_value: GenmcScalar,     // TODO GENMC: handle bigger values
        error: UniquePtr<CxxString>, // TODO GENMC: pass more error info here
    }

    #[must_use]
    #[derive(Debug)]
    struct StoreResult {
        error: UniquePtr<CxxString>, // TODO GENMC: pass more error info here
    }

    #[must_use]
    #[derive(Debug)]
    enum VerificationError {
        VE_NonErrorBegin,
        VE_OK,
        VE_WWRace,
        VE_UnfreedMemory,
        VE_NonErrorLast,
        VE_Safety,
        VE_Recovery,
        VE_Liveness,
        VE_RaceNotAtomic,
        VE_RaceFreeMalloc,
        VE_FreeNonMalloc,
        VE_DoubleFree,
        VE_Allocation,

        VE_InvalidAccessBegin,
        VE_UninitializedMem,
        VE_AccessNonMalloc,
        VE_AccessFreed,
        VE_InvalidAccessEnd,

        VE_InvalidCreate,
        VE_InvalidJoin,
        VE_InvalidUnlock,
        VE_InvalidBInit,
        VE_InvalidRecoveryCall,
        VE_InvalidTruncate,
        VE_Annotation,
        VE_MixedSize,
        VE_LinearizabilityError,
        VE_SystemError,
    }

    /**** /\ Result & Error types /\ ****/

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

        // Types for Scheduling queries:
        type ThreadStateInfo;
        type ThreadState;

        // Result / Error types:
        type LoadResult;
        type StoreResult;
        type ReadModifyWriteResult;
        type VerificationError;

        type GenmcScalar;

        // type OperatingMode; // Estimation(budget) or Verification

        type MiriGenMCShim;

        fn createGenmcHandle(config: &GenmcParams, /* OperatingMode */)
        -> UniquePtr<MiriGenMCShim>;

        fn handleExecutionStart(self: Pin<&mut MiriGenMCShim>);
        fn handleExecutionEnd(
            self: Pin<&mut MiriGenMCShim>,
            thread_states: &[ThreadState],
        ) -> UniquePtr<CxxString>;

        fn handleLoad(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            memory_ordering: MemoryOrdering,
        ) -> LoadResult; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleReadModifyWrite(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            load_ordering: MemoryOrdering,
            store_ordering: MemoryOrdering,
            rmw_op: RmwBinOp,
            rhs_value: GenmcScalar,
        ) -> ReadModifyWriteResult; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleCompareExchange(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            expected_value: GenmcScalar,
            new_value: GenmcScalar,
            success_load_ordering: MemoryOrdering,
            success_store_ordering: MemoryOrdering,
            fail_load_ordering: MemoryOrdering,
            can_fail_spuriously: bool,
        ) -> ReadModifyWriteResult;
        fn handleStore(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            value: GenmcScalar,
            memory_ordering: MemoryOrdering,
            store_event_type: StoreEventType,
        ) -> StoreResult;
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

        /**** Blocking instructions ****/
        fn handleUserBlock(self: Pin<&mut MiriGenMCShim>, thread_id: i32);

        fn scheduleNext(self: Pin<&mut MiriGenMCShim>, thread_states: &[ThreadState]) -> i64;
        fn isHalting(self: &MiriGenMCShim) -> bool;
        fn isMoot(self: &MiriGenMCShim) -> bool;
        fn isExplorationDone(self: Pin<&mut MiriGenMCShim>) -> bool;

        fn printGraph(self: Pin<&mut MiriGenMCShim>);
    }
}

impl GenmcScalar {
    pub const DUMMY: Self = Self { value: 0xDEADBEEF, extra: 0 };
}

pub struct GenmcCtx {
    // TODO GENMC: remove this Mutex if possible
    handle: RefCell<UniquePtr<MiriGenMCShim>>,

    #[allow(unused)] // TODO GENMC (CLEANUP)
    rng: RefCell<StdRng>, // TODO GENMC: temporary rng for handling scheduling

    // TODO GENMC (PERFORMANCE): could use one RefCell for all internals instead of multiple
    thread_infos: RefCell<ThreadInfoManager>,

    allow_data_races: Cell<bool>,

    stuck_execution_count: Cell<usize>,
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
        let allow_data_races = Cell::new(false);
        let stuck_execution_count = Cell::new(0);

        Self { handle, rng, thread_infos, allow_data_races, stuck_execution_count }
    }

    pub fn get_stuck_execution_count(&self) -> usize {
        // TODO GENMC: ask GenMC for this number
        self.stuck_execution_count.get()
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
        self.allow_data_races.replace(false);
        self.thread_infos.borrow_mut().reset();

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleExecutionStart();
    }

    pub(crate) fn handle_execution_end<'tcx>(
        &self,
        thread_manager: &ThreadManager<'tcx>,
    ) -> Result<(), String> {
        info!("GenMC: inform GenMC that execution ended!");
        let (thread_states, _enabled_count) = self.get_thread_states(thread_manager);
        info!("Thread states after execution ends: {thread_states:?}");

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let result = pinned_mc.handleExecutionEnd(&thread_states);
        if let Some(msg) = result.as_ref() {
            let msg = msg.to_string_lossy().to_string();
            info!("GenMC: execution ended with error \"{msg}\"");
            Err(msg) // TODO GENMC: add more error info here, and possibly handle this without requiring to clone the CxxString
        } else {
            Ok(())
        }
        // TODO GENMC: could return as result here maybe?
    }

    /// If `true` is passed, allow for data races to happen without an error, until `false` is passed
    ///
    /// Certain operations are not permitted in GenMC mode with data races disabled, e.g., atomic accesses
    /// TODO GENMC: Document this better (or enable more functionality with data races disabled)
    ///
    /// # Panics
    /// This method will panic if data races are nested
    pub(crate) fn set_ongoing_action_data_race_free(&self, enable: bool) {
        info!("GenMC: set_ongoing_action_data_race_free ({enable})");
        let old = self.allow_data_races.replace(enable);
        assert_ne!(old, enable, "cannot nest allow_data_races");
    }

    //* might fails if there's a race, load might also not read anything (returns None) */
    pub(crate) fn atomic_load<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        ordering: AtomicReadOrd,
        old_val: Option<Scalar>,
    ) -> InterpResult<'tcx, Scalar> {
        info!("GenMC: atomic_load: old_val: {old_val:?}");
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let ordering = ordering.convert();
        let read_value = self.atomic_load_impl(&ecx.machine, address, size, ordering)?;
        genmc_scalar_to_scalar(ecx, read_value, size)
    }

    pub(crate) fn atomic_store<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        value: Scalar,
        ordering: AtomicWriteOrd,
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let ordering = ordering.convert();
        let genmc_value = scalar_to_genmc_scalar(ecx, value)?;
        self.atomic_store_impl(&ecx.machine, address, size, genmc_value, ordering)
    }

    pub(crate) fn atomic_fence<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        ordering: AtomicFenceOrd,
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        info!("GenMC: atomic_fence with ordering: {ordering:?}");

        let ordering = ordering.convert();

        let thread_infos = self.thread_infos.borrow();
        let curr_thread = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread).genmc_tid;

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        pinned_mc.handleFence(genmc_tid.0, ordering);

        // TODO GENMC: can this operation ever fail?
        interp_ok(())
    }

    pub(crate) fn atomic_rmw_op<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        ordering: AtomicRwOrd,
        rmw_op: AtomicOp,
        rhs_scalar: Scalar,
        is_unsigned: bool,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let (load_ordering, store_ordering) = ordering.to_genmc_memory_orderings();
        let genmc_rmw_op = rmw_op.to_genmc_rmw_op(is_unsigned);
        tracing::info!(
            "GenMC: atomic_rmw_op (op: {genmc_rmw_op:?}): rhs value: {rhs_scalar:?}, is_unsigned: {is_unsigned}, orderings ({load_ordering:?}, {store_ordering:?})"
        );
        self.atomic_rmw_op_impl(
            ecx,
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
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        rhs_scalar: Scalar,
        ordering: AtomicRwOrd,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        // TODO GENMC: could maybe merge this with atomic_rmw?

        let (load_ordering, store_ordering) = ordering.to_genmc_memory_orderings();
        let genmc_rmw_op = RmwBinOp::Xchg;
        tracing::info!(
            "GenMC: atomic_exchange (op: {genmc_rmw_op:?}): new value: {rhs_scalar:?}, orderings ({load_ordering:?}, {store_ordering:?})"
        );
        self.atomic_rmw_op_impl(
            ecx,
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
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        expected_old_value: Scalar,
        new_value: Scalar,
        success: AtomicRwOrd,
        fail: AtomicReadOrd,
        can_fail_spuriously: bool,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let machine = &ecx.machine;
        let (success_load_ordering, success_store_ordering) = success.to_genmc_memory_orderings();
        let fail_load_ordering = fail.convert();

        info!(
            "GenMC: atomic_compare_exchange, address: {address:?}, size: {size:?} (expect: {expected_old_value:?}, new: {new_value:?}, {success:?}, {fail:?}), can fail spuriously: {can_fail_spuriously}"
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

        let genmc_expected_value = scalar_to_genmc_scalar(ecx, expected_old_value)?;
        let genmc_new_value = scalar_to_genmc_scalar(ecx, new_value)?;

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let cas_result = pinned_mc.handleCompareExchange(
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

        if let Some(error) = cas_result.error.as_ref() {
            let msg = error.to_string_lossy().to_string();
            info!("GenMC: RMW operation returned an error: \"{msg}\"");
            throw_ub_format!("{}", msg); // TODO GENMC: proper error handling: find correct error here
        }

        let return_scalar = genmc_scalar_to_scalar(ecx, cas_result.old_value, size)?;
        info!(
            "GenMC: atomic_compare_exchange: result: {cas_result:?}, returning scalar: {return_scalar:?}"
        );
        interp_ok((return_scalar, cas_result.is_success))
    }

    pub(crate) fn memory_load<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
    ) -> InterpResult<'tcx, Scalar> {
        if self.allow_data_races.get() {
            // TODO GENMC: handle this properly
            info!("GenMC: skipping `handle_load`");
            let dummy = Scalar::from_u64(0xDEADBEEF);
            return interp_ok(dummy);
        }
        info!("GenMC: received memory_load (non-atomic): address: {address:?}, size: {size:?}",);
        // GenMC doesn't like ZSTs, and they can't have any data races, so we skip them
        if size.bytes() == 0 {
            return interp_ok(Scalar::from_bool(false)); // TODO GENMC: what should be returned here?
        }
        let _read_value =
            self.atomic_load_impl(machine, address, size, MemoryOrdering::NotAtomic)?;

        // TODO GENMC (HACK): to handle large non-atomics, we ignore the value by GenMC for now
        interp_ok(Scalar::from_u64(0xDEADBEEF))
    }

    pub(crate) fn memory_store<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        // value: crate::Scalar,
    ) -> InterpResult<'tcx, ()> {
        if self.allow_data_races.get() {
            // TODO GENMC: handle this properly
            info!("GenMC: skipping `handle_store`");
            return interp_ok(());
        }
        info!("GenMC: received memory_store (non-atomic): address: {address:?}, size: {size:?}");
        // GenMC doesn't like ZSTs, and they can't have any data races, so we skip them
        if size.bytes() == 0 {
            return interp_ok(());
        }
        let dummy_scalar = GenmcScalar::DUMMY;
        self.atomic_store_impl(machine, address, size, dummy_scalar, MemoryOrdering::NotAtomic)
    }

    /**** Memory (de)allocation ****/

    pub(crate) fn handle_alloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        size: Size,
        alignment: Align,
        memory_kind: MemoryKind,
    ) -> InterpResult<'tcx, u64> {
        // eprintln!(
        //     "handle_alloc ({memory_kind:?}): Custom backtrace: {}",
        //     std::backtrace::Backtrace::force_capture()
        // );
        if self.allow_data_races.get() {
            // TODO GENMC: handle this properly
            info!("GenMC: skipping `handle_alloc`");
            return interp_ok(0);
        }
        let thread_infos = self.thread_infos.borrow();
        let curr_thread = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread).genmc_tid;
        // GenMC doesn't support ZSTs, so we set the minimum size to 1 byte
        let genmc_size = size_to_genmc(size).max(1);
        info!(
            "GenMC: handle_alloc (thread: {curr_thread:?} ({genmc_tid:?}), size: {size:?} (genmc size: {genmc_size} bytes), alignment: {alignment:?}, memory_kind: {memory_kind:?})"
        );
        if memory_kind == MemoryKind::Machine(crate::MiriMemoryKind::Global) {
            info!("GenMC: handle_alloc: TODO GENMC: maybe handle initialization of globals here?");
        }
        // kind: MemoryKind, TODO GENMC: Does GenMC care about the kind of Memory?

        let alignment = alignment.bytes_usize();

        let chosen_address = {
            let mut mc = self.handle.borrow_mut();
            let pinned_mc = mc.as_mut().expect("model checker should not be null");
            let genmc_address = pinned_mc.handleMalloc(genmc_tid.0, genmc_size, alignment);
            info!("GenMC: handle_alloc: got address '{genmc_address}' ({genmc_address:#x})");

            // TODO GENMC:
            if genmc_address == 0 {
                throw_unsup_format!("TODO GENMC: we got address '0' from malloc");
            }
            to_miri_size(genmc_address).bytes()
        };

        info!(
            "GenMC: writing to allocated memory with dummy value: TODO GENMC: handle 'backdating' of allocation"
        );
        self.memory_store(machine, Size::from_bytes(chosen_address), size)?;

        interp_ok(chosen_address)
    }

    pub(crate) fn init_allocation<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        // address: Size,
        size: Size,
        align: Align,
        kind: MemoryKind,
    ) {
        // TODO GENMC: handle "backdating" of allocation and their initialization
        info!(
            "GenMC: TODO GENMC: init_allocation: size: {size:?}, align: {align:?}, kind: {kind:?}"
        );

        // let dummy_scalar = Scalar::from_u64(0xDEADBEEF);
        // // TODO GENMC: proper error handling:
        // self.atomic_store_impl(machine, address, size, dummy_scalar, MemoryOrdering::NotAtomic)
        //     .unwrap();
    }

    pub(crate) fn handle_dealloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        align: Align,
        kind: MemoryKind,
    ) -> InterpResult<'tcx, ()> {
        if self.allow_data_races.get() {
            // TODO GENMC: handle this properly, should this be skipped in this mode?
            info!("GenMC: skipping `handle_dealloc`");
            return interp_ok(());
        }
        // eprintln!("handle_dealloc: Custom backtrace: {}", std::backtrace::Backtrace::force_capture());
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

        // TODO GENMC (ERROR HANDLING): can this ever fail?
        interp_ok(())
    }

    /**** Thread management ****/

    pub(crate) fn handle_thread_create<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
        new_thread_id: ThreadId,
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
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

        // TODO GENMC (ERROR HANDLING): can this ever fail?
        interp_ok(())
    }

    pub(crate) fn handle_thread_join(
        &self,
        // machine: &MiriMachine<'tcx>,
        // threads: &ThreadManager<'tcx>,
        active_thread_id: ThreadId,
        child_thread_id: ThreadId,
    ) -> Result<(), ()> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
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
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
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

        // TODO GENMC (ERROR HANDLING): can this ever fail?
        interp_ok(())
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
    ) -> InterpResult<'tcx, ThreadId> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly

        let (thread_states, enabled_count) = self.get_thread_states(thread_manager);
        assert_ne!(0, enabled_count);

        info!("GenMC: schedule_thread: thread states: {thread_states:?}");

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let result = pinned_mc.scheduleNext(&thread_states);
        info!("GenMC: scheduling result: {result}");
        if result >= 0 {
            let genmc_next_thread_id = GenmcThreadIdInner::try_from(result).unwrap();
            assert_eq!(
                thread_states.get(usize::try_from(genmc_next_thread_id).unwrap()),
                Some(&ThreadState::Enabled)
            );
            // TODO GENMC: can we ensure this thread_id is valid?
            let genmc_next_thread_id = GenmcThreadId(genmc_next_thread_id);
            let thread_infos = self.thread_infos.borrow();
            let next_thread_id = thread_infos.get_info_genmc(genmc_next_thread_id).miri_tid;
            info!(
                "GenMC: next thread to run is {next_thread_id:?} ({genmc_next_thread_id:?}), total {} threads",
                thread_states.len()
            );
            interp_ok(next_thread_id)
        } else {
            // Negative result means there is no next thread to schedule
            info!(
                "GenMC: scheduleNext returned no thread to schedule. Thread states: {thread_states:?}"
            );
            // TODO GENMC: stop the current execution and check if there are more if this happens
            // TODO GENMC: maybe add a new `throw_*` for these cases? new InterpErrorKind?
            self.stuck_execution_count.update(|count| count + 1);
            throw_unsup_format!("GenMC Execution stuck");
            // "GenMC returned no thread to schedule next: TODO GENMC: is this showing a deadlock or a bug?"
            // throw_machine_stop!();_
            // throw_machine_stop_str!(
            //     "GenMC returned no thread to schedule, aborting this execution..."
            // )
            // todo!();
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

    /**** Blocking instructions ****/

    pub(crate) fn handle_verifier_assume<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        condition: bool,
    ) -> InterpResult<'tcx, ()> {
        info!("GenMC: handle_verifier_assume, condition: {condition}");
        if !condition {
            let thread_infos = self.thread_infos.borrow();
            let curr_thread = machine.threads.active_thread();
            let genmc_curr_thread = thread_infos.get_info(curr_thread).genmc_tid;
            info!(
                "GenMC: handle_verifier_assume, blocking thread {curr_thread:?} ({genmc_curr_thread:?})"
            );

            let mut mc = self.handle.borrow_mut();
            let pinned_mc = mc.as_mut().expect("model checker should not be null");
            pinned_mc.handleUserBlock(genmc_curr_thread.0);
        }
        // TODO GENMC: is this a terminator, i.e., can GenMC schedule afterwards?
        interp_ok(())
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
    ) -> InterpResult<'tcx, GenmcScalar> {
        if IGNORE_NON_ATOMICS && memory_ordering == MemoryOrdering::NotAtomic {
            info!("GenMC: TODO GENMC: skipping non-atomic load!");
            return interp_ok(GenmcScalar::DUMMY);
        }
        // eprintln!(
        //     "atomic_load_impl ({memory_ordering:?}): Custom backtrace: {}",
        //     std::backtrace::Backtrace::force_capture()
        // );
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
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
        let load_result =
            pinned_mc.handleLoad(genmc_tid.0, genmc_address, genmc_size, memory_ordering);

        if let Some(error) = load_result.error.as_ref() {
            let msg = error.to_string_lossy().to_string();
            info!("GenMC: load operation returned an error: \"{msg}\"");
            throw_ub_format!("{}", msg); // TODO GENMC: proper error handling: find correct error here
        }

        interp_ok(load_result.read_value)
    }

    fn atomic_store_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        genmc_value: GenmcScalar,
        memory_ordering: MemoryOrdering,
    ) -> InterpResult<'tcx, ()> {
        if IGNORE_NON_ATOMICS && memory_ordering == MemoryOrdering::NotAtomic {
            info!("GenMC: TODO GENMC: skipping non-atomic store!");
            return interp_ok(());
        }
        assert_ne!(0, size.bytes());
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        info!(
            "GenMC: store, thread: {curr_thread_id:?} ({genmc_tid:?}), address: {address:?}, size: {size:?}, ordering {memory_ordering:?}, value: {genmc_value:?}"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let store_result = pinned_mc.handleStore(
            genmc_tid.0,
            genmc_address,
            genmc_size,
            genmc_value,
            memory_ordering,
            StoreEventType::Normal,
        );

        if let Some(error) = store_result.error.as_ref() {
            let msg = error.to_string_lossy().to_string();
            info!("GenMC: store operation returned an error: \"{msg}\"");
            throw_ub_format!("{}", msg); // TODO GENMC: proper error handling: find correct error here
        }

        interp_ok(())
    }

    pub(crate) fn atomic_rmw_op_impl<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        load_ordering: MemoryOrdering,
        store_ordering: MemoryOrdering,
        genmc_rmw_op: RmwBinOp,
        rhs_scalar: Scalar,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        let machine = &ecx.machine;
        assert_ne!(0, size.bytes());
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        info!(
            "GenMC: atomic_rmw_op, thread: {curr_thread_id:?} ({genmc_tid:?}) (op: {genmc_rmw_op:?}, rhs value: {rhs_scalar:?}), address: {address:?}, size: {size:?}, orderings: ({load_ordering:?}, {store_ordering:?})",
        );

        let genmc_rhs = scalar_to_genmc_scalar(ecx, rhs_scalar)?;

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut().expect("model checker should not be null");
        let rmw_result = pinned_mc.handleReadModifyWrite(
            genmc_tid.0,
            genmc_address,
            genmc_size,
            load_ordering,
            store_ordering,
            genmc_rmw_op,
            genmc_rhs,
        );

        if let Some(error) = rmw_result.error.as_ref() {
            let msg = error.to_string_lossy().to_string();
            info!("GenMC: RMW operation returned an error: \"{msg}\"");
            throw_ub_format!("{}", msg); // TODO GENMC: proper error handling: find correct error here
        }

        let old_value = rmw_result.old_value;
        let old_value_scalar = genmc_scalar_to_scalar(ecx, old_value, size)?;
        interp_ok((old_value_scalar, rmw_result.is_success))
    }

    // TODO GENMC: optimize this:
    fn get_thread_states<'tcx>(
        &self,
        thread_manager: &ThreadManager<'tcx>,
    ) -> (Vec<ThreadState>, usize) {
        let thread_infos = self.thread_infos.borrow();
        let thread_count = thread_infos.thread_count();

        // TODO GENMC: improve performance, e.g., with SmallVec
        let mut thread_states: Vec<ThreadState> = vec![ThreadState::Terminated; thread_count];

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
            thread_states[index] = match (is_enabled, user_code_finished) {
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
            for thread_state in thread_states.iter_mut().rev() {
                if ThreadState::StackEmpty == *thread_state {
                    *thread_state = ThreadState::Enabled;
                    enabled_count += 1;
                    break;
                }
            }
        }
        // TODO GENMC (OPTIMIZATION): could possibly skip scheduling call to GenMC if we only have 1 enabled thread (WARNING: may not be correct with GenMC BlockLabels)
        (thread_states, enabled_count)
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
