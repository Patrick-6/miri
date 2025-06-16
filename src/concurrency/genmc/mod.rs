use std::cell::{Cell, RefCell};
use std::sync::Arc;

use genmc_sys::{
    ActionKind, GENMC_GLOBAL_ADDRESSES_MASK, GenmcScalar, MemOrdering, MiriGenMCShim, RMWBinOp,
    StoreEventType, createGenmcHandle,
};
use rustc_abi::{Align, Size};
use rustc_const_eval::interpret::{AllocId, InterpCx, InterpResult, interp_ok};
use rustc_middle::{mir, throw_machine_stop, throw_ub_format, throw_unsup_format};
use tracing::{info, warn};

use self::cxx_extra::NonNullUniquePtr;
use self::global_allocations::{EvalContextExtPriv as _, GlobalAllocationHandler};
use self::helper::{
    NextInstrInfo, genmc_scalar_to_scalar, get_next_instr_info, option_scalar_to_genmc_scalar,
    rhs_scalar_to_genmc_scalar, scalar_to_genmc_scalar, size_to_genmc, to_miri_size,
};
use self::mapping::{min_max_to_genmc_rmw_op, to_genmc_rmw_op};
use self::thread_info_manager::{GenmcThreadId, GenmcThreadIdInner, ThreadInfoManager};
use crate::{
    AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd, MemoryKind, MiriConfig,
    MiriMachine, MiriMemoryKind, Scalar, TerminationInfo, ThreadId, ThreadManager, VisitProvenance,
    VisitWith,
};

mod config;
mod cxx_extra;
mod global_allocations;
mod helper;
mod mapping;
mod thread_info_manager;

pub use genmc_sys::GenmcParams;

pub use self::config::GenmcConfig;

const UNSUPPORTED_ATOMICS_SIZE_MSG: &str =
    "GenMC mode currently does not support atomics larger than 8 bytes.";

pub struct GenmcCtx {
    handle: RefCell<NonNullUniquePtr<MiriGenMCShim>>,

    // TODO GENMC (PERFORMANCE): could use one RefCell for all internals instead of multiple
    thread_infos: RefCell<ThreadInfoManager>,

    /// Some actions Miri does are allowed to cause data races.
    /// GenMC will not be informed about certain actions (e.g. non-atomic loads) when this flag is set.
    allow_data_races: Cell<bool>,

    curr_thread_user_block: Cell<bool>,

    /// Keep track of global allocations, to ensure they keep the same address across different executions, even if the order of allocations changes.
    /// The `AllocId` for globals is stable across executions, so we can use it as an identifier.
    global_allocations: Arc<GlobalAllocationHandler>,
    // TODO GENMC: maybe make this a (base, size), maybe BTreeMap/sorted vector for reverse lookups
    //          GenMC needs to have access to that
    // TODO: look at code of "pub struct GlobalStateInner"
}

/// GenMC Context creation and administrative / query actions
impl GenmcCtx {
    /// Create a new `GenmcCtx` from a given config.
    pub fn new(miri_config: &MiriConfig, genmc_config: &GenmcConfig) -> Self {
        assert!(miri_config.genmc_mode);
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

        let handle = createGenmcHandle(&genmc_config.params);
        let non_null_handle = NonNullUniquePtr::new(handle).expect("GenMC should not return null");
        let non_null_handle = RefCell::new(non_null_handle);

        Self {
            handle: non_null_handle,
            thread_infos: Default::default(),
            allow_data_races: Cell::new(false),
            curr_thread_user_block: Cell::new(false),
            global_allocations: Default::default(),
        }
    }

    pub fn get_stuck_execution_count(&self) -> u64 {
        let mc = self.handle.borrow();
        mc.as_ref().getStuckExecutionCount()
    }

    pub fn print_genmc_graph(&self) {
        info!("GenMC: print the Execution graph");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        pinned_mc.printGraph();
    }

    pub fn is_halting(&self) -> bool {
        // TODO GENMC: this probably shouldn't be exposed
        info!("GenMC: ask if execution is halting");
        let mc = self.handle.borrow();
        mc.as_ref().isHalting()
    }

    pub fn is_moot(&self) -> bool {
        // TODO GENMC: this probably shouldn't be exposed
        info!("GenMC: ask if execution is moot");
        let mc = self.handle.borrow();
        mc.as_ref().isMoot()
    }

    /// This function determines if we should continue exploring executions or if we are done.
    ///
    /// In GenMC mode, the input program should be repeatedly executed until this function returns `true` or an error is found.
    pub fn is_exploration_done(&self) -> bool {
        info!("GenMC: ask if execution exploration is done");
        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        pinned_mc.isExplorationDone()
    }
}

/// GenMC event handling. These methods are used to inform GenMC about events happening in the program, and to handle scheduling decisions.
impl GenmcCtx {
    /**** Memory access handling ****/

    /// Inform GenMC that a new program execution has started.
    /// This function should be called at the start of every execution.
    pub(crate) fn handle_execution_start(&self) {
        info!("GenMC: inform GenMC that new execution started");
        self.allow_data_races.replace(false);
        self.thread_infos.borrow_mut().reset();

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        pinned_mc.handleExecutionStart();
    }

    /// Inform GenMC that the program's execution has ended.
    ///
    /// This function must be called even when the execution got stuck (i.e., it returned a `InterpErrorKind::MachineStop` with error kind `TerminationInfo::GenmcStuckExecution`).
    pub(crate) fn handle_execution_end<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> Result<(), String> {
        info!("GenMC: inform GenMC that execution ended!");
        let mut mc = self.handle.borrow_mut();

        let pinned_mc = mc.as_mut();
        let result = pinned_mc.handleExecutionEnd();
        if let Some(msg) = result.as_ref() {
            let msg = msg.to_string_lossy().to_string();
            info!("GenMC: execution ended with error \"{msg}\"");
            Err(msg) // TODO GENMC: add more error info here, and possibly handle this without requiring to clone the CxxString
        } else {
            Ok(())
        }
    }

    /**** Memory access handling ****/

    /// Select whether data race free actions should be allowed. This function should be used carefully!
    ///
    /// If `true` is passed, allow for data races to happen without triggering an error, until this function is called again with argument `false`.
    /// This allows for racy non-atomic memory accesses to be ignored (GenMC is not informed about them at all).
    ///
    /// Certain operations are not permitted in GenMC mode with data races disabled and will cause a panic, e.g., atomic accesses or asking for scheduling decisions.
    ///
    /// # Panics
    /// If data race free is attempted to be set more than once (i.e., no nesting allowed).
    pub(super) fn set_ongoing_action_data_race_free(&self, enable: bool) {
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
        // The value that we would get, if we were to do a non-atomic load here.
        old_val: Option<Scalar>,
    ) -> InterpResult<'tcx, Scalar> {
        info!("GenMC: atomic_load: old_val: {old_val:?}");
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let ordering = ordering.convert();
        let genmc_old_value = option_scalar_to_genmc_scalar(ecx, old_val)?;
        let read_value =
            self.atomic_load_impl(&ecx.machine, address, size, ordering, genmc_old_value)?;
        info!("GenMC: atomic_load: received value from GenMC: {read_value:?}");
        genmc_scalar_to_scalar(ecx, read_value, size)
    }

    pub(crate) fn atomic_store<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        value: Scalar,
        // The value that we would get, if we were to do a non-atomic load here.
        old_value: Option<Scalar>,
        ordering: AtomicWriteOrd,
    ) -> InterpResult<'tcx, bool> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let ordering = ordering.convert();
        let genmc_value = scalar_to_genmc_scalar(ecx, value)?;
        let genmc_old_value = option_scalar_to_genmc_scalar(ecx, old_value)?;
        self.atomic_store_impl(&ecx.machine, address, size, genmc_value, genmc_old_value, ordering)
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
        let pinned_mc = mc.as_mut();
        pinned_mc.handleFence(genmc_tid.0, ordering);

        // TODO GENMC: can this operation ever fail?
        interp_ok(())
    }

    /// Inform GenMC about an atomic read-modify-write operation.
    ///
    /// Returns `(old_val, new_val)`.
    pub(crate) fn atomic_rmw_op<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        ordering: AtomicRwOrd,
        (rmw_op, not): (mir::BinOp, bool),
        rhs_scalar: Scalar,
        // The value that we would get, if we were to do a non-atomic load here.
        old_value: Scalar,
    ) -> InterpResult<'tcx, (Scalar, Scalar)> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let (load_ordering, store_ordering) = ordering.to_genmc_memory_orderings();
        let genmc_rmw_op = to_genmc_rmw_op(rmw_op, not);
        tracing::info!(
            "GenMC: atomic_rmw_op (op: {rmw_op:?}, not: {not}, genmc_rmw_op: {genmc_rmw_op:?}): rhs value: {rhs_scalar:?}, orderings ({load_ordering:?}, {store_ordering:?})"
        );
        let genmc_rhs_scalar = rhs_scalar_to_genmc_scalar(ecx, rhs_scalar)?;
        let genmc_old_value = scalar_to_genmc_scalar(ecx, old_value)?;
        self.atomic_rmw_op_impl(
            ecx,
            address,
            size,
            load_ordering,
            store_ordering,
            genmc_rmw_op,
            genmc_rhs_scalar,
            genmc_old_value,
        )
    }

    /// Inform GenMC about an atomic `min` or `max` operation.
    ///
    /// Returns `(old_val, new_val)`.
    pub(crate) fn atomic_min_max_op<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        ordering: AtomicRwOrd,
        min: bool,
        is_signed: bool,
        rhs_scalar: Scalar,
        // The value that we would get, if we were to do a non-atomic load here.
        old_value: Scalar,
    ) -> InterpResult<'tcx, (Scalar, Scalar)> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let (load_ordering, store_ordering) = ordering.to_genmc_memory_orderings();
        let genmc_rmw_op = min_max_to_genmc_rmw_op(min, is_signed);
        tracing::info!(
            "GenMC: atomic_min_max_op (min: {min}, signed: {is_signed}, genmc_rmw_op: {genmc_rmw_op:?}): rhs value: {rhs_scalar:?}, orderings ({load_ordering:?}, {store_ordering:?})"
        );
        let genmc_rhs_scalar = rhs_scalar_to_genmc_scalar(ecx, rhs_scalar)?;
        let genmc_old_value = scalar_to_genmc_scalar(ecx, old_value)?;
        self.atomic_rmw_op_impl(
            ecx,
            address,
            size,
            load_ordering,
            store_ordering,
            genmc_rmw_op,
            genmc_rhs_scalar,
            genmc_old_value,
        )
    }

    pub(crate) fn atomic_exchange<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        rhs_scalar: Scalar,
        ordering: AtomicRwOrd,
        // The value that we would get, if we were to do a non-atomic load here.
        old_value: Scalar,
    ) -> InterpResult<'tcx, (Scalar, Scalar)> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        // TODO GENMC: could maybe merge this with atomic_rmw?

        let (load_ordering, store_ordering) = ordering.to_genmc_memory_orderings();
        let genmc_rmw_op = RMWBinOp::Xchg;
        tracing::info!(
            "GenMC: atomic_exchange (op: {genmc_rmw_op:?}): new value: {rhs_scalar:?}, orderings ({load_ordering:?}, {store_ordering:?})"
        );
        let genmc_rhs_scalar = scalar_to_genmc_scalar(ecx, rhs_scalar)?;
        let genmc_old_value = scalar_to_genmc_scalar(ecx, old_value)?;
        self.atomic_rmw_op_impl(
            ecx,
            address,
            size,
            load_ordering,
            store_ordering,
            genmc_rmw_op,
            genmc_rhs_scalar,
            genmc_old_value,
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
        // The value that we would get, if we were to do a non-atomic load here.
        old_value: Scalar,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let machine = &ecx.machine;
        let (success_load_ordering, success_store_ordering) = success.to_genmc_memory_orderings();
        let fail_load_ordering = fail.convert();

        info!(
            "GenMC: atomic_compare_exchange, address: {address:?}, size: {size:?} (expect: {expected_old_value:?}, new: {new_value:?}, old_value: {old_value:?}, {success:?}, {fail:?}), can fail spuriously: {can_fail_spuriously}"
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
        let genmc_old_value = scalar_to_genmc_scalar(ecx, old_value)?;

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        let cas_result = pinned_mc.handleCompareExchange(
            genmc_tid.0,
            genmc_address,
            genmc_size,
            genmc_expected_value,
            genmc_new_value,
            genmc_old_value,
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

    /// Inform GenMC about a non-atomic memory load
    ///
    /// NOTE: Unlike for *atomic* loads, we don't return a value here. Non-atomic values are still handled by Miri.
    pub(crate) fn memory_load<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
    ) -> InterpResult<'tcx, ()> {
        if self.allow_data_races.get() {
            // TODO GENMC: handle this properly
            info!("GenMC: skipping `handle_load`");
            return interp_ok(());
        }
        info!(
            "GenMC: received memory_load (non-atomic): address: {:#x}, size: {}",
            address.bytes(),
            size.bytes()
        );
        // GenMC doesn't like ZSTs, and they can't have any data races, so we skip them
        if size.bytes() == 0 {
            return interp_ok(());
        }
        // let _read_value =
        //     self.atomic_load_impl(machine, address, size, MemOrdering::NotAtomic)?;

        // // TODO GENMC (HACK): to handle large non-atomics, we ignore the value by GenMC for now
        // interp_ok(Scalar::from_u64(0xDEADBEEF))

        if size.bytes() <= 8 {
            // NOTE: Values loaded non-atomically are still handled by Miri, so we discard whatever we get from GenMC
            let _read_value = self.atomic_load_impl(
                machine,
                address,
                size,
                MemOrdering::NotAtomic,
                GenmcScalar::UNINIT, // Don't use DUMMY here, since that might have it stored as the initial value
            )?;
            return interp_ok(());
        }
        // Handle possible misalignment: TODO GENMC: could always do largest power-of-two here
        const MAX_SIZE_BYTES: u64 = 8;
        let size_bytes = size.bytes();

        let start_address = address.bytes();
        let end_address = start_address + size_bytes;

        let start_missing = MAX_SIZE_BYTES - (start_address % MAX_SIZE_BYTES);
        let end_missing = end_address % MAX_SIZE_BYTES;

        let start_address_aligned = start_address + start_missing;
        let end_address_aligned = end_address - end_missing;
        assert_eq!(0, start_address_aligned % MAX_SIZE_BYTES);
        assert_eq!(0, end_address_aligned % MAX_SIZE_BYTES);

        info!(
            "GenMC: splitting memory_load into {MAX_SIZE_BYTES} byte chunks: {start_missing} + {} * {MAX_SIZE_BYTES} + {end_missing}",
            (end_address_aligned - start_address_aligned) / MAX_SIZE_BYTES
        );

        let start_chunks = (0..start_missing).map(|offset| (start_address + offset, 1));
        let aligned_chunks = (start_address..end_address)
            .step_by(MAX_SIZE_BYTES.try_into().unwrap())
            .map(|address| (address, MAX_SIZE_BYTES));
        let end_chunks = (0..end_missing).map(|offset| (end_address_aligned + offset, 1));

        for (address, size) in start_chunks.chain(aligned_chunks).chain(end_chunks) {
            let chunk_addr = Size::from_bytes(address);
            let chunk_size = Size::from_bytes(size);
            let _read_value = self.atomic_load_impl(
                machine,
                chunk_addr,
                chunk_size,
                MemOrdering::NotAtomic,
                GenmcScalar::UNINIT, // Don't use DUMMY here, since that might have it stored as the initial value
            )?;
        }
        interp_ok(())
    }

    pub(crate) fn memory_store<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        // old_value: Option<Scalar>, // TODO GENMC(mixed atomic-non-atomic): is this needed?
    ) -> InterpResult<'tcx, ()> {
        if self.allow_data_races.get() {
            // TODO GENMC: handle this properly
            info!(
                "GenMC: skipping `handle_store` for address {addr} == {addr:#x}, size: {}",
                size.bytes(),
                addr = address.bytes()
            );
            return interp_ok(());
        }
        // GenMC doesn't like ZSTs, and they can't have any data races, so we skip them
        if size.bytes() == 0 {
            return interp_ok(());
        }

        if size.bytes() <= 8 {
            // TODO GENMC(mixed atomic-non-atomics): anything to do here?
            let _is_co_max_write = self.atomic_store_impl(
                machine,
                address,
                size,
                GenmcScalar::DUMMY,
                GenmcScalar::UNINIT, // Don't use DUMMY here, since that might have it stored as the initial value
                MemOrdering::NotAtomic,
            )?;
            return interp_ok(());
        }
        // Handle possible misalignment: TODO GENMC: could always do largest power-of-two here
        const MAX_SIZE_BYTES: u64 = 8;
        let size_bytes = size.bytes();

        let start_address = address.bytes();
        let end_address = start_address + size_bytes;
        let start_missing = MAX_SIZE_BYTES - (start_address % MAX_SIZE_BYTES);
        let end_missing = size_bytes % MAX_SIZE_BYTES;

        let start_address_aligned = start_address + start_missing;
        let end_address_aligned = end_address - end_missing;
        assert_eq!(0, start_address_aligned % MAX_SIZE_BYTES);
        assert_eq!(0, end_address_aligned % MAX_SIZE_BYTES);

        info!(
            "GenMC: splitting memory_load into {MAX_SIZE_BYTES} byte chunks: {start_missing} + {} * {MAX_SIZE_BYTES} + {end_missing}",
            (end_address_aligned - start_address_aligned) / MAX_SIZE_BYTES
        );

        let start_chunks = (0..start_missing).map(|offset| (start_address + offset, 1));
        let aligned_chunks = (start_address..end_address)
            .step_by(MAX_SIZE_BYTES.try_into().unwrap())
            .map(|address| (address, MAX_SIZE_BYTES));
        let end_chunks = (0..end_missing).map(|offset| (end_address_aligned + offset, 1));

        for (address, size) in start_chunks.chain(aligned_chunks).chain(end_chunks) {
            let chunk_addr = Size::from_bytes(address);
            let chunk_size = Size::from_bytes(size);
            // TODO GENMC(mixed atomic-non-atomics): anything to do here?
            let _is_co_max_write = self.atomic_store_impl(
                machine,
                chunk_addr,
                chunk_size,
                GenmcScalar::DUMMY,
                GenmcScalar::UNINIT, // Don't use DUMMY here, since that might have it stored as the initial value
                MemOrdering::NotAtomic,
            )?;
        }
        interp_ok(())
    }

    /**** Memory (de)allocation ****/

    pub(crate) fn handle_alloc<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        alloc_id: AllocId,
        size: Size,
        alignment: Align,
        memory_kind: MemoryKind,
    ) -> InterpResult<'tcx, u64> {
        let machine = &ecx.machine;
        let chosen_address = if memory_kind == MiriMemoryKind::Global.into() {
            info!("GenMC: global memory allocation: {alloc_id:?}");
            ecx.get_global_allocation_address(&self.global_allocations, alloc_id)?
        } else {
            // TODO GENMC: Does GenMC need to know about the kind of Memory?

            // eprintln!(
            //     "handle_alloc ({memory_kind:?}): Custom backtrace: {}",
            //     std::backtrace::Backtrace::force_capture()
            // );
            // TODO GENMC: should we put this before the special handling for globals?
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
                "GenMC: handle_alloc (thread: {curr_thread:?} ({genmc_tid:?}), size: {} (genmc size: {genmc_size} bytes), alignment: {alignment:?}, memory_kind: {memory_kind:?})",
                size.bytes()
            );

            let alignment = alignment.bytes_usize();

            let mut mc = self.handle.borrow_mut();
            let pinned_mc = mc.as_mut();
            let genmc_address = pinned_mc.handleMalloc(genmc_tid.0, genmc_size, alignment);
            info!("GenMC: handle_alloc: got address '{genmc_address}' ({genmc_address:#x})");

            // TODO GENMC:
            if genmc_address == 0 {
                throw_unsup_format!("TODO GENMC: we got address '0' from malloc");
            }
            let chosen_addr = to_miri_size(genmc_address).bytes();
            assert_eq!(0, chosen_addr & GENMC_GLOBAL_ADDRESSES_MASK);
            chosen_addr
        };
        // Sanity check the address alignment:
        assert_eq!(
            0,
            chosen_address % alignment.bytes(),
            "GenMC returned address {chosen_address} == {chosen_address:#x} with lower alignment than requested ({:})!",
            alignment.bytes()
        );

        interp_ok(chosen_address)
    }

    pub(crate) fn handle_dealloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        alloc_id: AllocId,
        address: Size,
        size: Size,
        align: Align,
        kind: MemoryKind,
    ) -> InterpResult<'tcx, ()> {
        assert_ne!(
            kind,
            MiriMemoryKind::Global.into(),
            "we probably shouldn't try to deallocate global allocations (alloc_id: {alloc_id:?})"
        );
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
            "GenMC: memory deallocation, thread: {curr_thread:?} ({genmc_tid:?}), address: {addr} == {addr:#x}, size: {size:?}, align: {align:?}, memory_kind: {kind:?}",
            addr = address.bytes()
        );

        let genmc_address = size_to_genmc(address);
        // GenMC doesn't support ZSTs, so we set the minimum size to 1 byte
        let genmc_size = size_to_genmc(size).max(1);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        pinned_mc.handleFree(genmc_tid.0, genmc_address, genmc_size);

        // TODO GENMC (ERROR HANDLING): can this ever fail?
        interp_ok(())
    }

    /**** Thread management ****/

    pub(crate) fn handle_thread_create<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
        _start_routine: crate::Pointer, // TODO GENMC: pass info to GenMC
        _func_arg: &crate::ImmTy<'tcx>,
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
        let pinned_mc = mc.as_mut();
        pinned_mc.handleThreadCreate(genmc_new_tid.0, genmc_parent_tid.0);

        // TODO GENMC (ERROR HANDLING): can this ever fail?
        interp_ok(())
    }

    pub(crate) fn handle_thread_join<'tcx>(
        &self,
        active_thread_id: ThreadId,
        child_thread_id: ThreadId,
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let thread_infos = self.thread_infos.borrow();

        let genmc_curr_tid = thread_infos.get_info(active_thread_id).genmc_tid;
        let genmc_child_tid = thread_infos.get_info(child_thread_id).genmc_tid;

        info!(
            "GenMC: handling thread joining (thread {active_thread_id:?} ({genmc_curr_tid:?}) joining thread {child_thread_id:?} ({genmc_child_tid:?}))"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();

        // TODO GENMC: error handling:
        pinned_mc.handleThreadJoin(genmc_curr_tid.0, genmc_child_tid.0);

        interp_ok(())
    }

    pub(crate) fn handle_thread_stack_empty(&self, thread_id: ThreadId) {
        info!("GenMC: thread stack empty: {thread_id:?}");
        let mut thread_infos = self.thread_infos.borrow_mut();
        let info = thread_infos.get_info_mut(thread_id);
        info.user_code_finished = true;

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        pinned_mc.handle_thread_stack_empty(info.genmc_tid.0);
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
        let pinned_mc = mc.as_mut();
        pinned_mc.handleThreadFinish(genmc_tid.0, ret_val);

        // TODO GENMC (ERROR HANDLING): can this ever fail?
        interp_ok(())
    }

    /**** Scheduling functionality ****/

    pub(crate) fn should_preempt(&self) -> bool {
        true // TODO GENMC
    }

    /// Ask for a scheduling decision. This should be called before every MIR instruction.
    ///
    /// GenMC may realize that the execution got stuck, then this function will return a `InterpErrorKind::MachineStop` with error kind `TerminationInfo::GenmcStuckExecution`).
    ///
    /// This is **not** an error by iself! Treat this as if the program ended normally: `handle_execution_end` should be called next, which will determine if were are any actual errors.
    pub(crate) fn schedule_thread<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> InterpResult<'tcx, ThreadId> {
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let thread_manager = &ecx.machine.threads;
        let active_thread_id = thread_manager.active_thread();

        // let curr_thread_user_block = self.curr_thread_user_block.replace(false);
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_info = thread_infos.get_info(active_thread_id);

        let next_instr_info = get_next_instr_info(ecx, thread_manager, active_thread_id);
        let is_next_instr_atomic_load =
            matches!(next_instr_info, NextInstrInfo::Terminator { is_atomic: true });

        let curr_thread_next_instr_kind =
            if is_next_instr_atomic_load { ActionKind::Load } else { ActionKind::NonLoad };

        let state = thread_manager.threads_ref()[active_thread_id].get_state();
        info!(
            "GenMC: schedule_thread, active thread: {active_thread_id:?}, state: {state:?}, state.is_enabled(): {}, state.is_terminated(): {}",
            state.is_enabled(),
            state.is_terminated()
        );
        let curr_thread_state = match state {
            crate::concurrency::thread::ThreadState::Enabled => genmc_sys::ThreadState::Enabled,
            crate::concurrency::thread::ThreadState::Blocked { .. } =>
                genmc_sys::ThreadState::Blocked,
            crate::concurrency::thread::ThreadState::Terminated =>
                genmc_sys::ThreadState::Terminated,
        };

        info!(
            "GenMC: schedule_thread, active thread: {active_thread_id:?}, next instruction is a '{next_instr_info:?}', curr_thread_state: {curr_thread_state:?}"
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        let result = pinned_mc.scheduleNext(
            curr_thread_info.genmc_tid.0,
            curr_thread_next_instr_kind,
            curr_thread_state,
        );

        if result >= 0 {
            let genmc_next_thread_id = GenmcThreadIdInner::try_from(result).unwrap();

            // TODO GENMC: can we ensure this thread_id is valid?
            let genmc_next_thread_id = GenmcThreadId(genmc_next_thread_id);
            let thread_infos = self.thread_infos.borrow();
            let next_thread_id = thread_infos.get_info_genmc(genmc_next_thread_id).miri_tid;

            let next_thread_state = thread_manager.threads_ref()[next_thread_id].get_state();
            assert!(
                next_thread_state.is_enabled(),
                "cannot schedule requested thread '{next_thread_id:?}' (GenMC TID: {genmc_next_thread_id:?}), it is blocked, state: {next_thread_state:?}."
            );
            interp_ok(next_thread_id)
        } else {
            // Negative result means there is no next thread to schedule
            info!("GenMC: scheduleNext returned no thread to schedule");
            throw_machine_stop!(TerminationInfo::GenmcStuckExecution);
        }
    }

    /**** Blocking instructions ****/

    pub(crate) fn handle_verifier_assume<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        condition: bool,
    ) -> InterpResult<'tcx, ()> {
        info!("GenMC: handle_verifier_assume, condition: {condition}");
        if !condition {
            self.handle_user_block(machine)
        } else {
            // TODO GENMC: is this a terminator, i.e., can GenMC schedule afterwards?
            interp_ok(())
        }
    }
}

impl GenmcCtx {
    //* might fails if there's a race, load might also not read anything (returns None) */
    fn atomic_load_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        memory_ordering: MemOrdering,
        genmc_old_value: GenmcScalar,
    ) -> InterpResult<'tcx, GenmcScalar> {
        assert!(
            size.bytes() != 0
                && (memory_ordering == MemOrdering::NotAtomic || size.bytes().is_power_of_two())
        );
        if size.bytes() > 8 {
            throw_unsup_format!("{UNSUPPORTED_ATOMICS_SIZE_MSG}");
        }
        assert!(!self.allow_data_races.get()); // TODO GENMC: handle this properly
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        info!(
            "GenMC: load, thread: {curr_thread_id:?} ({genmc_tid:?}), address: {addr} == {addr:#x}, size: {size:?}, ordering: {memory_ordering:?}, old_value: {genmc_old_value:x?}",
            addr = address.bytes()
        );
        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        let load_result = pinned_mc.handleLoad(
            genmc_tid.0,
            genmc_address,
            genmc_size,
            memory_ordering,
            genmc_old_value,
        );

        if let Some(error) = load_result.error.as_ref() {
            let msg = error.to_string_lossy().to_string();
            info!("GenMC: load operation returned an error: \"{msg}\"");
            throw_ub_format!("{}", msg); // TODO GENMC: proper error handling: find correct error here
        }

        info!("GenMC: load returned value: {:?}", load_result.read_value);

        interp_ok(load_result.read_value)
    }

    fn atomic_store_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        genmc_value: GenmcScalar,
        genmc_old_value: GenmcScalar,
        memory_ordering: MemOrdering,
    ) -> InterpResult<'tcx, bool> {
        assert!(
            size.bytes() != 0
                && (memory_ordering == MemOrdering::NotAtomic || size.bytes().is_power_of_two())
        );
        if size.bytes() > 8 {
            throw_unsup_format!("{UNSUPPORTED_ATOMICS_SIZE_MSG}");
        }
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        info!(
            "GenMC: store, thread: {curr_thread_id:?} ({genmc_tid:?}), address: {addr} = {addr:#x}, size: {size:?}, ordering {memory_ordering:?}, value: {genmc_value:?}",
            addr = address.bytes()
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        let store_result = pinned_mc.handleStore(
            genmc_tid.0,
            genmc_address,
            genmc_size,
            genmc_value,
            genmc_old_value,
            memory_ordering,
            StoreEventType::Normal,
        );

        if let Some(error) = store_result.error.as_ref() {
            let msg = error.to_string_lossy().to_string();
            info!("GenMC: store operation returned an error: \"{msg}\"");
            throw_ub_format!("{}", msg); // TODO GENMC: proper error handling: find correct error here
        }

        interp_ok(store_result.isCoMaxWrite)
    }

    pub(crate) fn atomic_rmw_op_impl<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        load_ordering: MemOrdering,
        store_ordering: MemOrdering,
        genmc_rmw_op: RMWBinOp,
        genmc_rhs_scalar: GenmcScalar,
        genmc_old_value: GenmcScalar,
    ) -> InterpResult<'tcx, (Scalar, Scalar)> {
        assert!(
            size.bytes() <= 8,
            "TODO GENMC: no support for accesses larger than 8 bytes (got {} bytes)",
            size.bytes()
        );
        let machine = &ecx.machine;
        assert_ne!(0, size.bytes());
        let thread_infos = self.thread_infos.borrow();
        let curr_thread_id = machine.threads.active_thread();
        let genmc_tid = thread_infos.get_info(curr_thread_id).genmc_tid;

        let genmc_address = size_to_genmc(address);
        let genmc_size = size_to_genmc(size);

        info!(
            "GenMC: atomic_rmw_op, thread: {curr_thread_id:?} ({genmc_tid:?}) (op: {genmc_rmw_op:?}, rhs value: {genmc_rhs_scalar:?}), address: {address:?}, size: {size:?}, orderings: ({load_ordering:?}, {store_ordering:?})",
        );

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        let rmw_result = pinned_mc.handleReadModifyWrite(
            genmc_tid.0,
            genmc_address,
            genmc_size,
            load_ordering,
            store_ordering,
            genmc_rmw_op,
            genmc_rhs_scalar,
            genmc_old_value,
        );

        if let Some(error) = rmw_result.error.as_ref() {
            let msg = error.to_string_lossy().to_string();
            info!("GenMC: RMW operation returned an error: \"{msg}\"");
            throw_ub_format!("{}", msg); // TODO GENMC: proper error handling: find correct error here
        }

        let old_value_scalar = genmc_scalar_to_scalar(ecx, rmw_result.old_value, size)?;

        let new_value_scalar = genmc_scalar_to_scalar(ecx, rmw_result.new_value, size)?;
        interp_ok((old_value_scalar, new_value_scalar))
    }

    fn handle_user_block<'tcx>(&self, machine: &MiriMachine<'tcx>) -> InterpResult<'tcx, ()> {
        self.curr_thread_user_block.set(true);

        let thread_infos = self.thread_infos.borrow();
        let curr_thread = machine.threads.active_thread();
        let genmc_curr_thread = thread_infos.get_info(curr_thread).genmc_tid;
        info!("GenMC: handle_user_block, blocking thread {curr_thread:?} ({genmc_curr_thread:?})");

        let mut mc = self.handle.borrow_mut();
        let pinned_mc = mc.as_mut();
        pinned_mc.handleUserBlock(genmc_curr_thread.0);

        interp_ok(())
    }
}

/// Other functionality not directly related to event handling
impl GenmcCtx {
    /// Given a `ty::Instance<'tcx>`, do any required special handling. Returns true if this `instance` should be skipped (i.e., no Mir should be executed for it).
    pub fn check_intercept_function<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        instance: rustc_middle::ty::Instance<'tcx>,
        args: &[rustc_const_eval::interpret::FnArg<'tcx, crate::Provenance>],
    ) -> InterpResult<'tcx, bool> {
        use rustc_span::sym;
        if ecx.tcx.is_diagnostic_item(sym::sys_mutex_lock, instance.def_id()) {
            assert!(!args.is_empty());
            let arg = ecx.copy_fn_arg(&args[0]);
            let addr_scalar = ecx.read_scalar(&arg)?;
            let addr = ecx.read_target_usize(&arg)?;
            info!(
                "sys_mutex_lock, instance: {instance:?}, args: {args:?}, \n  read scalar: {addr_scalar:?}, address: {addr} == {addr:#x}",
            );
            todo!();
        } else if ecx.tcx.is_diagnostic_item(sym::sys_mutex_try_lock, instance.def_id()) {
            todo!();
        } else if ecx.tcx.is_diagnostic_item(sym::sys_mutex_unlock, instance.def_id()) {
            todo!();
        }
        interp_ok(false)
    }
}

impl VisitProvenance for GenmcCtx {
    fn visit_provenance(&self, _visit: &mut VisitWith<'_>) {
        // We don't have any tags.
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
