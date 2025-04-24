use std::cell::{Cell, RefCell};

use rustc_abi::{Align, Size};
use rustc_const_eval::interpret::{InterpCx, InterpResult, interp_ok};

use self::helper::{
    NextInstrInfo, Threads, genmc_scalar_to_scalar, get_next_instr_info,
    rhs_scalar_to_genmc_scalar, scalar_to_genmc_scalar,
};
use self::thread_info_manager::{GenmcThreadId, GenmcThreadIdInner, ThreadInfoManager};
use crate::intrinsics::AtomicOp;
use crate::{
    AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd, MemoryKind, MiriConfig,
    MiriMachine, Scalar, TerminationInfo, ThreadId, ThreadManager, VisitProvenance, VisitWith,
};

mod config;

pub use self::config::GenmcConfig;
pub use self::ffi::GenmcParams;

// TODO: add fields
pub struct GenmcCtx {
    /// Some actions Miri does are allowed to cause data races.
    /// GenMC will not be informed about certain actions (e.g. non-atomic loads) when this flag is set
    allow_data_races: Cell<bool>,
}

impl GenmcCtx {
    /// Validate the selected configuration options and create a new `GenmcCtx` if successful
    ///
    /// Some combinations of options are (currently) not allowed:
    /// - Aliasing model checking is incompatible with GenMC mode
    ///   - The reason is that the required information is lost when pointers are send to GenMC and back
    /// - Data race checking and weak memory emulation must be turned off, since GenMC does this by itself
    /// - "Many seeds" mode in Miri is currently incompatible with GenMC mode
    pub fn try_new(_miri_config: &MiriConfig) -> Option<Self> {
        todo!()
    }

    pub fn get_stuck_execution_count(&self) -> usize {
        todo!()
    }

    pub fn print_genmc_graph(&self) {
        todo!()
    }

    pub fn is_exploration_done(&self) -> bool {
        todo!()
    }

    pub(crate) fn handle_execution_start(&self) {
        todo!()
    }

    pub(crate) fn handle_execution_end<'tcx>(
        &self,
        _thread_manager: &ThreadManager<'tcx>,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> Result<(), String> {
        todo!()
    }

    /**** Memory access handling ****/

    /// If `true` is passed, allow for data races to happen without triggering an error, until this function is called again with argument `false`.
    /// This allows for racy non-atomic memory accesses to be ignored (GenMC is not informed about them at all).
    ///
    /// Certain operations are not permitted in GenMC mode with data races disabled and will cause a panic, e.g., atomic accesses or asking for scheduling decisions.
    ///
    /// # Panics
    /// This method will panic if data races are nested
    pub(crate) fn set_ongoing_action_data_race_free(&self, enable: bool) {
        let old = self.allow_data_races.replace(enable);
        assert_ne!(old, enable, "cannot nest allow_data_races");
    }

    pub(crate) fn atomic_load<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _ordering: AtomicReadOrd,
        _old_val: Option<Scalar>,
    ) -> InterpResult<'tcx, Scalar> {
        assert!(!self.allow_data_races.get());
        todo!()
    }

    pub(crate) fn atomic_store<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _value: Scalar,
        _ordering: AtomicWriteOrd,
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get());
        todo!()
    }

    pub(crate) fn atomic_fence<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        ordering: AtomicFenceOrd,
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get());
        todo!()
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
        assert!(!self.allow_data_races.get());
        todo!()
    }

    pub(crate) fn atomic_exchange<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        address: Size,
        size: Size,
        rhs_scalar: Scalar,
        ordering: AtomicRwOrd,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        assert!(!self.allow_data_races.get());
        todo!()
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
        assert!(!self.allow_data_races.get());
        todo!()
    }

    pub(crate) fn memory_load<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
    ) -> InterpResult<'tcx, Scalar> {
        todo!()
    }

    pub(crate) fn memory_store<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
    ) -> InterpResult<'tcx, ()> {
        todo!()
    }

    /**** Memory (de)allocation ****/

    pub(crate) fn handle_alloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        size: Size,
        alignment: Align,
        memory_kind: MemoryKind,
    ) -> InterpResult<'tcx, u64> {
        todo!()
    }

    pub(crate) fn handle_dealloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        address: Size,
        size: Size,
        align: Align,
        kind: MemoryKind,
    ) -> InterpResult<'tcx, ()> {
        todo!()
    }

    /**** Thread management ****/

    pub(crate) fn handle_thread_create<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
        new_thread_id: ThreadId,
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get());
        todo!()
    }

    pub(crate) fn handle_thread_join(
        &self,
        active_thread_id: ThreadId,
        child_thread_id: ThreadId,
    ) -> Result<(), ()> {
        assert!(!self.allow_data_races.get());
        todo!()
    }

    pub(crate) fn handle_thread_stack_empty(&self, _thread_id: ThreadId) {
        todo!()
    }

    pub(crate) fn handle_thread_finish<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
    ) -> InterpResult<'tcx, ()> {
        assert!(!self.allow_data_races.get());
        todo!()
    }

    /**** Scheduling functionality ****/

    pub(crate) fn should_preempt(&self) -> bool {
        true // TODO GENMC
    }

    pub(crate) fn schedule_thread<'tcx>(
        &self,
        thread_manager: &ThreadManager<'tcx>,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> InterpResult<'tcx, ThreadId> {
        assert!(!self.allow_data_races.get());
        todo!()
    }

    /**** Blocking instructions ****/

    pub(crate) fn handle_verifier_assume<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        condition: bool,
    ) -> InterpResult<'tcx, ()> {
        if condition { interp_ok(()) } else { self.handle_user_block(machine) }
    }
}

impl VisitProvenance for GenmcCtx {
    fn visit_provenance(&self, _visit: &mut VisitWith<'_>) {
        // We don't have any tags.
    }
}

impl GenmcCtx {
    fn handle_user_block<'tcx>(&self, machine: &MiriMachine<'tcx>) -> InterpResult<'tcx, ()> {
        todo!()
    }
}
