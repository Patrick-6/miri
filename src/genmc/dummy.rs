use rustc_abi::{Align, Size};
use rustc_const_eval::interpret::{InterpCx, InterpResult};

use crate::intrinsics::AtomicOp;
use crate::{
    AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd, MemoryKind, MiriConfig,
    MiriMachine, Scalar, ThreadId, ThreadManager, VisitProvenance, VisitWith,
};

#[derive(Debug)]
pub struct GenmcCtx {}

#[derive(Debug, Default, Clone)]
pub struct GenmcConfig {}

// TODO GENMC: add all exposed methods here too

impl GenmcCtx {
    pub fn try_new(_miri_config: &MiriConfig) -> Option<Self> {
        unimplemented!("GenMC feature in Miri is currently disabled.");
    }

    pub fn get_stuck_execution_count(&self) -> usize {
        unreachable!()
    }

    pub fn print_genmc_graph(&self) {
        unreachable!()
    }

    pub fn is_exploration_done(&self) -> bool {
        unreachable!()
    }

    /**** Memory access handling ****/

    pub(crate) fn handle_execution_start(&self) {
        unreachable!()
    }

    pub(crate) fn handle_execution_end<'tcx>(
        &self,
        _thread_manager: &ThreadManager<'tcx>,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> Result<(), String> {
        unreachable!()
    }

    pub(crate) fn set_ongoing_action_data_race_free(&self, _enable: bool) {
        unreachable!()
    }

    //* might fails if there's a race, load might also not read anything (returns None) */
    pub(crate) fn atomic_load<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _ordering: AtomicReadOrd,
        _old_val: Option<Scalar>,
    ) -> InterpResult<'tcx, Scalar> {
        unreachable!()
    }

    pub(crate) fn atomic_store<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _value: Scalar,
        _ordering: AtomicWriteOrd,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }

    pub(crate) fn atomic_fence<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        _ordering: AtomicFenceOrd,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }

    pub(crate) fn atomic_rmw_op<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _ordering: AtomicRwOrd,
        _rmw_op: AtomicOp,
        _rhs_scalar: Scalar,
        _is_unsigned: bool,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        unreachable!()
    }

    pub(crate) fn atomic_exchange<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _rhs_scalar: Scalar,
        _ordering: AtomicRwOrd,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        unreachable!()
    }

    pub(crate) fn atomic_compare_exchange<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _expected_old_value: Scalar,
        _new_value: Scalar,
        _success: AtomicRwOrd,
        _fail: AtomicReadOrd,
        _can_fail_spuriously: bool,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        unreachable!()
    }

    pub(crate) fn memory_load<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        _address: Size,
        _size: Size,
    ) -> InterpResult<'tcx, Scalar> {
        unreachable!()
    }

    pub(crate) fn memory_store<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        _address: Size,
        _size: Size,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }

    /**** Memory (de)allocation ****/

    pub(crate) fn handle_alloc<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        _size: Size,
        _alignment: Align,
        _memory_kind: MemoryKind,
    ) -> InterpResult<'tcx, u64> {
        unreachable!()
    }

    pub(crate) fn init_allocation<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        // address: Size,
        _size: Size,
        _align: Align,
        _kind: MemoryKind,
    ) {
        unreachable!()
    }

    pub(crate) fn handle_dealloc<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        _address: Size,
        _size: Size,
        _align: Align,
        _kind: MemoryKind,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }

    /**** Thread management ****/

    pub(crate) fn handle_thread_create<'tcx>(
        &self,
        _threads: &ThreadManager<'tcx>,
        _new_thread_id: ThreadId,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }

    pub(crate) fn handle_thread_join(
        &self,
        _active_thread_id: ThreadId,
        _child_thread_id: ThreadId,
    ) -> Result<(), ()> {
        unreachable!()
    }

    pub(crate) fn handle_thread_stack_empty(&self, _thread_id: ThreadId) {
        unreachable!()
    }

    pub(crate) fn handle_thread_finish<'tcx>(
        &self,
        _threads: &ThreadManager<'tcx>,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }

    /**** Scheduling functionality ****/

    pub(crate) fn should_preempt(&self) -> bool {
        unreachable!()
    }

    pub(crate) fn schedule_thread<'tcx>(
        &self,
        _thread_manager: &ThreadManager<'tcx>,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> InterpResult<'tcx, ThreadId> {
        unreachable!()
    }

    /**** Blocking instructions ****/

    pub(crate) fn handle_verifier_assume<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        _condition: bool,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }
}

impl VisitProvenance for GenmcCtx {
    fn visit_provenance(&self, _visit: &mut VisitWith<'_>) {
        unreachable!()
    }
}

impl GenmcConfig {
    pub fn parse_arg(_miri_config: &mut MiriConfig, trimmed_arg: &str) {
        unimplemented!(
            "GenMC feature im Miri is disabled, cannot handle argument: \"-Zmiri-genmc{trimmed_arg}\""
        );
    }

    pub fn should_print_graph(&self, _rep: usize) -> bool {
        unreachable!()
    }
}
