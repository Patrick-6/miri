use rustc_abi::{Align, Size};
use rustc_const_eval::interpret::{AllocId, InterpCx, InterpResult};
use rustc_middle::mir;

use crate::{
    AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd, MemoryKind, MiriConfig,
    MiriMachine, OpTy, Scalar, ThreadId, ThreadManager, VisitProvenance, VisitWith,
};

#[derive(Debug)]
pub struct GenmcCtx {}

#[derive(Debug, Default, Clone)]
pub struct GenmcConfig {}

// TODO GENMC: add all exposed methods here too

impl GenmcCtx {
    pub fn new(_miri_config: &MiriConfig, _genmc_config: &GenmcConfig) -> Self {
        unreachable!()
    }
    
    pub fn print_estimation_result(&self) {
        unreachable!()
    }

    pub fn get_blocked_execution_count(&self) -> usize {
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
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> Result<(), String> {
        unreachable!()
    }

    pub(super) fn set_ongoing_action_data_race_free(&self, _enable: bool) {
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
        _old_value: Option<Scalar>,
        _ordering: AtomicWriteOrd,
    ) -> InterpResult<'tcx, bool> {
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
        (_rmw_op, _not): (mir::BinOp, bool),
        _rhs_scalar: Scalar,
        _old_value: Scalar,
    ) -> InterpResult<'tcx, (Scalar, Scalar)> {
        unreachable!()
    }

    pub(crate) fn atomic_min_max_op<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _ordering: AtomicRwOrd,
        _min: bool,
        _is_signed: bool,
        _rhs_scalar: Scalar,
        _old_value: Scalar,
    ) -> InterpResult<'tcx, (Scalar, Scalar)> {
        unreachable!()
    }

    pub(crate) fn atomic_exchange<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _address: Size,
        _size: Size,
        _rhs_scalar: Scalar,
        _ordering: AtomicRwOrd,
        _old_value: Scalar,
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
        _old_value: Scalar,
    ) -> InterpResult<'tcx, (Scalar, bool)> {
        unreachable!()
    }

    pub(crate) fn memory_load<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        _address: Size,
        _size: Size,
    ) -> InterpResult<'tcx, ()> {
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
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        _alloc_id: AllocId,
        _size: Size,
        _alignment: Align,
        _memory_kind: MemoryKind,
    ) -> InterpResult<'tcx, u64> {
        unreachable!()
    }

    pub(crate) fn handle_dealloc<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        _alloc_id: AllocId,
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
        _start_routine: crate::Pointer,
        _func_arg: &crate::ImmTy<'tcx>,
        _new_thread_id: ThreadId,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }

    pub(crate) fn handle_thread_join<'tcx>(
        &self,
        _active_thread_id: ThreadId,
        _child_thread_id: ThreadId,
    ) -> InterpResult<'tcx, ()> {
        unreachable!()
    }

    pub(crate) fn handle_thread_stack_empty<'tcx>(
        &self,
        _threads: &ThreadManager<'tcx>,
        _thread_id: ThreadId,
    ) {
        unreachable!()
    }

    pub(crate) fn handle_main_thread_stack_empty<'tcx>(&self, _threads: &ThreadManager<'tcx>) {
        unreachable!()
    }

    pub(crate) fn handle_thread_finish<'tcx>(&self, _threads: &ThreadManager<'tcx>) {
        unreachable!()
    }

    /**** Scheduling functionality ****/

    pub(crate) fn schedule_thread<'tcx>(
        &self,
        _ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> InterpResult<'tcx, ThreadId> {
        unreachable!()
    }
}

/// Other functionality not directly related to event handling
impl<'tcx> EvalContextExt<'tcx> for crate::MiriInterpCx<'tcx> {}
pub trait EvalContextExt<'tcx>: crate::MiriInterpCxExt<'tcx> {
    fn check_genmc_intercept_function(
        &mut self,
        _instance: rustc_middle::ty::Instance<'tcx>,
        _args: &[rustc_const_eval::interpret::FnArg<'tcx, crate::Provenance>],
        _dest: &crate::PlaceTy<'tcx>,
        _ret: Option<mir::BasicBlock>,
    ) -> InterpResult<'tcx, bool> {
        unreachable!()
    }

    /**** Blocking instructions ****/

    fn handle_genmc_verifier_assume(&mut self, _condition: &OpTy<'tcx>) -> InterpResult<'tcx> {
        unreachable!()
    }
}

impl VisitProvenance for GenmcCtx {
    fn visit_provenance(&self, _visit: &mut VisitWith<'_>) {
        unreachable!()
    }
}

impl GenmcConfig {
    pub fn parse_arg(_genmc_config: &mut Option<GenmcConfig>, trimmed_arg: &str) {
        unimplemented!(
            "GenMC feature im Miri is disabled, cannot handle argument: \"-Zmiri-genmc{trimmed_arg}\""
        );
    }

    pub fn print_exec_graphs(&self) -> bool {
        unreachable!()
    }

    pub fn do_estimation(&self) -> bool {
        unreachable!()
    }
}
