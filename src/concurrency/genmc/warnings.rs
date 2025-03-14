use std::sync::RwLock;

use rustc_const_eval::interpret::InterpCx;
use rustc_data_structures::fx::FxHashSet;
use rustc_span::Span;

use crate::diagnostics::EvalContextExt;
use crate::{AtomicReadOrd, AtomicRwOrd, MiriMachine, NonHaltingDiagnostic};

#[derive(Default)]
pub struct WarningsCache {
    emitted_compare_exchange_weak: RwLock<FxHashSet<Span>>,
    emitted_compare_exchange_failure_ordering: RwLock<FxHashSet<Span>>,
}

impl WarningsCache {
    /// Warn about unsupported spurious failures of `compare_exchange_weak`, once per span, returning `true` if the warning was printed.
    pub fn warn_once_compare_exchange_weak<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    ) -> bool {
        let span = ecx.machine.current_span();
        if !self.emitted_compare_exchange_weak.read().unwrap().contains(&span) {
            // This span has not yet been reported, so we insert it into the cache and report it.
            let mut cache = self.emitted_compare_exchange_weak.write().unwrap();
            if !cache.insert(span) {
                return false; /* Some other thread added this span while we didn't hold the lock. */
            }
            ecx.emit_diagnostic(NonHaltingDiagnostic::GenmcCompareExchangeWeak);
            return true;
        }
        false
    }

    /// Check if the given failure ordering is unsupported by GenMC.
    /// Warning is printed only once per span.
    /// Returns `true` if the warning was printed.
    pub fn warn_once_rmw_failure_ordering<'tcx>(
        &self,
        ecx: &InterpCx<'tcx, MiriMachine<'tcx>>,
        success_ordering: AtomicRwOrd,
        upgraded_success_ordering: AtomicRwOrd,
        failure_ordering: AtomicReadOrd,
    ) -> bool {
        let (effective_failure_ordering, _) = upgraded_success_ordering.split_memory_orderings();

        // Return if the model is accurate for the given orderings.
        if success_ordering == upgraded_success_ordering
            && effective_failure_ordering == failure_ordering
        {
            return false;
        }
        // Return if we already reported a warning for this span.
        // TODO GENMC: `machine.current_span` or `exc.cur_span`?
        let span = ecx.machine.current_span();
        if self.emitted_compare_exchange_failure_ordering.read().unwrap().contains(&span) {
            return false;
        }
        // This span has not yet been reported, so we insert it into the cache and report it.
        let mut cache = self.emitted_compare_exchange_failure_ordering.write().unwrap();
        if !cache.insert(span) {
            return false; /* Some other thread added this span while we didn't hold the lock. */
        }

        // Miri might miss bugs related to this span, so we show a warning.
        ecx.emit_diagnostic(NonHaltingDiagnostic::GenmcCompareExchangeOrderingMismatch {
            success_ordering,
            upgraded_success_ordering,
            failure_ordering,
            effective_failure_ordering,
        });
        true
    }
}
