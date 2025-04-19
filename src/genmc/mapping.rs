use super::ffi::{MemOrdering, RMWBinOp};
use crate::intrinsics::AtomicOp;
use crate::{AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd};

impl AtomicReadOrd {
    pub(super) fn convert(self) -> MemOrdering {
        match self {
            AtomicReadOrd::Relaxed => MemOrdering::Relaxed,
            AtomicReadOrd::Acquire => MemOrdering::Acquire,
            AtomicReadOrd::SeqCst => MemOrdering::SequentiallyConsistent,
        }
    }
}

impl AtomicWriteOrd {
    pub(super) fn convert(self) -> MemOrdering {
        match self {
            AtomicWriteOrd::Relaxed => MemOrdering::Relaxed,
            AtomicWriteOrd::Release => MemOrdering::Release,
            AtomicWriteOrd::SeqCst => MemOrdering::SequentiallyConsistent,
        }
    }
}

impl AtomicFenceOrd {
    pub(super) fn convert(self) -> MemOrdering {
        match self {
            AtomicFenceOrd::Acquire => MemOrdering::Acquire,
            AtomicFenceOrd::Release => MemOrdering::Release,
            AtomicFenceOrd::AcqRel => MemOrdering::AcquireRelease,
            AtomicFenceOrd::SeqCst => MemOrdering::SequentiallyConsistent,
        }
    }
}

impl AtomicRwOrd {
    pub(super) fn to_genmc_memory_orderings(self) -> (MemOrdering, MemOrdering) {
        match self {
            // TODO GENMC: check if we need to implement Release ==> (Release, Release)
            AtomicRwOrd::Relaxed => (MemOrdering::Relaxed, MemOrdering::Relaxed),
            AtomicRwOrd::Acquire => (MemOrdering::Acquire, MemOrdering::Relaxed),
            AtomicRwOrd::Release => (MemOrdering::Relaxed, MemOrdering::Release),
            AtomicRwOrd::AcqRel => (MemOrdering::Acquire, MemOrdering::Release),
            AtomicRwOrd::SeqCst =>
                (MemOrdering::SequentiallyConsistent, MemOrdering::SequentiallyConsistent),
        }
    }
}

impl AtomicOp {
    pub(super) fn to_genmc_rmw_op(&self, is_unsigned: bool) -> RMWBinOp {
        match (self, is_unsigned) {
            (AtomicOp::Min, false) => RMWBinOp::Min, // TODO GENMC: is there a use for FMin? (Min, UMin, FMin)
            (AtomicOp::Max, false) => RMWBinOp::Max,
            (AtomicOp::Min, true) => RMWBinOp::UMin,
            (AtomicOp::Max, true) => RMWBinOp::UMax,
            (&AtomicOp::MirOp(bin_op, negate), _) =>
                match bin_op {
                    rustc_middle::mir::BinOp::Add => RMWBinOp::Add,
                    rustc_middle::mir::BinOp::Sub => RMWBinOp::Sub,
                    rustc_middle::mir::BinOp::BitOr if !negate => RMWBinOp::Or,
                    rustc_middle::mir::BinOp::BitXor if !negate => RMWBinOp::Xor,
                    rustc_middle::mir::BinOp::BitAnd if negate => RMWBinOp::Nand,
                    rustc_middle::mir::BinOp::BitAnd => RMWBinOp::And,
                    _ => {
                        panic!(
                            "unsupported atomic operation: bin_op: {bin_op:?}, negate: {negate}"
                        );
                    }
                },
        }
    }
}
