use super::ffi::{MemoryOrdering, RmwBinOp};
use crate::intrinsics::AtomicOp;
use crate::{AtomicFenceOrd, AtomicReadOrd, AtomicRwOrd, AtomicWriteOrd};

pub(super) trait ToGenmcMemoryOrdering {
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

impl AtomicRwOrd {
    pub(super) fn to_genmc_memory_orderings(self) -> (MemoryOrdering, MemoryOrdering) {
        match self {
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

impl AtomicOp {
    pub(super) fn to_genmc_rmw_op(&self, is_unsigned: bool) -> RmwBinOp {
        match (self, is_unsigned) {
            (AtomicOp::Min, false) => RmwBinOp::Min, // TODO GENMC: is there a use for FMin? (Min, UMin, FMin)
            (AtomicOp::Max, false) => RmwBinOp::Max,
            (AtomicOp::Min, true) => RmwBinOp::UMin,
            (AtomicOp::Max, true) => RmwBinOp::UMax,
            (&AtomicOp::MirOp(bin_op, negate), _) =>
                match bin_op {
                    rustc_middle::mir::BinOp::Add => RmwBinOp::Add,
                    rustc_middle::mir::BinOp::Sub => RmwBinOp::Sub,
                    rustc_middle::mir::BinOp::BitOr if !negate => RmwBinOp::Or,
                    rustc_middle::mir::BinOp::BitXor if !negate => RmwBinOp::Xor,
                    rustc_middle::mir::BinOp::BitAnd if negate => RmwBinOp::Nand,
                    rustc_middle::mir::BinOp::BitAnd => RmwBinOp::And,
                    _ => {
                        panic!(
                            "unsupported atomic operation: bin_op: {bin_op:?}, negate: {negate}"
                        );
                    }
                },
        }
    }
}
