#[allow(unused_imports)] // TODO GENMC: false warning?
use std::pin::Pin;
use std::sync::Mutex;

use cxx::UniquePtr;
use rustc_abi::{Align, Size};
use rustc_middle::mir::interpret::AllocId;

use self::ffi::{MemoryOrdering, MiriGenMCShim, createGenmcHandle};
use crate::{AtomicReadOrd, AtomicWriteOrd};

// TODO GENMC: extract the ffi module if possible, to reduce number of required recompilation
#[cxx::bridge]
mod ffi {

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

    unsafe extern "C++" {
        include!("miri/genmc/src/Verification/MiriInterface.hpp");

        type MemoryOrdering;
        // type GenmcConfig; // TODO GENMC
        // type OperatingMode; // Estimation(budget) or Verification
        type MiriGenMCShim;

        fn createGenmcHandle(/* GenmcConfig config */ /* OperatingMode */)
         -> UniquePtr<MiriGenMCShim>;

        fn handleLoad(
            self: Pin<&mut MiriGenMCShim>,
            alloc_id: u64,
            address: usize,
            memory_ordering: MemoryOrdering,
        );
        fn handleStore(
            self: Pin<&mut MiriGenMCShim>,
            alloc_id: u64,
            address: usize,
            memory_ordering: MemoryOrdering,
        );
        fn handleMalloc(
            self: Pin<&mut MiriGenMCShim>,
            alloc_id: u64,
            size: usize,
            alignment: usize,
        );
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
            AtomicWriteOrd::Release => MemoryOrdering::Relaxed,
            AtomicWriteOrd::SeqCst => MemoryOrdering::SequentiallyConsistent,
        }
    }
}

// fn to_genmc_memory_ordering(atomic_ordering: Option<AtomicOrdering>) -> MemoryOrdering {
//     let Some(atomic_ordering) = atomic_ordering else {
//         return MemoryOrdering::NotAtomic;
//     };
//     match atomic_ordering {
//         AtomicOrdering::Unordered => MemoryOrdering::Unordered,
//         AtomicOrdering::Relaxed => MemoryOrdering::Relaxed,
//         AtomicOrdering::Acquire => MemoryOrdering::Acquire,
//         AtomicOrdering::Release => MemoryOrdering::Release,
//         AtomicOrdering::AcquireRelease => MemoryOrdering::AcquireRelease,
//         AtomicOrdering::SequentiallyConsistent => MemoryOrdering::SequentiallyConsistent,
//     }
// }

#[derive(Clone, Debug)]
pub struct GenmcConfig {
    // TODO
    pub(crate) memory_model: Box<str>, // TODO: could potentially make this an enum
                                       // pub(crate) genmc_seed: u64; // OR: Option<u64>
}

#[allow(clippy::derivable_impls)] // TODO: remove
impl Default for GenmcConfig {
    fn default() -> Self {
        Self { memory_model: "RC11".into() }
    }
}

pub struct GenmcCtx {
    // TODO GENMC: remove this Mutex if possible
    handle: Mutex<UniquePtr<MiriGenMCShim>>,
    // TODO
}

impl GenmcCtx {
    pub(crate) fn new(config: &GenmcConfig) -> Self {
        // Need to call into GenMC, create new Model Checker
        // Store handle to Model Checker in the struct

        let _config = config; // TODO GENMC: implement GenMC config

        let handle = createGenmcHandle();
        assert!(!handle.is_null());
        let handle = Mutex::new(handle);
        eprintln!("DEBUG: Got a GenMC handle!");
        Self { handle }
    }

    //* might fails if there's a race, load might also not read anything (returns None) */
    pub(crate) fn atomic_load(
        &self,
        alloc_id: AllocId,
        address: usize,
        ordering: AtomicReadOrd,
    ) -> Result<(), ()> {
        let ordering = ordering.convert();
        self.atomic_load_impl(alloc_id, address, ordering)
    }

    pub(crate) fn atomic_store(
        &self,
        alloc_id: AllocId,
        address: usize,
        ordering: AtomicWriteOrd,
    ) -> Result<(), ()> {
        let ordering = ordering.convert();
        self.atomic_store_impl(alloc_id, address, ordering)
    }

    pub(crate) fn atomic_fence(&self) -> Result<(), ()> {
        // TODO GENMC
        todo!()
    }

    pub(crate) fn atomic_rmw_op(&self) -> Result<(), ()> {
        // TODO GENMC
        todo!()
    }

    pub(crate) fn atomic_exchange(&self) -> Result<(), ()> {
        // TODO GENMC
        todo!()
    }

    pub(crate) fn atomic_compare_exchange(&self, can_fail_spuriously: bool) -> Result<(), ()> {
        // TODO GENMC
        dbg!(can_fail_spuriously);
        todo!()
    }

    pub(crate) fn memory_load(&self, alloc_id: AllocId, address: usize) -> Result<(), ()> {
        self.atomic_load_impl(alloc_id, address, MemoryOrdering::NotAtomic)
    }

    pub(crate) fn memory_store(&self, alloc_id: AllocId, address: usize) -> Result<(), ()> {
        self.atomic_store_impl(alloc_id, address, MemoryOrdering::NotAtomic)
    }

    /**** Memory (de)allocation ****/

    pub(crate) fn handle_alloc(
        &self,
        alloc_id: AllocId,
        size: Size,
        alignment: Align,
    ) -> Result<(), ()> {
        let alloc_id = alloc_id.0.get();
        // kind: MemoryKind, TODO GENMC: Does GenMC care about the kind of Memory?
        let size = size.bits_usize();
        let alignment = alignment.bits_usize();
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleMalloc(alloc_id, size, alignment);
        Ok(())
    }

    /**** Scheduling queries ****/

    pub(crate) fn should_preempt(&self) -> bool {
        false // TODO GENMC
    }

    pub(crate) fn get_scheduling(&self) -> ! {
        // TODO GENMC
        todo!()
    }
}

impl GenmcCtx {
    //* might fails if there's a race, load might also not read anything (returns None) */
    fn atomic_load_impl(
        &self,
        alloc_id: AllocId,
        address: usize,
        memory_ordering: MemoryOrdering,
    ) -> Result<(), ()> {
        let alloc_id = alloc_id.0.get();
        // eprintln!("Calling into GenMC (load, {address:x}, {memory_ordering:?})");
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleLoad(alloc_id, address, memory_ordering);
        // TODO GENMC
        Ok(())
    }

    fn atomic_store_impl(
        &self,
        alloc_id: AllocId,
        address: usize,
        memory_ordering: MemoryOrdering,
    ) -> Result<(), ()> {
        let alloc_id = alloc_id.0.get();
        // eprintln!("Calling into GenMC (store, {address:x}, {memory_ordering:?})");
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleStore(alloc_id, address, memory_ordering);
        // TODO GENMC
        Ok(())
    }
}

impl std::fmt::Debug for GenmcCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenmcCtx")
            // .field("mc", &self.mc)
            .finish_non_exhaustive()
    }
}
