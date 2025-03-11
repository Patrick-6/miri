#[allow(unused_imports)] // TODO GENMC: false warning?
use std::pin::Pin;
use std::sync::Mutex;

use cxx::UniquePtr;
use rustc_abi::{Align, Size};
use rustc_middle::mir::interpret::AllocId;

use self::ffi::{MemoryOrdering, MiriGenMCShim, createGenmcHandle};
use crate::{AtomicReadOrd, AtomicWriteOrd, MemoryKind};

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
            size: usize,
            memory_ordering: MemoryOrdering,
        );
        fn handleStore(
            self: Pin<&mut MiriGenMCShim>,
            alloc_id: u64,
            address: usize,
            size: usize,
            value: u64,
            // value: u128, // TODO GENMC: handle this
            memory_ordering: MemoryOrdering,
        );
        fn handleMalloc(
            self: Pin<&mut MiriGenMCShim>,
            alloc_id: u64,
            requested_address: usize,
            size: usize,
            alignment: usize,
        );
        fn handleFree(
            self: Pin<&mut MiriGenMCShim>,
            alloc_id: u64,
            /* address: usize, */
            size: usize,
        );
        fn printGraph(self: Pin<&mut MiriGenMCShim>);
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
    #[allow(unused)]
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

fn scalar_to_genmc_scalar(value: crate::Scalar) -> u64 {
    // TODO: proper handling of `Scalar`
    match value {
        rustc_const_eval::interpret::Scalar::Int(scalar_int) => scalar_int.to_u64(),
        rustc_const_eval::interpret::Scalar::Ptr(pointer, _) => pointer.into_parts().1.bytes(),
    }
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
        size: usize,
        ordering: AtomicReadOrd,
    ) -> Result<(), ()> {
        let ordering = ordering.convert();
        eprintln!("MIRI: atomic_load with ordering {ordering:?}");
        self.atomic_load_impl(alloc_id, address, size, ordering)
    }

    pub(crate) fn atomic_store(
        &self,
        alloc_id: AllocId,
        address: usize,
        size: usize,
        value: crate::Scalar,
        ordering: AtomicWriteOrd,
    ) -> Result<(), ()> {
        let ordering = ordering.convert();

        let value_genmc = scalar_to_genmc_scalar(value);
        eprintln!(
            "MIRI: atomic_store with ordering {ordering:?}, value: {value:?} -> {value_genmc}"
        );
        self.atomic_store_impl(alloc_id, address, size, value_genmc, ordering)
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

    pub(crate) fn memory_load(
        &self,
        // ecx: TODO GENMC
        // Pointer
        alloc_id: AllocId,
        address: usize,
        size: usize,
    ) -> Result<(), ()> {
        eprintln!(
            "MIRI: SKIP! received memory_load (non-atomic): {alloc_id:?}, address: {address}, size: {size}"
        );
        Ok(())
        // self.atomic_load_impl(alloc_id, address, size, MemoryOrdering::NotAtomic)
    }

    pub(crate) fn memory_store(
        &self,
        alloc_id: AllocId,
        address: usize,
        size: usize,
        // value: crate::Scalar,
    ) -> Result<(), ()> {
        eprintln!(
            "MIRI: SKIP! received memory_store (non-atomic): {alloc_id:?}, address: {address}, size: {size}"
        );
        Ok(())
        // let value_genmc = scalar_to_genmc_scalar(value);
        // static VALUE_COUNT: AtomicU64 = AtomicU64::new(1);
        // // TODO GENMC: find a way to get the value from before_memory_read
        // let value_genmc = VALUE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // self.atomic_store_impl(alloc_id, address, size, value_genmc, MemoryOrdering::NotAtomic)
    }

    /**** Memory (de)allocation ****/

    pub(crate) fn handle_alloc(
        &self,
        alloc_id: AllocId,
        requested_address: usize,
        size: Size,
        alignment: Align,
    ) -> Result<(), ()> {
        eprintln!(
            "MIRI: handle_alloc ({alloc_id:?}, size: {size:?}, alignment: {alignment:?}, address: {requested_address})"
        );
        // if size == 0 {
        //     eprintln!("MIRI: SKIP telling GenMC about alloc of size 0");
        // }
        let alloc_id = alloc_id.0.get();
        // kind: MemoryKind, TODO GENMC: Does GenMC care about the kind of Memory?
        let size = size.bytes_usize();
        
        if size == 0 {
            eprintln!("SKIP telling GenMC about ZST allocation");
            return Ok(());
        }

        let alignment = alignment.bytes_usize();
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleMalloc(alloc_id, requested_address, size, alignment);
        Ok(())
    }

    pub(crate) fn handle_dealloc(
        &self,
        alloc_id: AllocId,
        size: Size,
        align: Align,
        kind: MemoryKind,
    ) -> Result<(), ()> {
        eprintln!(
            "TODO GENMC: inform GenMC about memory deallocation ({alloc_id:?}, size: {size:?}, align: {align:?}, memory_kind: {kind:?}"
        );

        let alloc_id = alloc_id.0.get();
        let size = size.bytes_usize();

        if size == 0 {
            eprintln!("SKIP telling GenMC about ZST deallocation");
            return Ok(());
        }

        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleFree(alloc_id, size);

        Ok(())
    }

    // pub(crate) fn handle_free(
    //     &self,
    //     alloc_id: AllocId,
    // ) {
    //     // TODO GENMC: implement
    // }

    /**** Scheduling queries ****/

    pub(crate) fn should_preempt(&self) -> bool {
        false // TODO GENMC
    }

    // pub(crate) fn get_scheduling(&self) -> ! {
    //     // TODO GENMC
    //     todo!()
    // }
}

impl GenmcCtx {
    //* might fails if there's a race, load might also not read anything (returns None) */
    fn atomic_load_impl(
        &self,
        alloc_id: AllocId,
        address: usize,
        size: usize,
        memory_ordering: MemoryOrdering,
    ) -> Result<(), ()> {
        // if size == 0 {
        //     eprintln!("MIRI: SKIP telling GenMC about read of size 0");
        // }
        let alloc_id = alloc_id.0.get();
        // eprintln!("Calling into GenMC (load, {address:x}, {memory_ordering:?})");
        eprintln!(
            "Calling into GenMC (load, alloc: {alloc_id:?}, address: {address}, size: {size}, {memory_ordering:?})"
        );
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleLoad(alloc_id, address, size, memory_ordering);
        // TODO GENMC
        Ok(())
    }

    fn atomic_store_impl(
        &self,
        alloc_id: AllocId,
        address: usize,
        size: usize,
        value: u64, // TODO GENMC: handle larger values
        memory_ordering: MemoryOrdering,
    ) -> Result<(), ()> {
        // if size == 0 {
        //     eprintln!("MIRI: SKIP telling GenMC about store of size 0");
        // }
        let alloc_id = alloc_id.0.get();
        eprintln!(
            "Calling into GenMC (store, alloc: {alloc_id:?}, address: {address}, size: {size}, {memory_ordering:?})"
        );
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleStore(alloc_id, address, size, value, memory_ordering);
        // TODO GENMC
        Ok(())
    }
}

impl Drop for GenmcCtx {
    fn drop(&mut self) {
        eprintln!("MIRI: attempting to get GenMC to print the Execution graph...");
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.printGraph();
    }
}

impl std::fmt::Debug for GenmcCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenmcCtx")
            // .field("mc", &self.mc)
            .finish_non_exhaustive()
    }
}
