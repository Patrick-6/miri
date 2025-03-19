#[allow(unused_imports)] // TODO GENMC: false warning?
use std::pin::Pin;
use std::sync::Mutex;

use cxx::UniquePtr;
use rand::prelude::*;
use rand::rngs::StdRng;
use rustc_abi::{Align, Size};
use rustc_middle::{mir::interpret::AllocId, ty::ScalarInt};

use self::ffi::{MemoryOrdering, MiriGenMCShim, createGenmcHandle};
use crate::{AtomicReadOrd, AtomicWriteOrd, MemoryKind, MiriMachine, ThreadId, ThreadManager};

mod cxx_extra;

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

    extern "Rust" {
        type Threads;
        fn is_enabled(self: &Threads, thread_id: u32) -> bool;
        // fn set_next_thread(self: &mut Threads, thread_id: u32);
    }

    unsafe extern "C++" {
        include!("miri/genmc/src/Verification/MiriInterface.hpp");

        type MemoryOrdering;
        // type GenmcConfig; // TODO GENMC
        // type OperatingMode; // Estimation(budget) or Verification
        type MiriGenMCShim;

        fn createGenmcHandle(/* GenmcConfig config */ /* OperatingMode */)
         -> UniquePtr<MiriGenMCShim>;

        fn handleExecutionStart(self: Pin<&mut MiriGenMCShim>);
        fn handleExecutionEnd(self: Pin<&mut MiriGenMCShim>);

        fn handleLoad(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            alloc_id: u64,
            address: usize,
            size: usize,
            memory_ordering: MemoryOrdering,
        ) -> u64; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleStore(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            alloc_id: u64,
            address: usize,
            size: usize,
            value: u64,
            // value: u128, // TODO GENMC: handle this
            memory_ordering: MemoryOrdering,
        );

        fn handleMalloc(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            alloc_id: u64,
            size: usize,
            alignment: usize,
        ) -> u64;
        fn handleFree(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: u32,
            alloc_id: u64,
            /* address: usize, */
            size: usize,
        );

        // fn handleThreadKill(self: Pin<&mut MiriGenMCShim>, thread_id: u32, parent_id: u32);
        fn handleThreadCreate(self: Pin<&mut MiriGenMCShim>, thread_id: u32, parent_id: u32);
        fn handleThreadJoin(self: Pin<&mut MiriGenMCShim>, thread_id: u32, child_id: u32);
        fn handleThreadFinish(self: Pin<&mut MiriGenMCShim>, thread_id: u32, ret_val: u64);

        fn scheduleNext(self: Pin<&mut MiriGenMCShim>, threads: &mut Threads) -> bool;
        fn isHalting(self: &MiriGenMCShim) -> bool;
        fn isMoot(self: &MiriGenMCShim) -> bool;
        fn isExplorationDone(self: Pin<&mut MiriGenMCShim>) -> bool;

        fn printGraph(self: Pin<&mut MiriGenMCShim>);
    }
}

#[derive(Debug)]
pub struct Threads {
    // TODO
    // inner: &ThreadManager
}

#[allow(unused)] // TODO GENMC: remove
impl Threads {
    pub fn new() -> Self {
        Self {}
    }

    fn is_enabled(&self, thread_id: u32) -> bool {
        eprintln!("Threads::is_enabled({thread_id})");
        true
    }

    fn set_next_thread(&mut self, thread_id: u32) {
        eprintln!("Threads::set_next_thread({thread_id})");
    }
}

// #[allow(non_snake_case)]
// fn isEnabled(threads: &Threads, thread_id: u32) -> bool {
//     threads.is_enabled(thread_id)
// }


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
    // pub(crate) genmc_seed: u64; // OR: Option<u64>
    pub(crate) rng: Mutex<StdRng>, // TODO GENMC: temporary rng for handling scheduling
}

fn scalar_to_genmc_scalar(value: crate::Scalar) -> u64 {
    // TODO: proper handling of `Scalar`
    match value {
        rustc_const_eval::interpret::Scalar::Int(scalar_int) => scalar_int.to_uint(scalar_int.size()).try_into().unwrap(), // TODO GENMC: doesn't work for size != 8
        rustc_const_eval::interpret::Scalar::Ptr(_pointer, _size) => todo!(), // pointer.into_parts().1.bytes(),
    }
}

impl GenmcCtx {
    pub fn new(config: &GenmcConfig) -> Self {
        // Need to call into GenMC, create new Model Checker
        // Store handle to Model Checker in the struct

        let _config = config; // TODO GENMC: implement GenMC config

        let handle = createGenmcHandle();
        assert!(!handle.is_null());
        let handle = Mutex::new(handle);
        eprintln!("DEBUG: Got a GenMC handle!");

        let rng = Mutex::new(StdRng::seed_from_u64(0));
        Self { handle, rng }
    }

    pub fn print_genmc_graph(&self) {
        eprintln!("MIRI: attempting to get GenMC to print the Execution graph...");
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.printGraph();
    }

    pub fn is_halting(&self) -> bool {
        eprintln!("MIRI: ask if GenMC is halting...");
        let mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let mc = mc_lock.as_ref().expect("model checker should not be null");
        mc.isHalting()
    }

    pub fn is_moot(&self) -> bool {
        eprintln!("MIRI: ask if GenMC execution is moot...");
        let mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let mc = mc_lock.as_ref().expect("model checker should not be null");
        mc.isMoot()
    }

    pub fn is_exploration_done(&self) -> bool {
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.isExplorationDone()
    }

    /**** Memory access handling ****/

    pub(crate) fn handle_execution_start(&self) {
        eprintln!("MIRI (TODO GENMC): inform GenMC that new execution started!");
        // todo!();
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleExecutionStart();
    }

    pub(crate) fn handle_execution_end(&self) {
        eprintln!("MIRI (TODO GENMC): inform GenMC that execution ended!");
        // todo!();
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleExecutionEnd();
        // TODO GENMC: could return as result here maybe?
    }

    //* might fails if there's a race, load might also not read anything (returns None) */
    pub(crate) fn atomic_load<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        alloc_id: AllocId,
        address: usize,
        size: usize,
        ordering: AtomicReadOrd,
    ) -> Result<crate::Scalar, ()> {
        let ordering = ordering.convert();
        eprintln!("MIRI: atomic_load with ordering {ordering:?}");
        self.atomic_load_impl(machine, alloc_id, address, size, ordering)
    }

    pub(crate) fn atomic_store<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
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
        self.atomic_store_impl(machine, alloc_id, address, size, value_genmc, ordering)
    }

    pub(crate) fn atomic_fence<'tcx>(&self, _machine: &MiriMachine<'tcx>) -> Result<(), ()> {
        // TODO GENMC
        eprintln!("MIRI: TODO GENMC: atomic_fence");
        todo!()
    }

    pub(crate) fn atomic_rmw_op<'tcx>(&self, _machine: &MiriMachine<'tcx>) -> Result<(), ()> {
        eprintln!("MIRI: TODO GENMC: atomic_rmw_op");
        // TODO GENMC
        todo!()
    }

    pub(crate) fn atomic_exchange<'tcx>(&self, _machine: &MiriMachine<'tcx>) -> Result<(), ()> {
        eprintln!("MIRI: TODO GENMC: atomic_exchange");
        // TODO GENMC
        todo!()
    }

    pub(crate) fn atomic_compare_exchange<'tcx>(
        &self,
        _machine: &MiriMachine<'tcx>,
        can_fail_spuriously: bool,
    ) -> Result<(), ()> {
        // TODO GENMC
        eprintln!("MIRI: TODO GENMC: atomic_compare_exchange");
        dbg!(can_fail_spuriously);
        todo!()
    }

    pub(crate) fn memory_load<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        // ecx: TODO GENMC
        // Pointer
        alloc_id: AllocId,
        address: usize,
        size: usize,
    ) -> Result<(), ()> {
        let curr_thread = machine.threads.active_thread().to_u32();
        eprintln!(
            "MIRI: SKIP! received memory_load (non-atomic): thread: {curr_thread}, {alloc_id:?}, address: {address}, size: {size}, thread_id: {:?}",
            machine.threads.active_thread(),
        );
        if size == 0 {
            eprintln!("MIRI: SKIP! skip telling GenMC about ZST access!");
        }
        Ok(())
        // self.atomic_load_impl(alloc_id, address, size, MemoryOrdering::NotAtomic)
    }

    pub(crate) fn memory_store<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        alloc_id: AllocId,
        address: usize,
        size: usize,
        // value: crate::Scalar,
    ) -> Result<(), ()> {
        let curr_thread = machine.threads.active_thread().to_u32();
        eprintln!(
            "MIRI: SKIP! received memory_store (non-atomic): thread: {curr_thread}, {alloc_id:?}, address: {address}, size: {size}"
        );
        if size == 0 {
            eprintln!("MIRI: SKIP! skip telling GenMC about ZST access!");
        }
        Ok(())
        // let value_genmc = scalar_to_genmc_scalar(value);
        // static VALUE_COUNT: AtomicU64 = AtomicU64::new(1);
        // // TODO GENMC: find a way to get the value from before_memory_read
        // let value_genmc = VALUE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // self.atomic_store_impl(alloc_id, address, size, value_genmc, MemoryOrdering::NotAtomic)
    }

    /**** Memory (de)allocation ****/

    pub(crate) fn handle_alloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        alloc_id: AllocId,
        size: Size,
        alignment: Align,
    ) -> Result<u64, ()> {
        let curr_thread = machine.threads.active_thread().to_u32();
        eprintln!(
            "MIRI: handle_alloc (thread: {curr_thread}, {alloc_id:?}, size: {size:?}, alignment: {alignment:?})"
        );
        // if size == 0 {
        //     eprintln!("MIRI: SKIP telling GenMC about alloc of size 0");
        // }
        let alloc_id = alloc_id.0.get();
        // kind: MemoryKind, TODO GENMC: Does GenMC care about the kind of Memory?
        let mut size = size.bytes_usize();

        if size == 0 {
            // eprintln!("SKIP telling GenMC about ZST allocation");
            eprintln!("Tell GenMC that ZST allocation actually is 1-byte allocation");

            // return Ok(());
            // return Err(());
            size = 1;
        }

        let alignment = alignment.bytes_usize();
        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        let chosen_address = pinned_mc.handleMalloc(curr_thread, alloc_id, size, alignment);
        Ok(chosen_address)
    }

    pub(crate) fn handle_dealloc<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        alloc_id: AllocId,
        size: Size,
        align: Align,
        kind: MemoryKind,
    ) -> Result<(), ()> { // TODO GENMC: interp_result
        let curr_thread = machine.threads.active_thread().to_u32();
        eprintln!(
            "TODO GENMC: inform GenMC about memory deallocation (thread: {curr_thread}, {alloc_id:?}, size: {size:?}, align: {align:?}, memory_kind: {kind:?}"
        );

        let alloc_id = alloc_id.0.get();
        let mut size = size.bytes_usize();

        // if size == 0 {
        //     eprintln!("SKIP telling GenMC about ZST deallocation");
        //     return Ok(());
        // }
        if size == 0 {
            // eprintln!("SKIP telling GenMC about ZST allocation");
            eprintln!("Tell GenMC that ZST deallocation actually is 1-byte deallocation");

            // return Ok(());
            // return Err(());
            size = 1;
        }

        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleFree(curr_thread, alloc_id, size);

        Ok(())
    }

    /**** Thread management ****/

    pub(crate) fn handle_thread_create<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
        new_thread_id: ThreadId,
    ) -> Result<(), ()> {
        let new_thread_id = new_thread_id.to_u32();
        let parent_thread_id = threads.active_thread().to_u32();

        eprintln!(
            "MIRI: handling thread creation (thread {parent_thread_id} spawned thread {new_thread_id})"
        );

        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");

        pinned_mc.handleThreadCreate(new_thread_id, parent_thread_id);

        Ok(())
    }

    pub(crate) fn handle_thread_join(
        &self,
        // machine: &MiriMachine<'tcx>,
        // threads: &ThreadManager<'tcx>,
        active_thread_id: ThreadId,
        child_thread_id: ThreadId,
    ) -> Result<(), ()> {
        // let curr_thread_id = machine.threads.active_thread().to_u32();
        let curr_thread_id = active_thread_id.to_u32();
        let child_thread_id = child_thread_id.to_u32();

        eprintln!(
            "MIRI: handling thread joining (thread {curr_thread_id} joining thread {child_thread_id})"
        );

        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");

        pinned_mc.handleThreadJoin(curr_thread_id, child_thread_id);

        Ok(())
    }

    pub(crate) fn handle_thread_finish<'tcx>(
        &self,
        threads: &ThreadManager<'tcx>,
    ) -> Result<(), ()> {
        let curr_thread_id = threads.active_thread().to_u32();
        let ret_val = 0; // TODO GENMC: do threads in Miri have a return value?

        eprintln!(
            "MIRI: handling thread finish (thread {curr_thread_id} returns with DUMMY value 0)"
        );

        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");

        pinned_mc.handleThreadFinish(curr_thread_id, ret_val);

        Ok(())
    }

    /**** Scheduling queries ****/

    pub(crate) fn should_preempt(&self) -> bool {
        true // TODO GENMC
    }

    pub(crate) fn schedule_thread<'tcx>(
        &self,
        thread_manager: &ThreadManager<'tcx>,
    ) -> Result<ThreadId, ()> {
        // TODO GENMC
        eprintln!("TODO GENMC: ask who to schedule next");

        let mut threads = Threads::new();

        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");

        eprintln!("TODO GENMC: call GenMC here, ask for scheduling");
        pinned_mc.scheduleNext(&mut threads);


        let enabled_thread_count = thread_manager.get_enabled_thread_count();
        let mut i = self.rng.lock().unwrap().random_range(0..enabled_thread_count);
        for (thread_id, thread) in thread_manager.threads_ref().iter_enumerated() {
            if !thread.get_state().is_enabled() {
                continue;
            }
            if i != 0 {
                i -= 1;
                continue;
            }
            return Ok(thread_id);
        }
        unreachable!()
    }
}

impl GenmcCtx {
    //* might fails if there's a race, load might also not read anything (returns None) */
    fn atomic_load_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        alloc_id: AllocId,
        address: usize,
        size: usize,
        memory_ordering: MemoryOrdering,
    ) -> Result<crate::Scalar, ()> {
        // if size == 0 {
        //     eprintln!("MIRI: SKIP telling GenMC about read of size 0");
        // }
        assert_ne!(0, size);
        let alloc_id = alloc_id.0.get();
        let curr_thread = machine.threads.active_thread().to_u32();
        eprintln!(
            "Calling into GenMC (load, thread: {curr_thread}, alloc: {alloc_id:?}, address: {address}, size: {size}, {memory_ordering:?})"
        );

        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        let read_value = pinned_mc.handleLoad(curr_thread, alloc_id, address, size, memory_ordering);
        let size = Size::from_bytes(size);
        let scalar_int = ScalarInt::try_from_uint(read_value, size).unwrap();
        let read_scalar = crate::Scalar::Int(scalar_int);

        Ok(read_scalar)
    }

    fn atomic_store_impl<'tcx>(
        &self,
        machine: &MiriMachine<'tcx>,
        alloc_id: AllocId,
        address: usize,
        size: usize,
        value: u64, // TODO GENMC: handle larger values
        memory_ordering: MemoryOrdering,
    ) -> Result<(), ()> {
        // if size == 0 {
        //     eprintln!("MIRI: SKIP telling GenMC about store of size 0");
        // }
        assert_ne!(0, size);
        let alloc_id = alloc_id.0.get();
        let curr_thread = machine.threads.active_thread().to_u32();
        eprintln!(
            "Calling into GenMC (store: thread: {curr_thread}, alloc: {alloc_id:?}, address: {address}, size: {size}, {memory_ordering:?})"
        );

        let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
        let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
        pinned_mc.handleStore(curr_thread, alloc_id, address, size, value, memory_ordering);
        // TODO GENMC
        Ok(())
    }
}

// impl Drop for GenmcCtx {
//     fn drop(&mut self) {
//         eprintln!("MIRI: attempting to get GenMC to print the Execution graph...");
//         let mut mc_lock = self.handle.lock().expect("Mutex should not be poisoned");
//         let pinned_mc = mc_lock.as_mut().expect("model checker should not be null");
//         pinned_mc.printGraph();
//     }
// }

impl std::fmt::Debug for GenmcCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenmcCtx")
            // .field("mc", &self.mc)
            .finish_non_exhaustive()
    }
}
