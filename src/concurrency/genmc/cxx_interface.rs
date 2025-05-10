pub use self::ffi::*;

// TODO GENMC: extract the ffi module if possible, to reduce number of required recompilation
#[cxx::bridge]
mod ffi {
    /// Parameters that will be given to GenMC for setting up the model checker.
    /// (The fields of this struct are visible to both Rust and C++)
    #[derive(Clone, Debug)]
    struct GenmcParams {
        #[allow(unused)]
        pub memory_model: String, // TODO GENMC: (is this even needed?) could potentially make this an enum

        // pub genmc_seed: u64; // OR: Option<u64>
        pub print_random_schedule_seed: bool,
        pub disable_race_detection: bool,
        pub quiet: bool, // TODO GENMC: maybe make log-level more fine grained
        pub log_level_trace: bool,
        pub do_symmetry_reduction: bool,
    }

    #[derive(Debug)]
    enum MemOrdering {
        NotAtomic = 0,
        Relaxed = 1,
        // In case we support consume
        Acquire = 3,
        Release = 4,
        AcquireRelease = 5,
        SequentiallyConsistent = 6,
    }

    #[derive(Debug)]
    enum RMWBinOp {
        Xchg = 0,
        Add = 1,
        Sub = 2,
        And = 3,
        Nand = 4,
        Or = 5,
        Xor = 6,
        Max = 7,
        Min = 8,
        UMax = 9,
        UMin = 10,
    }

    #[derive(Debug)]
    enum StoreEventType {
        Normal,
        ReadModifyWrite,
        CompareExchange,
    }

    #[derive(Debug)]
    enum ThreadState {
        Enabled = 0,
        Blocked = 1,
        StackEmpty = 2,
        Terminated = 3, // TODO GENMC: check if any other states/info is needed
    }

    #[derive(Debug, Clone, Copy)]
    #[allow(unused)] // TODO GENMC: remove once struct is used
    struct ThreadStateInfo {
        state: ThreadState,
        is_next_instr_load: bool,
    }

    #[derive(Debug, Clone, Copy)]
    struct GenmcScalar {
        value: u64,
        extra: u64,
        is_init: bool,
    }

    /**** \/ Result & Error types \/ ****/

    #[must_use]
    #[derive(Debug)]
    struct ReadModifyWriteResult {
        old_value: GenmcScalar,
        new_value: GenmcScalar,
        error: UniquePtr<CxxString>, // TODO GENMC: pass more error info here
    }

    #[must_use]
    #[derive(Debug)]
    struct CompareExchangeResult {
        old_value: GenmcScalar,      // TODO GENMC: handle bigger values
        error: UniquePtr<CxxString>, // TODO GENMC: pass more error info here
        is_success: bool,
    }

    #[must_use]
    #[derive(Debug)]
    struct LoadResult {
        read_value: GenmcScalar,     // TODO GENMC: handle bigger values
        error: UniquePtr<CxxString>, // TODO GENMC: pass more error info here
    }

    #[must_use]
    #[derive(Debug)]
    struct StoreResult {
        error: UniquePtr<CxxString>, // TODO GENMC: pass more error info here
        isCoMaxWrite: bool,
    }

    #[must_use]
    #[derive(Debug)]
    enum VerificationError {
        VE_NonErrorBegin,
        VE_OK,
        VE_WWRace,
        VE_UnfreedMemory,
        VE_NonErrorLast,
        VE_Safety,
        VE_Recovery,
        VE_Liveness,
        VE_RaceNotAtomic,
        VE_RaceFreeMalloc,
        VE_FreeNonMalloc,
        VE_DoubleFree,
        VE_Allocation,

        VE_InvalidAccessBegin,
        VE_UninitializedMem,
        VE_AccessNonMalloc,
        VE_AccessFreed,
        VE_InvalidAccessEnd,

        VE_InvalidCreate,
        VE_InvalidJoin,
        VE_InvalidUnlock,
        VE_InvalidBInit,
        VE_InvalidRecoveryCall,
        VE_InvalidTruncate,
        VE_Annotation,
        VE_MixedSize,
        VE_LinearizabilityError,
        VE_SystemError,
    }

    /**** /\ Result & Error types /\ ****/

    // extern "Rust" {
    // }

    unsafe extern "C++" {
        include!("miri/genmc/src/Verification/MiriInterface.hpp");

        type MemOrdering;
        type RMWBinOp;
        type StoreEventType;

        // Types for Scheduling queries:
        type ThreadStateInfo;
        type ThreadState;

        // Result / Error types:
        type LoadResult;
        type StoreResult;
        type ReadModifyWriteResult;
        type CompareExchangeResult;
        type VerificationError;

        type GenmcScalar;

        // type OperatingMode; // Estimation(budget) or Verification

        type MiriGenMCShim;

        fn createGenmcHandle(config: &GenmcParams, /* OperatingMode */)
        -> UniquePtr<MiriGenMCShim>;
        fn getGlobalAllocStaticMask() -> u64;

        fn handleExecutionStart(self: Pin<&mut MiriGenMCShim>);
        fn handleExecutionEnd(
            self: Pin<&mut MiriGenMCShim>,
            thread_states: &[ThreadStateInfo],
        ) -> UniquePtr<CxxString>;

        fn handleLoad(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            memory_ordering: MemOrdering,
            old_value: GenmcScalar,
        ) -> LoadResult; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleReadModifyWrite(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            load_ordering: MemOrdering,
            store_ordering: MemOrdering,
            rmw_op: RMWBinOp,
            rhs_value: GenmcScalar,
            old_value: GenmcScalar,
        ) -> ReadModifyWriteResult; // TODO GENMC: modify this to allow for handling pointers and u128
        fn handleCompareExchange(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            expected_value: GenmcScalar,
            new_value: GenmcScalar,
            old_value: GenmcScalar,
            success_load_ordering: MemOrdering,
            success_store_ordering: MemOrdering,
            fail_load_ordering: MemOrdering,
            can_fail_spuriously: bool,
        ) -> CompareExchangeResult;
        fn handleStore(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            address: usize,
            size: usize,
            value: GenmcScalar,
            old_value: GenmcScalar,
            memory_ordering: MemOrdering,
            store_event_type: StoreEventType,
        ) -> StoreResult;
        fn handleFence(self: Pin<&mut MiriGenMCShim>, thread_id: i32, memory_ordering: MemOrdering);

        fn handleMalloc(
            self: Pin<&mut MiriGenMCShim>,
            thread_id: i32,
            size: usize,
            alignment: usize,
        ) -> usize;
        fn handleFree(self: Pin<&mut MiriGenMCShim>, thread_id: i32, address: usize, size: usize);

        fn handleThreadCreate(self: Pin<&mut MiriGenMCShim>, thread_id: i32, parent_id: i32);
        fn handleThreadJoin(self: Pin<&mut MiriGenMCShim>, thread_id: i32, child_id: i32);
        fn handleThreadFinish(self: Pin<&mut MiriGenMCShim>, thread_id: i32, ret_val: u64);

        /**** Blocking instructions ****/
        fn handleUserBlock(self: Pin<&mut MiriGenMCShim>, thread_id: i32);

        fn scheduleNext(self: Pin<&mut MiriGenMCShim>, thread_states: &[ThreadStateInfo]) -> i64;

        fn isHalting(self: &MiriGenMCShim) -> bool;
        fn isMoot(self: &MiriGenMCShim) -> bool;
        fn isExplorationDone(self: Pin<&mut MiriGenMCShim>) -> bool;

        fn printGraph(self: Pin<&mut MiriGenMCShim>);
    }
}
