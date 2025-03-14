/** This file contains functionality related to handling mutexes.  */

#include "MiriInterface.hpp"

// CXX.rs generated headers:
#include "genmc-sys/src/lib.rs.h"

auto MiriGenmcShim::handle_mutex_lock(ThreadId thread_id, uint64_t address, uint64_t size)
    -> MutexLockResult {
    // TODO GENMC: this needs to be identical even in multithreading
    ModuleID::ID annot_id;
    if (annotation_id.contains(address)) {
        annot_id = annotation_id.at(address);
    } else {
        annot_id = annotation_id_counter++;
        annotation_id.insert(std::make_pair(address, annot_id));
    }
    const auto aSize = ASize(size);
    auto annot = std::move(Annotation(
        AssumeType::Spinloop,
        Annotation::ExprVP(NeExpr<AnnotID>::create(
                               RegisterExpr<AnnotID>::create(aSize.getBits(), annot_id),
                               ConcreteExpr<AnnotID>::create(aSize.getBits(), SVal(1))
        )
                               .release())
    ));

    // Mutex starts out unlocked, so we always say the previous value is "unlocked".
    auto old_val_setter = [this](SAddr addr) {
        this->handle_old_val(addr, GenmcScalarExt::from_sval(SVal(0)));
    };
    const auto load_ret = handle_load_reset_if_none<EventLabel::EventLabelKind::LockCasRead>(
        old_val_setter,
        thread_id,
        address,
        size,
        annot,
        EventDeps()
    );
    if (const auto* err = std::get_if<VerificationError>(&load_ret))
        return MutexLockResultExt::from_error(format_error(*err));

    const auto* ret_val = std::get_if<SVal>(&load_ret);
    if (!ret_val) {
        if (std::holds_alternative<Reset>(load_ret)) {
            // TODO TODO GENMC: what did I mean with this comment?
            // TODO GENMC: is_read_opt == Mutex is acquired
            // None	--> Someone else has lock, this thread will be rescheduled later
            // (currently block) 0	--> Got the lock 1 	--> Someone else has lock,
            // this thread will not be rescheduled later (block on Miri side)
            return MutexLockResultExt::ok(false);
        }
        ERROR("Unimplemented: mutex lock returned unexpected result.");
    }

    const bool is_lock_acquired = *ret_val == SVal(0);
    if (is_lock_acquired) {
        const auto store_ret = GenMCDriver::handleStore<EventLabel::EventLabelKind::LockCasWrite>(
            old_val_setter,
            inc_pos(thread_id),
            address,
            size,
            EventDeps()
        );

        if (const auto* err = std::get_if<VerificationError>(&store_ret))
            return MutexLockResultExt::from_error(format_error(*err));
        ERROR_ON(
            !std::holds_alternative<std::monostate>(store_ret),
            "Unsupported: mutex lock store returned unexpected result."
        );
    } else {
        ERROR_ON(*ret_val != SVal(1), "Mutex read value was neither 0 nor 1");
        GenMCDriver::handleAssume(inc_pos(thread_id), AssumeType::Spinloop);
    }

    return MutexLockResultExt::ok(is_lock_acquired);
}

auto MiriGenmcShim::handle_mutex_try_lock(ThreadId thread_id, uint64_t address, uint64_t size)
    -> MutexLockResult {
    const auto addr = SAddr(address);
    const auto aSize = ASize(size);

    auto& currPos = threads_action_[thread_id].event;
    // Mutex starts out unlocked, so we always say the previous value is "unlocked".
    auto old_val_setter = [this](SAddr addr) {
        this->handle_old_val(addr, GenmcScalarExt::from_sval(SVal(0)));
    };
    const auto load_ret = GenMCDriver::handleLoad<EventLabel::EventLabelKind::TrylockCasRead>(
        old_val_setter,
        ++currPos,
        addr,
        aSize
    );
    if (const auto* err = std::get_if<VerificationError>(&load_ret))
        return MutexLockResultExt::from_error(format_error(*err));
    const auto* ret_val = std::get_if<SVal>(&load_ret);
    if (nullptr == ret_val) {
        ERROR("Unimplemented: mutex trylock load returned unexpected result.");
    }

    const bool is_lock_acquired = *ret_val == SVal(0);
    if (!is_lock_acquired) {
        ERROR_ON(*ret_val != SVal(1), "Mutex read value was neither 0 nor 1");
        return MutexLockResultExt::ok(false); /* Lock already held. */
    }

    const auto store_ret = GenMCDriver::handleStore<EventLabel::EventLabelKind::TrylockCasWrite>(
        old_val_setter,
        ++currPos,
        addr,
        aSize
    );
    if (const auto* err = std::get_if<VerificationError>(&store_ret))
        return MutexLockResultExt::from_error(format_error(*err));
    if (!std::holds_alternative<std::monostate>(store_ret))
        ERROR("Unimplemented: mutex trylock store returned unexpected result.");
    // No error or unexpected result: lock is acquired.
    return MutexLockResultExt::ok(true);
}

auto MiriGenmcShim::handle_mutex_unlock(ThreadId thread_id, uint64_t address, uint64_t size)
    -> StoreResult {
    const auto pos = inc_pos(thread_id);
    const auto addr = SAddr(address);
    const auto aSize = ASize(size);

    const auto old_val_setter = [this](SAddr addr) {
        // TODO GENMC(HACK): is this the best way to do it?
        this->handle_old_val(addr, GenmcScalarExt::uninit());
    };
    const auto ret = GenMCDriver::handleStore<EventLabel::EventLabelKind::UnlockWrite>(
        old_val_setter,
        pos,
        MemOrdering::Release,
        addr,
        aSize,
        AType::Signed,
        SVal(0),
        EventDeps()
    );
    if (const auto* err = std::get_if<VerificationError>(&ret))
        return StoreResultExt::from_error(format_error(*err));
    if (!std::holds_alternative<std::monostate>(ret))
        ERROR("Unimplemented: mutex unlock store returned unexpected result.");

    // TODO GENMC: Mixed-accesses (`false` should be fine, since we never want to update Miri's
    // memory for mutexes anyway)
    // const bool is_coherence_order_maximal_write = false;
    const auto& g = getExec().getGraph();
    const bool is_coherence_order_maximal_write = g.co_max(addr)->getPos() == pos;
    return StoreResultExt::ok(is_coherence_order_maximal_write);
}
