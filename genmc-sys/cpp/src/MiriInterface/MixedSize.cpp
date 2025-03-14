/** This file contains functionality related to handling mutexes.  */

#include "MiriInterface.hpp"

// CXX.rs generated headers:
#include "genmc-sys/src/lib.rs.h"

// FIXME(genmc): remove once proper mixed atomic-non-atomic access support is implemented
void MiriGenmcShim::handle_old_val(const SAddr addr, GenmcScalar value) {
    LOG(VerbosityLevel::Tip) << "handle_old_val: " << addr << ", " << value.value << ", "
                             << value.extra << ", " << value.is_init << "\n";

    // TODO GENMC(CLEANUP): Pass this as a parameter:
    auto& g = getExec().getGraph();
    auto* coLab = g.co_max(addr);
    if (auto* wLab = llvm::dyn_cast<WriteLabel>(coLab)) {
        LOG(VerbosityLevel::Tip) << "handle_old_val: got WriteLabel, atomic: "
                                 << !wLab->isNotAtomic() << "\n";
        if (!value.is_init)
            LOG(VerbosityLevel::Tip) << "WARNING: TODO GENMC: handle_old_val tried to "
                                        "overwrite value of NA "
                                        "reads-from label, but old value is `uninit`\n";
        else if (wLab->isNotAtomic())
            wLab->setVal(GenmcScalarExt::to_sval(value));
    } else if (const auto* wLab = llvm::dyn_cast<InitLabel>(coLab)) {
        if (value.is_init) {
            auto result = init_vals_.insert(std::make_pair(addr, value));
            LOG(VerbosityLevel::Tip)
                << "handle_old_val: got InitLabel, insertion result: " << result.first->second.value
                << ", " << result.second << "\n";
            BUG_ON(
                result.second && ((*result.first).second.is_init != value.is_init ||
                                  ((*result.first).second.value != value.value &&
                                   (*result.first).second.extra != value.extra))
            ); /* Attempt to replace initial value */
        } else {
            LOG(VerbosityLevel::Tip) << "WARNING: TODO GENMC: handle_old_val tried set initial "
                                        "value, but old "
                                        "value is `uninit`\n";
        }
    } else {
        BUG(); /* Invalid label */
    }
    // either initLabel	==> update initValGetter
    // or WriteLabel    ==> Update its value in place (only if non-atomic)
}
