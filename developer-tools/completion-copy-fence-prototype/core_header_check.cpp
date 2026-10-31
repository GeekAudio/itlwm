#include "completion_copy_fence.hpp"

class InjectedLock {
public:
    InjectedLock() : held_(false) {}
    void lock() { held_ = true; }
    bool tryLock()
    {
        if (held_)
            return false;
        held_ = true;
        return true;
    }
    void unlock() { held_ = false; }

private:
    bool held_;
};

extern "C" int coreHeaderCheck()
{
    using namespace Test093CompletionCopyFence;
    InjectedLock lock;
    Registry<InjectedLock, 2> registry(lock);
    uint8_t mapping[8] = {0};
    char identity = 0;
    const ReserveResult reserved = registry.reserve(&identity);
    if (reserved.status != ReserveStatus::kReserved)
        return 1;
    if (registry.publish(reserved.handle, kObservedFamily, mapping,
                         sizeof(mapping)) != PublishStatus::kPublished)
        return 2;
    const CopyResult copy = registry.tryCopy(reserved.handle, 0);
    if (copy.status != CopyStatus::kCopied)
        return 3;
    return registry.unpublish(reserved.handle) ==
                   RetireStatus::kPublishedViewRetired
               ? 0
               : 4;
}
