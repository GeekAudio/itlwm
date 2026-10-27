// Host-test shim only: retained property snapshots model the actual API contract.
#pragma once
#include <libkern/c++/OSString.h>
#include <map>
#include <string>

class IORegistryEntry final : public OSObject {
public:
    static IORegistryEntry *root;
    static IORegistryEntry *getRegistryRoot() { return root; }
    ~IORegistryEntry() override {
        for (auto &entry : properties_) entry.second->release();
    }
    OSObject *copyProperty(const char *key) {
        auto found = properties_.find(key);
        if (found == properties_.end()) return nullptr;
        found->second->retain();
        return found->second;
    }
    void setProperty(const char *key, OSObject *value) {
        if (value) value->retain();
        auto found = properties_.find(key);
        if (found != properties_.end()) {
            found->second->release();
            properties_.erase(found);
        }
        if (value) properties_.emplace(key, value);
    }
    bool propertyReferencesBalanced() const {
        for (const auto &entry : properties_)
            if (entry.second->references() != 1) return false;
        return references() == 1;
    }
private:
    std::map<std::string, OSObject *> properties_;
};
