// Host-test shim only. Never include in a kernel or Xcode target.
#pragma once
#include <cassert>
#include <string>

class OSObject {
public:
    static unsigned liveObjects, retains, releases;
    OSObject() { ++liveObjects; }
    virtual ~OSObject() { assert(references_ == 0); --liveObjects; }
    void retain() { assert(references_); ++references_; ++retains; }
    void release() { assert(references_); ++releases; if (!--references_) delete this; }
    unsigned references() const { return references_; }
private:
    unsigned references_ {1};
};

class OSString final : public OSObject {
public:
    explicit OSString(const char *text) : value_(text) {}
    bool isEqualTo(const char *text) const { return value_ == text; }
    unsigned getLength() const { return unsigned(value_.size()); }
    const char *getCStringNoCopy() const { return value_.c_str(); }
private:
    std::string value_;
};

#define OSDynamicCast(type, value) dynamic_cast<type *>(value)
