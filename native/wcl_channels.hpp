// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace NativeWifi {
// Actual Apple25G241 GET449: 400 eight-byte channel records, then a u16
// count and four ancillary bytes. There is no leading version field.
// This writer exposes only real 2.4/5GHz 20MHz entries. Unknown ancillary
// fields and wide/6GHz/power capabilities remain zero.
class ChannelInfoWriter {
public:
    static constexpr size_t Size = 0xc86;
    static constexpr unsigned Capacity = 400;
    enum class AppendResult { Added, Skipped, Full, Invalid };

    ChannelInfoWriter(void *output, size_t bytes)
        : output_(bytes == Size ? static_cast<uint8_t *>(output) : nullptr) {
        if (output_)
            for (size_t i = 0; i < Size; ++i) output_[i] = 0;
    }

    bool valid() const { return output_ != nullptr; }
    AppendResult append(uint16_t channel, uint16_t frequency,
                        uint32_t flags, bool available) {
        if (!output_ || finished_) return AppendResult::Invalid;
        if (!available || !frequency || !flags) return AppendResult::Skipped;

        // The values below are the official upstream net80211 attributes.
        constexpr uint32_t Band2GHz = 0x0080, Band5GHz = 0x0100;
        constexpr uint32_t Passive = 0x0200, DFS = 0x00080000;
        const uint32_t band = flags & (Band2GHz | Band5GHz);
        uint16_t spec = 0;
        if (band == Band2GHz && channel >= 1 && channel <= 14 &&
            frequency == (channel == 14 ? 2484 : 2407 + channel * 5))
            spec = uint16_t(0x1000 | channel);
        else if (band == Band5GHz && channel >= 15 && channel <= 196 &&
                 frequency == 5000 + channel * 5)
            spec = uint16_t(0xd000 | channel);
        else return AppendResult::Invalid;

        if (count_ == Capacity) return AppendResult::Full;
        uint8_t *entry = output_ + count_ * 8;
        entry[0] = uint8_t(spec); entry[1] = uint8_t(spec >> 8);
        entry[6] = uint8_t(channel); // Actual producer's primary channel.
        entry[7] = uint8_t((flags & DFS ? 2 : 0) |
                           (flags & Passive ? 4 : 0));
        ++count_;
        return AppendResult::Added;
    }

    uint16_t finish() {
        if (!output_) return 0;
        finished_ = true;
        output_[0xc80] = uint8_t(count_);
        output_[0xc81] = uint8_t(count_ >> 8);
        return count_;
    }

private:
    uint8_t *output_ {nullptr};
    uint16_t count_ {0};
    bool finished_ {false};
};
}
