// SPDX-License-Identifier: GPL-2.0-only
import CoreFoundation
import Foundation
import IORegistryBooleanFlag107

@main
struct Test111IORegistryBooleanFlagTests {
    static func main() {
        precondition(IORegistryBooleanFlag107.read(kCFBooleanTrue) == true,
                     "CFBoolean true must pass")
        precondition(IORegistryBooleanFlag107.read(kCFBooleanFalse) == false,
                     "CFBoolean false must remain distinguishable")
        precondition(IORegistryBooleanFlag107.read(NSNumber(value: 1)) == nil,
                     "CFNumber integer 1 must not masquerade as a boolean")
        precondition(IORegistryBooleanFlag107.read(NSNumber(value: 0)) == nil,
                     "CFNumber integer 0 must not masquerade as a boolean")
        precondition(IORegistryBooleanFlag107.read(NSNumber(value: 1.0)) == nil,
                     "CFNumber floating point must be rejected")
        precondition(IORegistryBooleanFlag107.read("true") == nil,
                     "String boolean must be rejected")
        precondition(IORegistryBooleanFlag107.read(nil) == nil,
                     "Missing value must be rejected")
        print("Test111 strict IORegistry CFBoolean boundaries passed")
    }
}
