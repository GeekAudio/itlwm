// SPDX-License-Identifier: GPL-2.0-only
import CoreFoundation
import Foundation

/// Reads only a real CoreFoundation boolean, matching the driver's OSBoolean gate.
/// NSNumber integers, floating-point values, strings, and missing values are rejected.
public enum IORegistryBooleanFlag107 {
    public static func read(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }
}
