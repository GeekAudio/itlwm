import Foundation
import IOKit

// One explicit, receive-only Test086 trigger. This helper does not enqueue
// host management/data frames and does not arm the legacy ROC/TX profiles.
func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

guard CommandLine.arguments.count == 5,
      CommandLine.arguments[1] == "--expect-build",
      CommandLine.arguments[2] == "25G332-Test086",
      CommandLine.arguments[3] == "--expect-uuid",
      CommandLine.arguments[4].range(
        of: "^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$",
        options: .regularExpression) != nil,
      geteuid() == 0 else {
    fail("Usage: arm_p2p_rx149_probe --expect-build 25G332-Test086 --expect-uuid UUID")
}
let expectedUUID = CommandLine.arguments[4]

let loaded = Process()
loaded.executableURL = URL(fileURLWithPath: "/usr/bin/kmutil")
loaded.arguments = ["showloaded", "--list-only"]
let loadedOutput = Pipe()
loaded.standardOutput = loadedOutput
loaded.standardError = Pipe()
do {
    try loaded.run()
} catch {
    fail("Cannot inspect the loaded Test086 identity.")
}
let loadedBytes = loadedOutput.fileHandleForReading.readDataToEndOfFile()
loaded.waitUntilExit()
guard loaded.terminationStatus == 0,
      let loadedText = String(data: loadedBytes, encoding: .utf8),
      let loadedRegex = try? NSRegularExpression(
        pattern: "org\\.geekaudio\\.AirportItlwm \\([^)]*\\) ([0-9A-F-]{36})"),
      let loadedMatch = loadedRegex.firstMatch(
        in: loadedText, range: NSRange(loadedText.startIndex..., in: loadedText)),
      let uuidRange = Range(loadedMatch.range(at: 1), in: loadedText),
      String(loadedText[uuidRange]) == expectedUUID else {
    fail("Loaded AirportItlwm UUID does not match the armed Test086 candidate.")
}

var iterator: io_iterator_t = 0
guard IOServiceGetMatchingServices(kIOMainPortDefault,
                                  IOServiceMatching("AirportItlwm"),
                                  &iterator) == KERN_SUCCESS else {
    fail("Cannot enumerate the Intel Wi-Fi controller.")
}
var services: [io_service_t] = []
while true {
    let service = IOIteratorNext(iterator)
    if service == 0 { break }
    services.append(service)
}
IOObjectRelease(iterator)
defer { for service in services { IOObjectRelease(service) } }
guard services.count == 1 else {
    fail("Expected exactly one Intel Wi-Fi controller.")
}

let service = services[0]
func property(_ key: String) -> Any? {
    IORegistryEntryCreateCFProperty(service, key as CFString,
                                   kCFAllocatorDefault, 0)?.takeRetainedValue()
}
func number(_ key: String) -> Int? {
    (property(key) as? NSNumber)?.intValue
}
func flag(_ key: String) -> Bool? {
    property(key) as? Bool
}

guard property("NativeTestBuild") as? String == "25G332-Test086",
      number("NativePowerReady") == 1,
      flag("NativeP2PProbe") == true,
      flag("NativeP2PManualTrigger") == true,
      flag("NativeP2PRx149ObservationOnly") == true,
      flag("NativeP2PRx149DataInputExperiment") == true,
      number("NativeP2PRx149ProfileEnabled") == 1,
      number("NativeP2PRx149DataInputProfileEnabled") == 1,
      number("NativeP2PRx149Selected") == 0,
      number("NativeP2PRx149HostTxBlocked") == 1 else {
    fail("Test086 RX149 profile is not ready; no arm.")
}

let disabledFlags = [
    "NativeP2PRocProbe", "NativeP2PTxProbe",
    "NativeP2PAwdlPsfObservationOnly", "NativeP2PAwdlMifFollowup",
    "NativeP2PGp2Observation", "NativeAwdlDiscoveryExperimentEnabled",
    "NativeAwdlDiscoveryMifCurrentSlotEnabled",
    "NativeAwdlDiscoveryCurrentAwFallbackEnabled",
]
for key in disabledFlags {
    guard flag(key) == false else {
        fail("Legacy TX/discovery profile is enabled or unknown: " + key)
    }
}

let txZeroCounters = [
    "NativeP2PTxProbeEverDoorbelled",
    "NativeP2PAwdlActionFramesSubmitted",
    "NativeP2PAwdlPsfFrameSubmitted",
    "NativeP2PAwdlMifFrameSubmitted",
    "NativeP2PAwdlMifBootstrapSubmitted",
]
var before: [String: Int] = [:]
for key in txZeroCounters {
    guard let value = number(key), value == 0 else {
        fail("A required AWDL/P2P TX counter is missing or nonzero: " + key)
    }
    before[key] = value
}
guard number("NativeP2PManualArmed") == 0,
      number("NativeP2PProbeAttempted") == 0,
      number("NativeP2PProbeResourceMayExist") == 0 else {
    fail("Test086 one-shot was already attempted or has a live resource.")
}

let result = IORegistryEntrySetCFProperty(service,
    "NativeP2PRx149ArmOnce" as CFString, kCFBooleanTrue)
guard result == KERN_SUCCESS else {
    fail(String(format: "Test086 RX149 arm rejected: 0x%08x",
                UInt32(bitPattern: result)))
}
let payload: [String: Any] = [
    "schema": 1,
    "build": "25G332-Test086",
    "profile": "native_awdl_rx149_data_input_only",
    "native_data_input_experiment_enabled": true,
    "native_data_input_profile_enabled": true,
    "arm_property_accepted": true,
    "host_management_or_data_tx_blocked": true,
    "tx_control_counters_before": before,
    "mac_phy_session_protection_control_commands_may_occur": true,
    "radio_transmit_proven": false,
    "peer_receipt_proven": false,
    "airdrop_proven": false,
]
let json = try! JSONSerialization.data(withJSONObject: payload,
                                       options: [.sortedKeys])
FileHandle.standardOutput.write(json)
FileHandle.standardOutput.write(Data("\n".utf8))
