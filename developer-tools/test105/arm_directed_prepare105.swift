import Foundation
import IOKit
import Darwin

// Default mode validates arguments only. No socket, IOKit lookup, or RF action.
func fail(_ text: String) -> Never {
    FileHandle.standardError.write(Data((text + "\n").utf8)); exit(1)
}
let args = Array(CommandLine.arguments.dropFirst())
let run = args.last == "--run"
let values = run ? Array(args.dropLast()) : args
guard values.count == 8, values[0] == "--expect-build", values[1] == "25G332-Test105",
      values[2] == "--expect-uuid", values[4] == "--peer-mac",
      values[6] == "--run-token" else {
    fail("Usage: arm_directed_prepare105 --expect-build 25G332-Test105 --expect-uuid UUID --peer-mac MAC --run-token 32hex [--run]")
}
func matches(_ value: String, _ regex: String) -> Bool {
    value.range(of: regex, options: .regularExpression) != nil
}
guard matches(values[3], "^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$"),
      matches(values[5], "^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"),
      matches(values[7], "^[0-9a-f]{32}$"), values[7].contains(where: { $0 != "0" }) else {
    fail("Invalid candidate UUID, peer address, or run token.")
}
let peer = values[5].split(separator: ":").map { UInt8($0, radix: 16)! }
guard peer.count == 6, peer[0] & 1 == 0, peer.contains(where: { $0 != 0 }) else {
    fail("Peer must be a nonzero unicast address.")
}
func emit(_ object: [String: Any]) {
    let bytes = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    FileHandle.standardOutput.write(bytes); FileHandle.standardOutput.write(Data("\n".utf8))
}
if !run {
    emit(["schema": 1, "mode": "plan", "build": values[1],
          "hardware_action": false, "arm_accepted": false,
          "resource_prepare_only": true, "data_transmit_enabled": false])
    exit(0)
}
guard geteuid() == 0 else { fail("Explicit run requires administrator privileges.") }

// Bound identity inspection without skipping the loaded Mach-O UUID check.
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/kmutil")
process.arguments = ["showloaded", "--list-only", "--bundle-identifier", "org.geekaudio.AirportItlwm"]
let output = Pipe()
process.standardOutput = output
process.standardError = FileHandle.nullDevice
let finished = DispatchSemaphore(value: 0)
process.terminationHandler = { _ in finished.signal() }
do { try process.run() } catch { fail("Cannot inspect loaded driver identity.") }
if finished.wait(timeout: .now() + 30) != .success {
    if process.isRunning { process.terminate() }
    if finished.wait(timeout: .now() + 1) != .success && process.isRunning {
        kill(process.processIdentifier, SIGKILL)
    }
    fail("Loaded driver identity inspection timed out; no arm.")
}
let loaded = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
let rows = loaded.split(separator: "\n").filter { $0.contains("org.geekaudio.AirportItlwm ") }
guard process.terminationStatus == 0, rows.count == 1,
      let regex = try? NSRegularExpression(pattern: "org\\.geekaudio\\.AirportItlwm \\([^)]*\\) ([0-9A-F-]{36})"),
      let match = regex.firstMatch(in: String(rows[0]), range: NSRange(String(rows[0]).startIndex..., in: String(rows[0]))),
      let range = Range(match.range(at: 1), in: String(rows[0])),
      String(String(rows[0])[range]) == values[3] else {
    fail("Loaded UUID does not match this candidate; no arm.")
}
var iterator: io_iterator_t = 0
guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AirportItlwm"), &iterator) == KERN_SUCCESS else {
    fail("Cannot find Intel controller; no arm.")
}
var services: [io_service_t] = []
while true {
    let item = IOIteratorNext(iterator)
    if item == 0 { break }
    services.append(item)
}
IOObjectRelease(iterator)
defer { services.forEach { IOObjectRelease($0) } }
guard services.count == 1 else { fail("Expected exactly one Intel controller; no arm.") }
let service = services[0]
func property(_ key: String) -> Any? {
    IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue()
}
guard property("NativeTestBuild") as? String == values[1],
      (property("NativePowerReady") as? NSNumber)?.uint32Value == 1,
      property("NativeP2PManualTrigger") as? Bool == true,
      (property("NativeP2PDirectedPrepareEnabled") as? NSNumber)?.uint32Value == 1 else {
    fail("Directed prepare profile is not ready; no arm.")
}
// Kernel main-gate validation owns all epochs, resource identity and mutual
// exclusion. The token is correlation data, never hardware authorization.
let request: [String: Any] = [
    "NativeP2PDirectedPrepareOnce": true,
    "NativeP2PDirectedPreparePeerMAC": Data(peer),
    "NativeP2PDirectedPrepareRunToken": values[7],
]
let status = IORegistryEntrySetCFProperties(service, request as CFDictionary)
guard status == KERN_SUCCESS else {
    fail(String(format: "Directed prepare request did not return a confirmed receipt: 0x%08x; kernel state may have changed, do not retry automatically.", UInt32(bitPattern: status)))
}
guard property("NativeP2PDirectedPrepareAcceptedRunToken") as? String == values[7] else {
    fail("Arm returned success but token readback is missing; do not retry automatically.")
}
emit(["schema": 1, "mode": "explicit_run", "build": values[1],
      "loaded_uuid_matches": true, "arm_accepted": true,
      "resource_prepare_only": true, "resource_ack_proven": false,
      "data_transmit_enabled": false, "peer_receipt_proven": false,
      "airdrop_proven": false])
