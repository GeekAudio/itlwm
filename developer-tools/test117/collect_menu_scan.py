#!/usr/bin/env python3
"""Read-only capture of Wi-Fi scan-dispatch metadata. Never starts a scan."""
import argparse, hashlib, json, os, pathlib, plistlib, re, subprocess, time

def read(argv):
    start=time.time_ns()
    p=subprocess.run(argv,capture_output=True,timeout=5,check=True)
    return p.stdout, {"argv":argv,"start_epoch_ns":start,"end_epoch_ns":time.time_ns()}

def nodes(value):
    if isinstance(value,list):
        for child in value: yield from nodes(child)
    elif isinstance(value,dict):
        yield value
        for child in value.get("IORegistryEntryChildren",[]): yield from nodes(child)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=pathlib.Path,required=True)
    parser.add_argument("--phase",required=True,choices=("idle","settings","menu"))
    parser.add_argument("--expect-build",default="25G332-Test117")
    parser.add_argument("--expect-uuid")
    args=parser.parse_args()
    raw,controller_call=read(["ioreg","-a","-r","-c","AirportItlwm"])
    controllers=[n for n in nodes(plistlib.loads(raw)) if n.get("NativeTestBuild")]
    if len(controllers)!=1: raise RuntimeError("Expected one Intel native controller")
    build=controllers[0]["NativeTestBuild"]
    if build!=args.expect_build: raise RuntimeError("Loaded build differs: "+str(build))
    raw,load_call=read(["kmutil","showloaded"])
    matching=[line for line in raw.decode().splitlines() if "org.geekaudio.AirportItlwm " in line]
    if len(matching)!=1: raise RuntimeError("Expected one loaded Intel driver")
    match=re.search(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}",matching[0])
    if not match: raise RuntimeError("Loaded UUID unavailable")
    uuid=match.group().upper()
    if args.expect_uuid and uuid!=args.expect_uuid.upper(): raise RuntimeError("Loaded UUID differs")
    raw,interface_call=read(["ioreg","-a","-r","-c","IO80211InfraInterface"])
    interfaces=[n for n in nodes(plistlib.loads(raw)) if n.get("IOObjectClass")=="AirportItlwmSkywalkInterface"]
    if len(interfaces)!=1: raise RuntimeError("Expected one native Intel interface")
    item=interfaces[0];snapshot=item.get("NativeScanDispatchTraceSnapshot")
    if not isinstance(snapshot,bytes): raise RuntimeError("Scan-dispatch snapshot is not published yet")
    scalars={k:v for k,v in item.items() if k.startswith("NativeScan") and type(v) in (int,bool)}
    raw,boot_call=read(["sysctl","-n","kern.boottime"])
    m=re.search(r"sec = (\d+)",raw.decode())
    if not m: raise RuntimeError("Boot identity unavailable")
    args.out.mkdir(parents=True,exist_ok=False,mode=0o700)
    path=args.out/"scan-dispatch-metadata.bin";path.write_bytes(snapshot);path.chmod(0o600)
    power_trace=controllers[0].get("NativePowerTrace")
    power_file=None
    if isinstance(power_trace,bytes):
        power_path=args.out/"control-call-metadata.bin"
        power_path.write_bytes(power_trace);power_path.chmod(0o600)
        power_file={"file":power_path.name,"bytes":len(power_trace),
          "sha256":hashlib.sha256(power_trace).hexdigest()}
    report={"schema":"test117-readonly-menu-capture/v1","phase_label":args.phase,
      "phase_label_is_user_supplied":True,"candidate":build,"loaded_uuid":uuid,
      "expected_uuid_checked":bool(args.expect_uuid),"boot_epoch":int(m.group(1)),
      "captured_epoch_ns":time.time_ns(),"collector_monotonic_ns":time.monotonic_ns(),
      "clock_note":"Do not derive driver wall time by adding kern.boottime; correlate clocks explicitly.",
      "scan_scalars":scalars,"snapshot_bytes":len(snapshot),"snapshot_sha256":hashlib.sha256(snapshot).hexdigest(),
      "snapshot_file":path.name,"calls":[controller_call,load_call,interface_call,boot_call],
      "control_call_metadata":power_file,
      "active_scan_requested":False,"device_state_written":False,"ssid_or_mac_collected":False}
    target=args.out/"capture-private.json";target.write_text(json.dumps(report,indent=2));target.chmod(0o600)
    print(json.dumps({"status":"captured_readonly_metadata","candidate":build,"phase":args.phase,"out":str(args.out),"bytes":len(snapshot)}))

if __name__=="__main__":
    try:main()
    except (RuntimeError,subprocess.SubprocessError,OSError,ValueError) as error:
        raise SystemExit("Capture stopped: "+str(error))
