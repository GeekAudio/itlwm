#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import os,subprocess,sys
os.chdir(Path(__file__).resolve().parents[2])
base=['xcrun','clang++','-fsyntax-only','-arch','x86_64','-std=c++14','-mkernel','-fno-exceptions','-fno-rtti','-nostdinc','-DKERNEL','-DKERNEL_PRIVATE','-DDRIVER_PRIVATE','-DAIRPORT','-DAIRPORT_TAHOE=1','-DIO80211FAMILY_V2','-D__IO80211_TARGET=260000','-D__PRIVATE_SPI__','-DIEEE80211_STA_ONLY','-DITLWM_VERSION="2.4.0"','-DGIT_COMMIT=""','-include','itlwm/PrivateSPI.pch','-w','-ferror-limit=25']
for include in ['MacKernelSDK/Headers','MacKernelSDK/Headers/libkern','MacKernelSDK/Headers/bsd','MacKernelSDK/Headers/iokit','MacKernelSDK/Headers/libkern/c++','include','include/Airport','itlwm','itlwm/hal_iwx','itlwm/hal_iwm','itlwm/hal_iwn','itl80211','itl80211/openbsd','itl80211/linux']:
 base+=['-I',include]
status=0
for name in (sys.argv[1:] or ["AirportItlwm/AirportItlwmV2.cpp", "AirportItlwm/AirportItlwmSkywalkInterface.cpp", "native/wcl_wire.cpp", "native/wcl_backend.cpp"]):
 r=subprocess.run(base+[name],capture_output=True,text=True)
 print(name,'PASS' if not r.returncode else 'FAIL')
 print(r.stderr[:20000]);status |= bool(r.returncode)
sys.exit(status)
