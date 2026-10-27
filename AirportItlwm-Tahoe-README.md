# AirportItlwm Tahoe source

Corresponds to the `AirportItlwm-Tahoe.zip` Test059 binary. The release support claim is **Wi-Fi only**. P2P/AWDL code and the manual-gated diagnostics present in this source build are experimental; they do not establish AirDrop support.

## Tested support

macOS 26.7.2, build 25G332, x86_64, Intel AX201 PCI `8086:7AF0`, subsystem `8086:0074`. Other macOS builds, architectures, and adapters have not been established by this result.

## Build the matching Test059 profile

Requirements: full Xcode with `xcodebuild`, Python 3, and Acidanthera MacKernelSDK. Place the SDK at the project root. Keep `AirportItlwm/AirportItlwm-Tahoe-Info.plist` build marker `25G332-Test059` unchanged; the build script carries that marker into the output bundle. Then run the exact Test059 Debug profile:

```sh
git clone --depth 1 https://github.com/acidanthera/MacKernelSDK.git MacKernelSDK
python3 scripts/build_tahoe.py \
  --output /private/tmp/AirportItlwm-Tahoe-Test059-local.zip \
  --configuration Debug \
  --p2p-probe \
  --p2p-roc-probe \
  --p2p-tx-probe \
  --p2p-manual-trigger \
  --p2p-awdl-psf-observation-only \
  --p2p-awdl-mif-followup \
  --native-awdl-resident-data
```

The output goes only to the specified temporary path. The matching source build contains the experimental diagnostics above, but this release is supported and described for Wi-Fi only.

## OpenCore installation

Put `AirportItlwm.kext` in `EFI/OC/Kexts` and add its entry under `Kernel -> Add`. Enable only one Intel Wi-Fi driver matching this card; disable duplicate AirportItlwm/itlwm versions. The driver uses macOS system frameworks and needs no Lilu, BlueTool, helper kext, or extra boot argument. Do not block Apple's Wi-Fi framework in `Kernel -> Block`.

`itlwm/Info.plist` is the legacy itlwm network template and is not used by the Tahoe scheme. Its `WiFiConfig` is empty in this source archive.

GPL-2.0 source license: `LICENSE`. Intel firmware terms: `iwlwifi-firmware-license`.
