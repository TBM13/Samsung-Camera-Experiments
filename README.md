# Samsung Camera Experiments

This is a collection of Magisk Modules that enable **RAW Capture** on different Samsung Galaxy devices.

## How does it work?
It works by replacing the library located at <code>/vendor/lib/libexynoscamera3.so</code> with an edited one. Each device folder contains the patch applied to its libexynoscamera3 library.

## Prerequisites
- Magisk v20.4 or newer
- Android 11 vendor and kernel

## Installation
Install as a normal Magisk Module, through Magisk Manager or TWRP.

## Troubleshooting
- Camera doesn't work, shows Black Screen
  - Make sure you are using a compatible Android 11 kernel and vendor.
  - If this issue is happening after updating your firmware, please let me know.
- GCam's Night Sight takes blurred photos with pink tint
  - A workaround is to lock AF/AE before taking the photo.

## Tested Devices
**Note:** If you have any problem/weird behaviour not listed or confirmed here, please open an issue on this repo.

|Device Name|SoC|GCam Works|Module Available|Known Issues|
|:-:|:-:|:-:|:-:|:-:|
|Galaxy A12 Nacho (A12s)|Exynos 850|X|X|GCam freezes|
|Galaxy A20|Exynos 7884|✓|✓|Phone may freeze and reboot while using GCam|
|Galaxy A20e|Exynos 7884|✓|✓|Phone may freeze and reboot while using GCam (not confirmed)|
|Galaxy A30|Exynos 7904|✓|✓|Phone may freeze and reboot while using GCam (not confirmed)|
|Galaxy A30s|Exynos 7904|X|X|GCam freezes|
|Galaxy A40|Exynos 7904|Partially|X|Photos taken with the front camera are broken due to bad resolution. This is possible to fix, I need to investigate how|
|Galaxy A50s|Exynos 9611|✓|X|Photos have pink tint|
|Galaxy A51|Exynos 9611|✓|X|Photos have pink tint|
|Galaxy F62|Exynos 9825|Partially|X|Front camera doesn't work|
|Galaxy M31|Exynos 9611|✓|X|Photos have pink tint|