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
- Photos have a pink tint
	- This is a known issue in the Galaxy A51 and Galaxy M31. No solution has been found yet.
- GCam's Night Sight takes blurred photos with pink tint
  - A workaround is to lock AF/AE before taking the photo.