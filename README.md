# Samsung Camera Experiments

This is a collection of Magisk Modules that enable **RAW Capture** on different Samsung Galaxy devices.

## How does it work?
It works by replacing the library located at <code>/vendor/lib/libexynoscamera3.so</code> with an edited one. Each device folder contains the patch applied to its libexynoscamera3 library.

## Prerequisites
- Magisk v20.4 or newer
- Android 11 vendor and kernel (Eureka Kernel isn't compatible, take a look at [this for more info](https://forum.xda-developers.com/t/magisk-module-enable-raw-capture.4350059/post-86110713))

## Installation
Install as a normal Magisk Module, through Magisk Manager or TWRP.

## Troubleshooting
- Photos have a pink tint
	- This is a known issue in the Galaxy A51 and Galaxy M31. No solution has been found yet.
- Camera doesn't work, shows Black Screen
  - Make sure you are using a compatible Android 11 kernel and vendor.