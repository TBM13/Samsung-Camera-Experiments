# Samsung Camera Experiments
This repository contains a Python script that patches the `libexynoscamera3.so` camera lib of Exynos devices to enable different features.

Requires Python 3.10 or higher. Make sure to install the dependencies too (`pip install -r requirements.txt`).

### libexynoscamera3.so
Usually located at `/vendor/lib/libexynoscamera3.so` and/or `/vendor/lib64/libexynoscamera3.so`. Some devices have both but only use one, it's suggested to patch both in that case.

> Some newer Exynos devices like the Galaxy A55 don't have this library. Those aren't supported by this script at the moment.

If the script fails to patch your lib, open an issue with your device model, Android version and attach the lib.

## Features
The following camera features can be enabled or modified. \
Keep in mind that enabling them **doesn't mean they will work as expected** nor that something will change. It's up to you to test the modifications.

#### Hardware Level
* 0 ([LIMITED](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED))
* 1 ([FULL](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_FULL))
* 2 ([LEGACY](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY))
* 3 ([LEVEL_3](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_3))
    * The lib doesn't seem to expect this level, so it will probably behave like LIMITED
* 4 ([EXTERNAL](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL))

#### Capabilities
* These three are automatically enabled by the library if the Hardware Level is set to FULL:
    * [MANUAL_SENSOR](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR) and [READ_SENSOR_SETTINGS](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_READ_SENSOR_SETTINGS) (2)
    * [MANUAL_POST_PROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MANUAL_POST_PROCESSING) (4)
    * [BURST_CAPTURE](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_BURST_CAPTURE) (8)
* If this is disabled, GCam doesn't work and shows a black screen in photo mode. Enabling it is enough to make it work on some devices:
    * [RAW](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_RAW) (16)
* Others
    * [ZSL (Zero Shutter Lag) and Private Reprocessing](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING) (32)
        * This causes issues with some apps on the A20, A20e and A30 since they don't support ZSL. You can use [this app](https://github.com/sonyxperiadev/CameraTest) to check whether it works on your device.
    * [YUV Reprocessing](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING) (64)
    * [Depth Output](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_DEPTH_OUTPUT) (128)
    * [Constrained High Speed Video](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_CONSTRAINED_HIGH_SPEED_VIDEO) (256)
    * [Motion Tracking](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MOTION_TRACKING) (512)
    * [Logical Multi Camera](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA) (1024)
    * [Secure Image Data](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_SECURE_IMAGE_DATA) (2048)

## Usage
```
usage: patch_lib.py [-h] [-hw {0,1,2,3,4}]
                    [-cap {2,4,8,16,32,64,128,256,512,1024,2048} [{2,4,8,16,32,64,128,256,512,1024,2048} ...]]
                    [--skip-depth] [--model MODEL] [--android-version ANDROID_VERSION] [--version VERSION]
                    libs [libs ...]

positional arguments:
  libs                  Path(s) of the libexynoscamera3.so lib(s) to patch

options:
  -h, --help            show this help message and exit

Lib Modifications:
  -hw {0,1,2,3,4}       The hardware level that will be set
  -cap {2,4,8,16,32,64,128,256,512,1024,2048} [{2,4,8,16,32,64,128,256,512,1024,2048} ...]
                        The capabilities that will be enabled, separated by spaces
  --skip-depth          Skips modifications on cameras with the "Depth Output" capability. Recommended if your device
                        has a depth camera since the lib can crash if you enable RAW on them, for example.

Magisk Module:
  If all these settings are provided, a Magisk module with both patched libs will be created

  --model MODEL         The device model (e.g. Galaxy A20)
  --android-version ANDROID_VERSION
                        The Android version (e.g. 11)
  --version VERSION     The module version (e.g. 1)
```

### Example
`python3 ./patch_lib.py libexynoscamera3.so -cap 16` will enable the RAW capability. This should be enough to make GCam work.

`python3 ./patch_lib.py libexynoscamera3.so -hw 1 -cap 16 32` will enable the RAW & ZSL capabilities and set the hardware level to FULL.

## Troubleshooting
If Android doesn't show show any cameras, this means the camera lib crashed:
  * Can happen if your device has a depth camera, try patching with `--skip-depth`.
  * Someone [has reported](https://github.com/TBM13/Samsung-Camera-Experiments/issues/7#issuecomment-1949522917) that they had to move the lib to `/vendor/lib64/hw/`. Try it if you see something like `dlopen failed: library "libexynoscamera3.so" not found` in the logcat.

## GCam tests after enabling the RAW capability
**Note:** If you test this on a device not listed here or you have any issue/weird behaviour, please let me know.

All tests were done using [BSG's GCam 8.1](https://www.celsoazevedo.com/files/android/google-camera/dev-bsg/f/dl88/), as it seems to be the most stable one on Exynos devices.
|Device Name|SoC|GCam Works?|Details / Issues|
|:-:|:--:|:-:|:-:|
|Galaxy A12 Nacho (A12s)|Exynos 850|X|<table><th>Android 11</th><th>Android 13</th><tr><td>Freezes</td><td>Lags/freezes. Back cam doesn't save pics and front cam sometimes does</td></tr></table>|
|Galaxy A20|Exynos 7884|✓|<table><th>Android 10</th><th>Android 11</th><tr><td>Freezes</td><td>May freeze & reboot while using GCam</td></tr></table>|
|Galaxy A20e|Exynos 7884|✓|<table><th>Android 10</th><th>Android 11</th><tr><td>Freezes</td><td>May freeze & reboot while using GCam</td></tr></table>|
|Galaxy A30|Exynos 7904|✓|<table><th>Android 10</th><th>Android 11</th><tr><td>Freezes</td><td>May freeze & reboot while using GCam</td></tr></table>|
|Galaxy A30s|Exynos 7904|?|<table><th>Android 10</th><th>Android 11</th><tr><td>Freezes</td><td>Untested</td></tr></table>|
|Galaxy A40|Exynos 7904|Partially|<table><th>Android 11</th><tr><td>Front cam pics unusable due to bad resolution. It's possible to fix, need to investigate how</td></tr></table>|
|Galaxy A50s|Exynos 9611|Partially|<table><th>Android 11</th><tr><td>Photos have pink tint. Changing black level doesn't help</td></tr></table>|
|Galaxy A51|Exynos 9611|Partially|<table><th>Android 11</th><tr><td>Photos have pink tint. Changing black level doesn't help</td></tr></table>|
|Galaxy F62|Exynos 9825|Partially|<table><th>Android 11</th><tr><td>Issues with the front camera</td></tr></table>|
|Galaxy M31|Exynos 9611|Partially|<table><th>Android 11</th><tr><td>Photos have pink tint. Changing black level doesn't help</td></tr></table>|
|Galaxy M31s|Exynos 9611|Partially|<table><th>Android 12</th><tr><td>Photos have pink tint. Changing black level doesn't help</td></tr></table>|
