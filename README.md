# Samsung Camera Experiments
## `patch_lib.py`
A Python script that automatically patches the 32-bit and 64-bit camera libraries of Exynos devices to enable different features. \
Requires Python 3.10 or higher. May not work with Python 3.12+ since the `capstone` module requires `distutils` which was deprecated on that version.

The libraries are located at `/vendor/lib/libexynoscamera3.so` and `/vendor/lib64/libexynoscamera3.so`. \
If the script fails to patch yours, open an issue and attach them, specifying your device model and Android version.

> [!NOTE]  
> - The camera lib of old devices (those that launched with Android 8.1 or lower) seems to be very different so they may never be supported.

### Features
The following camera features can be enabled/modified:
> [!WARNING]  
> - Enabling a capability or feature doesn't mean it will work as expected. It's up to you to test them.

#### Capabilities
* These three are automatically enabled by the library if the Hardware Level is set to FULL:
    * [MANUAL_SENSOR](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR) and [READ_SENSOR_SETTINGS](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_READ_SENSOR_SETTINGS) (2)
    * [MANUAL_POST_PROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MANUAL_POST_PROCESSING) (4)
    * [BURST_CAPTURE](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_BURST_CAPTURE) (8)
* If this is disabled, GCam doesn't work and shows a black screen in photo mode. Enabling it is enough to make it work on some devices
    * [RAW](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_RAW) (16)
* Others
    * [ZSL (Zero Shutter Lag) and Private Reprocessing](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING) (32)
        * This one causes issues on the A20, A20e and A30 since ZSL doesn't work in them. You can use [this app](https://github.com/sonyxperiadev/CameraTest) to check if it works on your device.
    * [YUV Reprocessing](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING) (64)
    * [Depth Output](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_DEPTH_OUTPUT) (128)
    * [Constrained High Speed Video](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_CONSTRAINED_HIGH_SPEED_VIDEO) (256)
    * [Motion Tracking](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MOTION_TRACKING) (512)
    * [Logical Multi Camera](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA) (1024)
    * [Secure Image Data](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_SECURE_IMAGE_DATA) (2048)

#### Hardware Level
* 0 ([LIMITED](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED))
* 1 ([FULL](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_FULL))
* 2 ([LEGACY](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY))
* 3 ([LEVEL_3](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_3))
    * The lib doesn't seem to expect this level, so it will probably behave like LIMITED
* 4 ([EXTERNAL](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL))

### Usage
```
usage: patch_lib.py [-h] [-hw {0,1,2,3,4}]
                    [-cap {2,4,8,16,32,64,128,256,512,1024,2048} [{2,4,8,16,32,64,128,256,512,1024,2048} ...]]
                    [--model MODEL] [--android-version ANDROID_VERSION] [--version VERSION]
                    camera_lib camera_lib_64

positional arguments:
  camera_lib            Path of the 32-bit libexynoscamera3.so
  camera_lib_64         Path of the 64-bit libexynoscamera3.so

options:
  -h, --help            show this help message and exit

Lib Modifications:
  -hw {0,1,2,3,4}       The hardware level that will be set
  -cap {2,4,8,16,32,64,128,256,512,1024,2048} [{2,4,8,16,32,64,128,256,512,1024,2048} ...]
                        The capabilities that will be enabled, separated by spaces

Magisk Module:
  If all these settings are provided, a Magisk module with both patched libs will be created

  --model MODEL         The device model (e.g. Galaxy A20)
  --android-version ANDROID_VERSION
                        The Android version (e.g. 11)
  --version VERSION     The module version (e.g. 1)
```

### Example
`python3 ./patch_lib.py libexynoscamera3.so libexynoscamera3_64.so -cap 16` will enable the RAW capability. This should be enough to make GCam work.

`python3 ./patch_lib.py libexynoscamera3.so libexynoscamera3_64.so -hw 1 -cap 16` will enable the RAW capability and set the hardware level to FULL.

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