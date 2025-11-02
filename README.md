# Samsung Camera Experiments
This repository contains two Python scripts that can patch the camera lib of Exynos devices and enable/modify different features:
* `patch_libexynoscamera3.py` is for older Exynos devices that use the **libexynoscamera3.so** lib.
* `patch_s5e.py` is for newer Exynos devices that use the **camera.s5eXXXX.so** lib.

Both scripts require Python 3.10 or higher. \
Make sure to clone/download the whole repository (and not just the `patch_*.py` script) & install the dependencies too (`pip install -r requirements.txt`).

#### libexynoscamera3.so
Usually located at `/vendor/lib/libexynoscamera3.so` and/or `/vendor/lib64/libexynoscamera3.so`. \
Some devices have both but only use one; it's suggested to patch both in that case.

#### camera.s5eXXXX.so
Located at `/vendor/lib64/hw/camera.s5eXXXX.so`. \
Its name may vary depending your device, for example the Galaxy A54's lib is named `camera.s5e8835.so`.

If the script fails to patch your lib, open an issue with your device model, Android version and attach the lib.

## Usage, features & troubleshooting
Enabling or modifying something **doesn't mean it will work as expected** (it may even not do anything at all). It's up to you to test everything.

<details>
<summary><b>libexynoscamera3.so</b></summary>

```
usage: patch_libexynoscamera3.py [-h] [--hardware-level HARDWARE_LEVEL] [--enable-cap CAPABILITY [CAPABILITY ...]]
                                 [--disable-cap CAPABILITY [CAPABILITY ...]] [--skip-depth] [--model MODEL] [--android-version ANDROID_VERSION]
                                 [--version VERSION]
                                 libs [libs ...]

positional arguments:
  libs                  Path(s) of the lib(s) that will be patched

options:
  -h, --help            show this help message and exit

Lib Modifications:
  --hardware-level HARDWARE_LEVEL
                        The hardware level that will be set
  --enable-cap CAPABILITY [CAPABILITY ...]
                        The capabilities that will be enabled, separated by space.
  --disable-cap CAPABILITY [CAPABILITY ...]
                        The capabilities that will be disabled, separated by space.
  --skip-depth          Skips modifications on cameras with the "Depth Output" capability. Recommended if your device has a depth camera.

Magisk Module:
  If all the following args are provided, a Magisk module with the patched lib(s) will be created

  --model MODEL         The device the lib comes from (e.g. Galaxy A20)
  --android-version ANDROID_VERSION
                        The Android version the lib comes from (e.g. 11)
  --version VERSION     The module version (e.g. 1)
```

#### Hardware Level
* [LIMITED](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED) - default level on pretty much every lib
* [FULL](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_FULL) - enables some capabilities, more info below
* [LEVEL_3](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_3) - the lib doesn't seem to expect this level, it'll probably behave like LIMITED
* These are worse than LIMITED so you shouldn't use them:
   * [LEGACY](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY)
   * [EXTERNAL](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL)

Example: \
`python3 ./patch_lib.py libexynoscamera3.so --hardware-level FULL` will set the Hardware Level to FULL on all cameras.

#### Capabilities
* These three are automatically enabled by the library if the Hardware Level is set to FULL:
    * **ManualSensor_ReadSensorSettings** ([MANUAL_SENSOR](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR) and [READ_SENSOR_SETTINGS](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_READ_SENSOR_SETTINGS))
    * **ManualPostProcessing** ([MANUAL_POST_PROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MANUAL_POST_PROCESSING))
    * **BurstCapture** ([BURST_CAPTURE](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_BURST_CAPTURE))
* If this one is disabled, GCam doesn't work and shows a black screen in photo mode. Enabling it is enough to make it work on some devices:
    * [**RAW**](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_RAW)
* Others
    * **ZSL_PrivateReprocessing** (Zero Shutter Lag and [PRIVATE_REPROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING))
        * Enabling this causes issues with some apps on the A20, A20e and A30 since these devices don't support ZSL. You can use [this app](https://github.com/sonyxperiadev/CameraTest) to test ZSL.
    * **YUVReprocessing** ([YUV_REPROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING))
    * **DepthOutput** ([DEPTH_OUTPUT](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_DEPTH_OUTPUT))
    * **ConstrainedHighSpeedVideo** ([CONSTRAINED_HIGH_SPEED_VIDEO](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_CONSTRAINED_HIGH_SPEED_VIDEO))
    * **MotionTracking** ([MOTION_TRACKING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MOTION_TRACKING))
    * **LogicalMultiCamera** ([LOGICAL_MULTI_CAMERA](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA))
    * **SecureImageData** ([SECURE_IMAGE_DATA](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_SECURE_IMAGE_DATA))

Examples: \
`python3 ./patch_lib.py libexynoscamera3.so --enable-cap RAW` will enable the RAW capability. \
`python3 ./patch_lib.py libexynoscamera3.so --enable-cap RAW YUVReprocessing` will enable the RAW and YUV_REPROCESSING capabilities. \
`python3 ./patch_lib.py libexynoscamera3.so --disable-cap BurstCapture` will disable the BURST_CAPTURE capability.

### Troubleshooting
If Android doesn't show show any cameras, it means the lib crashed:
  * Try patching with `--skip-depth`. Some devices have depth cameras and enabling capabilities on them breaks the lib.
  * Someone [reported](https://github.com/TBM13/Samsung-Camera-Experiments/issues/7#issuecomment-1949522917) they had to move the lib to `/vendor/lib64/hw/`. Try it if you see something like `dlopen failed: library "libexynoscamera3.so" not found` in the logs.

</details>

<details>
<summary><b>camera.s5eXXXX.so</b></summary>

```
usage: patch_s5e.py [-h] [--enable-cap CAPABILITY [CAPABILITY ...]] [--lib-name LIB_NAME] [--model MODEL] [--android-version ANDROID_VERSION]
                    [--version VERSION]
                    libs [libs ...]

positional arguments:
  libs                  Path(s) of the lib(s) that will be patched

options:
  -h, --help            show this help message and exit

Lib Modifications:
  --enable-cap CAPABILITY [CAPABILITY ...]
                        The capabilities that will be enabled, separated by space.

Magisk Module:
  If all the following args are provided, a Magisk module with the patched lib(s) will be created

  --lib-name LIB_NAME   The name of the lib (e.g. camera.s5e9925.so)
  --model MODEL         The device the lib comes from (e.g. Galaxy A54)
  --android-version ANDROID_VERSION
                        The Android version the lib comes from (e.g. 15)
  --version VERSION     The module version (e.g. 1)
```

#### Capabilities
* If this one is disabled, GCam doesn't work and shows a black screen in photo mode. Enabling it should be enough to make it work:
    * [**RAW**](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_RAW)
* Others
    * **ManualSensor_ReadSensorSettings** ([MANUAL_SENSOR](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR) and [READ_SENSOR_SETTINGS](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_READ_SENSOR_SETTINGS))
    * **ManualPostProcessing** ([MANUAL_POST_PROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MANUAL_POST_PROCESSING))
    * **PrivateReprocessing** ([PRIVATE_REPROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING))
    * **BurstCapture** ([BURST_CAPTURE](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_BURST_CAPTURE))
    * **YUVReprocessing** ([YUV_REPROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING))
    * **MotionTracking** ([MOTION_TRACKING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_MOTION_TRACKING))
    * **LogicalMultiCamera** ([LOGICAL_MULTI_CAMERA](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA))
    * **SecureImageData** ([SECURE_IMAGE_DATA](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_SECURE_IMAGE_DATA))
    * **SystemCamera** ([SYSTEM_CAMERA](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_SYSTEM_CAMERA))
    * **OfflineProcessing** ([OFFLINE_PROCESSING](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_OFFLINE_PROCESSING))
    * **ControlZoom** (doesn't map to an Android capability)
    * **LensCal** (doesn't map to an Android capability)
    * **StreamUseCase** ([STREAM_USE_CASE](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_STREAM_USE_CASE))
    * **DynamicRangeTenBit** ([DYNAMIC_RANGE_TEN_BIT](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_DYNAMIC_RANGE_TEN_BIT))
    * **ColorSpaceProfiles** ([COLOR_SPACE_PROFILES](https://developer.android.com/reference/android/hardware/camera2/CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_COLOR_SPACE_PROFILES))

Examples: \
`python3 ./patch_lib.py camera.s5e8835.so --enable-cap RAW` will enable the RAW capability. \
`python3 ./patch_lib.py camera.s5e8835.so --enable-cap RAW YUVReprocessing` will enable the RAW and YUV_REPROCESSING capabilities.

</details>

## GCam tests after enabling the RAW capability
**Note:** If you test GCam on a device not listed here or you have any issue/weird behaviour, let me know.

Most tests were done using [BSG's GCam 8.1](https://www.celsoazevedo.com/files/android/google-camera/dev-bsg/f/dl88/), as it seems to be the most stable one on Exynos devices that do have GCam working.
|Device Name|SoC|GCam Works?|Notes|
|:-:|:--:|:-:|:-:|
|Galaxy A12 Nacho (A12s)|Exynos 850|X|<table><th>Android 11</th><th>Android 13</th><tr><td>Freezes</td><td>Lags/freezes. Back cam doesn't save pics and front cam sometimes does</td></tr></table>|
|Galaxy A20|Exynos 7884|✓|<table><th>Android 10</th><th>Android 11</th><tr><td>Freezes</td><td>HDR works & pics are 10x better than with the stock cam.<br/>Very laggy, sometimes the phone reboots while using it.</td></tr></table>|
|Galaxy A20e|Exynos 7884|✓|<table><th>Android 10</th><th>Android 11</th><tr><td>Freezes</td><td>HDR works & pics are 10x better than with the stock cam.<br/>Very laggy, sometimes the phone reboots while using it.</td></tr></table>|
|Galaxy A25|Exynos 1280|✓|<table><th>Android 14</th><tr><td>HDR works. Not much difference in quality with the stock cam.<br/>Laggy.</td></tr></table>|
|Galaxy A30|Exynos 7904|✓|<table><th>Android 10</th><th>Android 11</th><tr><td>Freezes</td><td>HDR works & pics are 10x better than with the stock cam.<br/>Very laggy, sometimes the phone reboots while using it.<br/>On few devices the front cam pics are unusable due to bad resolution.</td></tr></table>|
|Galaxy A30s|Exynos 7904|?|<table><th>Android 10</th><th>Android 11</th><tr><td>Freezes</td><td>Untested</td></tr></table>|
|Galaxy A33|Exynos 1280|X|<table><th>Android 14</th><tr><td>Saves black pics when HDR is on</td></tr></table>|
|Galaxy A40|Exynos 7904|Partially|<table><th>Android 11</th><tr><td>Front cam pics unusable due to bad resolution.<br/>It's possible to fix, need to investigate how</td></tr></table>|
|Galaxy A50s|Exynos 9611|Partially|<table><th>Android 11</th><tr><td>Photos have pink tint. Changing black level doesn't help</td></tr></table>|
|Galaxy A51|Exynos 9611|Partially|<table><th>Android 11</th><tr><td>Photos have pink tint. Changing black level doesn't help</td></tr></table>|
|Galaxy F62|Exynos 9825|Partially|<table><th>Android 11</th><tr><td>Issues with the front camera</td></tr></table>|
|Galaxy M31|Exynos 9611|Partially|<table><th>Android 11</th><tr><td>Photos have pink tint. Changing black level doesn't help</td></tr></table>|
|Galaxy M31s|Exynos 9611|Partially|<table><th>Android 12</th><tr><td>Photos have pink tint. Changing black level doesn't help</td></tr></table>|
|Galaxy M34 5G|Exynos 1280|X|<table><th>Android 13</th><tr><td>Saves black pics when HDR is on</td></tr></table>|

As you can see, GCam is usable only on a few Exynos devices. \
As someone who had an A20, I can say that the difference in quality with the stock camera is huge. You can check it yourself with [this comparison](https://cdn.knightlab.com/libs/juxtapose/latest/embed/index.html?uid=9fea4384-35b8-11f0-bb24-0936e1cb08fb) of two pics I took.
