This folder contains a collection of Magisk modules that replace the camera lib with a patched one to enable the RAW capability and set the Hardware Level to FULL.

Additionally, the Black Level Pattern value is changed to 64 in order to fix pink tint on photos taken with GCam (this change is not strictly required since most GCams have a setting to change the Black Level Pattern, but others don't)

These modules will only work with an **Android 11** kernel and vendor, since their camera libs were grabbed from that version. Android 9 and 10 libs freeze on GCam so they aren't supported.

## Installation
Through Magisk Manager, like any other Magisk module.

> [!IMPORTANT]  
> - Magisk v20.4 or newer is required
> - KernelSU should be compatible, but further testing is required
> - An Android 11 kernel and vendor is required

## Troubleshooting
- Camera doesn't work, shows Black Screen
  - If this only happens on GCam, it probably means that the module was not installed correctly or it's disabled.
  - If this happens on any camera app, it means the camera library crashed. Let me know of this.
- GCam's Night Sight takes blurred photos with pink tint
  - A workaround is to lock AF/AE before taking the photo.

## Patch details
The libraries were patched before I automated the process with the Python script.
The patch in these is messier but essentially it does the same thing: modifies values of the `ExynosCameraSensorInfo` struct of all the cameras.

### Galaxy A30 Details
Usually it's enough to patch a single Android 11 lib per device since it doesn't have much modifications between each update, but that's not the case on the A30.

Two different Android 11 libs were patched: an older one and a newer one. Both are included in the module and which one should be used is decided by `post-fs-data.sh`