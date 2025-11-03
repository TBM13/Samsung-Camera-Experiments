import enum

#
# https://developer.android.com/reference/android/hardware/camera2/CameraMetadata
#

class SupportedHardwareLevel(enum.IntEnum):
    LIMITED = 0
    FULL = 1
    LEGACY = 2
    LEVEL_3 = 3
    EXTERNAL = 4

class AvailableCapabilities(enum.IntEnum):
    BACKWARD_COMPATIBLE = 0
    MANUAL_SENSOR = 1
    MANUAL_POST_PROCESSING = 2
    RAW = 3
    PRIVATE_REPROCESSING = 4
    READ_SENSOR_SETTINGS = 5
    BURST_CAPTURE = 6
    YUV_REPROCESSING = 7
    DEPTH_OUTPUT = 8
    CONSTRAINED_HIGH_SPEED_VIDEO = 9
    MOTION_TRACKING = 10
    LOGICAL_MULTI_CAMERA = 11
    MONOCHROME = 12
    SECURE_IMAGE_DATA = 13
    SYSTEM_CAMERA = 14
    OFFLINE_PROCESSING = 15
    ULTRA_HIGH_RESOLUTION_SENSOR = 16
    REMOSAIC_REPROCESSING = 17
    DYNAMIC_RANGE_TEN_BIT = 18
    STREAM_USE_CASE = 19
    COLOR_SPACE_PROFILES = 20