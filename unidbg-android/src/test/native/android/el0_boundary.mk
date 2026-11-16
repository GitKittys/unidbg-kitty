LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := el0_boundary
LOCAL_SRC_FILES := el0_boundary.c
LOCAL_MODULE_PATH += $(LOCAL_PATH)
LOCAL_CFLAGS += -O2 -march=armv8.2-a
include $(BUILD_SHARED_LIBRARY)
