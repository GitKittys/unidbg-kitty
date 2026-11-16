LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := thread_scheduling
LOCAL_SRC_FILES := thread_scheduling.c
LOCAL_MODULE_PATH += $(LOCAL_PATH)
LOCAL_CFLAGS += -O2 -std=gnu11
include $(BUILD_SHARED_LIBRARY)
