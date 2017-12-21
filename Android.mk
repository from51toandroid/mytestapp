LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

#LOCAL_ARM_MODE := arm
#LOCAL_ARM_MODE := arm 
#LOCAL_MODULE_TAGS :=optional
#LOCAL_C_INCLUDES := $(KERNEL_HEADERS)
#LOCAL_SHARED_LIBRARIES := libcutils liblog
LOCAL_MODULE:= mytest
LOCAL_SRC_FILES:=mytest.c  asmhello.c asmhello_asm.S
LOCAL_PRELINK_MODULE := false
include $(BUILD_EXECUTABLE)




#LOCAL_LDFLAGS := -ldl
#LOCAL_MODULE_TAGS := tests
