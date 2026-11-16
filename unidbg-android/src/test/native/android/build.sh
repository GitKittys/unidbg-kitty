#!/usr/bin/env bash
set -e

$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_APPLICATION_MK=./Application.mk
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./signal.mk NDK_APPLICATION_MK=./sdk19.mk
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./library.mk NDK_APPLICATION_MK=./Application.mk
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./el0_boundary.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_el0
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./signal_fidelity.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_signal
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./behavior_compat.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_compat
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./memory_fault.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_memfault
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./thread_signals.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_threads
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./virtual_clock.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_clock
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./thread_scheduling.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_scheduling
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./syscall_fill.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_syscall
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./gap_fill.mk NDK_APPLICATION_MK=./el0_boundary_app.mk NDK_LIBS_OUT=./libs_gap
