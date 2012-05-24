
#
# Makefile fragment for Linux 2.6
# Broadcom 802.11abg Networking Device Driver
#
# Copyright (C) 2010, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: Makefile_kbuild_portsrc,v 1.6.54.4 2011-01-27 00:55:34 Exp $

ifneq ($(KERNELRELEASE),)

  LINUXVER_GOODFOR_CFG80211:=$(strip $(shell \
    if [ "$(VERSION)" -ge "2" -a "$(PATCHLEVEL)" -ge "6" -a "$(SUBLEVEL)" -ge "32" ]; then \
      echo TRUE; \
    else \
      echo FALSE; \
    fi \
  ))

    LINUXVER_WEXT_ONLY:=$(strip $(shell \
    if [ "$(VERSION)" -ge "2" -a "$(PATCHLEVEL)" -ge "6" -a "$(SUBLEVEL)" -ge "17" ]; then \
      echo FALSE; \
    else \
      echo TRUE; \
    fi \
  ))

  ifneq ($(API),)
    ifeq ($(API), CFG80211)
      APICHOICE := FORCE_CFG80211
      $(info CFG80211 API specified in command line)
    else
      ifeq ($(API), WEXT)
        APICHOICE := FORCE_WEXT
        $(info Wireless Extension API specified in command line)
      else
        $(error Unknown API type)
      endif
    endif
  else
    ifeq ($(LINUXVER_GOODFOR_CFG80211),TRUE)
      APICHOICE := PREFER_CFG80211
      $(info CFG80211 API is prefered for this kernel version)
    else
      ifeq ($(LINUXVER_WEXT_ONLY),TRUE)
        APICHOICE := FORCE_WEXT
        $(info Wireless Extension is the only possible API for this kernel version)
      else
        APICHOICE := PREFER_WEXT
        $(info Wireless Extension API is prefered for this kernel version)
      endif
    endif
  endif

  ifeq ($(APICHOICE),FORCE_CFG80211)
    ifneq ($(CONFIG_CFG80211),)
      APIFINAL := CFG80211
    else
      $(error CFG80211 is specified but it is not enabled in kernel)
    endif
  endif

  ifeq ($(APICHOICE),FORCE_WEXT)
    APIFINAL := WEXT
  endif

  ifeq ($(APICHOICE),PREFER_CFG80211)
    ifneq ($(CONFIG_CFG80211),)
      APIFINAL := CFG80211
    else
      ifneq ($(CONFIG_WIRELESS_EXT),)
        APIFINAL := WEXT
      else
        $(warning Neither CFG80211 nor Wireless Extension is enabled in kernel)
      endif
    endif
  endif

  ifeq ($(APICHOICE),PREFER_WEXT)
    ifneq ($(CONFIG_WIRELESS_EXT),)
      APIFINAL := WEXT
    else
      ifneq ($(CONFIG_CFG80211),)
        APIFINAL := CFG80211
      else
        $(warning Neither CFG80211 nor Wireless Extension is enabled in kernel)
      endif
    endif
  endif

endif

EXTRA_CFLAGS :=

ifeq ($(APIFINAL),CFG80211)
  EXTRA_CFLAGS += -DUSE_CFG80211
  $(info Using CFG80211 API)
endif

ifeq ($(APIFINAL),WEXT)
  EXTRA_CFLAGS += -DUSE_IW
  $(info Using Wireless Extension API)
endif

obj-m              += wl.o

wl-objs            := 
wl-objs            += src/shared/linux_osl.o
wl-objs            += src/wl/sys/wl_linux.o
wl-objs            += src/wl/sys/wl_iw.o
wl-objs            += src/wl/sys/wl_cfg80211.o

EXTRA_CFLAGS       += -I$(src)/src/include
EXTRA_CFLAGS       += -I$(src)/src/wl/sys -I$(src)/src/wl/phy
#EXTRA_CFLAGS       += -DBCMDBG_ASSERT
EXTRA_CFLAGS       += -DUSE_CFG80211

ifeq ($(KVER),)
	KVER = $(shell uname -r)
endif

KDIR     = /lib/modules/$(KVER)/build
PWD      = $(shell pwd)

KARCH := $(shell egrep 'CONFIG_X86_(32|64)=y' $(KDIR)/.config 2>/dev/null| cut -d= -f1)
ifeq ($(KARCH),CONFIG_X86_32)
    SHIPPED=wlc_hybrid.o_i386
    $(info Kernel architecture is X86_32)
else
    ifeq ($(KARCH),CONFIG_X86_64)
        SHIPPED=wlc_hybrid.o_amd64
        $(info Kernel architecture is X86_64)
    else # Error!
        $(error Unsupported kernel architecture)
    endif
endif

EXTRA_LDFLAGS      := $(src)/lib/$(SHIPPED)

all:
	KBUILD_NOPEDANTIC=1 make -C $(KDIR) M=$(PWD)

clean:
	KBUILD_NOPEDANTIC=1 make -C $(KDIR) M=$(PWD) clean

install:
	install -D -m 755 wl.ko /lib/modules/$(KVER)/kernel/drivers/net/wireless/wl.ko
