############################################################################
# boards/risc-v/qemu-rv/rv-virt/src/Makefile
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#
############################################################################

include $(TOPDIR)/Make.defs

RCSRCS = etc/init.d/rc.sysinit etc/init.d/rcS

CSRCS = qemu_rv_appinit.c

ifeq ($(CONFIG_BUILD_KERNEL),y)
ifeq ($(CONFIG_RISCV_SEMIHOSTING_HOSTFS),)
CSRCS += $(if $(wildcard romfs_boot.c), romfs_boot.c, romfs_stub.c)
endif
endif

ifeq ($(CONFIG_ARCH_LEDS),y)
CSRCS += qemu_rv_autoleds.c
endif

ifeq ($(CONFIG_USERLED),y)
CSRCS += qemu_rv_userleds.c
endif

include $(TOPDIR)/boards/Board.mk

# don't use single-colon targets as they may conflict with those included ones.
# use double-colon targets to avoid collisions below.

ifeq ($(CONFIG_BUILD_KERNEL),y)
.PHONY: clean
clean::
	$(call DELFILE, romfs_boot.c)
endif
