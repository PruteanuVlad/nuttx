/****************************************************************************
 * boards/xtensa/esp32/common/scripts/flat_memory.ld
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * ESP32 Linker Script Memory Layout
 *
 * This file describes the memory layout (memory blocks) as virtual
 * memory addresses.
 *
 * <legacy/mcuboot>_sections.ld contains output sections to link compiler
 * output into these memory blocks.
 *
 ****************************************************************************/

#include <nuttx/config.h>

#include "esp32_aliases.ld"

#ifdef CONFIG_ESP32_FLASH_2M
#  define FLASH_SIZE 0x200000
#elif defined (CONFIG_ESP32_FLASH_4M)
#  define FLASH_SIZE 0x400000
#elif defined (CONFIG_ESP32_FLASH_8M)
#  define FLASH_SIZE 0x800000
#elif defined (CONFIG_ESP32_FLASH_16M)
#  define FLASH_SIZE 0x1000000
#endif

#define SRAM1_IRAM_LEN 0xa000

MEMORY
{
#ifdef CONFIG_ESP32_APP_FORMAT_MCUBOOT
  /* The origin values for "metadata" and "ROM" memory regions are the actual
   * load addresses.
   *
   * NOTE: The memory region starting from 0x0 with length represented by
   * CONFIG_ESP32_APP_MCUBOOT_HEADER_SIZE is reserved for the MCUboot header,
   * which will be prepended to the binary file by the "imgtool" during the
   * signing of firmware image.
   */

  metadata (RX) :        org = CONFIG_ESP32_APP_MCUBOOT_HEADER_SIZE, len = 0x60
  ROM (RX) :             org = ORIGIN(metadata) + LENGTH(metadata),
                         len = FLASH_SIZE - ORIGIN(ROM)

#elif defined (CONFIG_ESPRESSIF_SIMPLE_BOOT)
  /* The 0x20 offset is a convenience for the app binary image generation.
   * Flash cache has 64KB pages. The .bin file which is flashed to the chip
   * has a 0x18 byte file header, and each segment has a 0x08 byte segment
   * header. Setting this offset makes it simple to meet the flash cache MMU's
   * constraint that (paddr % 64KB == vaddr % 64KB).
   */

  ROM (RX) :             org = 0x20,
                         len = FLASH_SIZE - ORIGIN(ROM)
#endif

  /* Below values assume the flash cache is on, and have the blocks this
   * uses subtracted from the length of the various regions. The 'data access
   * port' dram/drom regions map to the same iram/irom regions but are
   * connected to the data port of the CPU and e.g. allow bytewise access.
   */

  /* IRAM for PRO cpu. Not sure if happy with this, this is MMU area... */

  iram0_0_seg (RX) :     org = 0x40080000, len = 0x20000 + SRAM1_IRAM_LEN

  /* Flash mapped instruction data. */

#ifdef CONFIG_ESP32_APP_FORMAT_MCUBOOT
  irom0_0_seg (RX) :     org = 0x400d0000, len = 0x330000
#else
  /* The 0x20 offset is a convenience for the app binary image generation.
   * Flash cache has 64KB pages. The .bin file which is flashed to the chip
   * has a 0x18 byte file header, and each segment has a 0x08 byte segment
   * header. Setting this offset makes it simple to meet the flash cache MMU's
   * constraint that (paddr % 64KB == vaddr % 64KB).
   */

  irom0_0_seg (RX) :     org = 0x400d0020, len = 0x330000 - 0x20
#endif

  /* Shared data RAM, excluding memory reserved for ROM bss/data/stack.
   * Enabling Bluetooth & Trace Memory features in menuconfig will decrease
   * the amount of RAM available.
   *
   * Note: The length of this section should be 0x50000, and this extra
   * DRAM is available in heap at runtime. However due to static ROM memory
   * usage at this 176KB mark, the additional static memory temporarily cannot
   * be used.
   */

  dram0_0_seg (RW) :     org = 0x3ffb0000 + CONFIG_ESP32_BT_RESERVE_DRAM,
                         len = 0x2c200 - CONFIG_ESP32_TRACEMEM_RESERVE_DRAM - CONFIG_ESP32_BT_RESERVE_DRAM

  /* Flash mapped constant data */

#ifdef CONFIG_ESP32_APP_FORMAT_MCUBOOT
  /* The DROM segment origin is offset by 0x40 for mirroring the actual ROM
   * image layout:
   *    0x0  - 0x1F : MCUboot header
   *    0x20 - 0x3F : Application image metadata section
   *    0x40 onwards: ROM code and data
   * This is required to meet the following constraint from the external
   * flash MMU:
   *    VMA % 64KB == LMA % 64KB
   * i.e. the lower 16 bits of both the virtual address (address seen by the
   * CPU) and the load address (physical address of the external flash) must
   * be equal.
   */

  drom0_0_seg (R) :      org = 0x3f400000 + ORIGIN(ROM),
                         len = FLASH_SIZE - ORIGIN(ROM)
#else
  /* The 0x20 offset is a convenience for the app binary image generation.
   * Flash cache has 64KB pages. The .bin file which is flashed to the chip
   * has a 0x18 byte file header, and each segment has a 0x08 byte segment
   * header. Setting this offset makes it simple to meet the flash cache MMU's
   * constraint that (paddr % 64KB == vaddr % 64KB).
   */

  drom0_0_seg (R) :      org = 0x3f400020, len = FLASH_SIZE - 0x20
#endif

  /* RTC fast memory (executable). Persists over deep sleep. */

  rtc_iram_seg (RWX) :   org = 0x400c0000, len = 0x2000

  /* RTC slow memory (data accessible). Persists over deep sleep.
   * Start of RTC slow memory is reserved for ULP co-processor code + data,
   * if enabled.
   */

  rtc_slow_seg (RW) :    org = 0x50000000 + CONFIG_ESP32_ULP_COPROC_RESERVE_MEM,
                         len = 0x1000 - CONFIG_ESP32_ULP_COPROC_RESERVE_MEM

  /* External memory, including data and text */

  extmem_seg (RWX) :     org = 0x3f800000, len = 0x400000
}

#ifdef CONFIG_ESP32_RUN_IRAM
  REGION_ALIAS("default_rodata_seg", dram0_0_seg);
  REGION_ALIAS("default_code_seg", iram0_0_seg);
#else
  REGION_ALIAS("default_rodata_seg", drom0_0_seg);
  REGION_ALIAS("default_code_seg", irom0_0_seg);
#endif /* CONFIG_ESP32_RUN_IRAM */

_sram1_iram_start = 0x400a0000;
_sram1_iram_len = ( _iram_text_end > _sram1_iram_start) ? (_iram_text_end - _sram1_iram_start) : 0;

/* Heap ends at top of dram0_0_seg */

_eheap = (_iram_text_end > _sram1_iram_start) ?
  ALIGN(0x40000000 - _sram1_iram_len - 3, 4) - CONFIG_ESP32_TRACEMEM_RESERVE_DRAM :
  0x40000000 - CONFIG_ESP32_TRACEMEM_RESERVE_DRAM;

/* IRAM heap ends at top of dram0_0_seg */

_eiramheap = (_iram_text_end > _sram1_iram_start) ? ALIGN(_iram_text_end, 4) : 0x400a0000;

/* Mark the end of the RTC heap (top of the RTC region) */

_ertcheap = 0x50001fff;
