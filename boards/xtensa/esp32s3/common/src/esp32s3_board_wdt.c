/****************************************************************************
 * boards/xtensa/esp32s3/common/src/esp32s3_board_wdt.c
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
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <debug.h>

#include "esp32s3_board_wdt.h"
#include "esp32s3_wdt_lowerhalf.h"
#include "esp32s3_wdt.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: board_wdt_init
 *
 * Description:
 *   Configure the watchdog timer driver.
 *
 * Returned Value:
 *   Zero (OK) is returned on success; A negated errno value is returned
 *   to indicate the nature of any failure.
 *
 ****************************************************************************/

int board_wdt_init(void)
{
  int ret = OK;

#ifdef CONFIG_ESP32S3_MWDT0
  ret = esp32s3_wdt_initialize("/dev/watchdog0", ESP32S3_WDT_MWDT0);
  if (ret < 0)
    {
      syslog(LOG_ERR, "Failed to initialize MWDT0: %d\n", ret);
      return ret;
    }
#endif /* CONFIG_ESP32S3_MWDT0 */

#ifdef CONFIG_ESP32S3_MWDT1
  ret = esp32s3_wdt_initialize("/dev/watchdog1", ESP32S3_WDT_MWDT1);
  if (ret < 0)
    {
      syslog(LOG_ERR, "Failed to initialize MWDT1: %d\n", ret);
      return ret;
    }
#endif /* CONFIG_ESP32S3_MWDT1 */

#ifdef CONFIG_ESP32S3_RWDT
  ret = esp32s3_wdt_initialize("/dev/watchdog2", ESP32S3_WDT_RWDT);
  if (ret < 0)
    {
      syslog(LOG_ERR, "Failed to initialize RWDT: %d\n", ret);
      return ret;
    }
#endif /* CONFIG_ESP32S3_RWDT */

#ifdef CONFIG_ESP32S3_XTWDT
  ret = esp32s3_wdt_initialize("/dev/watchdog3", ESP32S3_WDT_XTWDT);
  if (ret < 0)
    {
      syslog(LOG_ERR, "Failed to initialize XTWDT: %d\n", ret);
      return ret;
    }
#endif /* CONFIG_ESP32S3_XTWDT */

  return ret;
}

