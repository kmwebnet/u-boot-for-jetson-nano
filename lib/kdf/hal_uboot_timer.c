/*
 * Copyright (C) 2020 kmwebnet
 *
 * 
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include "hal/atca_hal.h"

DECLARE_GLOBAL_DATA_PTR;

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */


/** \brief This function delays for a number of microseconds.
 *
 * \param[in] delay number of microseconds to delay
 */
void atca_delay_us(uint32_t delay)
{
    udelay(delay);
}

/** \brief This function delays for a number of tens of microseconds.
 *
 * \param[in] delay number of 0.01 milliseconds to delay
 */
void atca_delay_10us(uint32_t delay)
{
    atca_delay_us(delay * 10);
}


/** \brief This function delays for a number of milliseconds.
 *
 *         You can override this function if you like to do
 *         something else in your system while delaying.
 * \param[in] delay number of milliseconds to delay
 */

/* ASF already has delay_ms - see delay.h */
void atca_delay_ms(uint32_t delay)
{
    atca_delay_us(delay * 1000);
}

/** @} */
