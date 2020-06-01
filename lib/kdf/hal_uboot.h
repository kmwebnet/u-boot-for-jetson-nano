/*
 * Copyright (C) 2020 kmwebnet
 *
 * 
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */


#ifndef HAL_UBOOT_H_
#define HAL_UBOOT_H_

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

#define MAX_I2C_BUSES   4

// A structure to hold I2C information
typedef struct atcaI2Cmaster
{
    int i2c_num;
    int  ref_ct;
} ATCAI2CMaster_t;

/** @} */

#endif /* HAL_UBOOT_H_ */
