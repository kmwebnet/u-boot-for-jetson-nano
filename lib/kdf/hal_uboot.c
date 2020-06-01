/*
 * Copyright (C) 2020 kmwebnet
 *
 * 
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <dm.h>
#include <i2c.h>
#include "malloc.h"

#include "hal/atca_hal.h"
#include "hal_uboot.h"


static struct udevice *bus;
static struct udevice *dev;

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

/** \brief discover i2c buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application
 * of the a-priori knowledge.This function is not implemented.
 * \param[in] i2c_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 * \return ATCA_UNIMPLEMENTED
 */

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in]  bus_num  logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg     pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] found   number of devices found on this bus
 * \return ATCA_UNIMPLEMENTED
 */

ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg cfg[], int *found)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief HAL implementation of I2C init
 *
 * this implementation assumes I2C peripheral has been enabled by user. It only initialize an
 * I2C interface using given config.
 *
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_init(void* hal, ATCAIfaceCfg* cfg)
{
    ATCAHAL_t *pHal = (ATCAHAL_t*)hal;
    ATCA_STATUS ret = ATCA_BAD_PARAM;

    if (!pHal || !cfg)
    {
        return ret;
    }

    if (pHal->hal_data)
    {
        ATCAI2CMaster_t * hal_data = (ATCAI2CMaster_t*)pHal->hal_data;

        // Assume the bus had already been initialized
        hal_data->ref_ct++;

        ret = ATCA_SUCCESS;
    }
    else
    {
        ATCAI2CMaster_t * hal_data = malloc(sizeof(ATCAI2CMaster_t));
        int bus = cfg->atcai2c.bus; // 0-based logical bus number

        if (hal_data)
        {
            hal_data->ref_ct = 1;  // buses are shared, this is the first instance

            hal_data->i2c_num = bus;

            pHal->hal_data = hal_data;

            ret = ATCA_SUCCESS;
        }
        else
        {
            ret = ATCA_ALLOC_FAILURE;
        }
    }

    return ret;

}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send
 * \param[in] iface     instance
 * \param[in] txdata    pointer to space to bytes to send
 * \param[in] txlength  number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCAI2CMaster_t * hal_data = (ATCAI2CMaster_t*)atgetifacehaldat(iface);
    int ret;  // I2C file descriptor

    txdata[0] = 0x03; // insert the Word Address Value, Command token
    txlength++;       // account for word address value byte.

	/* get I2C handle and access to slave */
	debug("%s: access ATECC608A\n", __func__);

    // Send data
	ret = dm_i2c_write(dev, 0, txdata, txlength);
	if (ret) {
		debug("i2c_write failed: %d\n", ret);
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C receive function
 * \param[in]    iface     Device to interact with.
 * \param[out]   rxdata    Data received will be returned here.
 * \param[inout] rxlength  As input, the size of the rxdata buffer.
 *                         As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCAI2CMaster_t * hal_data = (ATCAI2CMaster_t*)atgetifacehaldat(iface);
    int ret;  // I2C file descriptor
    uint16_t count;
    uint16_t rxdata_max_size = *rxlength;

    *rxlength = 0;
    if (rxdata_max_size < 1)
    {
        return ATCA_SMALL_BUFFER;
    }


	/* get I2C handle and access to slave */
	debug("%s: access ATECC608A\n", __func__);

    // Receive count
    count = 1;

	ret = dm_i2c_read(dev, 0, rxdata, count);
	if (ret) {
		debug("i2c_read failed: %d\n", ret);
        return ATCA_COMM_FAIL;
    }


    if (rxdata[0] < ATCA_RSP_SIZE_MIN)
    {
        return ATCA_INVALID_SIZE;
    }
    if (rxdata[0] > rxdata_max_size)
    {
        return ATCA_SMALL_BUFFER;
    }

    count = rxdata[0] - 1;
    // Receive data

	ret = dm_i2c_read(dev, 0, &rxdata[1], count);
	if (ret) {
		debug("i2c_read failed: %d\n", ret);
        return ATCA_COMM_FAIL;
    }

    *rxlength = rxdata[0];

    return ATCA_SUCCESS;
}

/** \brief method to change the bus speed of I2C.This function is not used in Linux.
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */

void change_i2c_speed(ATCAIface iface, uint32_t speed)
{

}

/** \brief wake up CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCAI2CMaster_t * hal_data = (ATCAI2CMaster_t*)atgetifacehaldat(iface);
    ATCA_STATUS status;
    int ret;  // I2C file descriptor
	uint8_t buf[2];
    uint8_t data[4];
    
    // Send the wake by writing to an address of 0x00
    // Create wake up pulse by sending a slave address 0f 0x00.
    // This slave address is sent to device by using a dummy write command.
	debug("%s: wake ATECC608A\n", __func__);
	ret = uclass_get_device_by_seq(UCLASS_I2C, hal_data->i2c_num,  &bus);
	if (ret) {
		return ATCA_COMM_FAIL;
	}
    // Set bus speed

	ret = dm_i2c_set_bus_speed(bus, cfg->atcai2c.baud);
	if (ret) {
        return ATCA_COMM_FAIL;
	}

	ret = i2c_get_chip(bus, cfg->atcai2c.slave_address >> 1 , 0 , &dev);
	if (ret) {
        return ATCA_COMM_FAIL;
	}

    // Send the wake by writing to an address of 0x00
    // Create wake up pulse by sending a slave address 0f 0x00.
    // This slave address is sent to device by using a dummy write command.

    for (int try = 0; try < cfg->rx_retries; ++try) {

        buf[0] = 0;
        buf[1] = 0;
    
	    dm_i2c_write(dev, 0, buf, 2);

        atca_delay_us(cfg->wake_delay); 

        // read data
	    ret = dm_i2c_read(dev, 0, data, 4);
	    if (ret) {
	    	debug("contents i2c_read failed: %d\n", ret);
        }

        status = hal_check_wake(data, 4);
        if(status == ATCA_SUCCESS)
        {
    	    debug("%s: ATECC608A WAKE succeded.\n", __func__);
            return status;
        } 
        else
        {
            debug("%s: ATECC608A WAKE fail.%d\n", __func__, status);
            return status;
        }


    }
        return ATCA_COMM_FAIL;
}

/** \brief idle CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to idle
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{

    uint8_t buf[1];
    buf[0] = 0x02;
	dm_i2c_write(dev, 0, buf, 1);
    return ATCA_SUCCESS;

}

/** \brief sleep CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to sleep
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{

    uint8_t buf[1];
    buf[0] = 0x01;
	dm_i2c_write(dev, 0, buf, 1);
    return ATCA_SUCCESS;

}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t*)hal_data;

    // if the use count for this bus has gone to 0 references, disable it.  protect against an unbracketed release
    if (hal && --(hal->ref_ct) <= 0)
    {
        free(hal);
    }

    return ATCA_SUCCESS;
}

/** @} */
