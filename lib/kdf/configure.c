
/*
 * Copyright (C) 2020 kmwebnet
 *
 * 
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include "configure.h"



static uint8_t atecc608_configuration[] = {
    0xC0, 0x00, 0x00, 0x01, 0x87, 0x20, 0x87, 0x20, 0x87, 0x20, 0x87, 0x20, 0xC6, 0x46, 0x8F, 0x46,
    0x8F, 0x0F, 0x9D, 0x8F, 0x0F, 0x0F, 0xc6, 0x46, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xD7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x0E, 0x60, 0x00, 0x00, 0x00, 0x00,
    0x13, 0x00, 0x13, 0x00, 0x13, 0x00, 0x13, 0x00, 0x5C, 0x00, 0x38, 0x00, 0x5C, 0x00, 0x1C, 0x00,
    0x3C, 0x00, 0x5c, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x30, 0x00,
};

int atca_configure(uint8_t i2c_addr, ATCAIfaceCfg *cfg)
{
    ATCA_STATUS status;
    uint8_t buf[ATCA_BLOCK_SIZE];
    bool    lock = false;
    uint8_t pubkey[ATCA_PUB_KEY_SIZE];

    /* Initialize the interface */
    if (ATCA_SUCCESS != (status = atcab_init(cfg))) // modified to I2C structure
    {
        printf("Unable to initialize interface: %x\r\n", status);
        goto exit;
    }

    /* Check the config zone lock status */
    if (ATCA_SUCCESS != (status = atcab_is_locked(ATCA_ZONE_CONFIG, &lock)))
    {
        printf("Unable to get config lock status: %x\r\n", status);
        goto exit;
    }

    /* Get the device type */
    if (ATCA_SUCCESS != (status = atcab_info(buf)))
    {
        printf("Unable to read revision: %x\r\n", status);
        goto exit;
    }

    /* Program the configuration zone */
    if (!lock)
    {
        if (0x60 == buf[2])
        {
            if (i2c_addr != atecc608_configuration[0])
            {
                atecc608_configuration[0] = i2c_addr;
            }
            status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, (uint8_t *)atecc608_configuration, sizeof(atecc608_configuration));
        }
        else
        {
            goto exit;
        }

        if (ATCA_SUCCESS != status)
        {
            goto exit;
        }

        /* Lock the config zone */
        if (ATCA_SUCCESS != (status = atcab_lock_config_zone()))
        {
            goto exit;
        }
    }


    /* Check data zone lock */
    if (ATCA_SUCCESS != (status = atcab_is_locked(LOCK_ZONE_DATA, &lock)))
    {
        goto exit;
    }

    /* Lock the data zone */
    if (!lock)
    {
        if (ATCA_SUCCESS != (status = atcab_lock_data_zone()))
        {
            goto exit;
        }
    }

    /* Generate new keys */
    if (ATCA_SUCCESS != (status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 2, NULL, pubkey)))
    {
        goto exit;
    }


    status = ATCA_SUCCESS;

exit:
    return status;
}

