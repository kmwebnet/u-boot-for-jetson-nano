/*
 * Copyright (C) 2020 kmwebnet
 *
 * 
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef USE_HOSTCC
#include <common.h>
#else
#include <string.h>
#endif
#include "kdf.h"
#include "cryptoauthlib/lib/cryptoauthlib.h"
#include "host/atca_host.h"
#include "configure.h"
#include <command.h>
#include <fs.h>
#include <div64.h>
#include <linux/math64.h>
#include "cli.h"
#include <aes.h>
#include <malloc.h>
#include <asm/byteorder.h>
#include <mapmem.h>

DECLARE_GLOBAL_DATA_PTR;

void get_atecc608cfg(ATCAIfaceCfg *cfg)
{
//	config for Jetson Nano
		cfg->iface_type             = ATCA_I2C_IFACE;
                cfg->devtype                = ATECC608A;
                cfg->atcai2c.slave_address  = 0XC0;
                cfg->atcai2c.bus            = 2;
                cfg->atcai2c.baud           = 100000;
                cfg->wake_delay             = 1500;
                cfg->rx_retries             = 20;

return;
}

void cryptofunc (void)
{

    ATCAIfaceCfg cfg;

    get_atecc608cfg(&cfg);

    ATCA_STATUS status = atca_configure(0xc0, &cfg);
    if (status != ATCA_SUCCESS) {
        printf("atca_configure failed with ret=0x%08d\n", status);
        return;
    }

    status = atcab_init(&cfg);	
    if (status != ATCA_SUCCESS) {
        printf("atcab_init() failed with ret=0x%08d\n", status);
        return;
    }


    uint8_t encryptkey[32] ;
    atcab_random(encryptkey);

    if (ATCA_SUCCESS != (status = atcab_write_zone(ATCA_ZONE_DATA, 6,  0, 0,  encryptkey, ATCA_KEY_SIZE)))
    {
        printf("writing IO Protection Key by using atcab_write_zone() on slot 6 failed: %x\r\n", status);
        return;
    }

    atcab_release();
    status = atcab_init(&cfg);
	
    if (status != ATCA_SUCCESS) {
        printf("atcab_init() failed with ret=0x%08d\n", status);
        return;
    }

    //get environment variables
	uint32_t ramdisk_addr, fdt_addr, kernel_addr;
    uint8_t *ramdisk_ptr, *fdt_ptr, *kernel_ptr;

	ramdisk_addr = simple_strtoul(getenv("ramdisk_addr_r"), NULL, 16);
	fdt_addr = simple_strtoul(getenv("fdt_addr_r"), NULL, 16);
	kernel_addr = simple_strtoul(getenv("kernel_addr_r"), NULL, 16);

	ramdisk_ptr = (uint8_t *)ramdisk_addr;
	fdt_ptr = (uint8_t *)fdt_addr;
	kernel_ptr = (uint8_t *)kernel_addr;

    // init variables at once
    uint8_t aeskeyseed[32];
    uint8_t nonce [32];
    uint8_t out_nonce[32];
    uint8_t out_kdf_aes_encrypted[32];
    atca_io_decrypt_in_out_t io_dec_params;

    uint8_t digest[32];
    uint8_t pubkey[64];
    uint8_t signature[64];

    uint8_t outkeybuf[192];
    uint8_t readkeybuf[192];
    bool verify_result;

    uint8_t rootfskey [32];

    // file load prepare

	const char *filename;
	loff_t len_read;
	loff_t len_write;
	loff_t bytes;
	int ret;
	uint32_t time;
   	uint32_t addr;
	uint8_t key_exp[AES_EXPAND_KEY_LENGTH];
	uint32_t aes_blocks , len, offset;
    uint8_t *src_ptr, *dst_ptr;

    //boot prepare
	ulong kern_addr;
	void *buf;    

    //source file name 

    #define SRCDTB "/boot/tegra210-p3448-0000-p3449-0000-a02-user-custom.dtb"
    #define SRCINITRD "/boot/initrd.img-4.9.140-tegra"
    #define SRCKERNEL "/boot/Image"

    //plain boot file 

    // mmc1:partition 15
    #define CRYPTSRC "1:f"

    //encrypted boot file destination

    // mmc1:partition 16
    #define CRYPTDST "1:10"

    // set boot args
    #define SETBOOTARGS "tegraid=21.1.2.0.0 ddr_die=4096M@2048M section=512M " \
    "memtype=0 vpr_resize usb_port_owner_info=0 lane_owner_info=0 emc_max_dvfs=0 " \
    "touch_id=0@63 video=tegrafb no_console_suspend=1 console=ttyS0,115200n8 " \
    "debug_uartport=lsport,2 earlyprintk=uart8250-32bit,0x70006000 maxcpus=4 " \
    "usbcore.old_scheme_first=1 lp0_vec=0x1000@0xff780000 core_edp_mv=1075 " \
    "core_edp_ma=4000 tegra_fbmem=0x800000@0x92cb0000 is_hdmi_initialised=1 " \
    "cryptdevice=/dev/mmcblk0p1:luks " \
    "cryptopts=keyscript=/lib/cryptsetup/scripts/getinitramfskey.sh,source=/dev/mmcblk0p1,target=luks " \
    "root=/dev/mapper/luks rw rootwait rootfstype=ext4 console=ttyS0,115200n8 console=tty0 " \
    "fbcon=map:0 net.ifnames=0" 
    


    // determine encode / decode mode

    bool decode;

	if (fs_set_blk_dev("mmc", CRYPTDST, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed \r\n");
		return ;
    }

    filename = "/initrd";

	ret = fs_size(filename, &len_read);

	if (ret < 0)
    {
        decode = false;
    }
    else
    {
        decode = true;
    }

if (decode)
{
// -----decryption work start-----

    printf("device tree decryption start...\n");

    //file load from /dev/mmcblk0p16

	if (fs_set_blk_dev("mmc", CRYPTDST, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //device tree load

    filename = "/tegra210.dtb";
    addr = fdt_addr + 0x40000;
    printf("loading %s...\n",filename);

	time = get_timer(0);
	ret = fs_read(filename, addr, 0, 0, &len_read);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_read failed /r/n");
        return;
    }

	printf("%llu bytes read in %lu ms", len_read, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_read, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");

    len = (uint32_t)len_read;
    src_ptr = (uint8_t *)addr;
    dst_ptr = fdt_ptr;

    //extract certificate
    memcpy (readkeybuf, &src_ptr[len - 192] , 192);

    //make hash
    status = atcac_sw_sha2_256(src_ptr , (size_t)(len - 192), digest);
    if (status != ATCA_SUCCESS) {
    	printf("atcac_sw_sha2_256 failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy ( signature, &readkeybuf[128], 64);
    memcpy ( pubkey , &readkeybuf[64], 64);

    status = atcab_verify_extern(digest, signature, pubkey, &verify_result);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_verify_extern() failed with ret=0x%08d/r/n", status);
        return;
    }

    if (verify_result != true) {
    	printf("verify certificate failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(aeskeyseed ,readkeybuf,  32);

    //kdf aes

    if (ATCA_SUCCESS != (status = atcab_kdf(KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT_ENC, 0x0505,  0, aeskeyseed, out_kdf_aes_encrypted , out_nonce)))
    {
        printf("atcab_kdf_enc failed: %x\r\n", status);
    }

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = encryptkey;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_aes_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);

    //decryption
	/* First we expand the key. */
	aes_expand_key(out_kdf_aes_encrypted, key_exp);

	/* Calculate the number of AES blocks to decrypt. */
	aes_blocks = DIV_ROUND_UP(len - 192 , AES_KEY_LENGTH);

	aes_cbc_decrypt_blocks(key_exp, src_ptr, dst_ptr, aes_blocks);

    printf("decrypted.\n");


    printf("ramdisk decryption start...\n");

    //file load from /dev/mmcblk0p16

	if (fs_set_blk_dev("mmc", CRYPTDST, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //initrd load


    filename = "/initrd";
    addr = ramdisk_addr + 0x1640000;
    printf("loading %s...\n",filename);

	time = get_timer(0);
	ret = fs_read(filename, addr, 0, 0, &len_read);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_read failed /r/n");
        return;
    }

	printf("%llu bytes read in %lu ms", len_read, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_read, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");


    len = (uint32_t)len_read;
    src_ptr = (uint8_t *)addr;
    dst_ptr = ramdisk_ptr;

    //extract certificate
    memcpy (readkeybuf, &src_ptr[len - 192] , 192);

    //for ramdisk, len is important, restore it
    ulong rlen;
    rlen = (ulong)(len - 192 - readkeybuf[32]); 

	setenv_hex("initrd_filesize", rlen);


    //make hash
    status = atcac_sw_sha2_256(src_ptr , (size_t)(len - 192), digest);
    if (status != ATCA_SUCCESS) {
    	printf("atcac_sw_sha2_256 failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy ( signature, &readkeybuf[128], 64);
    memcpy ( pubkey , &readkeybuf[64], 64);

    status = atcab_verify_extern(digest, signature, pubkey, &verify_result);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_verify_extern() failed with ret=0x%08d/r/n", status);
        return;
    }

    if (verify_result != true) {
    	printf("verify certificate failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(aeskeyseed ,readkeybuf,  32);

    //kdf aes

    if (ATCA_SUCCESS != (status = atcab_kdf(KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT_ENC, 0x0505,  0, aeskeyseed, out_kdf_aes_encrypted , out_nonce)))
    {
        printf("atcab_kdf_enc failed: %x\r\n", status);
    }

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = encryptkey;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_aes_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);

    //decryption
	/* First we expand the key. */
	aes_expand_key(out_kdf_aes_encrypted, key_exp);

	/* Calculate the number of AES blocks to decrypt. */
	aes_blocks = DIV_ROUND_UP(len - 192 , AES_KEY_LENGTH);

	aes_cbc_decrypt_blocks(key_exp, src_ptr, dst_ptr, aes_blocks);

    printf("decrypted.\n");






    printf("kernel decryption start...\n");

    //file load from /dev/mmcblk0p16

	if (fs_set_blk_dev("mmc", CRYPTDST, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //kernel load

    filename = "/Image";
    addr = kernel_addr + 0x4d80000;
    printf("loading %s...\n",filename);

	time = get_timer(0);
	ret = fs_read(filename, addr, 0, 0, &len_read);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_read failed /r/n");
        return;
    }

	printf("%llu bytes read in %lu ms", len_read, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_read, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");

    len = (uint32_t)len_read;
    src_ptr = (uint8_t *)addr;
    dst_ptr = kernel_ptr;

    //extract certificate
    memcpy (readkeybuf, &src_ptr[len - 192] , 192);

    //make hash
    status = atcac_sw_sha2_256(src_ptr , (size_t)(len - 192), digest);
    if (status != ATCA_SUCCESS) {
    	printf("atcac_sw_sha2_256 failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy ( signature, &readkeybuf[128], 64);
    memcpy ( pubkey , &readkeybuf[64], 64);

    status = atcab_verify_extern(digest, signature, pubkey, &verify_result);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_verify_extern() failed with ret=0x%08d/r/n", status);
        return;
    }

    if (verify_result != true) {
    	printf("verify certificate failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(aeskeyseed ,readkeybuf,  32);

    //kdf aes

    if (ATCA_SUCCESS != (status = atcab_kdf(KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT_ENC, 0x0505,  0, aeskeyseed, out_kdf_aes_encrypted , out_nonce)))
    {
        printf("atcab_kdf_enc failed: %x\r\n", status);
    }

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = encryptkey;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_aes_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);

    //decryption
	/* First we expand the key. */
	aes_expand_key(out_kdf_aes_encrypted, key_exp);

	/* Calculate the number of AES blocks to decrypt. */
	aes_blocks = DIV_ROUND_UP(len - 192 , AES_KEY_LENGTH);

	aes_cbc_decrypt_blocks(key_exp, src_ptr, dst_ptr, aes_blocks);

    printf("decrypted.\n");


    printf("\nboot\n");

	char *bootm_argv[] = { "bootm", NULL, NULL, NULL, NULL };
	int bootm_argc = 4;
	char initrd_str[28];

	bootm_argv[1] = getenv("kernel_addr_r");

	bootm_argv[2] = initrd_str;
    strncpy(bootm_argv[2], getenv("ramdisk_addr_r"), 18);
	strcat(bootm_argv[2], ":");
	strncat(bootm_argv[2], getenv("initrd_filesize"), 9);   

    bootm_argv[3] = getenv("fdt_addr_r");


    setenv("bootargs", SETBOOTARGS);

    printf("bootm_argv[0]:%s\n",bootm_argv[0]);
    printf("bootm_argv[1]:%s\n",bootm_argv[1]);
    printf("bootm_argv[2]:%s\n",bootm_argv[2]);
    printf("bootm_argv[3]:%s\n",bootm_argv[3]);
    printf("bootargs:%s\n",SETBOOTARGS);


	kern_addr = genimg_get_kernel_addr(bootm_argv[1]);
	buf = map_sysmem(kern_addr, 0);
	/* Try bootm for legacy and FIT format image */
	if (genimg_get_format(buf) != IMAGE_FORMAT_INVALID)
		do_bootm(NULL, 0, bootm_argc, bootm_argv);
#ifdef CONFIG_CMD_BOOTI
	/* Try booting an AArch64 Linux kernel image */
	else
		do_booti(NULL, 0, bootm_argc, bootm_argv);
#elif defined(CONFIG_CMD_BOOTZ)
	/* Try booting a Image */
	else
		do_bootz(NULL, 0, bootm_argc, bootm_argv);
#endif
	unmap_sysmem(buf);


}
else
{
    //  init aes key once 
    atcab_random(nonce);

    if (ATCA_SUCCESS != (status = atcab_write_enc(5,  0,  nonce, encryptkey, 6)))
    {
        printf("writing AES Key by using atcab_write_zone() on slot 5 failed: %x\r\n", status);
        return;
    }


    atcab_random(rootfskey);
    if (ATCA_SUCCESS != (status = atcab_write_enc(4,  0,  rootfskey, encryptkey, 6)))
    {
        printf("writing rootfs Key by using atcab_write_zone() on slot 4 failed: %x\r\n", status);
        return;
    }  


// -----encryption work start-----


    printf("device tree encryption start...\n");

    //create aes key seed
    atcab_random(aeskeyseed);

    //kdf aes

    if (ATCA_SUCCESS != (status = atcab_kdf(KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT_ENC, 0x0505,  0, aeskeyseed, out_kdf_aes_encrypted , out_nonce)))
    {
        printf("atcab_kdf_enc failed: %x\r\n", status);
    }

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = encryptkey;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_aes_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);

    memcpy(outkeybuf, aeskeyseed , 32);
    memset(&outkeybuf[32], 0 , 32);

    printf("got KDF key...\n");

    status = atcab_genkey(2 , pubkey);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_genkey(1) failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(&outkeybuf[64], pubkey, 64);

    printf("got public key...\n");


    //file load from /dev/mmcblk0p15


	if (fs_set_blk_dev("mmc", CRYPTSRC, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //init
    filename = SRCDTB;
    addr = fdt_addr + 0x40000;
    printf("loading %s...\n",filename);

	time = get_timer(0);
	ret = fs_read(filename, addr, 0, 0, &len_read);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_read failed /r/n");
        return;
    }

	printf("%llu bytes read in %lu ms", len_read, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_read, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");

    //file encrypt

    len = (uint32_t)len_read;
    src_ptr = (uint8_t *)addr;
    dst_ptr = fdt_ptr;

	/* First we expand the key. */
	aes_expand_key(out_kdf_aes_encrypted, key_exp);

	/* Calculate the number of AES blocks to encrypt. */
	aes_blocks = DIV_ROUND_UP(len, AES_KEY_LENGTH);

	aes_cbc_encrypt_blocks(key_exp, src_ptr, dst_ptr, aes_blocks);

    //calculate offset include remainder     
    offset = aes_blocks * AES_KEY_LENGTH;

    printf("encrypted.\n");


    //make hash

    status = atcac_sw_sha2_256(dst_ptr , (size_t)offset, digest);
    if (status != ATCA_SUCCESS) {
    	printf("atcac_sw_sha2_256 failed with ret=0x%08d/r/n", status);
        return;
    }


    status = atcab_sign(2 , digest, signature);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_sign() failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(&outkeybuf[128], signature, 64);

    printf("hash and signature has made.\n");

    memcpy(&dst_ptr[offset], outkeybuf, 192);
    //offset update include signature
    offset += 192;
    printf("offset bytes:%d\n",offset);


    //file save to /dev/mmcblk0p16

	if (fs_set_blk_dev("mmc", CRYPTDST, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //initrd save
    filename = "/tegra210.dtb";

    printf("saving %s...\n",filename);

    addr = fdt_addr;
    bytes = (loff_t)offset;

	time = get_timer(0);
	ret = fs_write(filename, addr, 0, bytes, &len_write);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_write failed /r/n");
        return;
    }

	printf("%llu bytes write in %lu ms", len_write, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_write, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");


    printf("ramdisk encryption start...\n");

    //create aes key seed
    atcab_random(aeskeyseed);

    //kdf aes

    if (ATCA_SUCCESS != (status = atcab_kdf(KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT_ENC, 0x0505,  0, aeskeyseed, out_kdf_aes_encrypted , out_nonce)))
    {
        printf("atcab_kdf_enc failed: %x\r\n", status);
    }

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = encryptkey;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_aes_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);

    memcpy(outkeybuf, aeskeyseed , 32);
    memset(&outkeybuf[32], 0 , 32);

    printf("got KDF key...\n");

    status = atcab_genkey(2 , pubkey);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_genkey(1) failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(&outkeybuf[64], pubkey, 64);

    printf("got public key...\n");


    //file load from /dev/mmcblk0p15

	if (fs_set_blk_dev("mmc", CRYPTSRC, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //init
    filename = SRCINITRD;
    addr = ramdisk_addr + 0x1640000;

    printf("loading %s...\n",filename);



	time = get_timer(0);
	ret = fs_read(filename, addr, 0, 0, &len_read);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_read failed /r/n");
        return;
    }

	printf("%llu bytes read in %lu ms", len_read, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_read, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");

    //file encrypt

    len = (uint32_t)len_read;
    src_ptr = (uint8_t *)addr;
    dst_ptr = ramdisk_ptr;

	/* First we expand the key. */
	aes_expand_key(out_kdf_aes_encrypted, key_exp);

	/* Calculate the number of AES blocks to encrypt. */
	aes_blocks = DIV_ROUND_UP(len, AES_KEY_LENGTH);

	aes_cbc_encrypt_blocks(key_exp, src_ptr, dst_ptr, aes_blocks);

    //calculate offset include remainder     
    offset = aes_blocks * AES_KEY_LENGTH;

    printf("encrypted.\n");

    //for ramdisk, len is important, store it

    outkeybuf[32] = (uint8_t)(offset - len);

    //make hash

    status = atcac_sw_sha2_256(dst_ptr , (size_t)offset, digest);
    if (status != ATCA_SUCCESS) {
    	printf("atcac_sw_sha2_256 failed with ret=0x%08d/r/n", status);
        return;
    }


    status = atcab_sign(2 , digest, signature);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_sign() failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(&outkeybuf[128], signature, 64);

    printf("hash and signature has made.\n");


    memcpy(&dst_ptr[offset], outkeybuf, 192);
    //offset update include signature
    offset += 192;
    printf("offset bytes:%d\n",offset);

    //file save to /dev/mmcblk0p16


	if (fs_set_blk_dev("mmc", CRYPTDST, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //initrd save
    filename = "/initrd";

    printf("saving %s...\n",filename);

    addr = ramdisk_addr;
    bytes = (loff_t)offset;

	time = get_timer(0);
	ret = fs_write(filename, addr, 0, bytes, &len_write);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_write failed /r/n");
        return;
    }

	printf("%llu bytes write in %lu ms", len_write, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_write, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");





    printf("kernel encryption start...\n");

    //create aes key seed
    atcab_random(aeskeyseed);

    //kdf aes

    if (ATCA_SUCCESS != (status = atcab_kdf(KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT_ENC, 0x0505,  0, aeskeyseed, out_kdf_aes_encrypted , out_nonce)))
    {
        printf("atcab_kdf_enc failed: %x\r\n", status);
    }

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = encryptkey;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_aes_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);

    memcpy(outkeybuf, aeskeyseed , 32);
    memset(&outkeybuf[32], 0 , 32);

    printf("got KDF key...\n");

    status = atcab_genkey(2 , pubkey);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_genkey(1) failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(&outkeybuf[64], pubkey, 64);

    printf("got public key...\n");

    //file load from /dev/mmcblk0p15

	if (fs_set_blk_dev("mmc", CRYPTSRC, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //init
    filename = SRCKERNEL;
    addr = kernel_addr + 0x4d80000;
    printf("loading %s...\n",filename);

	time = get_timer(0);
	ret = fs_read(filename, addr, 0, 0, &len_read);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_read failed /r/n");
        return;
    }

	printf("%llu bytes read in %lu ms", len_read, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_read, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");

    //file encrypt

    len = (uint32_t)len_read;
    src_ptr = (uint8_t *)addr;
    dst_ptr = kernel_ptr;

	/* First we expand the key. */
	aes_expand_key(out_kdf_aes_encrypted, key_exp);

	/* Calculate the number of AES blocks to encrypt. */
	aes_blocks = DIV_ROUND_UP(len, AES_KEY_LENGTH);

	aes_cbc_encrypt_blocks(key_exp, src_ptr, dst_ptr, aes_blocks);

    //calculate offset include remainder     
    offset = aes_blocks * AES_KEY_LENGTH;

    printf("encrypted.\n");


    //make hash

    status = atcac_sw_sha2_256(dst_ptr , (size_t)offset, digest);
    if (status != ATCA_SUCCESS) {
    	printf("atcac_sw_sha2_256 failed with ret=0x%08d/r/n", status);
        return;
    }


    status = atcab_sign(2 , digest, signature);
    if (status != ATCA_SUCCESS) {
    	printf("atcab_sign() failed with ret=0x%08d/r/n", status);
        return;
    }

    memcpy(&outkeybuf[128], signature, 64);

    printf("hash and signature has made.\n");

    memcpy(&dst_ptr[offset], outkeybuf, 192);
    //offset update include signature
    offset += 192;
    printf("offset bytes:%d\n",offset);


    //file save to /dev/mmcblk0p16


	if (fs_set_blk_dev("mmc", CRYPTDST, FS_TYPE_EXT)) {
    	printf("fs_set_blk_dev failed /r/n");
		return ;
    }

    //initrd save
    filename = "/Image";

    printf("saving %s...\n",filename);

    addr = kernel_addr;
    bytes = (loff_t)offset;

	time = get_timer(0);
	ret = fs_write(filename, addr, 0, bytes, &len_write);
	time = get_timer(time);
	if (ret < 0)
    {
        printf("fs_write failed /r/n");
        return;
    }

	printf("%llu bytes write in %lu ms", len_write, time);
	if (time > 0) {
		puts(" (");
		print_size(div_u64(len_write, time) * 1000, "/s");
		puts(")");
	}
	puts("\n");

}

}
