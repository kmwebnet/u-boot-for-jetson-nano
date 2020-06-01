/*
 * Copyright (C) 2020 kmwebnet
 *
 * Command for encryption/decryption of linux boot image.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <command.h>
#include <environment.h>
#include <kdf.h>
#include <malloc.h>
#include <asm/byteorder.h>
#include <linux/compiler.h>

DECLARE_GLOBAL_DATA_PTR;

/**
 * do_kdf() - Handle the "bootlinux" command-line command
 * @cmdtp:	Command data struct pointer
 * @flag:	Command flag
 * @argc:	Command-line argument count
 * @argv:	Array of command-line arguments
 *
 * Returns zero on success, CMD_RET_USAGE in case of misuse and negative
 * on error.
 */
static int do_bootlinux(cmd_tbl_t *cmdtp, int flag, int argc, char *const argv[])
{


	cryptofunc();

	return 0;
}

/***************************************************/
#ifdef CONFIG_SYS_LONGHELP
static char bootlinux_help_text[] =
	"                    -     Decrypt / Encrypt file of data specified\n"
	"                          and boot. \n";
#endif

U_BOOT_CMD(
	bootlinux, 2, 1, do_bootlinux,
	"encrypt/decrypt linux image operation",
	bootlinux_help_text
);
