/*
 * Copyright (C) 2020 kmwebnet
 *
 * 
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef _KDF_REF_H_
#define _KDF_REF_H_

#ifdef USE_HOSTCC
/* Define compat stuff for use in fw_* tools. */
typedef unsigned char u8;
typedef unsigned int u32;
#define debug(...) do {} while (0)
#endif
#include  "linux/string.h"

void cryptofunc(void);

#endif /* _KDF_REF_H_ */
