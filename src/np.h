/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _NP_H_
#define _NP_H_

#include "types.h"
#include "sce.h"

/*! NPDRM config. */
typedef struct _npdrm_config
{
	/*! License type. */
	u32 license_type;
	/*! Application type. */
	u32 app_type;
	/*! klicensee. */
	u8 *klicensee;
	/*! Content ID. */
	u8 content_id[0x30];
	/*! Real file name. */
	s8 *real_fname;
} npdrm_config_t;

/*! Set klicensee. */
void np_set_klicensee(u8 *klicensee);

/*! Remove NPDRM layer. */
bool np_decrypt_npdrm(sce_buffer_ctxt_t *ctxt);

/*! Add NPDRM layer. */
bool np_encrypt_npdrm(sce_buffer_ctxt_t *ctxt);

/*! Create NPDRM control info. */
bool np_create_ci(npdrm_config_t *npconf, ci_data_npdrm_t *cinp);

/*! Add NP signature to file. */
bool np_sign_file(s8 *fname);

#endif
