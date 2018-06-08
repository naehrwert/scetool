/*
* Copyright (c) 2011-2013 by naehrwert
* Copyright (c) 2012 by flatz
* This file is released under the GPLv2.
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>

#include "types.h"
#include "config.h"
#include "np.h"
#include "self.h"
#include "sce.h"
#include "sce_inlines.h"
#include "aes_omac.h"
#include "sha1.h"
#include "ecdsa.h"
#include "keys.h"
#include "aes.h"
#include "util.h"

/*! klicensee key. */
static u8 *_klicensee_key;

static ci_data_npdrm_t *_sce_find_ci_npdrm(sce_buffer_ctxt_t *ctxt)
{
	if(ctxt->self.cis != NULL)
	{
		LIST_FOREACH(iter, ctxt->self.cis)
		{
			control_info_t *ci = (control_info_t *)iter->value;

			if(_ES32(ci->type) == CONTROL_INFO_TYPE_NPDRM)
			{
				ci_data_npdrm_t *np = (ci_data_npdrm_t *)((u8 *)ci + sizeof(control_info_t));
				return np;
			}
		}
	}

	return NULL;
}

void np_set_klicensee(u8 *klicensee)
{
	_klicensee_key = klicensee;
}

bool np_decrypt_npdrm(sce_buffer_ctxt_t *ctxt)
{
	aes_context aes_ctxt;
	ci_data_npdrm_t *np;
	keyset_t *ks_np_klic_free, *ks_klic_key, *ks_np_ci;
	u8 hash_check[0x10], ci_key[0x10];
	u8 npdrm_key[0x10];
	u8 npdrm_iv[0x10];
	int i;

	if((np = _sce_find_ci_npdrm(ctxt)) == NULL)
		return FALSE;

	//Try to find keysets.
	ks_klic_key = keyset_find_by_name(CONFIG_NP_KLIC_KEY_KNAME);
	if(ks_klic_key == NULL)
		return FALSE;
	if(_klicensee_key != NULL)
		memcpy(npdrm_key, _klicensee_key, 0x10);
	else if(_ES32(np->license_type) == NP_LICENSE_FREE)
	{
		ks_np_klic_free = keyset_find_by_name(CONFIG_NP_KLIC_FREE_KNAME);
		ks_np_ci = keyset_find_by_name(CONFIG_NP_CI_KNAME);
		if(ks_np_ci == NULL)
			return FALSE;
		
		//Generate control info hash key.
		for(i = 0; i < 0x10; i++)
		ci_key[i] = ks_np_ci->erk[i] ^ ks_np_klic_free->erk[i];

		//Check header for control info hash and try to load appropriate klicensee key.
		aes_omac1(hash_check, (u8 *)_sce_find_ci_npdrm(ctxt), 0x60, ci_key, KEYBITS(0x10));
		if (memcmp(hash_check, np->hash_ci, 0x10) != 0)
		{
			if((dev_klicensee_by_content_id((s8 *)np->content_id, npdrm_key)) == FALSE)
				return FALSE;
		}
		else 
			memcpy(npdrm_key, ks_np_klic_free->erk, 0x10);
	}
	else if(_ES32(np->license_type) == NP_LICENSE_LOCAL || _ES32(np->license_type) == NP_LICENSE_NETWORK )
	{
		if ((klicensee_by_content_id((s8 *)np->content_id, npdrm_key)) == FALSE)
			return FALSE;
	}
	else
		return FALSE;

	if(_raw == TRUE)
	{
		_hexdump(stdout, "[*] Klicensee:", 0, npdrm_key, sizeof(npdrm_key), FALSE);
	}

	aes_setkey_dec(&aes_ctxt, ks_klic_key->erk, METADATA_INFO_KEYBITS);
	aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, npdrm_key, npdrm_key);

	memset(npdrm_iv, 0, 0x10);
	aes_setkey_dec(&aes_ctxt, npdrm_key, METADATA_INFO_KEYBITS);
	aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, sizeof(metadata_info_t), npdrm_iv, (u8 *)ctxt->metai, (u8 *)ctxt->metai);

	return TRUE;
}

bool np_encrypt_npdrm(sce_buffer_ctxt_t *ctxt)
{
	aes_context aes_ctxt;
	keyset_t *ks_np_klic_free, *ks_klic_key;
	u8 npdrm_key[0x10];
	u8 npdrm_iv[0x10];
	ci_data_npdrm_t *np;

	if((np = _sce_find_ci_npdrm(ctxt)) == NULL)
		return FALSE;

	//Try to find keysets.
	ks_klic_key = keyset_find_by_name(CONFIG_NP_KLIC_KEY_KNAME);
	if(ks_klic_key == NULL)
		return FALSE;
	if(_klicensee_key != NULL)
		memcpy(npdrm_key, _klicensee_key, 0x10);
	else if(_ES32(np->license_type) == NP_LICENSE_FREE)
	{
		ks_np_klic_free = keyset_find_by_name(CONFIG_NP_KLIC_FREE_KNAME);
		if(ks_np_klic_free == NULL)
			return FALSE;
		memcpy(npdrm_key, ks_np_klic_free->erk, 0x10);
	}
	else if(_ES32(np->license_type) == NP_LICENSE_LOCAL)
	{
		if ((klicensee_by_content_id((s8 *)np->content_id, npdrm_key)) == FALSE)
			return FALSE;
	}
	else
		return FALSE;

	aes_setkey_dec(&aes_ctxt, ks_klic_key->erk, METADATA_INFO_KEYBITS);
	aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, npdrm_key, npdrm_key);

	memset(npdrm_iv, 0, 0x10);
	aes_setkey_enc(&aes_ctxt, npdrm_key, METADATA_INFO_KEYBITS);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, sizeof(metadata_info_t), npdrm_iv, ctxt->scebuffer + ctxt->off_metai, ctxt->scebuffer + ctxt->off_metai);

	return TRUE;
}

bool np_create_ci(npdrm_config_t *npconf, ci_data_npdrm_t *cinp)
{
	u32 i, len;
	u8 *cid_fname, ci_key[0x10];
	keyset_t *ks_np_tid, *ks_np_ci, *ks_np_klic_free;
	u8 npdrm_key[0x10];

	//Try to find keysets.
	ks_np_tid = keyset_find_by_name(CONFIG_NP_TID_KNAME);
	ks_np_ci = keyset_find_by_name(CONFIG_NP_CI_KNAME);
	if(ks_np_tid == NULL || ks_np_ci == NULL)
		return FALSE;

	//Can only create NPDRM SELF with "local" and free license.
	if(_klicensee_key != NULL)
		memcpy(npdrm_key, _klicensee_key, 0x10);
	else if(npconf->license_type == NP_LICENSE_FREE)
	{
		ks_np_klic_free = keyset_find_by_name(CONFIG_NP_KLIC_FREE_KNAME);
		if(ks_np_klic_free == NULL)
			return FALSE;
		memcpy(npdrm_key, ks_np_klic_free->erk, 0x10);
	}
	else if(npconf->license_type == NP_LICENSE_LOCAL)
	{
		if ((klicensee_by_content_id((s8 *)npconf->content_id, npdrm_key)) == FALSE)
			return FALSE;
	}
	else
		return FALSE;

	cinp->magic = _ES32(NP_CI_MAGIC);
	cinp->version = _ES32(1);
	cinp->license_type = _ES32(npconf->license_type);
	cinp->app_type = _ES32(npconf->app_type);
	memcpy(cinp->content_id, npconf->content_id, 0x30);
	_fill_rand_bytes(cinp->rndpad, 0x10);
	cinp->limited_time_start = _ES64(0);
	cinp->limited_time_end = _ES64(0);

	//Generate control info hash key.
	for(i = 0; i < 0x10; i++)
		ci_key[i] = ks_np_ci->erk[i] ^ npdrm_key[i];

	//Create hash of title id and real filename.
	len = strlen(npconf->real_fname) + 0x30;
	cid_fname = (u8 *)malloc(sizeof(u8) * (len + 1));
	memcpy(cid_fname, cinp->content_id, 0x30);
	strcpy((s8 *)(cid_fname + 0x30), npconf->real_fname);
	aes_omac1(cinp->hash_cid_fname, cid_fname, len, ks_np_tid->erk, KEYBITS(0x10));

	//Create control info hash.
	aes_omac1(cinp->hash_ci, (u8 *)cinp, 0x60 /* Only the first 0x60 bytes are hashed. */ , ci_key, KEYBITS(0x10));

	return TRUE;
}

//TODO: The fwrite/fread error checking was broken.
//Maybe the MS runtime is returning the number of bytes written instead of the element count?
bool np_sign_file(s8 *fname)
{
	u8 padding_data[0x10] = 
	{
		0xbc, 0x3f, 0x7a, 0x48, 0xaf, 0x45, 0xef, 0x28, 0x3a, 0x05, 0x98, 0x10, 0xbc, 0x3f, 0x7a, 0x48
	};

	keyset_t *ks;
	FILE *fp = NULL;
	u8 *buffer = NULL;
	u32 length;
	u32 padding;
	u8 hash[0x14], R[0x15], S[0x15];

	//Try to find keyset.
	if((ks = keyset_find_by_name(CONFIG_NP_SIG_KNAME)) == NULL)
		return FALSE;

	if((fp = fopen(fname, "r+b")) == NULL)
		return FALSE;

	fseek(fp, 0, SEEK_END);
	length = ftell(fp);

	padding = length % 0x10;
	if(padding > 0)
	{
		fwrite(padding_data, sizeof(u8), padding, fp);
		length += padding;
	}

	fseek(fp, 0, SEEK_SET);
	if((buffer = (u8 *)malloc(length)) == NULL)
	{
		fclose(fp);
		return FALSE;
	}
	fread(buffer, sizeof(u8), length, fp);

	//Generate header hash.
	sha1(buffer, length, hash);

	//Generate signature.
	/* TODO: Set the right curve and private key */
	ecdsa_set_curve(ks->ctype | USE_VSH_CURVE);
	ecdsa_set_pub(ks->pub);
	ecdsa_set_priv(ks->priv);
	ecdsa_sign(hash, R, S);
	fseek(fp, 0, SEEK_END);
	fwrite(R + 1, 0x14, 1, fp);
	fwrite(S + 1, 0x14, 1, fp);
	/* Let's be as stupid as sony here... */
	fwrite(hash + 0xC, 8, 1, fp);

	free(buffer);
	fclose(fp);

	return TRUE;
}
