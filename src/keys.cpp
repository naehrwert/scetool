/*
* Copyright (c) 2011-2013 by naehrwert
* Copyright (c) 2012 by flatz
* This file is released under the GPLv2.
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "config.h"
#include "types.h"
#include "list.h"
#include "sce.h"
#include "keys.h"
#include "util.h"
#include "tables.h"
#include "aes.h"

/*
[keyname]
category={SELF, RVK, PKG, SPP, OTHER}
revision={00, ..., 18, 8000}
version={..., 0001000000000000, ...}
program_type={LV0, LV1, LV2, APP, ISO, LDR, UNK_7, NPDRM}
key=...
erk=...
riv=...
pub=...
priv=...
ctype=...
*/

/*! Loaded keysets. */
list_t *_keysets;
/*! Loaded internal keysets. */
list_t *_internal_keysets;
/*! Loaded loader curves. */
curve_t *_curves;
/*! Loaded VSH curves. */
vsh_curve_t *_vsh_curves;
/*! Backup keyset. */
keyset_t *_used_keyset;

static void _fill_property(keyset_t *ks, s8 *prop, s8 *value)
{
	if(strcmp(prop, "category") == 0)
	{
		if(strcmp(value, "SELF") == 0)
			ks->category = KEYCATEGORY_SELF;
		else if(strcmp(value, "RVK") == 0)
			ks->category = KEYCATEGORY_RVK;
		else if(strcmp(value, "PKG") == 0)
			ks->category = KEYCATEGORY_PKG;
		else if(strcmp(value, "SPP") == 0)
			ks->category = KEYCATEGORY_SPP;
		else if(strcmp(value, "OTHER") == 0)
			ks->category = KEYCATEGORY_OTHER;
		else
			printf("[*] Error: Unknown category '%s'.\n", value);
	}
	else if(strcmp(prop, "revision") == 0)
		ks->key_revision = (u16)_x_to_u64(value);
	else if(strcmp(prop, "version") == 0)
		ks->version = _x_to_u64(value);
	else if(strcmp(prop, "program_type") == 0)
	{
		if(strcmp(value, "LV0") == 0)
			ks->program_type = PROGRAM_TYPE_LV0;
		else if(strcmp(value, "LV1") == 0)
			ks->program_type = PROGRAM_TYPE_LV1;
		else if(strcmp(value, "LV2") == 0)
			ks->program_type = PROGRAM_TYPE_LV2;
		else if(strcmp(value, "APP") == 0)
			ks->program_type = PROGRAM_TYPE_APP;
		else if(strcmp(value, "ISO") == 0)
			ks->program_type = PROGRAM_TYPE_ISO;
		else if(strcmp(value, "LDR") == 0)
			ks->program_type = PROGRAM_TYPE_LDR;
		else if(strcmp(value, "UNK_7") == 0)
			ks->program_type = PROGRAM_TYPE_UNK_7;
		else if(strcmp(value, "NPDRM") == 0)
			ks->program_type = PROGRAM_TYPE_NPDRM;
		else
			printf("[*] Error: unknown SELF type '%s'.\n", value);
	}
	else if(strcmp(prop, "erk") == 0 || strcmp(prop, "key") == 0)
	{
		ks->erk = _x_to_u8_buffer(value);
		ks->erklen = strlen(value) / 2;
	}
	else if(strcmp(prop, "riv") == 0)
	{
		ks->riv = _x_to_u8_buffer(value);
		ks->rivlen = strlen(value) / 2;
	}
	else if(strcmp(prop, "pub") == 0)
		ks->pub = _x_to_u8_buffer(value);
	else if(strcmp(prop, "priv") == 0)
		ks->priv = _x_to_u8_buffer(value);
	else if(strcmp(prop, "ctype") == 0)
		ks->ctype = (u8)_x_to_u64(value);
	else
		printf("[*] Error: Unknown keyfile property '%s'.\n", prop);
}

static s64 _compare_keysets(keyset_t *ks1, keyset_t *ks2)
{
	s64 res;

	if((res = (s64)ks1->version - (s64)ks2->version) == 0)
		res = (s64)ks1->key_revision - (s64)ks2->key_revision;

	return res;
}

static void _sort_keysets()
{
	u32 i, to = _keysets->count;
	lnode_t *max;

	list_t *tmp = list_create();

	for(i = 0; i < to; i++)
	{
		max = _keysets->head;
		LIST_FOREACH(iter, _keysets)
		{
			if(_compare_keysets((keyset_t *)max->value, (keyset_t *)iter->value) < 0)
				max = iter;
		}
		list_push(tmp, max->value);
		list_remove_node(_keysets, max);
	}

	list_destroy(_keysets);
	_keysets = tmp;
}

static void _sort_internal_keysets()
{
	u32 i, to = _internal_keysets->count;
	lnode_t *max;

	list_t *tmp = list_create();

	for(i = 0; i < to; i++)
	{
		max = _internal_keysets->head;
		LIST_FOREACH(iter, _internal_keysets)
		{
			if(_compare_keysets((keyset_t *)max->value, (keyset_t *)iter->value) < 0)
				max = iter;
		}
		list_push(tmp, max->value);
		list_remove_node(_internal_keysets, max);
	}

	list_destroy(_internal_keysets);
	_internal_keysets = tmp;
}

void _print_key_list(FILE *fp)
{
	const s8 *name;
	s32 len = 0, tmp;

	LIST_FOREACH(iter, _keysets)
		if((tmp = strlen(((keyset_t *)iter->value)->name)) > len)
			len = tmp;

	fprintf(fp, " Name");
	_print_align(fp, " ", len, 4);
	fprintf(fp, " Category Revision Version Program-Type\n");

	LIST_FOREACH(iter, _keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;
		fprintf(fp, " %s", ks->name);
		_print_align(fp, " ", len, strlen(ks->name));
		fprintf(fp, " %-5s    0x%04X   %s   ", _get_name(_key_categories, ks->category), ks->key_revision, sce_version_to_str(ks->version));
		if(ks->category == KEYCATEGORY_SELF)
		{
			name = _get_name(_program_types, ks->program_type);
			if(name != NULL)
				fprintf(fp, "[%s]\n", name);
			else
				fprintf(fp, "0x%08X\n", ks->program_type);
		}
		else
			fprintf(fp, "\n");
	}
}

void _print_internal_key_list(FILE *fp)
{
	const s8 *name;
	s32 len = 0, tmp;

	LIST_FOREACH(iter, _internal_keysets)
		if((tmp = strlen(((keyset_t *)iter->value)->name)) > len)
			len = tmp;

	fprintf(fp, " Name");
	_print_align(fp, " ", len, 4);
	fprintf(fp, " Category Revision Version Program-Type\n");

	LIST_FOREACH(iter, _internal_keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;
		fprintf(fp, " %s", ks->name);
		_print_align(fp, " ", len, strlen(ks->name));
		fprintf(fp, " %-5s    0x%04X   %s   ", _get_name(_key_categories, ks->category), ks->key_revision, sce_version_to_str(ks->version));
		if(ks->category == KEYCATEGORY_SELF)
		{
			name = _get_name(_program_types, ks->program_type);
			if(name != NULL)
				fprintf(fp, "[%s]\n", name);
			else
				fprintf(fp, "0x%08X\n", ks->program_type);
		}
		else
			fprintf(fp, "\n");
	}
}

#define LINEBUFSIZE 512
bool keys_load(const s8 *kfile)
{
	u32 i = 0, lblen;
	FILE *fp;
	s8 lbuf[LINEBUFSIZE];
	keyset_t *cks = NULL;

	if((_keysets = list_create()) == NULL)
		return FALSE;

	if((fp = fopen(kfile, "r")) == NULL)
	{
		list_destroy(_keysets);
		return FALSE;
	}

	do
	{
		//Get next line.
		lbuf[0] = 0;
		fgets(lbuf, LINEBUFSIZE, fp);
		lblen = strlen(lbuf);

		//Don't parse empty lines (ignore '\n') and comment lines (starting with '#').
		if(lblen > 1 && lbuf[0] != '#')
		{
			//Remove '\n'.
			lbuf[lblen-1] = 0;

			//Check for keyset entry.
			if(lblen > 2 && lbuf[0] == '[')
			{
				if(cks != NULL)
				{
					//Add to keyset list.
					list_push(_keysets, cks);
					cks = NULL;
				}

				//Find name end.
				for(i = 0; lbuf[i] != ']' && lbuf[i] != '\n' && i < lblen; i++);
				lbuf[i] = 0;

				//Allocate keyset and fill name.
				cks = (keyset_t *)malloc(sizeof(keyset_t));
				memset(cks, 0, sizeof(keyset_t));
				cks->name = strdup(&lbuf[1]);
			}
			else if(cks != NULL)
			{
				//Find property name end.
				for(i = 0; lbuf[i] != '=' && lbuf[i] != '\n' && i < lblen; i++);
				lbuf[i] = 0;

				//Fill property.
				_fill_property(cks, &lbuf[0], &lbuf[i+1]);
			}
		}
	} while(!feof(fp));

	//Add last keyset to keyset list.
	if(cks != NULL)
		list_push(_keysets, cks);

	//Sort keysets.
	_sort_keysets();

	return TRUE;
}

bool internal_keys_load(const s8 *kfile)
{
	u32 i = 0, lblen;
	FILE *fp;
	s8 lbuf[LINEBUFSIZE];
	keyset_t *cks = NULL;

	if((_internal_keysets = list_create()) == NULL)
		return FALSE;

	if((fp = fopen(kfile, "r")) == NULL)
	{
		list_destroy(_internal_keysets);
		return FALSE;
	}

	do
	{
		//Get next line.
		lbuf[0] = 0;
		fgets(lbuf, LINEBUFSIZE, fp);
		lblen = strlen(lbuf);

		//Don't parse empty lines (ignore '\n') and comment lines (starting with '#').
		if(lblen > 1 && lbuf[0] != '#')
		{
			//Remove '\n'.
			lbuf[lblen-1] = 0;

			//Check for keyset entry.
			if(lblen > 2 && lbuf[0] == '[')
			{
				if(cks != NULL)
				{
					//Add to keyset list.
					list_push(_internal_keysets, cks);
					cks = NULL;
				}

				//Find name end.
				for(i = 0; lbuf[i] != ']' && lbuf[i] != '\n' && i < lblen; i++);
				lbuf[i] = 0;

				//Allocate keyset and fill name.
				cks = (keyset_t *)malloc(sizeof(keyset_t));
				memset(cks, 0, sizeof(keyset_t));
				cks->name = strdup(&lbuf[1]);
			}
			else if(cks != NULL)
			{
				//Find property name end.
				for(i = 0; lbuf[i] != '=' && lbuf[i] != '\n' && i < lblen; i++);
				lbuf[i] = 0;

				//Fill property.
				_fill_property(cks, &lbuf[0], &lbuf[i+1]);
			}
		}
	} while(!feof(fp));

	//Add last keyset to keyset list.
	if(cks != NULL)
		list_push(_internal_keysets, cks);

	//Sort keysets.
	_sort_internal_keysets();

	return TRUE;
}
#undef LINEBUFSIZE

static bool validate_keyset(sce_buffer_ctxt_t *ctxt, keyset_t *ks)
{
	u8 *test_buf = (u8 *)malloc(sizeof(u8) * 0x50);
	u8 *test_buf2 = (u8 *)malloc(sizeof(u8) * 0x50);
	u8 *iv = (u8 *)malloc(sizeof(u8) * 0x10);
	u8 *sblk = (u8 *)malloc(sizeof(u8) * 0x10);
	u8 *ctr_iv = (u8 *)malloc(sizeof(u8) * 0x10);
	aes_context aes_ctxt;
	size_t nc_off;
	u64 sig_input_length;
	u32 sig_algo, section_count;

	memcpy(test_buf, ctxt->metai, 0x50);

	memcpy(test_buf2, test_buf, 0x50);
	nc_off = 0;

	memcpy(iv, ks->riv, 0x10);
	aes_setkey_dec(&aes_ctxt, ks->erk, KEYBITS(ks->erklen));
	aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, 0x40, iv, test_buf2, test_buf2);
		
	nc_off = 0;
	memcpy (ctr_iv, (test_buf2 + 0x20) ,0x10);
	aes_setkey_enc(&aes_ctxt, test_buf2, METADATA_INFO_KEYBITS);
	aes_crypt_ctr(&aes_ctxt, 0x10, &nc_off, ctr_iv, sblk, (test_buf2 + 0x40), (test_buf2 + 0x40));

	sig_input_length = _ES64(*(u64*)&test_buf2[0x40]);
	sig_algo = _ES32(*(u32*)&test_buf2[0x48]);
	section_count = _ES32(*(u32*)&test_buf2[0x4C]);

	if((sig_input_length < _ES64(ctxt->cfh->file_offset)) && sig_algo == 1 && section_count < 0xFF)
		return true;

	memcpy(test_buf2, test_buf, 0x50);
	memcpy(iv, ks->riv, 0x10);
	aes_setkey_enc(&aes_ctxt, ks->erk, KEYBITS(ks->erklen));
	aes_crypt_ctr(&aes_ctxt, 0x40, &nc_off, iv, sblk, test_buf2, test_buf2);

	nc_off = 0;
	memcpy (ctr_iv, (test_buf2 + 0x20) ,0x10);
	aes_setkey_enc(&aes_ctxt, test_buf2, METADATA_INFO_KEYBITS);
	aes_crypt_ctr(&aes_ctxt, 0x10, &nc_off, ctr_iv, sblk, (test_buf2 + 0x40), (test_buf2 + 0x40));

	sig_input_length = _ES64(*(u64*)&test_buf2[0x40]);
	sig_algo = _ES32(*(u32*)&test_buf2[0x48]);
	section_count = _ES32(*(u32*)&test_buf2[0x4C]);

	if((sig_input_length < _ES64(ctxt->cfh->file_offset)) && sig_algo == 1 && section_count < 0xFF)
		return true;

	return false;
}

static keyset_t *_keyset_bruteforce_for_self(sce_buffer_ctxt_t *ctxt, u32 program_type, list_t *__keysets)
{
	LIST_FOREACH(iter, __keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;

		if(ks->program_type == program_type)
		{
			switch(program_type)
			{
			case PROGRAM_TYPE_LV0:
				if (validate_keyset(ctxt, ks))
					return ks;
				break;
			case PROGRAM_TYPE_LV1:
				if (validate_keyset(ctxt, ks))
					return ks;
				break;
			case PROGRAM_TYPE_LV2:
				if (validate_keyset(ctxt, ks))
					return ks;
				break;
			case PROGRAM_TYPE_APP:
				if (validate_keyset(ctxt, ks))
					return ks;
				break;
			case PROGRAM_TYPE_ISO:
				if (validate_keyset(ctxt, ks))
					return ks;
				break;
			case PROGRAM_TYPE_LDR:
				if (validate_keyset(ctxt, ks))
					return ks;
				break;
			case PROGRAM_TYPE_NPDRM:
				if (validate_keyset(ctxt, ks))
					return ks;
				break;
			}
		}
	}

	return NULL;
}

static keyset_t *_keyset_bruteforce_for_rvk(sce_buffer_ctxt_t *ctxt, list_t *__keysets)
{
	LIST_FOREACH(iter, __keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;

		if(ks->category == KEYCATEGORY_RVK)
			if (validate_keyset(ctxt, ks))
				return ks;
	}

	return NULL;
}

static keyset_t *_keyset_bruteforce_for_pkg(sce_buffer_ctxt_t *ctxt, list_t *__keysets)
{
	LIST_FOREACH(iter, __keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;

		if(ks->category == KEYCATEGORY_PKG)
			if (validate_keyset(ctxt, ks))
				return ks;
	}

	return NULL;
}

static keyset_t *_keyset_bruteforce_for_spp(sce_buffer_ctxt_t *ctxt, list_t *__keysets)
{
	LIST_FOREACH(iter, __keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;

		if(ks->category == KEYCATEGORY_SPP)
			if (validate_keyset(ctxt, ks))
				return ks;
	}

	return NULL;
}

keyset_t *keyset_bruteforce(sce_buffer_ctxt_t *ctxt)
{
	keyset_t *res = NULL;

	switch(_ES16(ctxt->cfh->category))
	{
	case CF_CATEGORY_SELF:
		res = _keyset_bruteforce_for_self(ctxt, _ES32(ctxt->self.ai->program_type), _keysets);
		break;
	case CF_CATEGORY_RVK:
		res = _keyset_bruteforce_for_rvk(ctxt, _keysets);
		break;
	case CF_CATEGORY_PKG:
		res = _keyset_bruteforce_for_pkg(ctxt, _keysets);
		break;
	case CF_CATEGORY_SPP:
		res = _keyset_bruteforce_for_spp(ctxt, _keysets);
		break;
	}

	if(res == NULL)
	{
		switch(_ES16(ctxt->cfh->category))
		{
		case CF_CATEGORY_SELF:
			res = _keyset_bruteforce_for_self(ctxt, _ES32(ctxt->self.ai->program_type), _internal_keysets);
			break;
		case CF_CATEGORY_RVK:
			res = _keyset_bruteforce_for_rvk(ctxt, _internal_keysets);
			break;
		case CF_CATEGORY_PKG:
			res = _keyset_bruteforce_for_pkg(ctxt, _internal_keysets);
			break;
		case CF_CATEGORY_SPP:
			res = _keyset_bruteforce_for_spp(ctxt, _internal_keysets);
			break;
		}
	}
	//Backup keyset.
	if(res != NULL)
		_used_keyset = res;
	
	if(res == NULL)
		printf("[*] Error: Could not find keyset for %s.\n", _get_name(_cert_file_categories, _ES16(ctxt->cfh->category)));

	return res;
}

keyset_t *get_used_keyset()
{
	return _used_keyset;
}

static keyset_t *_keyset_find_for_self(u32 program_type, u16 key_revision, u64 version)
{
	LIST_FOREACH(iter, _keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;

		if(ks->program_type == program_type)
		{
			switch(program_type)
			{
			case PROGRAM_TYPE_LV0:
				return ks;
				break;
			case PROGRAM_TYPE_LV1:
				if(version <= ks->version)
					return ks;
				break;
			case PROGRAM_TYPE_LV2:
				if(version <= ks->version)
					return ks;
				break;
			case PROGRAM_TYPE_APP:
				if(key_revision == ks->key_revision)
					return ks;
				break;
			case PROGRAM_TYPE_ISO:
				if(version <= ks->version && key_revision == ks->key_revision)
					return ks;
				break;
			case PROGRAM_TYPE_LDR:
				return ks;
				break;
			case PROGRAM_TYPE_NPDRM:
				if(key_revision == ks->key_revision)
					return ks;
				break;
			}
		}
	}

	return NULL;
}

static keyset_t *_keyset_find_for_rvk(u32 key_revision)
{
	LIST_FOREACH(iter, _keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;

		if(ks->category == KEYCATEGORY_RVK && key_revision <= ks->key_revision)
			return ks;
	}

	return NULL;
}

static keyset_t *_keyset_find_for_pkg(u16 key_revision)
{
	LIST_FOREACH(iter, _keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;

		if(ks->category == KEYCATEGORY_PKG && key_revision <= ks->key_revision)
			return ks;
	}

	return NULL;
}

static keyset_t *_keyset_find_for_spp(u16 key_revision)
{
	LIST_FOREACH(iter, _keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;

		if(ks->category == KEYCATEGORY_SPP && key_revision <= ks->key_revision)
			return ks;
	}

	return NULL;
}

keyset_t *keyset_find(sce_buffer_ctxt_t *ctxt)
{
	keyset_t *res = NULL;

	switch(_ES16(ctxt->cfh->category))
	{
	case CF_CATEGORY_SELF:
		res = _keyset_find_for_self(_ES32(ctxt->self.ai->program_type), _ES16(ctxt->cfh->key_revision), _ES64(ctxt->self.ai->version));
		break;
	case CF_CATEGORY_RVK:
		res = _keyset_find_for_rvk(_ES16(ctxt->cfh->key_revision));
		break;
	case CF_CATEGORY_PKG:
		res = _keyset_find_for_pkg(_ES16(ctxt->cfh->key_revision));
		break;
	case CF_CATEGORY_SPP:
		res = _keyset_find_for_spp(_ES16(ctxt->cfh->key_revision));
		break;
	}

	if(res == NULL)
		printf("[*] Error: Could not find keyset for %s.\n", _get_name(_cert_file_categories, _ES16(ctxt->cfh->category)));

	return res;
}

keyset_t *keyset_find_by_name(const s8 *name)
{
	LIST_FOREACH(iter, _keysets)
	{
		keyset_t *ks = (keyset_t *)iter->value;
		if(strcmp(ks->name, name) == 0)
			return ks;
	}

	printf("[*] Error: Could not find keyset '%s'.\n", name);

	return NULL;
}

bool curves_load(const s8 *cfile)
{
	u32 len = 0;

	_curves = (curve_t *)_read_buffer(cfile, &len);
	
	if(_curves == NULL)
		return FALSE;
	
	if(len != CURVES_LENGTH)
	{
		free(_curves);
		return FALSE;
	}
	
	return TRUE;
}

curve_t *curve_find(u8 ctype)
{
	if(ctype > CTYPE_MAX)
		return NULL;
	return &_curves[ctype];
}

bool vsh_curves_load(const s8 *cfile)
{
	u32 len = 0;

	_vsh_curves = (vsh_curve_t *)_read_buffer(cfile, &len);
	
	if(_vsh_curves == NULL)
		return FALSE;
	
	if(len != VSH_CURVES_LENGTH)
	{
		free(_vsh_curves);
		return FALSE;
	}
	
	return TRUE;
}

static curve_t _tmp_curve;
curve_t *vsh_curve_find(u8 ctype)
{
	if(ctype > VSH_CTYPE_MAX)
		return NULL;

	memcpy(_tmp_curve.p, _vsh_curves[ctype].p, 20);
	memcpy(_tmp_curve.a, _vsh_curves[ctype].a, 20);
	memcpy(_tmp_curve.b, _vsh_curves[ctype].b, 20);
	_tmp_curve.N[0] = ~0x00;
	memcpy(_tmp_curve.N+1, _vsh_curves[ctype].N, 20);
	memcpy(_tmp_curve.Gx, _vsh_curves[ctype].Gx, 20);
	memcpy(_tmp_curve.Gy, _vsh_curves[ctype].Gy, 20);

	return &_tmp_curve;
}

static u8 *idps_load()
{
	s8 *ps3 = NULL, path[256];
	u8 *idps;
	u32 len = 0;

	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(access(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s", ps3, CONFIG_IDPS_FILE);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s", CONFIG_IDPS_PATH, CONFIG_IDPS_FILE);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s/%s", ps3, CONFIG_IDPS_PATH, CONFIG_IDPS_FILE);
	}
	else
		sprintf(path, "%s/%s", CONFIG_IDPS_PATH, CONFIG_IDPS_FILE);

	idps = (u8 *)_read_buffer(path, &len);
	
	if(idps == NULL)
		return NULL;
	
	if(len != IDPS_LENGTH)
	{
		free(idps);
		return NULL;
	}
	
	return idps;
}

static act_dat_t *act_dat_load()
{
	s8 *ps3 = NULL, path[256];
	act_dat_t *act_dat;
	u32 len = 0;
	
	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(access(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s", ps3, CONFIG_ACT_DAT_FILE);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s", CONFIG_ACT_DAT_PATH, CONFIG_ACT_DAT_FILE);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s/%s", ps3, CONFIG_ACT_DAT_PATH, CONFIG_ACT_DAT_FILE);
	}
	else
		sprintf(path, "%s/%s", CONFIG_ACT_DAT_PATH, CONFIG_ACT_DAT_FILE);

	act_dat = (act_dat_t *)_read_buffer(path, &len);
	
	if(act_dat == NULL)
		return NULL;
	
	if(len != ACT_DAT_LENGTH)
	{
		free(act_dat);
		return NULL;
	}
	
	return act_dat;
}

static rif_t *rif_load(const s8 *content_id)
{
	s8 *ps3 = NULL, path[256];
	rif_t *rif;
	u32 len = 0;
	
	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(access(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s%s", ps3, content_id, CONFIG_RIF_FILE_EXT);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s%s", CONFIG_RIF_PATH, content_id, CONFIG_RIF_FILE_EXT);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s/%s%s", ps3, CONFIG_RIF_PATH, content_id, CONFIG_RIF_FILE_EXT);
	}
	else
		sprintf(path, "%s/%s%s", CONFIG_RIF_PATH, content_id, CONFIG_RIF_FILE_EXT);

	rif = (rif_t *)_read_buffer(path, &len);
	if(rif == NULL)
		return NULL;
	
	if(len < RIF_LENGTH)
	{
		free(rif);
		return NULL;
	}
	
	return rif;
}

static u8 *rap_load(const s8 *content_id)
{
	s8 *ps3 = NULL, path[256];
	u8 *rap;
	u32 len = 0;
	
	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(access(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s%s", ps3, content_id, CONFIG_RAP_FILE_EXT);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s%s", CONFIG_RAP_PATH, content_id, CONFIG_RAP_FILE_EXT);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s/%s%s", ps3, CONFIG_RAP_PATH, content_id, CONFIG_RAP_FILE_EXT);
	}
	else
		sprintf(path, "%s/%s%s", CONFIG_RAP_PATH, content_id, CONFIG_RAP_FILE_EXT);

	rap = (u8 *)_read_buffer(path, &len);
	
	if(rap == NULL)
		return NULL;
	
	if(len != RAP_LENGTH)
	{
		free(rap);
		return NULL;
	}
	
	return rap;
}

static bool rap_to_klicensee(const s8 *content_id, u8 *klicensee)
{
	u8 *rap;
	aes_context aes_ctxt;
	int round_num;
	int i;
	keyset_t *rap_init_key, *rap_pbox, *rap_e1, *rap_e2;
	
	rap_init_key = keyset_find_by_name(CONFIG_NP_RAP_INITIAL_KNAME);
	if(rap_init_key == NULL)
		return FALSE;
	
	rap_pbox = keyset_find_by_name(CONFIG_NP_RAP_PBOX_KNAME);
	if(rap_pbox == NULL)
		return FALSE;
	
	rap_e1 = keyset_find_by_name(CONFIG_NP_RAP_E1_KNAME);
	if(rap_e1 == NULL)
		return FALSE;
	
	rap_e2 = keyset_find_by_name(CONFIG_NP_RAP_E2_KNAME);
	if(rap_e2 == NULL)
		return FALSE;

	rap = rap_load(content_id);
	if(rap == NULL)
		return FALSE;

	aes_setkey_dec(&aes_ctxt, rap_init_key->erk, RAP_KEYBITS);
	aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, rap, rap);

	for (round_num = 0; round_num < 5; ++round_num)
	{
		for (i = 0; i < 16; ++i)
		{
			int p = rap_pbox->erk[i];
			rap[p] ^= rap_e1->erk[p];
		}
		for (i = 15; i >= 1; --i)
		{
			int p = rap_pbox->erk[i];
			int pp = rap_pbox->erk[i - 1];
			rap[p] ^= rap[pp];
		}
		int o = 0;
		for (i = 0; i < 16; ++i)
		{
			int p = rap_pbox->erk[i];
			u8 kc = rap[p] - o;
			u8 ec2 = rap_e2->erk[p];
			if (o != 1 || kc != 0xFF)
			{
				o = kc < ec2 ? 1 : 0;
				rap[p] = kc - ec2;
			}
			else
				rap[p] = kc - ec2;
		}
	}

	memcpy(klicensee, rap, RAP_LENGTH);
	free(rap);

	return TRUE;
}

bool klicensee_by_content_id(const s8 *content_id, u8 *klicensee)
{
	aes_context aes_ctxt;

	if(rap_to_klicensee(content_id, klicensee) == FALSE)
	{
		keyset_t *ks_np_idps_const, *ks_np_rif_key;
		rif_t *rif;
		u8 idps_const[0x10];
		u8 act_dat_key[0x10];
		u32 act_dat_key_index;
		u8 *idps;
		act_dat_t *act_dat;

		if((idps = idps_load()) == NULL)
		{
			printf("[*] Error: Could not load IDPS.\n");
			return FALSE;
		}
		else
			_LOG_VERBOSE("IDPS loaded.\n");

		if((act_dat = act_dat_load()) == NULL)
		{
			printf("[*] Error: Could not load act.dat.\n");
			return FALSE;
		}
		else
			_LOG_VERBOSE("act.dat loaded.\n");

		ks_np_idps_const = keyset_find_by_name(CONFIG_NP_IDPS_CONST_KNAME);
		if(ks_np_idps_const == NULL)
			return FALSE;
		memcpy(idps_const, ks_np_idps_const->erk, 0x10);

		ks_np_rif_key = keyset_find_by_name(CONFIG_NP_RIF_KEY_KNAME);
		if(ks_np_rif_key == NULL)
			return FALSE;

		rif = rif_load(content_id);
		if(rif == NULL)
		{
			printf("[*] Error: Could not obtain klicensee for '%s'.\n", content_id);
			return FALSE;
		}

		aes_setkey_dec(&aes_ctxt, ks_np_rif_key->erk, RIF_KEYBITS);
		aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, rif->act_key_index, rif->act_key_index);

		act_dat_key_index = _ES32(*(u32 *)(rif->act_key_index + 12));
		if(act_dat_key_index > 127)
		{
			printf("[*] Error: act.dat key index out of bounds.\n");
			return FALSE;
		}

		memcpy(act_dat_key, act_dat->primary_key_table + act_dat_key_index * BITS2BYTES(ACT_DAT_KEYBITS), BITS2BYTES(ACT_DAT_KEYBITS));

		aes_setkey_enc(&aes_ctxt, idps, IDPS_KEYBITS);
		aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, idps_const, idps_const);

		aes_setkey_dec(&aes_ctxt, idps_const, IDPS_KEYBITS);
		aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, act_dat_key, act_dat_key);

		aes_setkey_dec(&aes_ctxt, act_dat_key, ACT_DAT_KEYBITS);
		aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, rif->klicensee, klicensee);

		free(rif);

		_LOG_VERBOSE("Klicensee decrypted.\n");
	}
	else
		_LOG_VERBOSE("Klicensee converted from %s.rap.\n", content_id);

	return TRUE;
}

bool dev_klicensee_by_content_id(const s8 *content_id, u8 *klicensee)
{

	s8 *ps3 = NULL, path[256];
	u8 *klic;
	u32 len = 0;
	
	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(access(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s%s", ps3, content_id, CONFIG_KLIC_FILE_EXT);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s%s", CONFIG_KLIC_PATH, content_id, CONFIG_KLIC_FILE_EXT);
		if(access(path, 0) != 0)
			sprintf(path, "%s/%s/%s%s", ps3, CONFIG_KLIC_PATH, content_id, CONFIG_KLIC_FILE_EXT);
	}
	else
		sprintf(path, "%s/%s%s", CONFIG_KLIC_PATH, content_id, CONFIG_KLIC_FILE_EXT);

	klic = (u8 *)_read_buffer(path, &len);
	
	if(klic == NULL)
		return FALSE;
	
	if(len != KLIC_LENGTH)
	{
		free(klic);
		return FALSE;
	}
	memcpy(klicensee, klic, KLIC_LENGTH);
	free(klic);
	_LOG_VERBOSE("Klicensee loaded from %s.klic.\n", content_id);
	
	return TRUE;
}

keyset_t *keyset_from_buffer(u8 *keyset)
{
	keyset_t *ks;

	if((ks = (keyset_t *)malloc(sizeof(keyset_t))) == NULL)
		return NULL;

	ks->erk = (u8 *)_memdup(keyset, 0x20);
	ks->erklen = 0x20;
	ks->riv = (u8 *)_memdup(keyset + 0x20, 0x10);
	ks->rivlen = 0x10;
	ks->pub = (u8 *)_memdup(keyset + 0x20 + 0x10, 0x28);
	ks->priv = (u8 *)_memdup(keyset + 0x20 + 0x10 + 0x28, 0x15);
	ks->ctype = (u8)*(keyset + 0x20 + 0x10 + 0x28 + 0x15);

	return ks;
}
