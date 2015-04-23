/*
* Copyright (c) 2011-2013 by naehrwert
* Copyright (c) 2011-2012 by Youness Alaoui <kakaroto@kakaroto.homelinux.net>
* This file is released under the GPLv2.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "types.h"
#include "util.h"
#include "elf.h"
#include "sce.h"
#include "sce_inlines.h"
#include "keys.h"
#include "aes.h"
#include "sha1.h"
#include "ecdsa.h"
#include "tables.h"
#include "config.h"
#include "zlib.h"
#include "np.h"

void _print_sce_header(FILE *fp, sce_header_t *h)
{
	const s8 *name;
	const s8 *key_revision;

	fprintf(fp, "[*] SCE Header:\n");
	fprintf(fp, " Magic           0x%08X [%s]\n", _ES32(h->magic), (_ES32(h->magic) == SCE_HEADER_MAGIC ? "OK" : "ERROR"));
	fprintf(fp, " Version         0x%08X\n", _ES32(h->version));
	
	if(_ES16(h->key_revision) == KEY_REVISION_DEBUG)
		fprintf(fp, " Key Revision    [DEBUG]\n");
	else
		fprintf(fp, " Key Revision    0x%04X\n", _ES16(h->key_revision));
	
	name = _get_name(_sce_header_types, _ES16(h->header_type));
	if(name != NULL)
		fprintf(fp, " Header Type     [%s]\n", name);
	else
		fprintf(fp, " Header Type     0x%04X\n", _ES16(h->header_type));

	fprintf(fp, " Metadata Offset 0x%08X\n", _ES32(h->metadata_offset));
	fprintf(fp, " Header Length   0x%016llX\n", _ES64(h->header_len));
	fprintf(fp, " Data Length     0x%016llX\n", _ES64(h->data_len));
}

void _print_metadata_info(FILE *fp, metadata_info_t *mi)
{
	fprintf(fp, "[*] Metadata Info:\n");
	_hexdump(fp, " Key", 0, mi->key, METADATA_INFO_KEY_LEN, FALSE);
	_hexdump(fp, " IV ", 0, mi->iv, METADATA_INFO_IV_LEN, FALSE);
}

void _print_metadata_header(FILE *fp, metadata_header_t *mh)
{
	fprintf(fp, "[*] Metadata Header:\n");
	fprintf(fp, " Signature Input Length 0x%016llX\n", _ES64(mh->sig_input_length));
	fprintf(fp, " unknown_0              0x%08X\n", _ES32(mh->unknown_0));
	fprintf(fp, " Section Count          0x%08X\n", _ES32(mh->section_count));
	fprintf(fp, " Key Count              0x%08X\n", _ES32(mh->key_count));
	fprintf(fp, " Optional Header Size   0x%08X\n", _ES32(mh->opt_header_size));
	fprintf(fp, " unknown_1              0x%08X\n", _ES32(mh->unknown_1));
	fprintf(fp, " unknown_2              0x%08X\n", _ES32(mh->unknown_2));
}

static void _print_metadata_section_header_header(FILE *fp)
{
	fprintf(fp, "[*] Metadata Section Headers:\n");
	fprintf(fp, " Idx Offset   Size     Type Index Hashed SHA1 Encrypted Key IV Compressed\n");
}

void _print_metadata_section_header(FILE *fp, metadata_section_header_t *msh, u32 idx)
{
	fprintf(fp, " %03d %08llX %08llX %02X   %02X    ", 
		idx, _ES64(msh->data_offset), _ES64(msh->data_size), _ES32(msh->type), _ES32(msh->index));

	if(_ES32(msh->hashed) == METADATA_SECTION_HASHED)
		fprintf(fp, "[YES]  %02X   ", _ES32(msh->sha1_index));
	else
		fprintf(fp, "[NO ]  --   ");

	if(_ES32(msh->encrypted) == METADATA_SECTION_ENCRYPTED)
		fprintf(fp, "[YES]     %02X  %02X ", _ES32(msh->key_index), _ES32(msh->iv_index));
	else
		fprintf(fp, "[NO ]     --  -- ");

	if(_ES32(msh->compressed) == METADATA_SECTION_COMPRESSED)
		fprintf(fp, "[YES]\n");
	else
		fprintf(fp, "[NO ]\n");
}

void _print_sce_file_keys(FILE *fp, sce_buffer_ctxt_t *ctxt)
{
	u32 i;

	//Get start of keys.
	u8 *keys = (u8 *)ctxt->metash + sizeof(metadata_section_header_t) * _ES32(ctxt->metah->section_count);

	fprintf(fp, "[*] SCE File Keys:\n");
	for(i = 0; i < _ES32(ctxt->metah->key_count); i++)
	{
		fprintf(fp, " %02X:", i);
		_hexdump(fp, "", i, keys+i*0x10, 0x10, FALSE);
	}
}

void _print_sce_signature(FILE *fp, signature_t *sig)
{
	fprintf(fp, "[*] Signature:\n");
	_hexdump(fp, " R", 0, sig->r, SIGNATURE_R_SIZE, FALSE);
	_hexdump(fp, " S", 0, sig->s, SIGNATURE_S_SIZE, FALSE);
}

void _print_sce_signature_status(FILE *fp, sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	u8 hash[0x14];
	u8 Q[0x28];
	u8 M[0x14];
	u8 zero_buf[0x14];
	keyset_t *ks;

	//Check if a keyset is provided.
	if(keyset == NULL)
	{
		//Try to find keyset.
		ks = keyset_find(ctxt);
	}
	else
	{
		//Use the provided keyset.
		ks = keyset_from_buffer(keyset);
	}
	//Generate header hash.
	sha1(ctxt->scebuffer, _ES64(ctxt->metah->sig_input_length), hash);
	_hexdump(fp, " E", 0, hash, 0x14, FALSE); 
	
	ecdsa_set_curve(ks->ctype);
	ecdsa_set_pub(ks->pub);
	
	#ifdef CONFIG_PRIVATE_BUILD
	//validate private key and calculate M
	ec_priv_to_pub(ks->priv, Q);
	get_m(ctxt->sig->r, ctxt->sig->s, hash, ks->priv, M);
	if (memcmp(ks->pub, Q, sizeof(Q)) == 0)
		_hexdump (fp, " M", 0, M, 0x14, FALSE);
	#endif
	
	//Validate the signature.
	memset(zero_buf, 0, sizeof(zero_buf));
	if ((memcmp(ctxt->sig->r, zero_buf, sizeof(zero_buf)) == 0) || (memcmp(ctxt->sig->s, zero_buf, sizeof(zero_buf)) == 0))
		fprintf(fp, "[*] Signature status: FAIL\n");
	else
		fprintf(fp, "[*] Signature status: %s\n", (ecdsa_verify(hash, ctxt->sig->r, ctxt->sig->s) == TRUE ? "OK" : "FAIL"));
}

static sce_buffer_ctxt_t *_sce_create_ctxt()
{
	sce_buffer_ctxt_t *res;

	if((res = (sce_buffer_ctxt_t *)malloc(sizeof(sce_buffer_ctxt_t))) == NULL)
		return NULL;

	memset(res, 0, sizeof(sce_buffer_ctxt_t));

	res->scebuffer = NULL;
	res->mdec = TRUE;

	//Allocate SCE header.
	res->sceh = (sce_header_t *)malloc(sizeof(sce_header_t));
	memset(res->sceh, 0, sizeof(sce_header_t));

	//Allocate metadata info (with random key/iv).
	res->metai = (metadata_info_t *)malloc(sizeof(metadata_info_t));
	_fill_rand_bytes(res->metai->key, 0x10);
	memset(res->metai->key_pad, 0, 0x10);
	_fill_rand_bytes(res->metai->iv, 0x10);
	memset(res->metai->iv_pad, 0, 0x10);
	//Allocate metadata header.
	res->metah = (metadata_header_t *)malloc(sizeof(metadata_header_t));
	//memset(res->metah, 0, sizeof(metadata_header_t));
	//Allocate signature.
	res->sig = (signature_t *)malloc(sizeof(signature_t));

	res->makeself = NULL;

	return res;
}

sce_buffer_ctxt_t *sce_create_ctxt_from_buffer(u8 *scebuffer)
{
	sce_buffer_ctxt_t *res;

	if((res = (sce_buffer_ctxt_t *)malloc(sizeof(sce_buffer_ctxt_t))) == NULL)
		return NULL;

	memset(res, 0, sizeof(sce_buffer_ctxt_t));

	res->scebuffer = scebuffer;
	res->mdec = FALSE;

	//Set pointer to SCE header.
	res->sceh = (sce_header_t *)scebuffer;

	//Set pointers to file type specific headers.
	switch(_ES16(res->sceh->header_type))
	{
		case SCE_HEADER_TYPE_SELF:
		{
			//SELF header.
			res->self.selfh = (self_header_t *)(res->scebuffer + sizeof(sce_header_t));

			//Application info.
			res->self.ai = (app_info_t *)(res->scebuffer + _ES64(res->self.selfh->app_info_offset));

			//Section infos.
			res->self.si = (section_info_t *)(res->scebuffer + _ES64(res->self.selfh->section_info_offset));

			//SCE version.
			if(_ES64(res->self.selfh->sce_version_offset) != NULL)
			{
				res->self.sv = (sce_version_t *)(res->scebuffer + _ES64(res->self.selfh->sce_version_offset));
			}
			else
				res->self.sv = 0;

			//Get pointers to all control infos.
			u32 len = (u32)(_ES64(res->self.selfh->control_info_size));
			if(len > 0)
			{
				u8 *ptr = res->scebuffer + _ES64(res->self.selfh->control_info_offset);
				res->self.cis = list_create();

				while(len > 0)
				{
					control_info_t *tci = (control_info_t *)ptr;
					ptr += _ES32(tci->size);
					len -= _ES32(tci->size);
					list_add_back(res->self.cis, tci);
				}
			}
			else
				res->self.cis = NULL;
		}
		break;
	case SCE_HEADER_TYPE_RVK:
		//TODO
		break;
	case SCE_HEADER_TYPE_PKG:
		//TODO
		break;
	case SCE_HEADER_TYPE_SPP:
		//TODO
		break;
	default:
		free(res);
		return NULL;
		break;
	}

	//Set pointers to metadata headers.
	res->metai = (metadata_info_t *)(scebuffer + sizeof(sce_header_t) + _ES32(res->sceh->metadata_offset));
	res->metah = (metadata_header_t *)((u8 *)res->metai + sizeof(metadata_info_t));
	res->metash = (metadata_section_header_t *)((u8 *)res->metah + sizeof(metadata_header_t));

	return res;
}

sce_buffer_ctxt_t *sce_create_ctxt_build_self(u8 *elf, u32 elf_len)
{
	sce_buffer_ctxt_t *res;

	if((res = _sce_create_ctxt()) == NULL)
		return NULL;

	res->sceh->magic = _ES32(SCE_HEADER_MAGIC);
	res->sceh->version = _ES32(SCE_HEADER_VERSION_2);
	res->sceh->header_type = _ES16(SCE_HEADER_TYPE_SELF);

	//Allocate SELF header.
	res->self.selfh = (self_header_t *)malloc(sizeof(self_header_t));
	memset(res->self.selfh, 0, sizeof(self_header_t));
	res->self.selfh->header_type = _ES64(SUB_HEADER_TYPE_SELF);
	//Allocate application info.
	res->self.ai = (app_info_t *)malloc(sizeof(app_info_t));
	memset(res->self.ai, 0, sizeof(app_info_t));
	//SCE version.
	res->self.sv = (sce_version_t *)malloc(sizeof(sce_version_t));
	//Create control info list.
	res->self.cis = list_create();
	//Create optional headers list.
	res->self.ohs = list_create();

	//Makeself context.
	res->makeself = (makeself_ctxt_t *)malloc(sizeof(makeself_ctxt_t));
	memset(res->makeself, 0, sizeof(makeself_ctxt_t));
	//ELF buffer.
	res->makeself->elf = elf;
	res->makeself->elf_len = elf_len;

	//Section list.
	res->secs = list_create();

	return res;
}

void sce_add_data_section(sce_buffer_ctxt_t *ctxt, void *buffer, u32 size, BOOL may_compr)
{
	sce_section_ctxt_t *sctxt = (sce_section_ctxt_t *)malloc(sizeof(sce_section_ctxt_t));
	sctxt->buffer = buffer;
	sctxt->size = size;
	sctxt->may_compr = may_compr;
	list_add_back(ctxt->secs, sctxt);
}

void sce_set_metash(sce_buffer_ctxt_t *ctxt, u32 type, BOOL encrypted, u32 idx)
{
	ctxt->metash[idx].type = _ES32(type);
	ctxt->metash[idx].index = _ES32(_ES32(type) == METADATA_SECTION_TYPE_PHDR ? idx : _ES32(type) == METADATA_SECTION_TYPE_SHDR ? idx + 1 : idx);
	ctxt->metash[idx].hashed = _ES32(METADATA_SECTION_HASHED);
	ctxt->metash[idx].encrypted = _ES32(encrypted == TRUE ? METADATA_SECTION_ENCRYPTED : METADATA_SECTION_NOT_ENCRYPTED);
	ctxt->metash[idx].compressed = _ES32(METADATA_SECTION_NOT_COMPRESSED);
}

void sce_compress_data(sce_buffer_ctxt_t *ctxt)
{
	u32 i = 0;
	uLongf size_comp, size_bound;

	LIST_FOREACH(iter, ctxt->secs)
	{
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;
		
		//Check if the section may be compressed.
		if(sec->may_compr == TRUE)
		{
			if(sec->size > 0)
			{
				size_comp = size_bound = compressBound(sec->size);
				u8 *buf = (u8 *)malloc(sizeof(u8) * size_bound);
				compress(buf, &size_comp, (const u8 *)sec->buffer, sec->size);

				if(size_comp < sec->size)
				{
					//Set compressed buffer and size.
					sec->buffer = buf;
					sec->size = size_comp;

					//Set compression in section info.
					if(_ES16(ctxt->sceh->header_type) == SCE_HEADER_TYPE_SELF && i < ctxt->makeself->si_sec_cnt)
					{
						ctxt->self.si[i].compressed = SECTION_INFO_COMPRESSED;
						//Update size too.
						ctxt->self.si[i].size = size_comp;
					}

					//Set compression in metadata section header.
					ctxt->metash[i].compressed = _ES32(METADATA_SECTION_COMPRESSED);
				}
				else
				{
					free(buf);
					_LOG_VERBOSE("Skipped compression of section %03d (0x%08X >= 0x%08X)\n", i, size_comp, sec->size);
				}
			}
			else
				_LOG_VERBOSE("Skipped compression of section %03d (size is zero)\n", i);
		}

		i++;
	}
}

static u32 _sce_get_ci_len(sce_buffer_ctxt_t *ctxt)
{
	u32 res = 0;

	LIST_FOREACH(iter, ctxt->self.cis)
		res += _ES32(((control_info_t *)iter->value)->size);

	return res;
}

static u32 _sce_get_oh_len(sce_buffer_ctxt_t *ctxt)
{
	u32 res = 0;

	LIST_FOREACH(iter, ctxt->self.ohs)
		res += _ES32(((opt_header_t *)iter->value)->size);

	return res;
}

void _sce_fixup_ctxt(sce_buffer_ctxt_t *ctxt)
{
	u32 i = 0, base_off, last_off;

	//Set section info data.
	base_off = _ES64(ctxt->sceh->header_len);
	LIST_FOREACH(iter, ctxt->secs)
	{
		//Save last offset.
		last_off = base_off;

		//Section offsets.
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;
		sec->offset = base_off;

		//Section infos for SELF (that are present as data sections).
		if(_ES16(ctxt->sceh->header_type) == SCE_HEADER_TYPE_SELF && i < ctxt->makeself->si_sec_cnt)
		//{
			ctxt->self.si[i].offset = base_off;
		//	ctxt->self.si[i].size = sec->size;
		//}

		//Metadata section headers.
		ctxt->metash[i].data_offset = _ES64(base_off);
		ctxt->metash[i].data_size = _ES64(sec->size);

		//Update offset and data length.
		base_off += sec->size;
		ctxt->sceh->data_len = _ES64(base_off - _ES64(ctxt->sceh->header_len));
		base_off = ALIGN(base_off, SCE_ALIGN);

		i++;
	}

	//Set metadata offset (counted from after SCE header).
	ctxt->sceh->metadata_offset = _ES32(ctxt->off_metai - sizeof(sce_header_t));

	//Set metadata header values.
	ctxt->metah->sig_input_length = _ES64(ctxt->off_sig);
	ctxt->metah->unknown_0 = _ES32(1);
	ctxt->metah->opt_header_size = _ES32(_sce_get_oh_len(ctxt));
	ctxt->metah->unknown_1 = _ES32(0);
	ctxt->metah->unknown_2 = _ES32(0);

	switch(_ES16(ctxt->sceh->header_type))
	{
	case SCE_HEADER_TYPE_SELF:
		{
			//Set header offsets.
			ctxt->self.selfh->app_info_offset = _ES64(ctxt->off_self.off_ai);
			ctxt->self.selfh->elf_offset = _ES64(ctxt->off_self.off_ehdr);
			ctxt->self.selfh->phdr_offset = _ES64(ctxt->off_self.off_phdr);
			ctxt->self.selfh->section_info_offset = _ES64(ctxt->off_self.off_si);
			ctxt->self.selfh->sce_version_offset = _ES64(ctxt->off_self.off_sv);
			ctxt->self.selfh->control_info_offset = _ES64(ctxt->off_self.off_cis);
			ctxt->self.selfh->control_info_size = _ES64(_sce_get_ci_len(ctxt));

			//Set section headers offset in SELF header (last data section) if available.
			if(ctxt->makeself->shdrs != NULL)
				ctxt->self.selfh->shdr_offset = _ES64(last_off);
			else
				ctxt->self.selfh->shdr_offset = _ES64(0);
		}
		break;
	case SCE_HEADER_TYPE_RVK:
		//TODO
		break;
	case SCE_HEADER_TYPE_PKG:
		//TODO
		break;
	case SCE_HEADER_TYPE_SPP:
		//TODO
		break;
	default:
		//TODO
		break;
	}
}

void _sce_fixup_keys(sce_buffer_ctxt_t *ctxt)
{
	u32 i;

	//Build keys array.
	ctxt->keys_len = 0;
	ctxt->metah->key_count = _ES32(0);
	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
	{
		if(_ES32(ctxt->metash[i].encrypted) == METADATA_SECTION_ENCRYPTED)
		{
			ctxt->keys_len += 0x80; //0x60 HMAC, 0x20 key/iv
			ctxt->metah->key_count += _ES32(8);
			ctxt->metash[i].sha1_index = _ES32(_ES32(ctxt->metah->key_count) - 8);
			ctxt->metash[i].key_index = _ES32(_ES32(ctxt->metah->key_count) - 2);
			ctxt->metash[i].iv_index = _ES32(_ES32(ctxt->metah->key_count) - 1);
		}
		else
		{
			ctxt->keys_len += 0x60; //0x60 HMAC
			ctxt->metah->key_count += _ES32(6);
			ctxt->metash[i].sha1_index = _ES32(_ES32(ctxt->metah->key_count) - 6);
			ctxt->metash[i].key_index = _ES32(0xFFFFFFFF);
			ctxt->metash[i].iv_index = _ES32(0xFFFFFFFF);
		}
	}

	//Allocate and fill keys array.
	ctxt->keys = (u8 *)malloc(sizeof(u8) * ctxt->keys_len);
	_fill_rand_bytes(ctxt->keys, ctxt->keys_len);

#ifndef CONFIG_PRIVATE_BUILD
	time_t rawtime;
	struct tm *ti;
	s8 buf[16+1];

	time(&rawtime);
	ti = localtime(&rawtime);
	sprintf(buf, "%02d%02d%02d::%02d%02d%04d", 
		ti->tm_hour, ti->tm_min, ti->tm_sec, 
		ti->tm_mday, ti->tm_mon, ti->tm_year+1900);

	memcpy(ctxt->keys + 0x20, "SURPRIZE :D "/**/, 12);
	memcpy(ctxt->keys + 0x30, "IM IN UR KEYZ !!", 16);
	u8 foo[16] = {0x09, 0xB8, 0xBE, 0xAE, 0x83, 0xC0, 0x17, 0xA6, 0x3B, 0x11, 0xB0, 0x50, 0xC4, 0xCE, 0xED, 0xF9};
	memcpy(ctxt->keys + 0x40, foo, 16);
	memcpy(ctxt->keys + 0x50, buf, 16);
#endif
}

/*! Increase offset and align it. */
#define _INC_OFF_TYPE(off, type) off; \
	off += sizeof(type); \
	off = ALIGN(off, SCE_ALIGN)
#define _INC_OFF_SIZE(off, size) off; \
	off += (size); \
	off = ALIGN(off, SCE_ALIGN)

void sce_layout_ctxt(sce_buffer_ctxt_t *ctxt)
{
	u32 coff = 0;

	//SCE header.
	ctxt->off_sceh = _INC_OFF_TYPE(coff, sce_header_t);

	switch(_ES16(ctxt->sceh->header_type))
	{
	case SCE_HEADER_TYPE_SELF:
		{
			//SELF header.
			ctxt->off_self.off_selfh = _INC_OFF_TYPE(coff, self_header_t);
			//Application info.
			ctxt->off_self.off_ai = _INC_OFF_TYPE(coff, app_info_t);
			//ELF header.
			ctxt->off_self.off_ehdr = _INC_OFF_SIZE(coff, ctxt->makeself->ehsize);
			//ELF Program headers.
			ctxt->off_self.off_phdr = _INC_OFF_SIZE(coff, ctxt->makeself->phsize);
			//Section info.
			ctxt->off_self.off_si = _INC_OFF_SIZE(coff, sizeof(section_info_t) * ctxt->makeself->si_cnt);
			//SCE version.
			ctxt->off_self.off_sv = _INC_OFF_TYPE(coff, sce_version_t);
			//Control infos.
			ctxt->off_self.off_cis = _INC_OFF_SIZE(coff, _sce_get_ci_len(ctxt));
		}
		break;
	case SCE_HEADER_TYPE_RVK:
		//TODO
		break;
	case SCE_HEADER_TYPE_PKG:
		//TODO
		break;
	case SCE_HEADER_TYPE_SPP:
		//TODO
		break;
	default:
		//TODO
		break;
	}

	//Metadata info.
	ctxt->off_metai = _INC_OFF_TYPE(coff, metadata_info_t);
	//Metadata header.
	ctxt->off_metah = _INC_OFF_TYPE(coff, metadata_header_t);
	//Metadata section headers.
	ctxt->off_metash = _INC_OFF_SIZE(coff, _ES32(ctxt->metah->section_count) * sizeof(metadata_section_header_t));
	//Keys.
	_sce_fixup_keys(ctxt);
	ctxt->off_keys = _INC_OFF_SIZE(coff, ctxt->keys_len);

	//SELF only headers.
	if(_ES16(ctxt->sceh->header_type) == SCE_HEADER_TYPE_SELF)
	{
		//Optional headers.
		ctxt->off_self.off_ohs = _INC_OFF_SIZE(coff, _sce_get_oh_len(ctxt));
	}

	//Signature.
	ctxt->off_sig = _INC_OFF_TYPE(coff, signature_t);

	//Header padding.
	ctxt->off_hdrpad = coff;
	coff = ALIGN(coff, HEADER_ALIGN);
	
	//Set header length.
	ctxt->sceh->header_len = _ES64(coff);

	//Set missing values, etc.
	_sce_fixup_ctxt(ctxt);
}

static void _sce_build_header(sce_buffer_ctxt_t *ctxt)
{
	u32 i;

	//Allocate header buffer.
	ctxt->scebuffer = (u8*)malloc(sizeof(u8) * _ES64(ctxt->sceh->header_len));
	memset(ctxt->scebuffer, 0, sizeof(u8) * _ES64(ctxt->sceh->header_len));

	//SCE header.
	memcpy((sce_header_t *)(ctxt->scebuffer + ctxt->off_sceh), ctxt->sceh, sizeof(sce_header_t));

	//File type dependent headers.
	switch(_ES16(ctxt->sceh->header_type))
	{
	case SCE_HEADER_TYPE_SELF:
		{
			//SELF header.
			memcpy((self_header_t *)(ctxt->scebuffer + ctxt->off_self.off_selfh), ctxt->self.selfh, sizeof(self_header_t));
			//Application info.
			memcpy((app_info_t *)(ctxt->scebuffer + ctxt->off_self.off_ai), ctxt->self.ai, sizeof(app_info_t));
			//ELF header.
			memcpy(ctxt->scebuffer + ctxt->off_self.off_ehdr, ctxt->makeself->ehdr, ctxt->makeself->ehsize);
			//ELF program headers.
			memcpy(ctxt->scebuffer + ctxt->off_self.off_phdr, ctxt->makeself->phdrs, ctxt->makeself->phsize);

			//Section info.
			u32 i;
			for(i = 0; i < ctxt->makeself->si_cnt; i++)
				_copy_es_section_info((section_info_t *)(ctxt->scebuffer + ctxt->off_self.off_si + sizeof(section_info_t) * i), &ctxt->self.si[i]);

			//SCE version.
			memcpy((sce_version_t *)(ctxt->scebuffer + ctxt->off_self.off_sv), ctxt->self.sv, sizeof(sce_version_t));

			//Control infos.
			u32 ci_base = ctxt->off_self.off_cis;
			LIST_FOREACH(iter, ctxt->self.cis)
			{
				control_info_t *ci = (control_info_t *)iter->value;

				//Copy control info header.
				memcpy((control_info_t *)(ctxt->scebuffer + ci_base), ci, sizeof(control_info_t));
				//Copy data.
				memcpy(ctxt->scebuffer + ci_base + sizeof(control_info_t), ((u8 *)ci) + sizeof(control_info_t), _ES32(ci->size) - sizeof(control_info_t));

				ci_base += _ES32(ci->size);
			}
		}
		break;
	case SCE_HEADER_TYPE_RVK:
		//TODO
		break;
	case SCE_HEADER_TYPE_PKG:
		//TODO
		break;
	case SCE_HEADER_TYPE_SPP:
		//TODO
		break;
	default:
		//TODO
		break;
	}

	//Metadata info.
	memcpy(ctxt->scebuffer + ctxt->off_metai, ctxt->metai, sizeof(metadata_info_t));
	//Metadata header.
	memcpy((metadata_header_t *)(ctxt->scebuffer + ctxt->off_metah), ctxt->metah, sizeof(metadata_header_t));
	//Metadata section headers.
	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
		memcpy((metadata_section_header_t *)(ctxt->scebuffer + ctxt->off_metash + sizeof(metadata_section_header_t) * i), &ctxt->metash[i], sizeof(metadata_section_header_t));

	//Keys.
	//memcpy(ctxt->scebuffer + ctxt->off_keys, ctxt->keys, ctxt->keys_len);

	//SELF only headers.
	if(_ES16(ctxt->sceh->header_type) == SCE_HEADER_TYPE_SELF)
	{
		//Optional headers.
		u32 oh_base = ctxt->off_self.off_ohs;
		LIST_FOREACH(iter, ctxt->self.ohs)
		{
			opt_header_t *oh = (opt_header_t *)iter->value;

			//Copy optional header.
			memcpy((opt_header_t *)(ctxt->scebuffer + oh_base), oh, sizeof(opt_header_t));
			//Copy data.
			memcpy(ctxt->scebuffer + oh_base + sizeof(opt_header_t), ((u8 *)oh) + sizeof(opt_header_t), _ES32(oh->size) - sizeof(opt_header_t));

			oh_base += _ES32(oh->size);
		}
	}
}

static BOOL _sce_sign_header(sce_buffer_ctxt_t *ctxt, keyset_t *ks)
{
	u8 hash[0x14];

	//Well...
	if(ks->priv == NULL || ks->pub == NULL)
		return FALSE;

	//Generate header hash.
	sha1(ctxt->scebuffer, _ES64(ctxt->metah->sig_input_length), hash);

	//Generate signature.
	ecdsa_set_curve(ks->ctype);
	ecdsa_set_pub(ks->pub);
	ecdsa_set_priv(ks->priv);
	ecdsa_sign(hash, ctxt->sig->r, ctxt->sig->s);

	//Copy Signature.
	memcpy(ctxt->scebuffer + ctxt->off_sig, ctxt->sig, sizeof(signature_t));

	return TRUE;
}

static void _sce_calculate_hashes(sce_buffer_ctxt_t *ctxt)
{
	u32 i = 0, sha1_idx;

	LIST_FOREACH(iter, ctxt->secs)
	{
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;

		sha1_idx = _ES32(ctxt->metash[i].sha1_index);
		memset(ctxt->keys + sha1_idx * 0x10, 0, 0x20);
		sha1_hmac(ctxt->keys + (sha1_idx + 2) * 0x10, 0x40, (u8 *)sec->buffer, sec->size, ctxt->keys + sha1_idx * 0x10);

		i++;
	}
}

static BOOL _sce_encrypt_header(sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	u8 *ptr;
	size_t nc_off;
	u8 sblk[0x10], iv[0x10];
	keyset_t *ks;
	aes_context aes_ctxt;

	//Check if a keyset is provided.
	if(keyset == NULL)
	{
		//Try to find keyset.
		if((ks = keyset_find(ctxt)) == NULL)
			return FALSE;
	}
	else
	{
		//Use the provided keyset.
		ks = keyset_from_buffer(keyset);
	}

	//Calculate hashes.
	_sce_calculate_hashes(ctxt);

	//Copy keys.
	memcpy(ctxt->scebuffer + ctxt->off_keys, ctxt->keys, ctxt->keys_len);

	//Sign header.
	_sce_sign_header(ctxt, ks);

	//Encrypt metadata header, metadata section headers and keys.
	nc_off = 0;
	ptr = ctxt->scebuffer + ctxt->off_metah;
	aes_setkey_enc(&aes_ctxt, ctxt->metai->key, METADATA_INFO_KEYBITS);
	memcpy(iv, ctxt->metai->iv, 0x10);
	aes_crypt_ctr(&aes_ctxt, 
		_ES64(ctxt->sceh->header_len) - (sizeof(sce_header_t) + _ES32(ctxt->sceh->metadata_offset) + sizeof(metadata_info_t)), 
		&nc_off, iv, sblk, ptr, ptr);

	//Encrypt metadata info.
	aes_setkey_enc(&aes_ctxt, ks->erk, KEYBITS(ks->erklen));
	ptr = ctxt->scebuffer + ctxt->off_metai;
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, sizeof(metadata_info_t), ks->riv, ptr, ptr);

	//Add NPDRM layer.
	if(_ES16(ctxt->sceh->header_type) == SCE_HEADER_TYPE_SELF && _ES32(ctxt->self.ai->self_type) == SELF_TYPE_NPDRM)
		if(np_encrypt_npdrm(ctxt) == FALSE)
			return FALSE;

	return TRUE;
}

static void _sce_encrypt_data(sce_buffer_ctxt_t *ctxt)
{
	u32 i = 0;
	aes_context aes_ctxt;

	LIST_FOREACH(iter, ctxt->secs)
	{
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;

		size_t nc_off = 0;
		u8 buf[16];
		u8 iv[16];

		if(_ES32(ctxt->metash[i].encrypted) == METADATA_SECTION_ENCRYPTED)
		{
			memcpy(iv, ctxt->keys + _ES32(ctxt->metash[i].iv_index) * 0x10, 0x10);
			aes_setkey_enc(&aes_ctxt, ctxt->keys + _ES32(ctxt->metash[i].key_index) * 0x10, 128);
			aes_crypt_ctr(&aes_ctxt, sec->size, &nc_off, iv, buf, (u8 *)sec->buffer, (u8 *)sec->buffer);
		}

		i++;
	}
}

BOOL sce_encrypt_ctxt(sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	//Build SCE file header.
	_sce_build_header(ctxt);

	//Encrypt header.
	if(_sce_encrypt_header(ctxt, keyset) == FALSE)
		return FALSE;

	//Encrypt data.
	_sce_encrypt_data(ctxt);

	return TRUE;
}

BOOL sce_write_ctxt(sce_buffer_ctxt_t *ctxt, s8 *fname)
{
	FILE *fp;

	if((fp = fopen(fname, "wb")) == NULL)
		return FALSE;

	//Write SCE file header.
	fwrite(ctxt->scebuffer, sizeof(u8), _ES64(ctxt->sceh->header_len), fp);

	//Write SCE file sections.
	LIST_FOREACH(iter, ctxt->secs)
	{
		sce_section_ctxt_t *sec = (sce_section_ctxt_t *)iter->value;
		fseek(fp, sec->offset, SEEK_SET);
		fwrite(sec->buffer, sizeof(u8), sec->size, fp);
	}

	fclose(fp);

	return TRUE;
}

BOOL sce_decrypt_header(sce_buffer_ctxt_t *ctxt, u8 *metadata_info, u8 *keyset)
{
	u32 i;
	size_t nc_off;
	u8 sblk[0x10], iv[0x10], ctr_iv[0x10];
	keyset_t *ks;
	aes_context aes_ctxt;

	//Check if provided metadata info should be used.
	if(metadata_info == NULL)
	{
		//Check if a keyset is provided.
		if(keyset == NULL)
		{
			//Try to find keyset.
			if((ks = keyset_find(ctxt)) == NULL)
				return FALSE;

			_LOG_VERBOSE("Using keyset [%s 0x%04X %s]\n", ks->name, ks->key_revision, sce_version_to_str(ks->version));
		}
		else
		{
			//Use the provided keyset.
			ks = keyset_from_buffer(keyset);
		}

		//Remove NPDRM layer.
		if(_ES16(ctxt->sceh->header_type) == SCE_HEADER_TYPE_SELF && _ES32(ctxt->self.ai->self_type) == SELF_TYPE_NPDRM)
			if(np_decrypt_npdrm(ctxt) == FALSE)
				return FALSE;

		//Decrypt metadata info.
		aes_setkey_dec(&aes_ctxt, ks->erk, KEYBITS(ks->erklen));
		memcpy(iv, ks->riv, 0x10); //!!!
		aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, sizeof(metadata_info_t), iv, (u8 *)ctxt->metai, (u8 *)ctxt->metai);
	}
	else
	{
		//Copy provided metadata info over SELF metadata.
		memcpy((u8 *)ctxt->metai, metadata_info, sizeof(metadata_info));
	}

	//Decrypt metadata header, metadata section headers and keys.
	nc_off = 0;
	memcpy (ctr_iv, ctxt->metai->iv ,0x10);
	aes_setkey_enc(&aes_ctxt, ctxt->metai->key, METADATA_INFO_KEYBITS);
	aes_crypt_ctr(&aes_ctxt, 
		_ES64(ctxt->sceh->header_len) - (sizeof(sce_header_t) + _ES32(ctxt->sceh->metadata_offset) + sizeof(metadata_info_t)), 
		&nc_off, ctr_iv, sblk, (u8 *)ctxt->metah, (u8 *)ctxt->metah);

	//Check if the metadata was decrypted properly.
	 if (_ES64(ctxt->metah->sig_input_length) > _ES64(ctxt->sceh->header_len))
		return FALSE;

	//Metadata decrypted.
	ctxt->mdec = TRUE;

	//Set start of SCE file keys.
	ctxt->keys = (u8 *)ctxt->metash + sizeof(metadata_section_header_t) * _ES32(ctxt->metah->section_count);
	ctxt->keys_len = _ES32(ctxt->metah->key_count) * 0x10;

	//Set SELF only headers.
	if(_ES16(ctxt->sceh->header_type) == SCE_HEADER_TYPE_SELF)
	{
		//Get pointers to all optional headers.
		ctxt->self.ohs = list_create();
		opt_header_t *oh = (opt_header_t *)(ctxt->keys + _ES32(ctxt->metah->key_count) * 0x10);
		list_add_back(ctxt->self.ohs, oh);
		while(_ES64(oh->next) != 0)
		{
			oh = (opt_header_t *)((u8 *)oh + _ES32(oh->size));
			list_add_back(ctxt->self.ohs, oh);
		}

		//Signature.
		ctxt->sig = (signature_t *)((u8 *)oh + _ES32(oh->size));
	}
	else
		ctxt->sig = (signature_t *)(ctxt->keys + _ES32(ctxt->metah->key_count) * 0x10);

	return TRUE;
}

BOOL sce_decrypt_data(sce_buffer_ctxt_t *ctxt)
{
	u32 i;
	aes_context aes_ctxt;

	//Decrypt sections.
	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
	{
		size_t nc_off = 0;
		u8 buf[16];
		u8 iv[16];

		//Only decrypt encrypted sections.
		if(_ES32(ctxt->metash[i].encrypted) == METADATA_SECTION_ENCRYPTED)
		{
			if(_ES32(ctxt->metash[i].key_index) > _ES32(ctxt->metah->key_count) - 1 || _ES32(ctxt->metash[i].iv_index) > _ES32(ctxt->metah->key_count))
				printf("[*] Warning: Skipped decryption of section %03d (marked encrypted but key/iv index out of range)\n", i);
			else
			{
				memcpy(iv, ctxt->keys + _ES32(ctxt->metash[i].iv_index) * 0x10, 0x10);
				aes_setkey_enc(&aes_ctxt, ctxt->keys + _ES32(ctxt->metash[i].key_index) * 0x10, 128);
				u8 *ptr = ctxt->scebuffer + _ES64(ctxt->metash[i].data_offset);
				aes_crypt_ctr(&aes_ctxt, _ES64(ctxt->metash[i].data_size), &nc_off, iv, buf, ptr, ptr);
			}
		}
	}

	return TRUE;
}

void sce_print_info(FILE *fp, sce_buffer_ctxt_t *ctxt, u8 *keyset)
{
	u32 i;

	//Print SCE header.
	_print_sce_header(fp, ctxt->sceh);

	//Check if the metadata was decrypted.
	if(ctxt->mdec == FALSE)
		return;

	//Print metadata infos.
	_print_metadata_info(fp, ctxt->metai);
	_print_metadata_header(fp, ctxt->metah);

	//Print section infos.
	_print_metadata_section_header_header(fp);
	for(i = 0; i < _ES32(ctxt->metah->section_count); i++)
		_print_metadata_section_header(fp, &ctxt->metash[i], i);

	//Print keys.
	_print_sce_file_keys(fp, ctxt);
	
	//Print signature.
	_print_sce_signature(fp, ctxt->sig);
	
	//Print signature status.
	_print_sce_signature_status(fp, ctxt, keyset);
}

static s8 _sce_tmp_vstr[16];
s8 *sce_version_to_str(u64 version)
{
	u32 v = version >> 32;
	sprintf(_sce_tmp_vstr, "%02X.%02X", (v & 0xFFFF0000) >> 16, v & 0x0000FFFF);
	return _sce_tmp_vstr;
}

u64 sce_str_to_version(s8 *version)
{
	u16 h, l;
	sscanf(version, "%02X.%02X", &h, &l);
	return ((u64)(h << 16 | l)) << 32;
}

u64 sce_hexver_to_decver(u64 version)
{
	//TODO: hackity hack.
	s8 tmp[16];
	u32 v = version >> 32;
	u64 res;

	sprintf(tmp, "%02X%02X", (v & 0xFFFF0000) >> 16, v & 0x0000FFFF);
	sscanf(tmp, "%d", &v);
	res = v*100;

	return res;
}

control_info_t *sce_get_ctrl_info(sce_buffer_ctxt_t *ctxt, u32 type)
{
	LIST_FOREACH(iter, ctxt->self.cis)
	{
		control_info_t *ci = (control_info_t *)iter->value;
		if(_ES32(ci->type) == type)
			return ci;
	}

	return NULL;
}

opt_header_t *sce_get_opt_header(sce_buffer_ctxt_t *ctxt, u32 type)
{
	LIST_FOREACH(iter, ctxt->self.ohs)
	{
		opt_header_t *oh = (opt_header_t *)iter->value;
		if(_ES32(oh->type) == type)
			return oh;
	}

	return NULL;
}