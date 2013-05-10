/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _SPP_H_
#define _SPP_H_

#include "types.h"
#include "sce.h"

/*! SPP entry types. */
#define SPP_ENTRY_TYPE_1 1
#define SPP_ENTRY_TYPE_2 2

/*! SPP header. */
typedef struct _spp_header
{
	u16 unk1;
	u16 unk2;
	u32 spp_size;
	u32 unk3;
	u32 unk4;
	u64 unk5;
	u32 entcnt;
	u32 unk7;
} spp_header_t;

static inline void _es_spp_header(spp_header_t *h)
{
	h->unk1 = _ES16(h->unk1);
	h->unk2 = _ES16(h->unk2);
	h->spp_size = _ES32(h->spp_size);
	h->unk3 = _ES32(h->unk3);
	h->unk4 = _ES32(h->unk4);
	h->unk5 = _ES64(h->unk5);
	h->entcnt = _ES32(h->entcnt);
	h->unk7 = _ES32(h->unk7);
}

/*! SPP entry header. */
typedef struct _spp_entry_header
{
	u32 entry_size;
	u32 type;
	u64 laid;
	u64 paid;
	u8 name[0x20];
} spp_entry_header_t;

static inline void _es_spp_entry_header(spp_entry_header_t *h)
{
	h->entry_size = _ES32(h->entry_size);
	h->type = _ES32(h->type);
	h->laid = _ES64(h->laid);
	h->paid = _ES64(h->paid);
}

/*! Print SPP infos. */
void spp_print(FILE *fp, sce_buffer_ctxt_t *ctxt);

#endif
