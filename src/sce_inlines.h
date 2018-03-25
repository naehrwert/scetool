/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _SCE_INLINES_H_
#define _SCE_INLINES_H_

#include <string.h>

#include "types.h"
#include "sce.h"


static inline void _es_segment_info(segment_info_t *si)
{
	si->offset = _ES64(si->offset);
	si->size = _ES64(si->size);
	si->compressed = _ES32(si->compressed);
	si->unknown_0 = _ES32(si->unknown_0);
	si->unknown_1 = _ES32(si->unknown_1);
	si->encrypted = _ES32(si->encrypted);
}

static inline void _copy_es_segment_info(segment_info_t *dst, segment_info_t *src)
{
	memcpy(dst, src, sizeof(segment_info_t)); 
	_es_segment_info(dst);
}

static inline void _es_ci_data_digest_40(ci_data_digest_40_t *dig)
{
	dig->fw_version = _ES64(dig->fw_version);
}

static inline void _copy_es_ci_data_digest_40(ci_data_digest_40_t *dst, ci_data_digest_40_t *src)
{
	memcpy(dst, src, sizeof(ci_data_digest_40_t)); 
	_es_ci_data_digest_40(dst);
}

static inline void _es_oh_data_cap_flags(oh_data_cap_flags_t *cf)
{
	cf->unk3 = _ES64(cf->unk3);
	cf->unk4 = _ES64(cf->unk4);
	cf->flags = _ES64(cf->flags);
	cf->unk6 = _ES32(cf->unk6);
	cf->unk7 = _ES32(cf->unk7);
}

static inline void _copy_es_cap_flags(oh_data_cap_flags_t *dst, oh_data_cap_flags_t *src)
{
	memcpy(dst, src, sizeof(oh_data_cap_flags_t)); 
	_es_oh_data_cap_flags(dst);
}

#endif
