/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _KEYS_H_
#define _KEYS_H_

#include "types.h"
#include "sce.h"

#define KEYBITS(klen) BYTES2BITS(klen)

#define KEYTYPE_SELF 1
#define KEYTYPE_RVK 2
#define KEYTYPE_PKG 3
#define KEYTYPE_SPP 4
#define KEYTYPE_OTHER 5

/*! Flag to use VSH curve. */
#define USE_VSH_CURVE 0x40

/*! Length of whole curves file. */
#define CURVES_LENGTH 0x1E40
#define CTYPE_MIN 0
#define CTYPE_MAX 63

/*! Length of the whole VSH curves file. */
#define VSH_CURVES_LENGTH 0x168
#define VSH_CTYPE_MIN 0
#define VSH_CTYPE_MAX 2

/*! Length of the idps, act.dat, .rif and .rap files. */
#define IDPS_LENGTH 0x10
#define ACT_DAT_LENGTH 0x1038
#define RIF_LENGTH 0x98
#define RAP_LENGTH 0x10

/*! IDPS, RIF, act.dat key lengths. */
#define IDPS_KEYBITS 128
#define ACT_DAT_KEYBITS 128
#define RIF_KEYBITS 128
#define RAP_KEYBITS 128

/*! Keyset. */
typedef struct _keyset
{
	/*! Name. */
	s8 *name;
	/*! Type. */
	u32 type;
	/*! Key revision. */
	u16 key_revision;
	/*! Version. */
	u64 version;
	/*! SELF type. */
	u32 self_type;
	/*! Key length. */
	u32 erklen;
	/*! Key. */
	u8 *erk;
	/*! IV length. */
	u32 rivlen;
	/*! IV. */
	u8 *riv;
	/*! Pub. */
	u8 *pub;
	/*! Priv. */
	u8 *priv;
	/*! Curve type. */
	u8 ctype;
} keyset_t;

/*! Curve entry. */
typedef struct _curve
{
	u8 p[20];
	u8 a[20];
	u8 b[20];
	u8 N[21];
	u8 Gx[20];
	u8 Gy[20];
} curve_t;

/*! VSH Curve entry. */
typedef struct _vsh_curve
{
	u8 a[20];
	u8 b[20];
	u8 N[20];
	u8 p[20];
	u8 Gx[20];
	u8 Gy[20];
} vsh_curve_t;

/*! act.dat. */
typedef struct _act_dat
{
	u8 account_info[16];
    u8 primary_key_table[2048];
    u8 secondary_key_table[2048];
    u8 signature[40];
} act_dat_t;

/*! RIF. */
typedef struct _rif
{
	u8 account_info[16];
	u8 content_id[48];
	u8 act_key_index[16];
	u8 klicensee[16];
	u64 timestamp;
	u64 zero;
	u8 signature[40];
} rif_t;

void _print_key_list(FILE *fp);

BOOL keys_load(const s8 *kfile);
keyset_t *keyset_find(sce_buffer_ctxt_t *ctxt);
keyset_t *keyset_find_by_name(const s8 *name);

BOOL curves_load(const s8 *cfile);
curve_t *curve_find(u8 ctype);

BOOL vsh_curves_load(const s8 *cfile);
curve_t *vsh_curve_find(u8 ctype);

BOOL klicensee_by_content_id(const s8 *content_id, u8 *klicensee);

keyset_t *keyset_from_buffer(u8 *keyset);

#endif
