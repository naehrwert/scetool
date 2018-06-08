/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _SELF_H_
#define _SELF_H_

#include "types.h"
#include "config.h"
#include "np.h"

/*! PS3 specific ELF constants. */
/*! LV2 OS ABI. */
#define ELFOSABI_CELL_LV2 0x66
/*! PRX ELF type. */
#define ET_PS3PRX 0xFFA4
/*! PS3 Params. */
#define PT_PS3_PARAMS 0x60000001
/*! PS3 PRX. */
#define PT_PS3_PRX 0x60000002
/*! PRX Relocations. */
#define PT_PS3_PRX_RELOC 0x700000A4

/*! SELF config. */
typedef struct _self_config
{
	/*! Add section headers. */
	bool add_shdrs;
	/*! Compress data. */
	bool compress_data;
	/*! Skip sections. */
	bool skip_sections;

	/*! Key revision. */
	u16 key_revision;
	/*! Auth ID. */
	u64 auth_id;
	/*! Vendor ID. */
	u32 vendor_id;
	/*! Program type. */
	u32 program_type;
	/*! Application version. */
	u64 app_version;
	/*! Firmware version. */
	u64 fw_version;
	/*! Control flags. */
	u8 *ctrl_flags;
	/*! Capability flags. */
	u8 *cap_flags;
	/*! Individuals seed. */
	u8 *indiv_seed;
	/*! Individuals seed size. */
	u32 indiv_seed_size;

	/*! NPDRM config (used if not NULL). */
	npdrm_config_t *npdrm_config;
} self_config_t;

/*! Print SELF info. */
bool self_print_info(FILE *fp, sce_buffer_ctxt_t *ctxt);

/*! Print SELF encrypted info. */
bool self_print_encrypted_info(FILE *fp, sce_buffer_ctxt_t *ctxt);

/*! Create ELF from SELF. */
bool self_write_to_elf(sce_buffer_ctxt_t *ctxt, const s8 *elf_out);

/*! Create SELF from ELF. */
bool self_build_self(sce_buffer_ctxt_t *ctxt, self_config_t *sconf);

#endif
