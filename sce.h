/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _SCE_H_
#define _SCE_H_

#include <stdio.h>
#include <string.h>

#include "types.h"
#include "list.h"

/*! SCE file align. */
#define SCE_ALIGN 0x10
/*! Header align. */
#define HEADER_ALIGN 0x80

/*! SCE header magic value ("SCE\0"). */
#define SCE_HEADER_MAGIC 0x53434500

/*! SCE header versions. */
/*! Header version 2. */
#define SCE_HEADER_VERSION_2 2

/*! Key revisions. */
#define KEY_REVISION_0 0x00
#define KEY_REVISION_092_330 0x01
#define KEY_REVISION_1 0x02
//#define KEY_REVISION_ 0x03
#define KEY_REVISION_340_342 0x04
//#define KEY_REVISION_ 0x05
//#define KEY_REVISION_ 0x06
#define KEY_REVISION_350 0x07
//#define KEY_REVISION_ 0x08
//#define KEY_REVISION_ 0x09
#define KEY_REVISION_355 0x0a
//#define KEY_REVISION_ 0x0b
//#define KEY_REVISION_ 0x0c
#define KEY_REVISION_356 0x0d
//#define KEY_REVISION_ 0x0e
//#define KEY_REVISION_ 0x0f
#define KEY_REVISION_360_361 0x10
//#define KEY_REVISION_ 0x11
//#define KEY_REVISION_ 0x12
#define KEY_REVISION_365 0x13
//#define KEY_REVISION_ 0x14
//#define KEY_REVISION_ 0x15
#define KEY_REVISION_370_373 0x16
//#define KEY_REVISION_ 0x17
//#define KEY_REVISION_ 0x18
#define KEY_REVISION_DEBUG 0x8000

/*! SCE header types. */
/*! SELF header. */
#define SCE_HEADER_TYPE_SELF 1
/*! RVK header. */
#define SCE_HEADER_TYPE_RVK 2
/*! PKG header. */
#define SCE_HEADER_TYPE_PKG 3
/*! SPP header. */
#define SCE_HEADER_TYPE_SPP 4

/*! Sub header types. */
/*! SCE version header. */
#define SUB_HEADER_TYPE_SCEVERSION 1
/*! SELF header. */
#define SUB_HEADER_TYPE_SELF 3

/*! Control info types. */
/*! Control flags. */
#define CONTROL_INFO_TYPE_FLAGS 1
/*! Digest. */
#define CONTROL_INFO_TYPE_DIGEST 2
/*! NPDRM block. */
#define CONTROL_INFO_TYPE_NPDRM 3

/*! Optional header types. */
/*! Capability flags header. */
#define OPT_HEADER_TYPE_CAP_FLAGS 1
/*! Individuals seed header. */
#define OPT_HEADER_TYPE_INDIV_SEED 2

/*! Metadata key/iv lengths. */
#define METADATA_INFO_KEYBITS 128
#define METADATA_INFO_KEY_LEN 16
#define METADATA_INFO_KEYPAD_LEN 16
#define METADATA_INFO_IV_LEN 16
#define METADATA_INFO_IVPAD_LEN 16

/*! Metadata section types. */
/*! Segment header. */
#define METADATA_SECTION_TYPE_SHDR 1
/*! Program header. */
#define METADATA_SECTION_TYPE_PHDR 2
/*! Unknown header type 3. */
#define METADATA_SECTION_TYPE_UNK_3 3

/*! Section is hashed. */
#define METADATA_SECTION_HASHED 2
/*! Section is not encrypted. */
#define METADATA_SECTION_NOT_ENCRYPTED 1
/*! Section is encrypted. */
#define METADATA_SECTION_ENCRYPTED 3
/*! Section is not compressed. */
#define METADATA_SECTION_NOT_COMPRESSED 1
/*! Section is compressed. */
#define METADATA_SECTION_COMPRESSED 2

/*! Signature sizes. */
/*! Signature S part size. */
#define SIGNATURE_S_SIZE 21
/*! Signature R part size. */
#define SIGNATURE_R_SIZE 21

/*! Compressed. */
#define SECTION_INFO_COMPRESSED 2
/*! Not compressed. */
#define SECTION_INFO_NOT_COMPRESSED 1

/*! SCE version not present. */
#define SCE_VERSION_NOT_PRESENT 0
/*! SCE version present. */
#define SCE_VERSION_PRESENT 1

/*! SELF types. */
/*! lv0. */
#define SELF_TYPE_LV0 1
/*! lv1. */
#define SELF_TYPE_LV1 2
/*! lv2. */
#define SELF_TYPE_LV2 3
/*! Application. */
#define SELF_TYPE_APP 4
/*! Isolated SPU module. */
#define SELF_TYPE_ISO 5
/*! Secure loader. */
#define SELF_TYPE_LDR 6
/*! Unknown type 7. */
#define SELF_TYPE_UNK_7 7
/*! NPDRM application. */
#define SELF_TYPE_NPDRM 8

/*! NPDRM control info magic value ("NPD\0"). */
#define NP_CI_MAGIC 0x4E504400

/*! NPDRM license types. */
#define NP_LICENSE_NETWORK 1
#define NP_LICENSE_LOCAL 2
#define NP_LICENSE_FREE 3

/*! NPDRM application types. */
#define NP_TYPE_UPDATE 0x20
#define NP_TYPE_SPRX 0
#define NP_TYPE_EXEC 1
#define NP_TYPE_USPRX (NP_TYPE_UPDATE | NP_TYPE_SPRX)
#define NP_TYPE_UEXEC (NP_TYPE_UPDATE | NP_TYPE_EXEC)

/*! SCE header. */
typedef struct _sce_header
{
	/*! Magic value. */
	u32 magic;
	/*! Header version .*/
	u32 version;
	/*! Key revision. */
	u16 key_revision;
	/*! Header type. */
	u16 header_type;
	/*! Metadata offset. */
	u32 metadata_offset;
	/*! Header length. */
	u64 header_len;
	/*! Length of encapsulated data. */
	u64 data_len;
} sce_header_t;

/*! SELF header. */
typedef struct _self_header
{
	/*! Header type. */
	u64 header_type;
	/*! Application info offset. */
	u64 app_info_offset;
	/*! ELF offset. */
	u64 elf_offset;
	/*! Program headers offset. */
	u64 phdr_offset;
	/*! Section headers offset. */
	u64 shdr_offset;
	/*! Section info offset. */
	u64 section_info_offset;
	/*! SCE version offset. */
	u64 sce_version_offset;
	/*! Control info offset. */
	u64 control_info_offset;
	/*! Control info size. */
	u64 control_info_size;
	/*! Padding. */
	u64 padding;
} self_header_t;

/*! Metadata info. */
typedef struct _metadata_info
{
	/*! Key. */
	u8 key[METADATA_INFO_KEY_LEN];
	/*! Key padding. */
	u8 key_pad[METADATA_INFO_KEYPAD_LEN];
	/*! IV. */
	u8 iv[METADATA_INFO_IV_LEN];
	/*! IV padding. */
	u8 iv_pad[METADATA_INFO_IVPAD_LEN];
} metadata_info_t;

typedef struct _metadata_header
{
	/*! Signature input length. */
	u64 sig_input_length;
	u32 unknown_0;
	/*! Section count. */
	u32 section_count;
	/*! Key count. */
	u32 key_count;
	/*! Optional header size. */
	u32 opt_header_size;
	u32 unknown_1;
	u32 unknown_2;
} metadata_header_t;

/*! Metadata section header. */
typedef struct _metadata_section_header
{
	/*! Data offset. */
	u64 data_offset;
	/*! Data size. */
	u64 data_size;
	/*! Type. */
	u32 type;
	/*! Index. */
	u32 index;
	/*! Hashed. */
	u32 hashed;
	/*! SHA1 index. */
	u32 sha1_index;
	/*! Encrypted. */
	u32 encrypted;
	/*! Key index. */
	u32 key_index;
	/*! IV index. */
	u32 iv_index;
	/*! Compressed. */
	u32 compressed;
} metadata_section_header_t;

/*! SCE file signature. */
typedef struct _signature
{
	u8 r[SIGNATURE_R_SIZE];
	u8 s[SIGNATURE_S_SIZE];
	u8 padding[6];
} signature_t;

/*! Section info. */
typedef struct _section_info
{
	u64 offset;
	u64 size;
	u32 compressed;
	u32 unknown_0;
	u32 unknown_1;
	u32 encrypted;
} section_info_t;

/*! SCE version. */
typedef struct _sce_version
{
	/*! Header type. */
	u32 header_type;
	/*! SCE version section present? */
	u32 present;
	/*! Size. */
	u32 size;
	u32 unknown_3;
} sce_version_t;

/*! SCE version data 0x30. */
typedef struct _sce_version_data_30
{
	u16 unknown_1; //Dunno.
	u16 unknown_2; //0x0001
	u32 unknown_3; //Padding?
	u32 unknown_4; //Number of sections?
	u32 unknown_5; //Padding?
	/*! Data offset. */
	u64 offset;
	/*! Data size. */
	u64 size;
} sce_version_data_30_t;

//(auth_id & AUTH_ONE_MASK) has to be 0x1000000000000000
#define AUTH_ONE_MASK 0xF000000000000000
#define AUTH_TERRITORY_MASK 0x0FF0000000000000
#define VENDOR_TERRITORY_MASK 0xFF000000
#define VENDOR_ID_MASK 0x00FFFFFF

/*! Application info. */
typedef struct _app_info
{
	/*! Auth ID. */
	u64 auth_id;
	/*! Vendor ID. */
	u32 vendor_id;
	/*! SELF type. */
	u32 self_type;
	/*! Version. */
	u64 version;
	/*! Padding. */
	u64 padding;
} app_info_t;

/*! Control info. */
typedef struct _control_info
{
	/*! Control info type. */
	u32 type;
	/*! Size of following data. */
	u32 size;
	/*! Next flag (1 if another info follows). */
	u64 next;
} control_info_t;

#define CI_FLAG_00_80 0x80
#define CI_FLAG_00_40 0x40 //root access
#define CI_FLAG_00_20 0x20 //kernel access

#define CI_FLAG_17_01 0x01
#define CI_FLAG_17_02 0x02
#define CI_FLAG_17_04 0x04
#define CI_FLAG_17_08 0x08
#define CI_FLAG_17_10 0x10

//1B:
//bdj 0x01, 0x09
//psp_emu 0x08
//psp_transl 0x0C
#define CI_FLAG_1B_01 0x01 //may use shared mem?
#define CI_FLAG_1B_02 0x02
#define CI_FLAG_1B_04 0x04
#define CI_FLAG_1B_08 0x08 //ss

#define CI_FLAG_1F_SHAREABLE 0x01
#define CI_FLAG_1F_02 0x02 //internal?
#define CI_FLAG_1F_FACTORY 0x04
#define CI_FLAG_1F_08 0x08 //???

/*! Control info data flags. */
typedef struct _ci_data_flags
{
	u8 data[0x20];
} ci_data_flags_t;

/*! Control info data digest 0x30. */
typedef struct _ci_data_digest_30
{
	u8 digest[20];
	u64 unknown_0;
} ci_data_digest_30_t;

/*! Control info data digest 0x40. */
typedef struct _ci_data_digest_40
{
	u8 digest1[20];
	u8 digest2[20];
	u64 fw_version;
} ci_data_digest_40_t;

/*! Control info data NPDRM. */
typedef struct _ci_data_npdrm
{
	/*! Magic. */
	u32 magic;
	u32 unknown_0;
	/*! License type. */
	u32 license_type;
	/*! Application type. */
	u32 app_type;
	/*! Content ID. */
	u8 content_id[0x30];
	/*! Random padding. */
	u8 rndpad[0x10];
	/*! ContentID_FileName hash. */
	u8 hash_cid_fname[0x10];
	/*! Control info hash. */
	u8 hash_ci[0x10];
	u64 unknown_1;
	u64 unknown_2;
} ci_data_npdrm_t;

/*! Optional header. */
typedef struct _opt_header
{
	/*! Type. */
	u32 type;
	/*! Size. */
	u32 size;
	/*! Next flag (1 if another header follows). */
	u64 next;
} opt_header_t;

/*! Capability flags. */
#define CAP_FLAG_1 0x01 //only seen in PPU selfs
#define CAP_FLAG_2 0x02 //only seen in PPU selfs
#define CAP_FLAG_4 0x04 //only seen in bdj PPU self
#define CAP_FLAG_REFTOOL 0x08
#define CAP_FLAG_DEBUG 0x10
#define CAP_FLAG_RETAIL 0x20
#define CAP_FLAG_SYSDBG 0x40

#define UNK7_2000 0x2000 //hddbind?
#define UNK7_20000 0x20000 //flashbind?
#define UNK7_40000 0x40000 //discbind?
#define UNK7_80000 0x80000

#define UNK7_PS3SWU 0x116000 //dunno...

/*! SCE file capability flags. */
typedef struct _oh_data_cap_flags
{
	u64 unk3; //0
	u64 unk4; //0
	/*! Flags. */
	u64 flags;
	u32 unk6;
	u32 unk7;
} oh_data_cap_flags_t;

/*! Section context. */
typedef struct _sce_section_ctxt
{
	/*! Data buffer. */
	void *buffer;
	/*! Size. */
	u32 size;
	/*! Offset. */
	u32 offset;
	/*! May be compressed. */
	BOOL may_compr;
} sce_section_ctxt_t;

typedef struct _makeself_ctxt
{
	/*! ELF file buffer (for ELF -> SELF). */
	u8 *elf;
	/*! ELF file length. */
	u32 elf_len;
	/*! ELF header. */
	void *ehdr;
	/*! ELF header size. */
	u32 ehsize;
	/*! Program headers. */
	void *phdrs;
	/*! Program headers size. */
	u32 phsize;
	/*! Section headers. */
	void *shdrs;
	/*! Section headers size. */
	u32 shsize;
	/*! Section info count. */
	u32 si_cnt;
	/*! Number of section infos that are present as data sections. */
	u32 si_sec_cnt;
} makeself_ctxt_t;

/*! SCE file buffer context. */
typedef struct _sce_buffer_ctxt
{
	/*! SCE file buffer. */
	u8 *scebuffer;

	/*! SCE header. */
	sce_header_t *sceh;
	/*! File type dependent header. */
	union
	{
		struct
		{
			/*! SELF header. */
			self_header_t *selfh;
			/*! Application info. */
			app_info_t *ai;
			/*! Section info. */
			section_info_t *si;
			/*! SCE version. */
			sce_version_t *sv;
			/*! Control infos. */
			list_t *cis;
			/*! Optional headers. */
			list_t *ohs;
		} self;
	};
	/*! Metadata info. */
	metadata_info_t *metai;
	/*! Metadata header. */
	metadata_header_t *metah;
	/*! Metadata section headers. */
	metadata_section_header_t *metash;
	/*! SCE file keys. */
	u8 *keys;
	/*! Keys length. */
	u32 keys_len;
	/*! Signature. */
	signature_t *sig;

	/*! Metadata decrypted? */
	BOOL mdec;

	/*! Data layout. */
	/*! SCE header offset. */
	u32 off_sceh;
	union
	{
		struct
		{
			/*! SELF header offset. */
			u32 off_selfh;
			/*! Application info offset. */
			u32 off_ai;
			/*! ELF header offset. */
			u32 off_ehdr;
			/*! Program header offset. */
			u32 off_phdr;
			/*! Section info offset. */
			u32 off_si;
			/*! SCE version offset. */
			u32 off_sv;
			/*! Control infos offset. */
			u32 off_cis;
			/*! Optional headers offset. */
			u32 off_ohs;
		} off_self;
	};
	/*! Metadata info offset. */
	u32 off_metai;
	/*! Metadata header offset. */
	u32 off_metah;
	/*! Metadata section headers offset. */
	u32 off_metash;
	/*! Keys offset. */
	u32 off_keys;
	/*! Signature offset. */
	u32 off_sig;
	/*! Header padding end offset. */
	u32 off_hdrpad;

	/*! File creation type dependent data. */
	union
	{
		/*! ELF -> SELF. */
		makeself_ctxt_t *makeself;
	};

	/*! Data sections. */
	list_t *secs;
} sce_buffer_ctxt_t;

/*! Create SCE file context from SCE file buffer. */
sce_buffer_ctxt_t *sce_create_ctxt_from_buffer(u8 *scebuffer);

/*! Create SCE file context for SELF creation. */
sce_buffer_ctxt_t *sce_create_ctxt_build_self(u8 *elf, u32 elf_len);

/*! Add data section to SCE context. */
void sce_add_data_section(sce_buffer_ctxt_t *ctxt, void *buffer, u32 size, BOOL may_compr);

/*! Set metadata section header. */
void sce_set_metash(sce_buffer_ctxt_t *ctxt, u32 type, BOOL encrypted, u32 idx);

/*! Compress data. */
void sce_compress_data(sce_buffer_ctxt_t *ctxt);

/*! Layout offsets for SCE file creation. */
void sce_layout_ctxt(sce_buffer_ctxt_t *ctxt);

/*! Encrypt context. */
BOOL sce_encrypt_ctxt(sce_buffer_ctxt_t *ctxt, u8 *keyset);

/*! Write context to file. */
BOOL sce_write_ctxt(sce_buffer_ctxt_t *ctxt, s8 *fname);

/*! Decrypt header (use passed metadata_into if not NULL). */
BOOL sce_decrypt_header(sce_buffer_ctxt_t *ctxt, u8 *metadata_info, u8 *keyset);

/*! Decrypt data. */
BOOL sce_decrypt_data(sce_buffer_ctxt_t *ctxt);

/*! Print SCE file info. */
void sce_print_info(FILE *fp, sce_buffer_ctxt_t *ctxt);

/*! Get version string from version. */
s8 *sce_version_to_str(u64 version);

/*! Get version from version string. */
u64 sce_str_to_version(s8 *version);

/*! Convert hex version to dec version. */
u64 sce_hexver_to_decver(u64 version);

/*! Get control info. */
control_info_t *sce_get_ctrl_info(sce_buffer_ctxt_t *ctxt, u32 type);

/*! Get optional header. */
opt_header_t *sce_get_opt_header(sce_buffer_ctxt_t *ctxt, u32 type);

#endif
