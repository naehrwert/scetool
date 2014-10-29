/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "types.h"
#include "util.h"
#include "zlib.h"
#include "mt19937.h"

void _hexdump(FILE *fp, const char *name, u32 offset, u8 *buf, int len, BOOL print_addr)
{
	int i, j, align = strlen(name) + 1;

	fprintf(fp, "%s ", name);
	if(print_addr == TRUE)
		fprintf(fp, "%08x: ", offset);
	for(i = 0; i < len; i++)
	{
		if(i % 16 == 0 && i != 0)
		{
			fprintf(fp, "\n");
			for(j = 0; j < align; j++)
				putchar(' ');
			if(print_addr == TRUE)
				fprintf(fp, "%08X: ", offset + i);
		}
		fprintf(fp, "%02X ", buf[i]);
	}
	fprintf(fp, "\n");
}

void _print_align(FILE *fp, const s8 *str, s32 align, s32 len)
{
	s32 i, tmp;
	tmp = align - len;
	if(tmp < 0)
			tmp = 0;
	for(i = 0; i < tmp; i++)
		fputs(str, fp);
}

u8 *_read_buffer(const s8 *file, u32 *length)
{
	FILE *fp;
	u32 size;

	if((fp = fopen(file, "rb")) == NULL)
		return NULL;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	u8 *buffer = (u8 *)malloc(sizeof(u8) * size);
	fread(buffer, sizeof(u8), size, fp);

	if(length != NULL)
		*length = size;

	fclose(fp);

	return buffer;
}

int _write_buffer(const s8 *file, u8 *buffer, u32 length)
{
	FILE *fp;

	if((fp = fopen(file, "wb")) == NULL)
		return 0;

	/**/
	while(length > 0)
	{
		u32 wrlen = 1024;
		if(length < 1024)
			wrlen = length;
		fwrite(buffer, sizeof(u8), wrlen, fp);
		length -= wrlen;
		buffer += 1024;
	}
	/**/

	//fwrite(buffer, sizeof(u8), length, fp);

	fclose(fp);

	return 1;
}

const s8 *_get_name(id_to_name_t *tab, u64 id)
{
	u32 i = 0;

	while(!(tab[i].name == NULL && tab[i].id == 0))
	{
		if(tab[i].id == id)
			return tab[i].name;
		i++;
	}

	return NULL;
}

u64 _get_id(id_to_name_t *tab, const s8 *name)
{
	u32 i = 0;

	while(!(tab[i].name == NULL && tab[i].id == 0))
	{
		if(strcmp(tab[i].name, name) == 0)
			return tab[i].id;
		i++;
	}

	return (u64)(-1);
}

void _zlib_inflate(u8 *in, u64 len_in, u8 *out, u64 len_out)
{
	z_stream s;
	memset(&s, 0, sizeof(z_stream));

	s.zalloc = Z_NULL;
	s.zfree = Z_NULL;
	s.opaque = Z_NULL;

	inflateInit(&s);

	s.avail_in = len_in;
	s.next_in = in;
	s.avail_out = len_out;
	s.next_out = out;

	inflate(&s, Z_FINISH);

	inflateEnd(&s);
}

void _zlib_deflate(u8 *in, u64 len_in, u8 *out, u64 len_out)
{
	z_stream s;
	memset(&s, 0, sizeof(z_stream));

	s.zalloc = Z_NULL;
	s.zfree = Z_NULL;
	s.opaque = Z_NULL;

	deflateInit(&s, Z_BEST_COMPRESSION);

	s.avail_in = len_in;
	s.next_in = in;
	s.avail_out = len_out;
	s.next_out = out;

	deflate(&s, Z_FINISH);

	deflateEnd(&s);
}

static mt19937_ctxt_t _mt19937_ctxt;
static BOOL _mt_init = FALSE;

u8 _get_rand_byte()
{
	if(_mt_init == FALSE)
	{
		_mt_init = TRUE;
		mt19937_init(&_mt19937_ctxt, clock());
	}

	return (u8)(mt19937_update(&_mt19937_ctxt) & 0xFF);
}

void _fill_rand_bytes(u8 *dst, u32 len)
{
	u32 i;

	for(i = 0; i < len; i++)
		dst[i] = _get_rand_byte();
}

void _memcpy_inv(u8 *dst, u8 *src, u32 len)
{
	u32 i;
	for (i = 0; i < len; i++)
		dst[i] = ~src[i];
}

void *_memdup(void *ptr, u32 size)
{
	void *res = malloc(size);

	if(res != NULL)
		memcpy(res, ptr, size);
	
	return res;
}

u64 _x_to_u64(const s8 *hex)
{
	u64 t = 0, res = 0;
	u32 len = strlen(hex);
	char c;

	while(len--)
	{
		c = *hex++;
		if(c >= '0' && c <= '9')
			t = c - '0';
		else if(c >= 'a' && c <= 'f')
			t = c - 'a' + 10;
		else if(c >= 'A' && c <= 'F')
			t = c - 'A' + 10;
		else
			t = 0;
		res |= t << (len * 4);
	}

	return res;
}

u8 *_x_to_u8_buffer(const s8 *hex)
{
	u32 len = strlen(hex);
	s8 xtmp[3] = {0, 0, 0};

	//Must be aligned to 2.
	if(len % 2 != 0)
		return NULL;

	u8 *res = (u8 *)malloc(sizeof(u8) * len);
	u8 *ptr = res;

	while(len--)
	{
		xtmp[0] = *hex++;
		xtmp[1] = *hex++;

		*ptr++ = (u8)_x_to_u64(xtmp);
	}

	return res;
}
