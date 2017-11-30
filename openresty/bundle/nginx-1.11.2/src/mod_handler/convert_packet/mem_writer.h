#ifndef __MEM_WRITER_H
#define __MEM_WRITER_H

#include "conv_header.h"

/*
 * si 为输入输出参数
 * */

struct conv_mem_writer
{
    u_char      *start;
    u_char      *end;
    u_char      *pos;
    conv_size_t  si;
    conv_mem_writer():
    start(NULL),
    end(NULL),
    pos(NULL),
    si(0)
    {
    }
};

conv_size_t  conv_write_data(conv_mem_writer *b, const void *data, conv_size_t n);

int conv_skip_field(conv_mem_writer * bytes,u_char * pos);

int conv_write_field_64(conv_mem_writer * bytes,uint64_t n);

int conv_write_field_32(conv_mem_writer * bytes,uint32_t n);

int conv_write_field_24(conv_mem_writer * bytes,uint32_t n);

int conv_write_field_16(conv_mem_writer * bytes,uint16_t n);

int conv_write_field_8(conv_mem_writer * bytes,uint8_t n);

int conv_wfourcc(conv_mem_writer * bytes, const char s[4]);
#endif
