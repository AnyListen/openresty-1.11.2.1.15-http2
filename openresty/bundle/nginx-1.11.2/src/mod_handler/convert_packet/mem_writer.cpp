/*
 * =====================================================================================
 *
 *       Filename:  mem_writer.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2015年02月02日 22时21分37秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (490479164@qq.com), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "mem_writer.h"

conv_size_t  conv_write_data(conv_mem_writer *b, const void *data, conv_size_t n)
{
    if(b->si < n)
        return 0;

    memcpy(b->pos, data, n);
    b->pos += n;
    b->si -= n;
    return n;
}


int conv_wfourcc(conv_mem_writer * bytes,const char s[4])
{
    if(bytes->si < 4)
        return 0;
    memcpy(bytes->pos,s,4);
    bytes->si -= 4;
    bytes->pos += 4;
    return 4;
}

int conv_skip_field(conv_mem_writer * bytes,u_char * pos)
{
    if(pos < bytes->start || pos > bytes->end)
        return 0;

    bytes->pos = pos;
    bytes->si = bytes->end - pos;
    return 1;
}

int conv_write_field_64(conv_mem_writer * bytes, uint64_t n)
{
    conv_size_t old = bytes->si;
    conv_write_field_32(bytes, (uint32_t)(n >> 32));
    conv_write_field_32(bytes, (uint32_t)(n & 0xffffffff));
    return bytes->si - old;
}

int conv_write_field_32(conv_mem_writer * bytes, uint32_t n)
{
    if(bytes->si < 4)
        return 0;

    bytes->pos[0] = ((uint32_t) n >> 24) & 0xFF;
    bytes->pos[1] = ((uint32_t) n >> 16) & 0xFF;
    bytes->pos[2] = ((uint32_t) n >> 8) & 0xFF;
    bytes->pos[3] = (uint32_t) n & 0xFF;

    bytes->si -= 4;
    bytes->pos += 4;
    return 4;
}

int conv_write_field_24(conv_mem_writer * bytes,uint32_t n)
{
    if(bytes->si < 3)
        return 0;

    bytes->pos[0] = ((uint32_t) n >> 16) & 0xFF;
    bytes->pos[1] = ((uint32_t) n >> 8) & 0xFF;
    bytes->pos[2] = (uint32_t) n & 0xFF;

    bytes->si -= 3;
    bytes->pos += 3;
    return 3;
}

int conv_write_field_16(conv_mem_writer * bytes, uint16_t n)
{
    if(bytes->si < 2)
        return 0;

    bytes->pos[0] = ((uint32_t) n >> 8) & 0xFF;
    bytes->pos[1] = (uint32_t) n & 0xFF;

    bytes->si -= 2;
    bytes->pos += 2;
    return 2;
}

int conv_write_field_8(conv_mem_writer * bytes, uint8_t n)
{
    if(bytes->si < 1)
        return 0;

    bytes->pos[0] = n & 0xFF;

    bytes->si -= 1;
    bytes->pos += 1;
    return 1;
}
