/*
 * =====================================================================================
 *
 *       Filename:  mem_reader.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2015年01月29日 19时34分57秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (490479164@qq.com), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "mem_reader.h"

u_char conv_read_8(u_char ** p,u_char * pend)
{
    if(*p + 1 > pend)
        return -1;

    ++(*p);
    return (*p)[-1];
}

int conv_read_32(u_char ** p,u_char * pend)
{
    if(*p + 4 > pend)
        return -1;

    int len = 0;
    conv_swicth_int((*p),4,&len);
    *p += 4;
    return len;
}

double conv_char2double(u_char ** pbuf,u_char * pend)
{
    double scr = 0.0;
    unsigned char * buf_2 = (unsigned char*)&scr;
    //大小端问题
    u_char * buf = *pbuf;
    if(buf + 8 > pend)
        return scr;

    if(conv_big_endian_test())
    {
        memcpy(&scr,buf,8);
    }
    else
    {
        buf_2[0] = buf[7];
        buf_2[1] = buf[6];
        buf_2[2] = buf[5];
        buf_2[3] = buf[4];
        buf_2[4] = buf[3];
        buf_2[5] = buf[2];
        buf_2[6] = buf[1];
        buf_2[7] = buf[0];
    }
    (*pbuf) += 8;
    return scr;
}

bool conv_big_endian_test() 
{  
#define FLV_BIGENDIAN true  
#define FLV_LITTLEENDIAN  false 
	const short n = 1;  
	if(*(char *)&n)  
	{  
		return FLV_LITTLEENDIAN;  
	}  
	return FLV_BIGENDIAN;  
} 

