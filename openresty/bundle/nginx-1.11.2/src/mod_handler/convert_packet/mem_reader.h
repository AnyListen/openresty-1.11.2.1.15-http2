#ifndef __MEM_READER_H
#define __MEM_READER_H

#include "conv_header.h"

u_char conv_read_8(u_char ** p,u_char * pend);
int conv_read_32(u_char ** p,u_char * pend);
double conv_char2double(u_char ** pbuf,u_char * pend);
bool conv_big_endian_test(); 


#define conv_swicth_int(tag_data,len,pd) \
do{\
    char * ppc_tp = (char *)pd;\
    *(pd) = 0;\
    if(conv_big_endian_test()){\
        memcpy(ppc_tp,tag_data,len);\
    }\
    else{\
        size_t n_tp = 0;\
        for(; n_tp < len;++n_tp){\
            ppc_tp[n_tp] = tag_data[len-n_tp-1];\
        }\
    }\
}while(0)

#define Swap16(s) ((((s) & 0xff) << 8) | (((s) >> 8) & 0xff))

#define Swap32(l) (((l) >> 24) | \
(((l) & 0x00ff0000) >> 8)  | \
	(((l) & 0x0000ff00) << 8)  | \
	((l) << 24))

#define Swap64(ll) (((ll) >> 56) |\
	(((ll) & 0x00ff000000000000) >> 40) |\
	(((ll) & 0x0000ff0000000000) >> 24) |\
	(((ll) & 0x000000ff00000000) >> 8)    |\
	(((ll) & 0x00000000ff000000) << 8)    |\
	(((ll) & 0x0000000000ff0000) << 24) |\
	(((ll) & 0x000000000000ff00) << 40) |\
	(((ll) << 56)))

#define BigEndian_16(s) conv_big_endian_test() ? s : Swap16(s)
#define LittleEndian_16(s) conv_big_endian_test() ? Swap16(s) : s
#define BigEndian_32(l) conv_big_endian_test() ? l : Swap32(l)
#define LittleEndian_32(l) conv_big_endian_test() ? Swap32(l) : l
#define BigEndian_64(ll) conv_big_endian_test() ? ll : Swap64(ll)
#define LittleEndian_64(ll) conv_big_endian_test() ? Swap64(ll) : ll

#endif
