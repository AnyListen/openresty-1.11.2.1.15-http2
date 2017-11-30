
#ifndef __SPCIAL_CONFIG
#define __SPCIAL_CONFIG

#include "conv_header.h"
#include "mem_reader.h"

int  audio_specific_config (u_char objectType,int samplerate, int channels, u_char *p);

int  write_video_specific_Config(u_char * pBuf,int nBufLen,const u_char * sps,int nspsLength,const u_char * pps,int nppsLength);

bool conv_parse_aac_header(const conv_str_t * audio_config, uint32_t *objtype, uint32_t *srindex, uint32_t *chconf);

int index_to_samplerate(int index);

conv_in_out_packe_t *conv_append_sps_pps(long stamp,conv_str_t * video_config,class c_conv_base * base);

bool convert_copy(void* out,u_char ** in,int size,u_char * last);
void * convert_rmemcpy(void *dst, const void* src, size_t n);

#endif
