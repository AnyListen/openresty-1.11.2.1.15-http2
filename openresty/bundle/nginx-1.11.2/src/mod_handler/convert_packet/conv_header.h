#ifndef __CONV_HEADER__
#define __CONV_HEADER__
/*
 * caoc
 * 封装转换
 * */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#ifdef __cplusplus
#include <iostream>
#include <vector>
using namespace std;
#endif

#if defined( _WIN32 ) || defined( __MINGW32__ )
#   if defined( CONVERT_PACKET_EXPORTS )
#       define CONV_EXPORT __declspec(dllexport)
#   elif defined( CONVERT_PACKET_DLL_IMPORT ) || !defined( CONVERT_PACKET_USE_STATIC_LIB )
#       define CONV_EXPORT __declspec(dllimport)
#   else
#       define CONV_EXPORT
#   endif
#else
#   define CONV_EXPORT __attribute__((visibility("default")))
#endif

#if defined( __GNUC__ )
#   define  CONV_DEPRECATED __attribute__((deprecated))
#else
#   define CONV_DEPRECATED
#endif


typedef enum
{
	conv_unknow = 0,
	conv_raw,
	conv_ts,
	conv_flv,
	conv_mp4,
	conv_avi,
    conv_mp3
}conv_packet_type;

typedef enum
{
	conv_packet_unuse = 0,
	conv_packet_header = 1,
	conv_packet_audio = 8,
	conv_packet_video = 9
}conv_packet_type_t;

typedef void*			conv_handler_t;
typedef unsigned char	conv_char_t;
typedef int64_t         conv_size_t;
typedef unsigned char   u_char;
typedef struct conv_in_out_packe_s conv_in_out_packe_t;
typedef struct conv_chain_s conv_chain_t;

struct conv_in_out_packe_s 
{
	conv_char_t         *p;
	conv_size_t          si;
	long                 stamp;
	uint32_t             cts;
	conv_packet_type_t   type;
	conv_in_out_packe_t *next;
    unsigned             frag:1;
	unsigned             key_frame:1;
#ifdef __cplusplus
	conv_in_out_packe_s():
		p(NULL),
		si(0),
		stamp(0),
		cts(0),
		type(conv_packet_unuse),
		next(NULL),
        frag(0),
        key_frame(0){}
#endif
};

typedef struct conv_str_s
{
	conv_char_t * p;
	conv_size_t   si;
#ifdef __cplusplus
	conv_str_s()
	{
		p = NULL;
		si = 0;
	}
#endif
}conv_str_t;

typedef struct  conv_codec_ctx_s
{
	int codec_video;
	int codec_audio;
	int fps;
	int w;
	int h;
	int samplerate;
	int nchannels;
	int samplesize;
	int aac_profile;
	int video_data_rate;
	int audio_data_rate;
    int bit_rate;
	conv_str_t video_config;
	conv_str_t audio_config;
	conv_str_t meta;
#ifdef __cplusplus
	conv_codec_ctx_s()
	{
		codec_video = codec_audio = fps = 
			w = h = samplerate = nchannels = samplesize = aac_profile = 
			video_data_rate = audio_data_rate = 0;
        bit_rate = 0;
	}
#endif
}conv_codec_ctx_t;

typedef struct conv_buf_s {
    u_char          *pos;
    u_char          *last;
    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
#ifdef __cplusplus
	conv_buf_s()
	{
		pos = NULL;
		last = NULL;
		start = NULL;
		end = NULL;
	}
#endif
}conv_buf_t;

struct conv_chain_s
{
	conv_buf_t buf;
	conv_chain_t * next;
#ifdef __cplusplus
	conv_chain_s()
	{
		next = NULL;
	}
#endif
};

struct _conv_frame_info
{
    conv_size_t pos;
    long stamp;
#ifdef __cplusplus
    _conv_frame_info(conv_size_t ppos = 0,long sstamp = 0):
        pos(ppos),
        stamp(sstamp)
    {
    }
#endif
};

typedef struct _conv_frame_info conv_frame_info;

typedef conv_size_t (*conv_packet_pt)(void * user,const conv_in_out_packe_t * out,int demux);

struct _conv_mem_nd
{
    void * (*newer)(void * user,conv_size_t );
    void   (*freeer)(void * user,void * );
    void * user;
#ifdef __cplusplus
	_conv_mem_nd()
	{
		user = NULL;
        newer = NULL;
        freeer = NULL;
	}
#endif
};
typedef struct _conv_mem_nd conv_mem_nd;

#define conv_movemem(dst, src, n)   (((u_char *) memmove(dst, src, n)) + (n))
#define conv_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#endif
