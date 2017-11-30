/*
 * =====================================================================================
 *
 *       Filename:  convert_packet.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月07日 15时00分06秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (), 
 *   Organization:  490479164@qq.com
 *
 * =====================================================================================
 */
#include "stdafx.h"
#include "convert_packet.h"
#include "c_conv_base.h"

CONV_EXPORT conv_handler_t conv_create_convert(
        conv_packet_type src,
        conv_packet_type dst,
        conv_char_t * psrc,
        conv_size_t si,
		conv_packet_pt pt,
        void *user,
        int all_conv,
        const conv_mem_nd * nd
        )
{
	c_conv_impl * h = new c_conv_impl;
	if (!h->create(src,dst,psrc,si,pt,user,all_conv,nd))
	{
		delete h;
		return NULL;
	}
	return h;
}

CONV_EXPORT void conv_destory_convert(conv_handler_t h)
{
	c_conv_impl * hh = (c_conv_impl*)h;
	delete hh;
}

CONV_EXPORT conv_size_t conv_get_key_frmaes_size(conv_handler_t h,int mux_demux)
{
	c_conv_impl * hh = (c_conv_impl*)h;
    return hh->get_key_frames_size(mux_demux);
}

CONV_EXPORT int conv_get_key_frames(conv_handler_t h,conv_frame_info * out,int si,int mux_demux)
{
	c_conv_impl * hh = (c_conv_impl*)h;
    return hh->get_key_frames(out,si,mux_demux);
}

CONV_EXPORT double conv_get_duration(conv_handler_t h)
{
	c_conv_impl * hh = (c_conv_impl*)h;
    return hh->get_duration();
}

CONV_EXPORT int conv_convert_frames(conv_handler_t h,conv_size_t start_frame,int gop,int rebuild_header,const conv_mem_nd * nd)
{
	c_conv_impl * hh = (c_conv_impl*)h;
    return hh->convert_frams(start_frame,gop,rebuild_header,nd);
}
