#ifndef __CONVERT_PACKET
#define __CONVERT_PACKET

#include "conv_header.h"

/*
 * 转封装的库.
 * caoc
 * 490479164@qq.com
 * 2015-02-10
 * */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 开始转封装.
 * 参数说明:
 * src 源类型
 * dst 需要转换的类型
 * psrc 源数据.可以是内存,也可以是文件名.是文件名的时候,si为0.否则si为内存大小.
 * pt  为转封装数据的回调.
 * user 用户参数
 * all_conv 是否一次性转完.ts可以按关键帧切片.
 * nd 内存操作的回调函数.为空的时候内部使用new delete销毁,pt回调函数中就不能保留数据指针,需要拷贝了.
* */
CONV_EXPORT conv_handler_t conv_create_convert( 
        conv_packet_type src, 
        conv_packet_type dst, 
        conv_char_t * psrc, 
        conv_size_t si, 
        conv_packet_pt pt, 
        void * user, 
        int all_conv,
        const conv_mem_nd * nd
        );

/*
 * 销毁句柄
 * */
CONV_EXPORT void conv_destory_convert(conv_handler_t h);

/*
 *  获取时长
 * */
CONV_EXPORT double conv_get_duration(conv_handler_t h);

/*
 * 获取关键帧信息
 * 参数说明:
 * mux_demux 
 * 0 为获取复用的关键帧列表
 * 1 为获取解复用的关键帧列表
 * */
CONV_EXPORT conv_size_t conv_get_key_frmaes_size(conv_handler_t h,int mux_demux);
CONV_EXPORT int conv_get_key_frames(conv_handler_t h,conv_frame_info * out,int si,int mux_demux);

/*
 * 按起始帧开始转换
 * 参数说明:
 * start_frame 开始从哪个关键帧开始转换.
 * gop 需要转换的gop个数.
 * rebuild_header 是否重建头
 * */
CONV_EXPORT int conv_convert_frames(conv_handler_t h,conv_size_t start_frame,int gop,int rebuild_header,const conv_mem_nd * nd);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
