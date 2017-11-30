#pragma once

/*
 * caoc 
 * 转封装的基类与控制类 2015-02-09
 * */

#include "conv_header.h"
#include "FileProvider.h"
#include "codec_id.h"
#include <limits.h>
#include  <errno.h>

#define caoc_pf printf
#define conv_max(a,b) a > b ? a : b
#define CONV_DEBUG 1
#define CONV_WRITE_TEST_FILE 1
#define OUT 

#ifndef INT32_MAX
#define INT32_MAX   0x7fffffffL
#endif

#ifndef UINT16_MAX
#define UINT16_MAX     (65535) 
#endif

#ifndef UINT32_MAX
#define UINT32_MAX     (4294967295U)
#endif

#ifndef UINT64_C
# if __WORDSIZE == 64
#  define UINT64_C(c)	c ## UL
# else
#  define UINT64_C(c)	c ## ULL
# endif
#endif

using namespace std;

#define FF_ARRAY_ELEMS(a) (sizeof(a) / sizeof((a)[0]))
#define conv_zero(data,si) memset(data,0,si)
#define conv_safe_cb(cb,...) if(cb) cb(__VA_ARGS__)
#define conv_safe_cbr(cb,ret,...) \
    do{\
        if(cb) return cb(__VA_ARGS__);\
        else return ret;\
    }while(0)

#define FFMAX(a,b) ((a) > (b) ? (a) : (b))
#define FFMAX3(a,b,c) FFMAX(FFMAX(a,b),c)
#define FFMIN(a,b) ((a) > (b) ? (b) : (a))
#define FFMIN3(a,b,c) FFMIN(FFMIN(a,b),c)

#define MKBETAG(a,b,c,d) ((d) | ((c) << 8) | ((b) << 16) | ((unsigned)(a) << 24))

class conv_node_opt_s
{
public:
    conv_node_opt_s()
    {
        get_node_cb = NULL;
        push_node_cb = NULL;
        free_node_cb = NULL;
        user = NULL;
        push_keyframe_cb = NULL;
    }
    conv_in_out_packe_t * get_node(conv_size_t si)
    {
        conv_safe_cbr(get_node_cb,NULL,user,si); 
    }
    bool push_node(const conv_in_out_packe_t * node,bool freenow)
    {
        conv_safe_cbr(push_node_cb,false,user,node,freenow);
    }
    bool free_node(const conv_in_out_packe_t * node)
    {
        conv_safe_cbr(free_node_cb,false,user,node);
    }
    bool push_keyframe(const conv_frame_info * node)
    {
        conv_safe_cbr(push_keyframe_cb,false,user,node);
    }
    void clear_keyframes()
    {
        conv_safe_cb(cliear_keyframe_cb,user);
    }
public:
    conv_in_out_packe_t * (*get_node_cb)(void * user,conv_size_t si);
    bool (*push_node_cb)(void * user,const conv_in_out_packe_t * node,bool freenow);
    bool (*free_node_cb)(void * user,const conv_in_out_packe_t * node);
    bool (*push_keyframe_cb)(void * user,const conv_frame_info * node);
    void (*cliear_keyframe_cb)(void * user);
    void * user;
};

class c_conv_base
{
public:
	c_conv_base(void);
	virtual ~c_conv_base();
	virtual bool init(conv_char_t * psrc,conv_size_t si,conv_packet_pt pt,void * user);
	/*
	 * default no demux and mux
	 * */
	virtual bool demux(c_conv_base * mux,conv_size_t start_frame,int gop);
	virtual conv_in_out_packe_t * mux_header (const conv_codec_ctx_t & ctx,long stamp);
	virtual conv_in_out_packe_t * mux( const conv_in_out_packe_t *in, const conv_codec_ctx_t & ctx,int & ret);

	virtual bool get_codec_ctx(conv_codec_ctx_t * ctx);
    /*  解析关键帧列表*/
    virtual int  demux_keyframes(){return 0;}

    /*是否需要预读出所有的帧,比如封装mp4*/
    virtual bool advance_read(){return false;}
    virtual int  advace_process(conv_in_out_packe_t * pkt,const conv_codec_ctx_t * ctx){return 0;}

    virtual void need_rebuild_header(){}

	bool push_node(const conv_in_out_packe_t * node,bool free_now);
	bool notify_end();
	conv_in_out_packe_t * get_node(Size data_len);
	void free_node(const conv_in_out_packe_t * packet);
    void set_mem_nd(const conv_mem_nd * nd){m_mem_allocter  = *nd;}
    conv_size_t get_mem_checker(){return m_mem_checker;}
    bool is_build_header(){return m_b_build_header;}
    void had_build_header(){m_b_build_header = true;}
    /*文件属性*/
public:
    conv_size_t get_key_frames_size()
    {
        return m_keyframes.size();
    }
    bool get_key_frames(conv_frame_info * out,int si)
    {
        si = si > get_key_frames_size() ? get_key_frames_size() : si;
        for(int n = 0;n < si;++n)
        {
            out[n] = m_keyframes[n];
        }
        return true;
    }
    double get_duration()
    {
        return m_duration;
    }
protected:
	bool mux_header_process(const conv_codec_ctx_t & ctx,long stamp);
	bool mux_process( const conv_in_out_packe_t *in, const conv_codec_ctx_t & ctx);
protected:
	bool          m_is_in;
	FileProvider  *m_io;
	c_conv_base   *m_mux;
	conv_packet_pt m_pt;
	void * m_user;
	conv_codec_ctx_t * m_codec_ctx;
    vector<conv_frame_info> m_keyframes;
    double         m_duration;
    conv_node_opt_s m_node_opt;
	bool m_b_build_header;
private:
    conv_mem_nd m_mem_allocter;
#if CONV_DEBUG
    /*
     * 内存检查 
     * */
    conv_size_t m_mem_checker;
#endif
};

class c_conv_impl
{
public:
	c_conv_impl(void)
	{
		m_in= NULL;
		m_out= NULL;
	}
	virtual ~c_conv_impl(void)
	{
		if(m_in)
		{
			delete m_in;
		}
		if(m_out)
		{
			delete m_out;
		}
		m_out= m_in= NULL;
	}

	bool  create(
			conv_packet_type src,
			conv_packet_type dst,
			conv_char_t * psrc,
			conv_size_t si,
			conv_packet_pt pt,
			void * user,
            bool all_conv,
            const conv_mem_nd * nd);

    bool convert_frams(conv_size_t start_frame,int gop,int rebuild_header,const conv_mem_nd * nd);

    conv_size_t get_key_frames_size(int mux_demux) 
    {
        return mux_demux == 0 ? m_out->get_key_frames_size() :  m_in->get_key_frames_size(); 
    }

    bool get_key_frames(conv_frame_info * out,int si,int mux_demux) 
    { 
        return mux_demux == 0 ? m_out->get_key_frames(out,si) : m_in->get_key_frames(out,si); 
    }

    double get_duration(){return m_in->get_duration();}

protected:
	c_conv_base *m_in;
	c_conv_base *m_out;
private:
	c_conv_base * init_base(conv_packet_type type,conv_char_t * psrc,conv_size_t si,conv_packet_pt pt, void * user);
	c_conv_base * create_conv_base(conv_packet_type type);
};

