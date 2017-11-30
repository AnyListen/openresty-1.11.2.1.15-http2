/*
 * =====================================================================================
 *
 *       Filename:  c_conv_base.cpp
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
#include "c_conv_base.h"
#include "c_mp3_file.h"
#include "c_mp4_file.h"
#include "c_flv_file.h"
#include "c_ts_file.h"
#include <stdlib.h>

static void * conv_mem_malloc(void * user,conv_size_t si)
{
    return malloc(si);
}

static void conv_mem_free(void * user,void *p)
{
    free(p);
}

static conv_in_out_packe_t * conv_get_node_static(void * user,conv_size_t si)
{
    c_conv_base * p = (c_conv_base *)user;
    return p->get_node(si);
}

static bool conv_free_node_static(void * user,const conv_in_out_packe_t *node)
{
    c_conv_base * p = (c_conv_base *)user;
    p->free_node(node);
    return true;
}

static bool conv_push_node_static(void * user,const conv_in_out_packe_t * node,bool free_now)
{
    c_conv_base * p = (c_conv_base *)user;
    return p->push_node(node,free_now);
}

c_conv_base::c_conv_base(void)
{
	m_is_in = true;
	m_io = NULL;
	m_pt = NULL;
	m_user = NULL;
	m_mux = NULL;
	m_codec_ctx = NULL;
	m_b_build_header = false;
    m_duration = 0;
    m_mem_allocter.freeer = conv_mem_free;
    m_mem_allocter.newer = conv_mem_malloc;
    m_mem_checker = 0;
    m_node_opt.user = this;
    m_node_opt.get_node_cb = conv_get_node_static;
    m_node_opt.free_node_cb = conv_free_node_static;
    m_node_opt.push_node_cb = conv_push_node_static;
}

c_conv_base::~c_conv_base()
{
	if(m_io !=  NULL)
	{
		delete m_io;
		m_io = NULL;
	}
	if(m_codec_ctx != NULL)
	{
		delete m_codec_ctx;
		m_codec_ctx = NULL;
	}
}

bool c_conv_base::init(conv_char_t * psrc,conv_size_t si,conv_packet_pt pt,void * user)
{
	m_pt = pt;
	m_user = user;
	if(NULL == psrc)
	{
		m_is_in = false;
	}
	else
	{
        if(si > 0)
        {
            m_io = new MemFileProvider;
		    return m_io->open((const char *)psrc,si,MODE_READ_MEM);
        }
        else
        {
            m_io = new DiskFileProvider;
            return m_io->open((const char *)psrc,si,MODE_READ);
        }
	}
	return true;
}

/*
 * default no demux and mux
 * */
bool c_conv_base::demux(c_conv_base * mux,conv_size_t start_frame,int gop)
{
	return false;
}

conv_in_out_packe_t * c_conv_base::mux_header (const conv_codec_ctx_t & ctx,long stamp)
{
	return NULL;
}

conv_in_out_packe_t * c_conv_base::mux( const conv_in_out_packe_t *in, const conv_codec_ctx_t & ctx,int & ret)
{
	return NULL;
} 

bool c_conv_base::get_codec_ctx(conv_codec_ctx_t * ctx)
{
	if(m_codec_ctx == NULL)
	{
		m_codec_ctx = new conv_codec_ctx_t;
	}

	if(ctx != NULL && m_codec_ctx != NULL)
	{
		*ctx = *m_codec_ctx;
		return true;
	}
	return false;
}

bool c_conv_base::notify_end()
{
	if(m_pt)
		m_pt(m_user,NULL,m_is_in);
	return true;
}

bool c_conv_base::push_node(const conv_in_out_packe_t * node,bool free_now )
{
	if(NULL == node)
		return true;

    bool ret = false;

	if(m_pt != NULL)
	{
		if(m_pt(m_user,node,m_is_in) == 0)
			goto finish;
	}

	if(m_mux != NULL && node->type != conv_packet_unuse)
	{
		if(!m_mux->is_build_header())
		{
            get_codec_ctx(NULL);
			if(m_mux->mux_header_process(*m_codec_ctx,node->stamp))
            {
                m_mux->had_build_header();
            }
			else
			{
				cout << "mux header failed" << endl;
			    goto finish;
			}
		}
		if(!m_mux->mux_process(node,*m_codec_ctx))
			goto finish;
	}

    ret =true;

finish:
    if(free_now)
        free_node(node);
	return ret;
}

conv_in_out_packe_t * c_conv_base::get_node(Size data_len)
{
    u_char * p = (u_char*)m_mem_allocter.newer(m_mem_allocter.user,sizeof(conv_in_out_packe_t) + data_len);
	conv_in_out_packe_t * ps = (conv_in_out_packe_t *)p;
	conv_zero(ps,sizeof(*ps));
	ps->si = data_len;
	ps->p = p + sizeof(*ps);
#if CONV_DEBUG
    ++m_mem_checker;
#endif
	return ps;
}

void  c_conv_base::free_node(const conv_in_out_packe_t * packet)
{
	if(NULL == packet)
		return;

	free_node(packet->next);

	u_char * p = (u_char*)packet;
    conv_safe_cb(m_mem_allocter.freeer,m_mem_allocter.user,p);
#if CONV_DEBUG
    --m_mem_checker;
#endif
}

bool c_conv_base::mux_header_process(const conv_codec_ctx_t & ctx,long stamp)
{
	conv_in_out_packe_t * node = mux_header(ctx,stamp);
	if(node == NULL)
		return false;

	return push_node(node,true);
}

bool c_conv_base::mux_process( const conv_in_out_packe_t *in, const conv_codec_ctx_t & ctx)
{
    int ret = 0;
    /*
     * 这样可以支持复用过程返回数据,由这里回调通知,
     * 也可以支持复用过程中直接调用push回调通知.这里的node就会为NULL,返回值为1. 
     * */
	conv_in_out_packe_t * node = mux(in,ctx,ret);

    if(ret == 0)
        return false;

    if(node)
	    push_node(node,true);
    
    return ret > 0;
}

c_conv_base * c_conv_impl::create_conv_base(conv_packet_type type)
{
	switch(type)
	{
	case conv_unknow:
		break;
	case conv_raw:
		return new c_conv_base;
		break;
	case conv_ts:
		return new c_ts_file;
		break;
	case conv_flv:
		return new c_flv_file;
		break;
	case conv_mp4:
		return new c_mp4_file;
	case conv_avi:
		break;
    case conv_mp3:
        return new c_mp3_file;
	default:
		break;
	}
	return NULL;
}

c_conv_base * c_conv_impl::init_base(
	conv_packet_type type,
	conv_char_t * psrc,
	conv_size_t si,
	conv_packet_pt pt,
	void * user)
{
	c_conv_base * handle = create_conv_base(type);
	if(NULL == handle)
		return NULL;

	if(!handle->init(psrc,si,pt,user))
	{
		delete handle;
		return NULL;
	}
	return handle;
}

bool  c_conv_impl::create(
        conv_packet_type src, 
        conv_packet_type dst, 
        conv_char_t * psrc, 
        conv_size_t si, 
        conv_packet_pt pt, 
        void * user,
        bool all_conv,
        const conv_mem_nd * nd
        )
{
	m_out = init_base(dst,NULL,0,pt,user);
	m_in = init_base(src,psrc,si,pt,user);

    if(nd != NULL)
    {
        /*
         * in out的需要设置成一致
         * */
        if(m_out)
            m_out->set_mem_nd(nd);
        if(m_in)
            m_in->set_mem_nd(nd);
    }

    if(m_in)
	    m_in->get_codec_ctx(NULL);
    if(m_out)
        m_out->get_codec_ctx(NULL);

    if(all_conv)
    {
        if(m_in != NULL)
        {
            m_in->demux(m_out,0,0);
            m_in->notify_end();
        }
        if(m_out != NULL)
        {
            m_out->notify_end();
        }
    }
    else
    {
        if(m_in )
        {
            m_in->demux_keyframes();
        }
    }
	return m_out && m_in;
}

bool c_conv_impl::convert_frams(conv_size_t start_frame,int gop,int rebuild_header,const conv_mem_nd * nd)
{
    if(NULL == m_in || NULL == m_out)
        return false;

    if(rebuild_header)
        m_out->need_rebuild_header();

    if(nd != NULL)
    {
        m_out->set_mem_nd(nd);
        m_in->set_mem_nd(nd);
    }
    //cout << "before dmux mem checker:" << m_in->get_mem_checker() << ",mux mem checker:" << m_out->get_mem_checker() << endl;
    bool ret = m_in->demux(m_out,start_frame,gop);
    cout << "after dmux mem checker:" << m_in->get_mem_checker() << ",mux mem checker:" << m_out->get_mem_checker() << endl;
    return ret;
}
