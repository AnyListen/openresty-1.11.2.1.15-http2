/*
 * =====================================================================================
 *
 *       Filename:  c_ts_file.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月08日 19时37分00秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (490479164@qq.com), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "c_ts_file.h"
#include "spcialconfig.h"
#include <string.h>

#define AV_NOPTS_VALUE          ((int64_t)UINT64_C(0x8000000000000000))

static u_char conv_mpegts_header[] = {

    /* TS */
    0x47, 0x40, 0x00, 0x10, 0x00,
    /* PSI */
    0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PAT */
    0x00, 0x01, 0xf0, 0x01,
    /* CRC */
    0x2e, 0x70, 0x19, 0x05,
    /* stuffing 167 bytes */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,

    /* TS */
    0x47, 0x50, 0x01, 0x10, 0x00,
    /* PSI */
    0x02, 0xb0, 0x17, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PMT */
    0xe1, 0x00,
    0xf0, 0x00,
    0x1b, 0xe1, 0x00, 0xf0, 0x00, /* h264 */
    0x0f, 0xe1, 0x01, 0xf0, 0x00, /* aac */
    /*0x03, 0xe1, 0x01, 0xf0, 0x00,*/ /* mp3 */
    /* CRC */
    0x2f, 0x44, 0xb9, 0x9b, /* crc for aac */
    /*0x4e, 0x59, 0x3d, 0x1e,*/ /* crc for mp3 */
    /* stuffing 157 bytes */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#define TS_AUDIO_SIZE 50 * 1024
#define TS_MAX_LENGTH 1

c_ts_file::c_ts_file(void)
{
	m_video_cc = m_audio_cc = 0;
	m_aframe_pts = 0;
    m_aframe.last = m_aframe.pos = m_aframe.start = new u_char[TS_AUDIO_SIZE];
	m_aframe.end = m_aframe.start +TS_AUDIO_SIZE;
	m_aframe_num = 0;
	m_aframe_base = 0;
	m_sync = 2;
	m_sps.next = &m_pps;
    m_slice_length = 0;
    m_frag_ts = 0;
}

c_ts_file::~c_ts_file(void)
{
	delete []m_aframe.start;
}

u_char * c_ts_file::conv_mpegts_write_pcr(u_char *p, uint64_t pcr)
{
    *p++ = (u_char) (pcr >> 25);
    *p++ = (u_char) (pcr >> 17);
    *p++ = (u_char) (pcr >> 9);
    *p++ = (u_char) (pcr >> 1);
    *p++ = (u_char) (pcr << 7 | 0x7e);
    *p++ = 0;

    return p;
}


u_char * c_ts_file::conv_mpegts_write_pts(u_char *p, uint32_t fb, uint64_t pts)
{
    uint32_t val;

    val = fb << 4 | (((pts >> 30) & 0x07) << 1) | 1;
    *p++ = (u_char) val;

    val = (((pts >> 15) & 0x7fff) << 1) | 1;
    *p++ = (u_char) (val >> 8);
    *p++ = (u_char) val;

    val = (((pts) & 0x7fff) << 1) | 1;
    *p++ = (u_char) (val >> 8);
    *p++ = (u_char) val;

    return p;
}

#define NGX_RTMP_HLS_DELAY  63000

static conv_size_t get_chain_size(const conv_chain_t * cl)
{
	conv_size_t si = 0;
	const conv_chain_t * ll = cl;
	for(;ll != NULL;ll=ll->next)
	{
		si += (ll->buf.last - ll->buf.pos);
	}
	return si;
}

static bool conv_copy_chain(void *dst, size_t n, conv_chain_t **in)
{
    u_char  *last;
	u_char  *pos;
    size_t   pn;

    if (*in == NULL) 
	{
        return false;
    }

    for ( ;; ) 
	{
        last = (*in)->buf.last;
		pos = (*in)->buf.pos;

        if ((size_t)(last - pos) >= n) 
		{
            if (dst) 
			{
                memcpy(dst, pos, n);
            }

            (*in)->buf.pos += n;

            while (*in && (*in)->buf.pos == (*in)->buf.last) 
			{
                *in = (*in)->next;
            }
            return true;
        }

        pn = last - pos;

        if (dst) 
		{
            memcpy(dst, pos, pn);
            dst = (u_char *)dst + pn;
        }

        n -= pn;
        *in = (*in)->next;

        if (*in == NULL) 
		{
            return false;
        }
    }
}

/* Set an adaptation field flag in an MPEG-TS packet*/                                                                                                            
static void set_af_flag(uint8_t *pkt, int flag)
{
    // expect at least one flag to set
    if ((pkt[3] & 0x20) == 0) { 
        // no AF yet, set adaptation field flag
        pkt[3] |= 0x20;
        // 1 byte length, no flags
        pkt[4] = 1; 
        pkt[5] = 0; 
    }    
    pkt[5] |= flag;
}

/* Get a pointer to MPEG-TS payload (right after TS packet header) */                                                                                             
static uint8_t *get_ts_payload_start(uint8_t *pkt)
{
    if (pkt[3] & 0x20)
        return pkt + 5 + pkt[4];
    else
        return pkt + 4;
}

/* Extend the adaptation field by size bytes */                                                                                                                   
static void extend_af(uint8_t *pkt, int size)
{
    // expect already existing adaptation field
    pkt[4] += size;
}    

bool c_ts_file::conv_mpegts_write_frame(conv_in_out_packe_t ** out, conv_mpegts_frame_t *f, conv_chain_t  *cl,long stamp)
{
    uint32_t    pes_size, header_size, body_size, stuff_size, flags;
    u_char      *p, *base;
    bool   first;

#if 0
    printf("ts: pid=%d, sid=%d, pts=%d, "
                   "dts=%d, key=%d \n",
                   (int)f->pid, (int)f->sid, (int)f->pts, (int)f->dts,
                   (int) f->key);
#endif

    first = 1;
	const uint32_t packet_size = 188;
	conv_in_out_packe_t ** pheader = out;
    bool write_pcr = false;
	while (1) 
	{
		uint32_t csize = get_chain_size(cl);
		if(csize == 0)
			break;

		conv_in_out_packe_t * packet = get_node(packet_size);
        packet->stamp = stamp;
		packet->type = f->pid == 0x100 ? conv_packet_video : conv_packet_audio;

		p = packet->p;
		f->cc++;

		/*
		 * audio 
		 * frame.pid = 0x101;
		 * frame.sid = 0xc0;
		 * 
		 * video
    	 * frame.pid = 0x100;
    	 * frame.sid = 0xe0;
		 * */
		*p++ = 0x47;
		*p++ = (u_char) (f->pid >> 8);

		if (first) 
		{
			p[-1] |= 0x40;
		}

		*p++ = (u_char) f->pid;
		*p++ = 0x10 | (f->cc & 0x0f); /* payload */

		if (first) 
		{
			if (f->key) 
			{
                set_af_flag(packet->p, 0x40); 
                p = get_ts_payload_start(packet->p);
                write_pcr = true;
#if 0
			    packet->p[3] |= 0x20; /* adaptation */
				*p++ = 7;    /* size */
				*p++ = 0x50; /* random access + PCR */
				p = conv_mpegts_write_pcr(p, f->dts - NGX_RTMP_HLS_DELAY);
#endif
			}

            if(f->pid == 0x100)
            {
                write_pcr = true;
            }
            
            if(write_pcr)
            {
                set_af_flag(packet->p, 0x10); 
                p = get_ts_payload_start(packet->p);
				p = conv_mpegts_write_pcr(p, f->dts - NGX_RTMP_HLS_DELAY);
                extend_af(packet->p,6);
            }
			/* PES header */

			*p++ = 0x00;
			*p++ = 0x00;
			*p++ = 0x01;
			*p++ = (u_char) f->sid;

			header_size = 5;
			flags = 0x80; /* PTS */

			if (f->dts != f->pts) 
			{
				header_size += 5;
				flags |= 0x40; /* DTS */
			}

			pes_size = csize + header_size + 3;
			if (pes_size > 0xffff) 
			{
				pes_size = 0;
			}

			*p++ = (u_char) (pes_size >> 8);
			*p++ = (u_char) pes_size;
			*p++ = 0x80; /* H222 */
			*p++ = (u_char) flags;
			*p++ = (u_char) header_size;

			p = conv_mpegts_write_pts(p, flags >> 6, f->pts + NGX_RTMP_HLS_DELAY);

			if (f->dts != f->pts) 
			{
				p = conv_mpegts_write_pts(p, 1, f->dts + NGX_RTMP_HLS_DELAY);
			}

			first = 0;
		}

		body_size = (uint32_t) (packet->p + packet_size - p);

		if (body_size <= csize) 
		{
			conv_copy_chain(p,body_size,&cl);	
		} 
		else 
		{
			stuff_size = (body_size - csize);

			if (packet->p[3] & 0x20) 
			{
				/* has adaptation */
				base = &packet->p[5] + packet->p[4];
				p = conv_movemem(base + stuff_size, base, p - base);
				memset(base, 0xff, stuff_size);
				packet->p[4] += (u_char) stuff_size;

			} 
			else 
			{
				/* no adaptation */
				packet->p[3] |= 0x20;
				p = conv_movemem(&packet->p[4] + stuff_size, &packet->p[4],
						p - &packet->p[4]);

				packet->p[4] = (u_char) (stuff_size - 1);
				if (stuff_size >= 2) {
					packet->p[5] = 0;
					memset(&packet->p[6], 0xff, stuff_size - 2);
				}
			}
			conv_copy_chain(p,csize,&cl);
			cl = NULL;
		}
		*pheader = packet;
		pheader = &(*pheader)->next;
	}
    return true;
}
bool c_ts_file::conv_mpegts_write_header(u_char * p ,conv_size_t si,int64_t stamp)
{
    m_frag_ts = stamp;

	if(si < (conv_size_t)sizeof(conv_mpegts_header))
		return false;

    memcpy(p, conv_mpegts_header, sizeof(conv_mpegts_header));
	return true;
}

conv_in_out_packe_t * c_ts_file::open_frag(int64_t stamp)
{
    cout << "open ts frag stamp:" << stamp << endl;
    
	conv_in_out_packe_t * node = get_node(sizeof(conv_mpegts_header));
	node->type = conv_packet_header; 
	conv_mpegts_write_header(node->p,node->si,stamp);

    conv_in_out_packe_t * out = NULL;
    conv_hls_flush_audio(&out);

    if(out != NULL)
        node->stamp = out->stamp;
    else
        node->stamp = stamp;
    node->frag = 1;

    node->next = out;

    return node;
}

conv_in_out_packe_t * c_ts_file::mux_header(const conv_codec_ctx_t & ctx,long stamp)
{
	return open_frag(stamp);
}

void c_ts_file::set_buf_by_packet(const conv_in_out_packe_t * in,conv_buf_t * out)
{
	out->pos = out->start = (u_char*)in->p;
	out->last = out->end = (u_char *)in->p + in->si;
}

conv_in_out_packe_t * c_ts_file::mux_video(const conv_in_out_packe_t * in,const conv_codec_ctx_t & ctx)
{
	int nalu_type = in->p[4] & 0x1f;
    conv_in_out_packe_t * node = NULL;
	switch(nalu_type)
	{
		case 7:
			set_buf_by_packet(in,&m_sps.buf);	
            if(in->next == NULL)
                break;
		case 8:
			set_buf_by_packet(in,&m_pps.buf);
            if(in->next == NULL)
                break;
        case 6:
			set_buf_by_packet(in,&m_sei.buf);	
            if(in->next == NULL)
                break;
		default:
			node = conv_hls_video(in,ctx);
	}
	return node;
}

int  c_ts_file::advace_process(conv_in_out_packe_t * pkt,const conv_codec_ctx_t * ctx)
{
    return 1;
}

conv_in_out_packe_t * c_ts_file::mux( const conv_in_out_packe_t *in, const conv_codec_ctx_t & ctx,int & ret)
{
    ret = 1;
	switch(in->type)
	{
		case conv_packet_video:
			return mux_video(in,ctx);
		case conv_packet_audio:
			return mux_audio(in,ctx);
		default:
			break;
	}
	return NULL;
}

bool c_ts_file::is_frag(const conv_in_out_packe_t * in)
{
    const conv_in_out_packe_t * n = in;
    bool bfrag = false;
    int nal_type;
    int last = 0;
    for(;n != NULL;n=n->next)
    {
        nal_type = n->p[4] & 0x1f;
        if(nal_type == 5 || last == 6)
        {
            bfrag = (m_slice_length > 0 &&  (m_slice_length % TS_MAX_LENGTH) == 0);
            ++m_slice_length;
        }
        last = nal_type;
    }
    return bfrag;
}

conv_in_out_packe_t * c_ts_file::conv_hls_video(const conv_in_out_packe_t * in,const conv_codec_ctx_t & ctx)
{
    uint32_t                        cts;
    conv_mpegts_frame_t         frame;

    /* Only H264 is supported */
    if (ctx.codec_video != CONVERT_VIDEO_H264)
	{
        return NULL;
    }

    cts = in->cts;

    frame.cc = m_video_cc;
    frame.dts = (uint64_t) in->stamp * 90;
    frame.pts = frame.dts + cts * 90;
    frame.pid = 0x100;
    frame.sid = 0xe0;
    frame.key = in->key_frame ? 1 : 0;

    /*
     * start new fragment if
     * - we have video key frame AND
     * - we have audio buffered or have no audio at all or stream is closed
     */

	conv_in_out_packe_t * pout = NULL;
	conv_in_out_packe_t ** pnext = &pout;
	int nalu_type = in->p[4] & 0x1f;
    
	*pnext = conv_hls_update_fragment(frame.dts, 1,in->key_frame);
	
	if(*pnext != NULL)
		pnext = &(*pnext)->next;

#define VIDEO_MAX_CHAIN 256
	conv_chain_t  in_buf[VIDEO_MAX_CHAIN];
	conv_chain_t * header = NULL;
    conv_chain_t ** plast = &header;

    const conv_in_out_packe_t * n = in;
    int m = 0;
    bool aud_send = false;
    int oft = 0;
    static int video_frame =0;
    int nn = 0;
    for(;n != NULL;n = n->next)
    {
        if(m >= VIDEO_MAX_CHAIN)
        {
            cout << "max chain is error" << endl;
            break;
        }

	    nalu_type = n->p[4] & 0x1f;
        ++nn;
#if 0
        cout << "nalu type:" << nalu_type << ",size:"<< n->si << ";";
        char debug[] = {0x41,0x9E,0xC8,0x45,0x15 ,0x2C ,0x2B ,0xFF ,0x6B ,0x51 ,0x69 ,0xC4 ,0x18 ,0xEE ,0xBA ,0xAF ,0xB7 ,0x7E, 0x11};
        if(memcmp(n->p+4,debug,sizeof(debug)) == 0)
        {
            cout << "b slice" << endl;
        }
#endif
        switch(nalu_type)
        {
            case 5:
                frame.key = 1;
                break;
            case 7:
                frame.key = 1;
            case 1:
            case 6:
                {
                    static u_char   aud_nal[] = { 0x00, 0x00, 0x00, 0x01, 0x09, 0xf0 };
                    if(!aud_send)
                    {
                        in_buf[m].buf.pos = in_buf[m].buf.start = aud_nal;
                        in_buf[m].buf.last = in_buf[m].buf.end = aud_nal + sizeof(aud_nal);
                        *plast = &in_buf[m];
                        plast = &in_buf[m].next;
                        ++m;
                        aud_send = true;
                        oft = 1;
                    }
                }
                break;
            case 9:
                aud_send = true;
                break;
        }
        switch(nalu_type)
        {
            case 7:
            case 8:
                {
                    oft = 0;
                }
                break;
            default:
                {
#if 0
                    oft = m == 0 ? 0 : 1;
#endif
                    oft = 0;
                }
                break;
        }
        
        in_buf[m].buf.pos = in_buf[m].buf.start = n->p + oft;
        in_buf[m].buf.end = in_buf[m].buf.last = n->p + n->si;
        *plast = &in_buf[m];
        plast = &in_buf[m].next;
        ++m;
    }
    ++video_frame;
   // cout << "frame num is " << ++video_frame <<  endl; 
    if (!conv_mpegts_write_frame(pnext, &frame, header,in->stamp)) 
    {
        cout << "hls: video frame failed" << endl;
    }
    m_video_cc = frame.cc;

    return pout;
}

conv_in_out_packe_t * c_ts_file::mux_audio(const conv_in_out_packe_t * in,const conv_codec_ctx_t & ctx)
{
    uint64_t                        pts;
    size_t                          bsize;
    conv_buf_t                      *b;
    u_char                          *p;
    uint32_t                        objtype, srindex, chconf, size;

    if (ctx.codec_audio != CONVERT_AUDIO_AAC)
    {
        return NULL;
    }

    b = &m_aframe;

    size = in->si + 7;
    pts = (uint64_t) in->stamp * 90;

    if (b->start + size > b->end) 
	{
        cout << "hls: too big audio frame" << endl;
        return NULL;
    }

    /*
     * start new fragment here if
     * there's no video at all, otherwise
     * do it in video handler
     */

	conv_in_out_packe_t * node = NULL;
	conv_in_out_packe_t ** pnext = &node;

    /*
     *pnext = conv_hls_update_fragment(pts, 2,false);

	if(*pnext)
		pnext = &(*pnext)->next;

    if (b->last + size > b->end) 
	{
        conv_hls_flush_audio(pnext);
    }
    */


    if (b->last + 7 > b->end) 
	{
		cout << "hls: not enough buffer for audio header" << endl;
        return node;
    }

    p = b->last;
    b->last += 7;

    /* copy payload */

	bsize = in->si;
	if (b->last + bsize > b->end)
	{
		bsize = b->end - b->last;
	}

	b->last = conv_cpymem(b->last, in->p, bsize);

    /* make up ADTS header */

    if (!conv_parse_aac_header(&ctx.audio_config, &objtype, &srindex, &chconf))
    {
        cout << "hls: aac header error" << endl;
        return node;
    }

    /* we have 5 free bytes + 2 bytes of RTMP frame header */

    p[0] = 0xff;
    p[1] = 0xf1;
    p[2] = (u_char) (((objtype - 1) << 6) | (srindex << 2) |
                     ((chconf & 0x04) >> 2));
    p[3] = (u_char) (((chconf & 0x03) << 6) | ((size >> 11) & 0x03));
    p[4] = (u_char) (size >> 3);
    p[5] = (u_char) ((size << 5) | 0x1f);
    p[6] = 0xfc;

/*  if (p != b->start) 
	{
        ++m_aframe_num;
        return node;
    }
    */

    m_aframe_pts = pts;

	int samplerate = index_to_samplerate(srindex);

	samplerate =  samplerate == 0 ? ctx.samplerate : (samplerate != ctx.samplerate ? samplerate : ctx.samplerate);

    if (samplerate == 0)
	{
        return node;
    }

    /* align audio frames */

    /* TODO: We assume here AAC frame size is 1024
     *       Need to handle AAC frames with frame size of 960 */

    /*
    est_pts = m_aframe_base + m_aframe_num * 90000 * 1024 / samplerate;
    dpts = (int64_t) (est_pts - pts);

    if (dpts <= (int64_t) m_sync * 90 &&
        dpts >= (int64_t) m_sync * -90)
    {
        ++m_aframe_num;
        m_aframe_pts = est_pts;
    	return node;
    }
    */
    m_aframe_base = pts;
    m_aframe_num  = 1;
    conv_hls_flush_audio(pnext);
    return node;
}

bool c_ts_file::conv_hls_flush_audio(conv_in_out_packe_t ** out)
{
    conv_mpegts_frame_t         frame;
    bool                       rc;
	conv_chain_t                    cl;

    cl.buf = m_aframe;

    if (cl.buf.last - cl.buf.pos == 0) 
	{
        return true;
    }

    frame.dts = m_aframe_pts;
    frame.pts = frame.dts;
    frame.cc = m_audio_cc;
    frame.pid = 0x101;
    frame.sid = 0xc0;

    rc = conv_mpegts_write_frame(out, &frame, &cl,frame.pts/90);

    if (rc != true) 
	{
    	cout << "hls: audio flush failed" << endl;
    }

    m_audio_cc = frame.cc;
    m_aframe.pos = m_aframe.last = m_aframe.start;

    return rc;
}

void c_ts_file::conv_hls_close_frag()
{
}

conv_in_out_packe_t * c_ts_file::conv_hls_update_fragment(uint64_t ts, uint32_t flush_rate,bool boundary)
{
    int force = 0;
    int64_t d = (int64_t) (ts - m_frag_ts);

    float duration = d / 90000.0;
    if (d < -90000) 
    {
        cout << "force fragment split:" <<  d / 90000 << endl;
        force = 1;
    } 

    if(duration < 5.0)
        boundary = 0;

    conv_in_out_packe_t *header = NULL;
    conv_in_out_packe_t ** pn = &header;

    if(force || boundary)
    {
        conv_hls_flush_audio(&header);
        
        for(;(*pn)!= NULL;pn=&((*pn)->next));

        conv_hls_close_frag();

	    *pn = open_frag(ts/90);
    }

    for(;(*pn)!= NULL;pn=&((*pn)->next));

  //  if (b && b->last - b->pos  > 0 &&
  //      m_aframe_pts + (uint64_t) 300 * 90 / flush_rate < ts)
    {
  //      conv_hls_flush_audio(pn);
    }
	return header;
}

bool c_ts_file::demux(c_conv_base * mux,conv_size_t start_frame,int gop)
{
	return false;
}

int c_ts_file::analyze(const uint8_t *buf, int size, int packet_size, int *index)
{
    int stat[TS_MAX_PACKET_SIZE];
    int i;
    int best_score = 0;
    int best_score2 = 0;

    memset(stat, 0, packet_size * sizeof(*stat));

    for (i = 0; i < size - 3; i++) 
	{
        if (buf[i] == 0x47 && !(buf[i + 1] & 0x80) && buf[i + 3] != 0x47) 
		{
            int x = i % packet_size;
            stat[x]++;
            if (stat[x] > best_score) 
			{
                best_score = stat[x];
                if (index)
                    *index = x;
            }
			else if (stat[x] > best_score2) 
			{
                best_score2 = stat[x];
            }
        }
    }

    return best_score - best_score2;
}

int c_ts_file::get_packet_size(const uint8_t *buf, int size)
{
    int score, fec_score, dvhs_score;

    if (size < (TS_FEC_PACKET_SIZE * 5 + 1))
        return AVERROR_INVALIDDATA;

    score      = analyze(buf, size, TS_PACKET_SIZE, NULL);
    dvhs_score = analyze(buf, size, TS_DVHS_PACKET_SIZE, NULL);
    fec_score  = analyze(buf, size, TS_FEC_PACKET_SIZE, NULL);
    caoc_pf("score: %d, dvhs_score: %d, fec_score: %d \n",
            score, dvhs_score, fec_score);

    if (score > fec_score && score > dvhs_score)
        return TS_PACKET_SIZE;
    else if (dvhs_score > score && dvhs_score > fec_score)
        return TS_DVHS_PACKET_SIZE;
    else if (score < fec_score && dvhs_score < fec_score)
        return TS_FEC_PACKET_SIZE;
    else
        return AVERROR_INVALIDDATA;
}

MpegTSFilter *c_ts_file::mpegts_open_filter(MpegTSContext *ts, unsigned int pid,enum MpegTSFilterType type)
{
    MpegTSFilter *filter;

    caoc_pf("Filter: pid=0x%x\n", pid);

    if (pid >= NB_PID_MAX || ts->pids[pid])
        return NULL;
    filter = new MpegTSFilter;
    if (!filter)
        return NULL;
    ts->pids[pid] = filter;

    filter->type    = type;
    filter->pid     = pid;
    filter->es_id   = -1;
    filter->last_cc = -1;
    filter->last_pcr= -1;

    return filter;
}

MpegTSFilter *c_ts_file::mpegts_open_section_filter(MpegTSContext *ts,
                                                unsigned int pid,
                                                SectionCallback *section_cb,
                                                void *opaque,
                                                int check_crc)
{
    MpegTSFilter *filter;
    MpegTSSectionFilter *sec;

    if (!(filter = mpegts_open_filter(ts, pid, MPEGTS_SECTION)))
        return NULL;
    sec = &filter->u.section_filter;
    sec->section_cb  = section_cb;
    sec->opaque      = opaque;
    sec->section_buf = new uint8_t[MAX_SECTION_SIZE];
    sec->check_crc   = check_crc;
    if (!sec->section_buf) 
	{
        delete filter;
        return NULL;
    }
    return filter;
}

static inline int get8(const uint8_t **pp, const uint8_t *p_end)
{
    const uint8_t *p;
    int c;

    p = *pp;
    if (p >= p_end)
        return AVERROR_INVALIDDATA;
    c   = *p++;
    *pp = p;
    return c;
}

static inline int get16(const uint8_t **pp, const uint8_t *p_end)
{
    const uint8_t *p;
    int c;

    p = *pp;
    if ((p + 1) >= p_end)
        return AVERROR_INVALIDDATA;
    c   = AV_RB16(p);
    p  += 2;
    *pp = p;
    return c;
}

static int parse_section_header(SectionHeader *h,
                                const uint8_t **pp, const uint8_t *p_end)
{
    int val;

    val = get8(pp, p_end);
    if (val < 0)
        return val;
    h->tid = val;
    *pp += 2;
    val  = get16(pp, p_end);
    if (val < 0)
        return val;
    h->id = val;
    val = get8(pp, p_end);
    if (val < 0)
        return val;
    h->version = (val >> 1) & 0x1f;
    val = get8(pp, p_end);
    if (val < 0)
        return val;
    h->sec_num = val;
    val = get8(pp, p_end);
    if (val < 0)
        return val;
    h->last_sec_num = val;
    return 0;
}

static char *getstr8(const uint8_t **pp, const uint8_t *p_end)
{
    int len;
    const uint8_t *p;
    char *str;

    p   = *pp;
    len = get8(&p, p_end);
    if (len < 0)
        return NULL;
    if ((p + len) > p_end)
        return NULL;
    str = new char[len + 1];
    if (!str)
        return NULL;
    memcpy(str, p, len);
    str[len] = '\0';
    p  += len;
    *pp = p;
    return str;
}

static void sdt_cb(MpegTSFilter *filter, const uint8_t *section, int section_len)
{
}

typedef struct AVProgram {
    int            id;
    int            flags;
//    enum AVDiscard discard;        ///< selects which program to discard and which to feed to the caller
    unsigned int   *stream_index;
    unsigned int   nb_stream_indexes;
//    AVDictionary *metadata;

    int program_num;
    int pmt_pid;
    int pcr_pid;

    /*****************************************************************
     * All fields below this line are not part of the public API. They
     * may not be used outside of libavformat and can be changed and
     * removed at will.
     * New public fields should be added right above.
     *****************************************************************
     */
    int64_t start_time;
    int64_t end_time;

    int64_t pts_wrap_reference;    ///< reference dts for wrap detection
    int pts_wrap_behavior;         ///< behavior on wrap detection
} AVProgram;

static void clear_programs(MpegTSContext *ts)
{
	if(ts->prg != NULL)
		delete ts->prg;
	ts->prg = NULL;
    ts->nb_prg = 0;
}
static void pat_cb(MpegTSFilter *filter, const uint8_t *section, int section_len)
{
}

#define TS_PROBE_SIZE 500000
#define FF_INPUT_BUFFER_PADDING_SIZE 32

/**
 * @brief discard_pid() decides if the pid is to be discarded according
 *                      to caller's programs selection
 * @param ts    : - TS context
 * @param pid   : - pid
 * @return 1 if the pid is only comprised in programs that have .discard=AVDISCARD_ALL
 *         0 otherwise
 */
int c_ts_file::discard_pid(MpegTSContext *ts, unsigned int pid)
{
	return 0;
}

MpegTSFilter *c_ts_file::mpegts_open_pes_filter(MpegTSContext *ts, unsigned int pid,
                                            PESCallback *pes_cb,
                                            void *opaque)
{
    MpegTSFilter *filter;
    MpegTSPESFilter *pes;

    if (!(filter = mpegts_open_filter(ts, pid, MPEGTS_PES)))
        return NULL;

    pes = &filter->u.pes_filter;
    pes->pes_cb = pes_cb;
    pes->opaque = opaque;
    return filter;
}

static int mpegts_push_data(MpegTSFilter *filter,
                            const uint8_t *buf, int buf_size, int is_start,
                            int64_t pos)
{
	return 0;
}

PESContext *c_ts_file::add_pes_stream(MpegTSContext *ts, int pid, int pcr_pid)
{
    MpegTSFilter *tss;
    PESContext *pes;

    /* if no pid found, then add a pid context */
    pes = new PESContext;
    if (!pes)
        return 0;
    pes->ts      = ts;
    pes->pid     = pid;
    pes->pcr_pid = pcr_pid;
    pes->state   = MPEGTS_SKIP;
    pes->pts     = AV_NOPTS_VALUE;
    pes->dts     = AV_NOPTS_VALUE;
    tss          = mpegts_open_pes_filter(ts, pid, mpegts_push_data, pes);
    if (!tss) 
	{
		delete pes;
        return 0;
    }
    return pes;
}

void c_ts_file::write_section_data(MpegTSContext *ts, MpegTSFilter *tss1,
                               const uint8_t *buf, int buf_size, int is_start)
{
    MpegTSSectionFilter *tss = &tss1->u.section_filter;
    int len;

    if (is_start) 
	{
        memcpy(tss->section_buf, buf, buf_size);
        tss->section_index = buf_size;
        tss->section_h_size = -1;
        tss->end_of_section_reached = 0;
    } 
	else 
	{
        if (tss->end_of_section_reached)
            return;
        len = 4096 - tss->section_index;
        if (buf_size < len)
            len = buf_size;
        memcpy(tss->section_buf + tss->section_index, buf, len);
        tss->section_index += len;
    }

    /* compute section length if possible */
    if (tss->section_h_size == -1 && tss->section_index >= 3) 
	{
        len = (AV_RB16(tss->section_buf + 1) & 0xfff) + 3;
        if (len > 4096)
            return;
        tss->section_h_size = len;
    }

    if (tss->section_h_size != -1 &&
        tss->section_index >= tss->section_h_size) 
	{
        int crc_valid = 1;
        tss->end_of_section_reached = 1;

        if (tss->check_crc) 
		{
            crc_valid = 1;//don't  check crc
            if (crc_valid) 
			{
                ts->crc_validity[ tss1->pid ] = 100;
            }
			else if (ts->crc_validity[ tss1->pid ] > -10) 
			{
                ts->crc_validity[ tss1->pid ]--;
            }
			else
                crc_valid = 2;
        }
        if (crc_valid)
            tss->section_cb(tss1, tss->section_buf, tss->section_h_size);
    }
}
/* handle one TS packet */
int c_ts_file::handle_packet(MpegTSContext *ts, const uint8_t *packet)
{
    MpegTSFilter *tss;
    int len, pid, cc, expected_cc, cc_ok, afc, is_start, is_discontinuity,
        has_adaptation, has_payload;
    const uint8_t *p, *p_end;
    int64_t pos;

	FileProvider * pb = ts->pb;

    pid = AV_RB16(packet + 1) & 0x1fff;
    if (pid && discard_pid(ts, pid))
        return 0;

    is_start = packet[1] & 0x40;
    tss = ts->pids[pid];
    if (ts->auto_guess && tss == NULL && is_start) 
	{
        add_pes_stream(ts, pid, -1);
        tss = ts->pids[pid];
    }
    if (!tss)
        return 0;

    ts->current_pid = pid;

    afc = (packet[3] >> 4) & 3;
    if (afc == 0) /* reserved value */
        return 0;
    has_adaptation   = afc & 2;
    has_payload      = afc & 1;
    is_discontinuity = has_adaptation &&
                       packet[4] != 0 && /* with length > 0 */
                       (packet[5] & 0x80); /* and discontinuity indicated */

    /* continuity check (currently not used) */
    cc = (packet[3] & 0xf);
    expected_cc = has_payload ? (tss->last_cc + 1) & 0x0f : tss->last_cc;
    cc_ok = pid == 0x1FFF || // null packet PID
            is_discontinuity ||
            tss->last_cc < 0 ||
            expected_cc == cc;

    tss->last_cc = cc;
    if (!cc_ok) 
	{
        printf("Continuity check failed for pid %d expected %d got %d\n", pid, expected_cc, cc);
        if (tss->type == MPEGTS_PES) 
		{
            PESContext *pc = (PESContext*)tss->u.pes_filter.opaque;
            pc->flags |= AV_PKT_FLAG_CORRUPT;
        }
    }

    if (!has_payload && tss->type != MPEGTS_PCR)
        return 0;
    p = packet + 4;
    if (has_adaptation) 
	{
        /* skip adaptation field */
        p += p[0] + 1;
    }
    /* if past the end of packet, ignore */
    p_end = packet + TS_PACKET_SIZE;
    if (p > p_end || (p == p_end && tss->type != MPEGTS_PCR))
        return 0;

    pos = pb->tell();
    if (pos >= 0) 
	{
        assert(pos >= TS_PACKET_SIZE);
        ts->pos47_full = pos - TS_PACKET_SIZE;
    }

    if (tss->type == MPEGTS_SECTION) 
	{
        if (is_start) 
		{
            /* pointer field present */
            len = *p++;
            if (p + len > p_end)
                return 0;
            if (len && cc_ok) 
			{
                /* write remaining section bytes */
                write_section_data(ts, tss,p, len, 0);
                /* check whether filter has been closed */
                if (!ts->pids[pid])
                    return 0;
            }
            p += len;
            if (p < p_end) 
			{
                write_section_data(ts, tss, p, p_end - p, 1);
            }
        } 
		else 
		{
            if (cc_ok) 
			{
                write_section_data(ts, tss, p, p_end - p, 0);
            }
        }

    } 
	else 
	{
        int ret;
        int64_t pcr_h;
        int pcr_l;
        if (parse_pcr(&pcr_h, &pcr_l, packet) == 0)
            tss->last_pcr = pcr_h * 300 + pcr_l;
        // Note: The position here points actually behind the current packet.
        if (tss->type == MPEGTS_PES) 
		{
            if ((ret = tss->u.pes_filter.pes_cb(tss, p, p_end - p, is_start, pos - ts->raw_packet_size)) < 0)
                return ret;
        }
    }

    return 0;
}

/* return the 90kHz PCR and the extension for the 27MHz PCR. return
 * (-1) if not available */
int c_ts_file::parse_pcr(int64_t *ppcr_high, int *ppcr_low, const uint8_t *packet)
{
    int afc, len, flags;
    const uint8_t *p;
    unsigned int v;

    afc = (packet[3] >> 4) & 3;
    if (afc <= 1)
        return AVERROR_INVALIDDATA;
    p   = packet + 4;
    len = p[0];
    p++;
    if (len == 0)
        return AVERROR_INVALIDDATA;
    flags = *p++;
    len--;
    if (!(flags & 0x10))
        return AVERROR_INVALIDDATA;
    if (len < 6)
        return AVERROR_INVALIDDATA;
    v          = AV_RB32(p);
    *ppcr_high = ((int64_t) v << 1) | (p[4] >> 7);
    *ppcr_low  = ((p[4] & 1) << 8) | p[5];
    return 0;
}

int c_ts_file::handle_packets(MpegTSContext *ts, int nb_packets)
{
    uint8_t packet[TS_PACKET_SIZE + FF_INPUT_BUFFER_PADDING_SIZE];
    const uint8_t *data;
    int packet_num, ret = 0;
	FileProvider * pb = ts->pb;
    if (pb->tell() != ts->last_pos) 
	{
        int i;
        caoc_pf("Skipping after seek\n");
        /* seek detected, flush pes buffer */
        for (i = 0; i < NB_PID_MAX; i++) 
		{
            if (ts->pids[i]) 
			{
                if (ts->pids[i]->type == MPEGTS_PES) 
				{
                    PESContext *pes = (PESContext*)ts->pids[i]->u.pes_filter.opaque;
                    free_node(pes->buffer);
                    pes->data_index = 0;
                    pes->state = MPEGTS_SKIP; /* skip until pes header */
                }
                ts->pids[i]->last_cc = -1;
                ts->pids[i]->last_pcr = -1;
            }
        }
    }

    ts->stop_parse = 0;
    packet_num = 0;
    memset(packet + TS_PACKET_SIZE, 0, FF_INPUT_BUFFER_PADDING_SIZE);
    for (;;) 
	{
        packet_num++;
        if ((nb_packets != 0 && packet_num >= nb_packets) ||
            ts->stop_parse > 1) 
		{
            ret = AVERROR(EAGAIN);
            break;
        }
        if (ts->stop_parse > 0)
            break;

        ret = read_packet(ts,pb, packet, ts->raw_packet_size, &data);
        if (ret != 0)
            break;
#if 0
        ret = handle_packet(ts, data);
        finished_reading_packet(s, ts->raw_packet_size);
#endif
        if (ret != 0)
            break;
    }
    ts->last_pos = pb->tell();
    return ret;
}

#define MAX_RESYNC_SIZE 65536

void c_ts_file::reanalyze(MpegTSContext *ts,FileProvider * pb) 
{
    int64_t pos = pb->tell();
    if (pos < 0)
        return;

    pos -= ts->pos47_full;
    if (pos == TS_PACKET_SIZE) 
	{
        ts->size_stat[0] ++;
    } 
	else if (pos == TS_DVHS_PACKET_SIZE) 
	{
        ts->size_stat[1] ++;
    } 
	else if (pos == TS_FEC_PACKET_SIZE) 
	{
        ts->size_stat[2] ++;
    }

    ts->size_stat_count ++;
    if (ts->size_stat_count > SIZE_STAT_THRESHOLD) 
	{
        int newsize = 0;
        if (ts->size_stat[0] > SIZE_STAT_THRESHOLD) 
		{
            newsize = TS_PACKET_SIZE;
        } 
		else if (ts->size_stat[1] > SIZE_STAT_THRESHOLD) 
		{
            newsize = TS_DVHS_PACKET_SIZE;
        } 
		else if (ts->size_stat[2] > SIZE_STAT_THRESHOLD) 
		{
            newsize = TS_FEC_PACKET_SIZE;
        }
        if (newsize && newsize != ts->raw_packet_size) 
		{
            ts->raw_packet_size = newsize;
        }
        ts->size_stat_count = 0;
        memset(ts->size_stat, 0, sizeof(ts->size_stat));
    }
}

int c_ts_file::mpegts_resync(MpegTSContext *ts,FileProvider * pb)
{
    int c, i;

    for (i = 0; i < MAX_RESYNC_SIZE; i++) 
	{
        c = pb->read8();
        if (pb->feof())
            return AVERROR_EOF;

        if (c == 0x47) 
		{
            pb->seek_poisx(-1, SEEK_CUR);
            reanalyze(ts,pb);
            return 0;
        }
    }
    caoc_pf("max resync size reached, could not find sync byte\n");
    /* no sync found */
    return AVERROR_INVALIDDATA;
}

int c_ts_file::read_packet(MpegTSContext *ts,FileProvider *pb, uint8_t *buf, int raw_packet_size,
                       const uint8_t **data)
{
    int len;

    for (;;) 
	{
        len = pb->readex(buf, TS_PACKET_SIZE);
		*data = buf;

        if (len != TS_PACKET_SIZE)
            return len < 0 ? len : AVERROR_EOF;
        /* check packet sync byte */
        if ((*data)[0] != 0x47) 
		{
            /* find a new packet start */
            int64_t pos = pb->tell();
            pb->seek_poisx(-FFMIN(raw_packet_size, pos), SEEK_CUR);

            if (mpegts_resync(ts,pb) < 0)
                return AVERROR(EAGAIN);
            else
                continue;
        }
		else 
		{
            break;
        }
    }
    return 0;
}

int c_ts_file::mpegts_read_header(MpegTSContext * ts)
{
    uint8_t buf[8 * 1024] = {0};
    int len;
    int64_t pos;
	FileProvider * pb = ts->pb;
    /* read the first 8192 bytes to get packet size */
    pos = pb->tell();
    len = pb->readex(buf, sizeof(buf));
    ts->raw_packet_size = get_packet_size(buf, len);
    if (ts->raw_packet_size <= 0) 
	{
        caoc_pf("Could not detect TS packet size, defaulting to non-FEC/DVHS\n");
        ts->raw_packet_size = TS_PACKET_SIZE;
    }
    ts->auto_guess = 0;

	/* normal demux */

	/* first do a scan to get all the services */
	pb->seek(pos);

	mpegts_open_section_filter(ts, SDT_PID, sdt_cb, ts, 1);

	mpegts_open_section_filter(ts, PAT_PID, pat_cb, ts, 1);

	handle_packets(ts, TS_PROBE_SIZE / ts->raw_packet_size);
	/* if could not find service, enable auto_guess */

	ts->auto_guess = 1;

	printf("tuning done\n");

	ts->ctx_flags |= AVFMTCTX_NOHEADER;

    pb->seek(pos); 
    return 0;
}
