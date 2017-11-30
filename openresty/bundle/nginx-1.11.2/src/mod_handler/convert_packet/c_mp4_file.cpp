/* 
 * caoc
 * mp4 file demux and mux 
 * 2014-11-04 21:04
 * 490479164@qq.com
 *
 * */
#include "stdafx.h"
#include "c_mp4_file.h"
#include "spcialconfig.h"

#define CONVERT_CSID_AUDIO             6
#define CONVERT_CSID_VIDEO             7

#if CONV_WRITE_TEST_FILE
static FILE * s_h264 = NULL;
#endif

#define convert_mp4_make_tag(a, b, c, d)  \
    ((uint32_t)d << 24 | (uint32_t)c << 16 | (uint32_t)b << 8 | (uint32_t)a)

typedef bool (*convert_mp4_box_pt)(c_conv_base * base,u_char *pos, u_char *last);

typedef struct {
    uint32_t                            tag;
    convert_mp4_box_pt                 handler;
} convert_mp4_box_t;


typedef bool (*convert_mp4_descriptor_pt)(c_conv_base * base, u_char *pos, u_char *last);

typedef struct 
{
    uint8_t                             tag;
    convert_mp4_descriptor_pt          handler;
} convert_mp4_descriptor_t;

static bool convert_mp4_parse_es(c_conv_base * base,u_char *pos, u_char *last);
static bool convert_mp4_parse_dc(c_conv_base * base,u_char *pos, u_char *last);
static bool convert_mp4_parse_ds(c_conv_base * base,u_char *pos, u_char *last);

static convert_mp4_descriptor_t        convert_mp4_descriptors[] = {
    { 0x03,   convert_mp4_parse_es   },    /* MPEG ES Descriptor */
    { 0x04,   convert_mp4_parse_dc   },    /* MPEG DecoderConfig Descriptor */
    { 0x05,   convert_mp4_parse_ds   }     /* MPEG DecoderSpec Descriptor */
};

static bool convert_mp4_parse(c_conv_base * base,u_char *pos, u_char *last);
static bool convert_mp4_parse_trak(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_mdhd(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_hdlr(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_stsd(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_stsc(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_stts(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_ctts(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_stss(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_stsz(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_stz2(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_stco(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_co64(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_avc1(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_avcC(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_mp4a(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_mp4v(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_esds(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_mp3(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_nmos(c_conv_base *base, u_char *pos, u_char *last);
static bool convert_mp4_parse_spex(c_conv_base *base, u_char *pos, u_char *last);

static convert_mp4_box_t                       s_convert_rtmp_mp4_boxes[] = {
    { convert_mp4_make_tag('t','r','a','k'),   convert_mp4_parse_trak   },
    { convert_mp4_make_tag('m','d','i','a'),   convert_mp4_parse         },
    { convert_mp4_make_tag('m','d','h','d'),   convert_mp4_parse_mdhd   },
    { convert_mp4_make_tag('h','d','l','r'),   convert_mp4_parse_hdlr   },
    { convert_mp4_make_tag('m','i','n','f'),   convert_mp4_parse         },
    { convert_mp4_make_tag('s','t','b','l'),   convert_mp4_parse         },
    { convert_mp4_make_tag('s','t','s','d'),   convert_mp4_parse_stsd   },
    { convert_mp4_make_tag('s','t','s','c'),   convert_mp4_parse_stsc   },
    { convert_mp4_make_tag('s','t','t','s'),   convert_mp4_parse_stts   },
    { convert_mp4_make_tag('c','t','t','s'),   convert_mp4_parse_ctts   },
    { convert_mp4_make_tag('s','t','s','s'),   convert_mp4_parse_stss   },
    { convert_mp4_make_tag('s','t','s','z'),   convert_mp4_parse_stsz   },
    { convert_mp4_make_tag('s','t','z','2'),   convert_mp4_parse_stz2   },
    { convert_mp4_make_tag('s','t','c','o'),   convert_mp4_parse_stco   },
    { convert_mp4_make_tag('c','o','6','4'),   convert_mp4_parse_co64   },
    { convert_mp4_make_tag('a','v','c','1'),   convert_mp4_parse_avc1   },
    { convert_mp4_make_tag('a','v','c','C'),   convert_mp4_parse_avcC   },
    { convert_mp4_make_tag('m','p','4','a'),   convert_mp4_parse_mp4a   },
    { convert_mp4_make_tag('m','p','4','v'),   convert_mp4_parse_mp4v   },
    { convert_mp4_make_tag('e','s','d','s'),   convert_mp4_parse_esds   },
    { convert_mp4_make_tag('.','m','p','3'),   convert_mp4_parse_mp3    },
    { convert_mp4_make_tag('n','m','o','s'),   convert_mp4_parse_nmos   },
    { convert_mp4_make_tag('s','p','e','x'),   convert_mp4_parse_spex   },
    { convert_mp4_make_tag('w','a','v','e'),   convert_mp4_parse }
};

static bool push_keyframe_mp4_static(void * user,const conv_frame_info * node)
{
    c_mp4_file * f = (c_mp4_file *)user;
    if(NULL == f)
        return false;

    return f->push_keyframe(node);
}

static void cliear_keyframe_mp4_static(void *user)
{
    c_mp4_file * f = (c_mp4_file *)user;
    if(NULL == f)
        return ;

    f->clear_keyframe();
}

c_mp4_file::c_mp4_file(void)
{
	conv_zero(&m_ctx,sizeof(m_ctx));
    m_pdata = NULL;
    m_node_opt.push_keyframe_cb = push_keyframe_mp4_static;
    m_node_opt.cliear_keyframe_cb = cliear_keyframe_mp4_static;
    m_node_opt.user  = this;
}

c_mp4_file::~c_mp4_file(void)
{
    if(m_pdata)
        delete []m_pdata;
    m_pdata = NULL;
}

bool c_mp4_file::clear_keyframe()
{
    m_keyframes.clear();
    return true;
}

bool c_mp4_file::push_keyframe(const conv_frame_info * node)
{
//    m_keyframes.push_back(*node);
    return true;
}

const char * c_mp4_file::switch_box_to_printf(uint32_t * tag)
{
	static char ctag[5];
	memcpy(ctag,tag,4);
	ctag[4] = '\0';
	return ctag;
}

void c_mp4_file::print_box_tag(uint32_t* tag)
{
	cout << "box:" << switch_box_to_printf(tag) << endl;
}

bool c_mp4_file::get_codec_ctx(conv_codec_ctx_t * ctx)
{
	if(c_conv_base::get_codec_ctx(ctx))
		return true;

	m_codec_ctx->w = m_ctx.width;
	m_codec_ctx->h = m_ctx.height;
	m_codec_ctx->samplerate = m_ctx.sample_rate;
	m_codec_ctx->samplesize = m_ctx.sample_size;
	m_codec_ctx->fps = 0;
	m_codec_ctx->nchannels = m_ctx.nchannels;
	convert_mp4_track_t    *track;
	conv_str_t *pconfig;
	for(uint32_t n = 0 ; n < m_ctx.ntracks;++n)
	{
		track = &m_ctx.tracks[n];
		if(n == (uint32_t)m_ctx.vindex)
		{
			pconfig = &m_codec_ctx->video_config;
			m_codec_ctx->codec_video = track->codec;
            cout << "video config ";
		}
		else
		{
			pconfig = &m_codec_ctx->audio_config;
			m_codec_ctx->codec_audio = track->codec;
            cout << "audio config ";
		}
        
		pconfig->si = track->header_size;
		pconfig->p = track->header;

	}
	if(ctx)
		*ctx = *m_codec_ctx;
	return true;
}

int  c_mp4_file::demux_keyframes()
{
    Size offset, size,shift;

    if(m_io == NULL)
        return false;

    if(!parse_moov(offset,size,shift))
        return false;

    m_pdata = new u_char[size];
    m_io->read_poisx(m_pdata,size,offset);
    m_moov_oft = offset;
    if(!mp4_parse((u_char *) m_pdata, (u_char *) m_pdata + size))
        return false;

    if(!convert_mp4_seek(0))
        return false;

    set_keyframes();

    if(!convert_mp4_seek(0))
        return false;

    return m_keyframes.size();
}

bool c_mp4_file::set_keyframes()
{
    convert_mp4_ctx_t             *	ctx = get_ctx();
    convert_mp4_track_t           	*t, *cur_t;
    convert_mp4_cursor_t          	*cr, *cur_cr;
    uint32_t                     	timestamp ,
                                    cur_timestamp;
	uint32_t                        n;

    for ( ;; ) 
	{
        timestamp = 0;
        t = NULL;

        for (n = 0; n < ctx->ntracks; n++)
		{
            cur_t = &ctx->tracks[n];
            cur_cr = &cur_t->cursor;

            if (!cur_cr->valid)
			{
                continue;
            }

            cur_timestamp = convert_mp4_to_rtmp_timestamp(cur_t, cur_cr->timestamp);

            if (t == NULL || cur_timestamp < timestamp)
			{
                timestamp = cur_timestamp;
                t = cur_t;
            }
        }

        if (t == NULL)
		{
            cout << "mp4: no track" << endl;
            return true;
        }

        cr = &t->cursor;
        if(t->type == conv_packet_audio)
            goto next;
        if(cr->key)
        {
            m_keyframes.push_back(conv_frame_info(cr->size_pos,timestamp));
        }
next:
        if (!mp4_next(t) )
		{
            return 0;
        }
    }
}
bool c_mp4_file::demux(c_conv_base * mux,conv_size_t start_frame,int gop)
{
	if(m_io == NULL)
		return false;

	m_mux = mux;
    if(gop == 0)
    {
        demux_keyframes();
    }
    else
    {
        if((size_t)start_frame < m_keyframes.size())
        {
            convert_mp4_seek(m_keyframes[start_frame].stamp);
	        return mp4_parse_frame(gop);
        }
    }
	return mp4_parse_frame();
}

bool c_mp4_file::parse_moov(Size & offset,Size & size,Size & shift)
{
    uint32_t                    hdr[2];
    ssize_t                     n;
    uint64_t                    extended_size;

    offset = 0;
    size   = 0;

    for ( ;; ) 
	{
        n = m_io->read_poisx((u_char *) &hdr, sizeof(hdr), offset);

        if (n != sizeof(hdr))
		{
            caoc_pf("mp4: error reading file at offset=%d while searching for moov box,n=%d", (int)offset,(int)n);
            return false;
        }

        size = (size_t) convert_r32(hdr[0]);
        shift = sizeof(hdr);
        cout << "------new  box size :" << size << ",pos =" << m_io->tell() << endl;
		print_box_tag(hdr + 1);
        if (size == 1)
		{
            n = m_io->read_poisx((u_char *) &extended_size,
                              sizeof(extended_size), offset + sizeof(hdr));

            if (n != sizeof(extended_size))
			{
                caoc_pf("mp4: error reading file at offset=%d while searching for moov box", (int)offset + 8);
                return false;
            }

            size = (size_t) convert_r64(extended_size);
            shift += sizeof(extended_size);

        }
		else if (size == 0)
		{
            size = m_io->get_size() - offset;
        }

        if (hdr[1] == convert_mp4_make_tag('m','o','o','v')) 
        {
            break;
        }
        else if(hdr[1] == convert_mp4_make_tag('f','t','y','p'))
        {
#if CONV_DEBUG
            u_char *ftyp = new u_char[size];
            m_io->read_poisx(ftyp, size, offset+shift);
            print_box_tag((uint32_t*)ftyp);
            int minor = convert_r32(*(uint32_t*)(ftyp+4));
            cout << "ftype minor:" << minor << endl;
            /*size包括头与上面2个 */
            for(int nm = 0; nm < (size - 8 - 8);nm += 4)
            {
                print_box_tag((uint32_t*)(ftyp+8+nm));
            }
            cout << "ftype end" << endl;
            delete []ftyp;
#endif
        }

        offset += size;
    }

    if (size < shift)
	{
        return false;
    }

    size   -= shift;
    offset += shift;
	return true;
}

bool c_mp4_file::mp4_parse_stsd(u_char * pos,u_char * last)
{
    if (pos + 8 > last) 
	{
        return false;
    }
	
	/*
	 * FullBox 4 Byte
	 * entry_count 4 Byte
	 * */
    pos += 8;

    convert_mp4_parse(this, pos, last);

    return true;
}

bool c_mp4_file::mp4_parse_avcC(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();

    if (pos == last)
	{
        return true;
    }

    if (ctx->track == NULL || ctx->track->codec != CONVERT_VIDEO_H264)
	{
        return true;
    }

    ctx->track->header = pos;
    ctx->track->header_size = (size_t) (last - pos);

    cout << "mp4: video h264 header size=" << ctx->track->header_size << endl;

    return true;
}

bool  c_mp4_file::mp4_parse_video(u_char *pos, u_char *last,int codec)
{
    convert_mp4_ctx_t         *ctx = get_ctx();

    if (ctx->track == NULL)
	{
        return true;
    }

    ctx->track->codec = codec;

	/*
	 * SampleEntry 
	 * * reversed  1*6 Byte
	 * * data_reference_index 2 Byte
	 * pre_defined 2 Byte
	 * reverved    2 Byte
	 * pre_defined 4*3 Byte
	 *
	 * width       2 Byte
	 * height      2 Byte
	 *
	 * horizeresolution 4 Byte
	 * vertresolution   4 Byte
	 * reserved    4 Byte
	 * framecount  2 Byte
	 * compressorname 32 Byte
	 * depth       2 Byte
	 * pre_defined 2 Byte
	 * */
    if (pos + 78 > last)
	{
        return false;
    }

    pos += 24;

    ctx->width = convert_r16(*(uint16_t *) pos);

    pos += 2;

    ctx->height = convert_r16(*(uint16_t *) pos);

    pos += 52;

    cout << "mp4: video settings codec=" << codec <<  ",width=" << ctx->width <<  ",height=" << ctx->height << endl;

    if (!convert_mp4_parse(this, pos, last))
	{
        return false;
    }

    return true;
}

bool c_mp4_file::mp4_parse_hdlr(u_char * pos,u_char * last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    uint32_t                    type;

    if (ctx->track == NULL)
	{
        return true;
    }

    if (pos + 12 > last)
	{
        return true;
    }

	/*
	 * FullBox 4 Byte
	 *
	 * pre_defined 4 Byte
	 * handler_type 4 Byte
	 *  *vide - video track
	 *  *soun - Audio track
	 *  *hint - Hint track
	 *  *meta - Timed Metadata trunk
	 *  *auxv - Auxiliary Video track 
	 *  *
	 * reversed     4 Byte
	 * clap Box     optional
	 * pasp Box     optional
	 * */
    type = *(uint32_t *)(pos + 8);

    if (type == convert_mp4_make_tag('v','i','d','e'))
	{
        ctx->track->type = conv_packet_video;

        cout << "mp4: video track" << endl;

    }
	else if (type == convert_mp4_make_tag('s','o','u','n'))
	{
        ctx->track->type = conv_packet_audio;

        cout << "mp4: audio track" << endl;
    } 
	else 
	{
    	cout << "mp4: unknown track" << endl;
    }

    return true;
}

bool c_mp4_file::mp4_parse_mdhd(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();

    convert_mp4_track_t       *t;
    uint8_t                     version;

    if (ctx->track == NULL) 
	{
        return 0;
    }

    t = ctx->track;

    if (pos + 1 > last) {
        return 0;
    }

    version = *(uint8_t *) pos;
	/*
	 * //FullBox 
	 * version 1 Byte
	 * flag    3 Byte
	 * 
	 * if(version == 1)
	 * creationtime  8 Byte
	 * modification  8 Byte
	 * timescale     4 Byte
	 * duration      4 Byte
	 * else
	 * creationtime  4 
	 * modification  4
	 * timescale     4
	 * duration      4
   */

    switch (version) {
        case 0:
            if (pos + 20 > last) {
                return 0;
            }

            pos += 12;
            t->time_scale = convert_r32(*(uint32_t *) pos);
            pos += 4;
            t->duration = convert_r32(*(uint32_t *) pos);
            break;

        case 1:
            if (pos + 28 > last) {
                return 0;
            }

            pos += 20;
            t->time_scale = convert_r32(*(uint32_t *) pos);
            pos += 4;
            t->duration = convert_r64(*(uint64_t *) pos);
            break;

        default:
            return 0;
    }

    cout << "mp4: duration time_scale=" << t->time_scale << ", duration=" << t->duration << endl;

    return 1;
}

bool c_mp4_file::mp4_parse(u_char * pos,u_char * last)
{
    uint32_t                   *hdr, tag;
    size_t                      size, nboxes;
    uint32_t                  n;
    convert_mp4_box_t         *b;
    uint64_t                    extended_size;
    int  shift = 0;

    nboxes = sizeof(s_convert_rtmp_mp4_boxes) / sizeof(s_convert_rtmp_mp4_boxes[0]);

    while (pos != last)
	{
        if (pos + 8 > last)
		{
            cout<< "mp4: too small box: size=" << last - pos << endl;
            return false;
        }

        hdr = (uint32_t *) pos;
        size = convert_r32(hdr[0]);
        tag  = hdr[1];

        if (pos + size > last)
		{
            cout << "mp4: too big box" << "size=" <<  size;
            switch_box_to_printf(&tag);
            cout  << endl;
            return false;
        }
        if (size == 1)
		{
            cout << "size == 1" << endl;
            memcpy(&extended_size,pos + 8,8);
            size = (size_t) convert_r64(extended_size);
            shift = sizeof(extended_size);
        }
        else if(size == 0)
        {
            cout << "mp4 size is 0";
            switch_box_to_printf(&tag);
            cout  << endl;
            return false;
            size = last - pos;
        }

        b = s_convert_rtmp_mp4_boxes;

        for (n = 0; n < nboxes && b->tag != tag; ++n, ++b);

        if (n == nboxes) 
		{
        	cout << "mp4: box unhandled " <<  switch_box_to_printf(&tag) << ",sizee = "<< size << endl;
        }
		else
		{
            cout << "box size:" << size << " ";
			print_box_tag(&tag);
            cout  << endl;
            b->handler(this, pos + 8 + shift, pos + size);
        }

        pos += (size + shift);
        shift = 0;
    }

	return true;
}

bool c_mp4_file::mp4_parse_trak(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();

    if (ctx->track)
	{
        return 0;
    }

    ctx->track = (ctx->ntracks == sizeof(ctx->tracks) / sizeof(ctx->tracks[0]))
                 ? NULL : &ctx->tracks[ctx->ntracks];

    if (ctx->track)
	{
        conv_zero(ctx->track, sizeof(*ctx->track));
        ctx->track->id = ctx->ntracks;
    }

    if (!mp4_parse(pos, last))
	{
        return 0;
    }

    if (ctx->track && ctx->track->type &&
            (ctx->ntracks == 0 ||
             ctx->tracks[0].type != ctx->tracks[ctx->ntracks].type))
    {
        if (ctx->track->type == conv_packet_audio )
        {
            if (ctx->atracks++ != ctx->aindex)
            {
                ctx->track = NULL;
                return 1;
            }

        } 
        else 
        {
            if (ctx->vtracks++ != ctx->vindex)
            {
                ctx->track = NULL;
                return 1;
            }
        }

        ++ctx->ntracks;

    } 
    else
    {
        cout << "mp4: ignoring track:" <<  ctx->ntracks << " "<< ctx->track->type  << endl;
    }

    ctx->track = NULL;

    return 1;
}

bool c_mp4_file::mp4_parse_audio(u_char *pos, u_char *last,int codec)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    uint32_t                  version;

    if (ctx->track == NULL)
	{
        return true;
    }

    ctx->track->codec = codec;

    if (pos + 28 > last)
	{
        return false;
    }
	/*
	 * * reversed  1*6 Byte
	 * * data_reference_index 2 Byte
	 * reverved 2 * 4 Byte
	 * channelcount 2 Byte
	 * samplesize   2 Byte
	 * pre_defined  2 Byte
	 * reversed     2 Byte
	 * samplerate   4 Byte
	 * */

    pos += 8;

	/*reserved[0] is version*/
    version = convert_r16(*(uint16_t *) pos);

    pos += 8;

    ctx->nchannels = convert_r16(*(uint16_t *) pos);

    pos += 2;

    ctx->sample_size = convert_r16(*(uint16_t *) pos);

    pos += 6;

    ctx->sample_rate = convert_r16(*(uint16_t *) pos);

    pos += 4;

   cout << "mp4: audio settings version=" << version << 
	   ", codec=" << codec << ", nchannels==" << ctx->nchannels << 
	   ", sample_size=" << ctx->sample_size << ", sample_rate=" << ctx->sample_rate << endl;

    switch (version) 
	{
        case 1:
            pos += 16;
            break;

        case 2:
            pos += 36;
    }

    if (pos > last) 
	{
        return false;
    }

    if (!mp4_parse(pos, last))
	{
        return false;
    }

    return true;
}

/*
 * 时间戳与sample的关系
 * entry count  3
 * sample count         sample duration
 *     4个                    3
 *     2个                    1
 *     3个                    2
 * */
bool c_mp4_file::mp4_parse_stts(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx =get_ctx();
    convert_mp4_track_t       *t;

    t = ctx->track;

    if (t == NULL) 
	{
        return true;
    }

    t->times = (convert_mp4_times_t *) pos;
    t->times->entry_count = convert_r32(t->times->entry_count);

    if (pos + sizeof(*t->times) + (t->times->entry_count) *
                                  sizeof(t->times->entries[0])
        <= last)
    {
        cout << "mp4: times entries=" << t->times->entry_count << endl;
        return true;
    }

    t->times = NULL;
    return false;
}

/*
 * 时间戳偏移表 
 * 有些B帧需要cts的相对时间戳时间戳
 * */
bool c_mp4_file::mp4_parse_ctts(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    convert_mp4_track_t       *t;

    t = ctx->track;

    if (t == NULL)
	{
        return true;
    }

    t->delays = (convert_mp4_delays_t *) pos;
    t->delays->entry_count = convert_r32(t->delays->entry_count);

    if (pos + sizeof(*t->delays) + t->delays->entry_count * sizeof(t->delays->entries[0])
        <= last)
    {
        cout << "mp4: delays entries=" << (t->delays->entry_count) << endl;
        return true;
    }

    t->delays = NULL;
    return false;
}

/*
 * 关键帧列表
 *
 * sample 1
 * sample 10
 * sample 20 
 * 依次递增 
 * */
bool c_mp4_file::mp4_parse_stss(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    convert_mp4_track_t       *t;

    t = ctx->track;

    if (t == NULL) {
        return true;
    }

    t->keys = (convert_mp4_keys_t *) pos;
    t->keys->entry_count = convert_r32(t->keys->entry_count);
    if (pos + sizeof(*t->keys) + t->keys->entry_count * sizeof(t->keys->entries[0])
        <= last)
    {
        cout << "mp4: keys entries=" << (t->keys->entry_count) << endl;
        return true;
    }

    t->keys = NULL;
    return false;
}

/*
 * 每个sample的大小
 * */
bool c_mp4_file::mp4_parse_stsz(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    convert_mp4_track_t       *t;

    t = ctx->track;

    if (t == NULL)
	{
        return true;
    }

    t->sizes = (convert_mp4_sizes_t *) pos;

    if (pos + sizeof(*t->sizes) <= last && t->sizes->sample_size)
	{
        cout << "mp4: sizes size=" << convert_r32(t->sizes->sample_size) << endl;
        return true;
    }

    if (pos + sizeof(*t->sizes) + convert_r32(t->sizes->sample_count) *
                                  sizeof(t->sizes->entries[0])
        <= last)

    {
        cout << "mp4: sizes entries=" << convert_r32(t->sizes->sample_count) << endl;
        return true;
    }

    t->sizes = NULL;
    return false;
}

bool c_mp4_file::mp4_parse_stz2(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    convert_mp4_track_t       *t;

    t = ctx->track;

    if (t == NULL) 
	{
        return true;
    }

    t->sizes2 = (convert_mp4_sizes2_t *) pos;

    if (pos + sizeof(*t->sizes) + convert_r32(t->sizes2->sample_count) *
                                  convert_r32(t->sizes2->field_size) / 8
        <= last)
    {
       cout << "mp4: sizes2 field_size=" << convert_r32(t->sizes2->field_size) <<
		   "entries=" << convert_r32(t->sizes2->sample_count) << endl;
        return true;
    }

    t->sizes2 = NULL;
    return false;
}

/*
 * @caoc
 * chunk的信息
 * chunk包含了一个或者多个sample.
 * 每个chunk的size可能不同,
 * chunk里的每个sample也会不同.
 * 
 * example:
 * mp4: chunks entries=2                                                                                                                          
 * 0, first chunk:1,samples_per_chunk:10,sample_descrption_index:1
 * 1, first chunk:855,samples_per_chunk:3,sample_descrption_index:1
 *
 * 0条记录表明这个从1个chunk开始,每个chunk有10个sample.直到855结束.
 * 以上的例子里记录了2个chunk的entry.一共有855个chunk.只看图时计算不出chunk的个数的,
 * 这里的855个chunk可以根据stco的个数来得到,或者根据sample的个数推算出来.
 * 
 * 一个chunk里有多少个sample,
 * 每个sample的大小是在stsz中,
 * 每个chunk的位置在stco/co64中,这样就能计算出每个sample的位置.
 * 这样做的好处在于避免给每个sample记录位置.
 * */
bool c_mp4_file::mp4_parse_stsc(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    convert_mp4_track_t       *t;

    t = ctx->track;

    if (t == NULL)
	{
        return true;
    }

    t->chunks = (convert_mp4_chunks_t *) pos;
    t->chunks->entry_count = convert_r32(t->chunks->entry_count);

    if (pos + sizeof(*t->chunks) + t->chunks->entry_count *
                                   sizeof(t->chunks->entries[0])
        <= last)
    {
        uint32_t si = t->chunks->entry_count;
        cout << "mp4: chunks entries=" << si << endl;
        /*
        for(uint32_t n = 0; n < si;++n)
        {
            cout << n << ", first chunk:" << convert_r32(t->chunks->entries[n].first_chunk) << 
                ",samples_per_chunk:" << convert_r32(t->chunks->entries[n].samples_per_chunk) << 
                ",sample_descrption_index:" << convert_r32(t->chunks->entries[n].sample_descrption_index) << endl;
        }
        */
        return true;
    }

    t->chunks = NULL;
    return false;
}

/*
 * 记录每个chunk的偏移.
 * co64为64的版本.
 * */
bool c_mp4_file::mp4_parse_stco(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    convert_mp4_track_t       *t;

    t = ctx->track;

    if (t == NULL)
	{
        return true;
    }

    t->offsets = (convert_mp4_offsets_t *) pos;
    t->offsets->entry_count = convert_r32(t->offsets->entry_count);

    if (pos + sizeof(*t->offsets) + t->offsets->entry_count *
                                    sizeof(t->offsets->entries[0])
        <= last)
    {
        cout <<"mp4: offsets entries=" << t->offsets->entry_count << endl;
        return true;
    }

    t->offsets = NULL;
    return false;
}

bool c_mp4_file::mp4_parse_co64(u_char *pos, u_char *last)
{
    convert_mp4_ctx_t         *ctx = get_ctx();
    convert_mp4_track_t       *t;

    t = ctx->track;

    if (t == NULL) 
	{
        return true;
    }

    t->offsets64 = (convert_mp4_offsets64_t *) pos;
    t->offsets64->entry_count = convert_r32(t->offsets64->entry_count);

    if (pos + sizeof(*t->offsets64) + t->offsets64->entry_count *
                                      sizeof(t->offsets64->entries[0])
        <= last)
    {
        cout << "mp4: offsets64 entries=" << t->offsets64->entry_count << endl;
        return true;
    }

    t->offsets64 = NULL;
    return false;
}

bool c_mp4_file::mp4_parse_esds(u_char *pos, u_char *last)
{
    if (pos + 4 > last)
	{
        return false;
    }

    pos += 4; /* version */

    return mp4_parse_descr(pos, last);
}

/*
 * esds box in ISO-14496-14 page:15
 * caoc 
 *
 * esdsbox
 *
 * Fullbox 4 Byte
 * ES_Descriptor ES; This In ISO-14496-1 page:170
 * * 5 byte Es_Number
 * * 1 byte streamDependence
 * * 1 url_flag
 * * 1 extensionFlag
 * */
bool c_mp4_file::mp4_parse_descr(u_char *pos, u_char *last)
{
    uint8_t                     tag, v;
    uint32_t                    size;
    uint32_t                  n, ndesc;
    convert_mp4_descriptor_t   *ds;

    ndesc = sizeof(convert_mp4_descriptors)
          / sizeof(convert_mp4_descriptors[0]);

    while (pos < last)
	{
        tag = *(uint8_t *) pos++;

        for (size = 0, n = 0; n < 4; ++n) 
		{
            if (pos == last) 
			{
                return false;
            }

            v = *(uint8_t *) pos++;

            size = (size << 7) | (v & 0x7f);

            if (!(v & 0x80)) 
			{
                break;
            }
        }

        if (pos + size > last) 
		{
            return false;
        }

        ds = convert_mp4_descriptors;;

        for (n = 0; n < ndesc; ++n, ++ds) 
		{
            if (tag == ds->tag) 
			{
                break;
            }
        }

        if (n == ndesc) 
		{
            ds = NULL;
        }

        cout << "mp4: descriptor" << (ds ? "" : " unhandled") << 
			" tag=" << tag << "size=" << size << endl;

        if (ds && ds->handler(this, pos, pos + size) != true)
		{
            return false;
        }

        pos += size;
    }

    return true;
}

bool c_mp4_file::mp4_parse_es(u_char *pos, u_char *last)
{
    uint16_t    id;
    uint8_t     flags;

    if (pos + 3 > last) 
	{
        return false;
    }

    id = convert_r16(*(uint16_t *) pos);
    pos += 2;

    flags = *(uint8_t *) pos;
    ++pos;

    if (flags & 0x80)
	{ /* streamDependenceFlag */
        pos += 2;
    }

    if (flags & 0x40) 
	{ /* URL_FLag */
        return true;
    }

    if (flags & 0x20)
	{ /* OCRstreamFlag */
        pos += 2;
    }

    if (pos > last) {
        return false;
    }

    (void) id;

    cout << "mp4: es descriptor es id=" << id << "flags=" << flags  << endl;

    return mp4_parse_descr(pos, last);
}

bool c_mp4_file::mp4_parse_ds(u_char * pos,u_char * last)
{
    convert_mp4_ctx_t     *ctx = get_ctx();
    convert_mp4_track_t   *t;

    t = ctx->track;

    if (t == NULL)
	{
        return true;
    }

    t->header = pos;
    t->header_size = (size_t) (last - pos);

    cout << "mp4: decoder header size=" << t->header_size << endl;
#if CONV_DEBUG
        cout.setf(ios::showbase);
        cout.unsetf(ios::dec); 
        cout.setf(ios::hex); 
        for(uint32_t n = 0 ; n < t->header_size ;++n)
        {
            cout << " ";
            cout << (int)pos[n];
        }
        cout << endl;
        cout.unsetf(ios::hex);  
#endif

    return true;

}

bool c_mp4_file::mp4_parse_dc(u_char * pos,u_char * last)
{
    uint8_t                 id;
    convert_mp4_ctx_t     *ctx = get_ctx();
    int                    *pc;

    if (ctx->track == NULL)
	{
        return true;
    }

    if (pos + 13 > last)
	{
        return false;
    }

    id = * (uint8_t *) pos;
    pos += 13;
    pc = &ctx->track->codec;

    switch (id)
	{
        case 0x21:
            *pc = CONVERT_VIDEO_H264;
            break;

        case 0x40:
        case 0x66:
        case 0x67:
        case 0x68:
            *pc = CONVERT_AUDIO_AAC;
            break;

        case 0x69:
        case 0x6b:
            *pc = CONVERT_AUDIO_MP3;
            break;
    }

    cout << "mp4: decoder descriptor id=" << id <<  "codec=" << *pc << endl;

    return mp4_parse_descr(pos, last);
}

bool c_mp4_file::mp4_parse_frame(int gop)
{
    convert_mp4_ctx_t             *	ctx = get_ctx();
    convert_mp4_track_t           	*t, *cur_t;
    convert_mp4_cursor_t          	*cr, *cur_cr;
    uint32_t                     	timestamp ,
                                    cur_timestamp;
    ssize_t                         ret;
    long                            counter;
	uint32_t                        n;

#define CONVERT_MP4_BUFLEN_ADDON       1000

    if (ctx == NULL)
	{
        return false;
    }

    counter = 0;

	conv_str_t header;
	header.p = m_ctx.tracks[m_ctx.vindex].header;
	header.si = m_ctx.tracks[m_ctx.vindex].header_size;
    bool append_sps = false;
    int dst_count = gop + 1;
    for ( ;; ) 
	{
        counter++;
        timestamp = 0;
        t = NULL;

        for (n = 0; n < ctx->ntracks; n++)
		{
            cur_t = &ctx->tracks[n];
            cur_cr = &cur_t->cursor;

            if (!cur_cr->valid)
			{
                continue;
            }

            cur_timestamp = convert_mp4_to_rtmp_timestamp(cur_t, cur_cr->timestamp);

            if (t == NULL || cur_timestamp < timestamp)
			{
                timestamp = cur_timestamp;
                t = cur_t;
            }
        }

        if (t == NULL)
		{
            cout << "mp4: no track" << endl;
            return true;
        }

        cr = &t->cursor;

		conv_in_out_packe_t *node = get_node(cr->size);
		node->stamp = timestamp;
		node->type = t->type;

        //cout << "mp4 timestamp:" << timestamp << endl;
		//可以优化，不需要拷贝，这里没做
        //cout << "frame pos :" << cr->offset << ",size:" << cr->size << ",type:" << t->type << endl; 
        ret = m_io->read_poisx(node->p,cr->size, cr->offset);

        if (ret != (ssize_t) cr->size)
		{
       //   cout << "mp4: track#" << t->id <<  "could not read frame" << endl;
            goto next;
        }

        if(gop > 0 && cr->key)
        {
            dst_count--;
        }
        if(dst_count <= 0)
            return true;

        if (t->type == conv_packet_video && t->header != NULL)
		{
            uint32_t nsi = cr->size;
            conv_in_out_packe_t * pheader = node;
            conv_in_out_packe_t ** plast = &pheader;
            int bkeyframe = t->cursor.key;
            while(nsi > 0)
            {
			    uint32_t nal_size = convert_r32(*(uint32_t*)node->p);
                nsi -= (nal_size + 4);
                caoc_pf("nal_size = %d\n",nal_size);
                node->si = nal_size + 4;
                node->cts = convert_mp4_to_rtmp_timestamp(t, cr->delay);
                u_char prefix[] = {0,0,0,1};
                memcpy(node->p , prefix,4);

                int nal_type = node->p[4] & 0x1f;
                conv_in_out_packe_t * h264_header = NULL;

                if(nal_type != 5 && nal_type != 6)
                {
                    append_sps = false;
                }
                else if(!append_sps) 
                {
                    bkeyframe = 1;	
                    h264_header = conv_append_sps_pps(timestamp,&header,this);
                    if (h264_header != NULL)
                    {
                        *plast = h264_header;
                        for(;h264_header->next != NULL;h264_header=h264_header->next){}
                        h264_header->next = node;
                    }
                    append_sps = true;
                }


                if(nsi > 0)
                {
                    conv_in_out_packe_t *node2 = get_node(sizeof(void*));
                    *node2 = *node;
                    node2->p = node->p + nal_size +  4;
                    node2->next  = NULL;

                    node->next = node2;
                    plast = &node->next;
                    node = node2;
                }
            }
#if CONV_WRITE_TEST_FILE
#if 0
		if(t->type == conv_packet_video)
		{
			if(NULL == s_h264)
			{
				s_h264 = fopen("test.h264","wb");
			}
            conv_in_out_packe_t * pp = pheader;
            for(;pp != NULL;pp=pp->next)
            {
                if(pp->p)
                    fwrite(pp->p ,pp->si,1,s_h264);
            }
		}
#endif
#endif
            if(pheader)
                pheader->key_frame = bkeyframe;
            push_node(pheader,true);
		}
		else
		{
			node->key_frame = t->cursor.key;
            push_node(node,true);
		}

#if 0
        cout << "mp4: track#" << t->id << ",read frame offset=" << cr->offset << ", size=" << cr->size << 
			", timestamp=" << timestamp << ", type=" << t->type << ",cts="<< node->cts << endl;
#endif

#if 0
		if(t->type == conv_packet_audio)
		{
			static FILE * s_aac = NULL;
			if(NULL == s_aac)
			{
				s_aac = fopen("test.aac","wb");
			}
			fwrite(node->p,node->si,1,s_aac);
		}
#endif
next:
        if (!mp4_next(t) )
		{
            return 0;
        }
    }
#if CONV_WRITE_TEST_FILE	
	if(s_h264)
		fclose(s_h264);
#endif
	return 1;
}

bool c_mp4_file::mp4_next(convert_mp4_track_t *t)
{
    if (!convert_mp4_next_time(t) ||
        !convert_mp4_next_key(t)  ||
        !convert_mp4_next_chunk(t)  ||
        !convert_mp4_next_size(t)  ||
        !convert_mp4_next_delay(t))
    {
        t->cursor.valid = 0;
        return false;
    }

    t->cursor.valid = 1;
    return true;
}

bool c_mp4_file::convert_mp4_next_size(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t          *cr;

    cr = &t->cursor;

    cr->offset += cr->size;

    if (t->sizes)
	{
        if (t->sizes->sample_size)
		{
            cr->size = convert_r32(t->sizes->sample_size);
            return true;
        }

        cr->size_pos++;

        if (cr->size_pos >= convert_r32(t->sizes->sample_count))
		{
            return false;
        }

        cr->size = convert_r32(t->sizes->entries[cr->size_pos]);

        return true;
    }

    if (t->sizes2)
	{
        if (cr->size_pos >= convert_r32(t->sizes2->sample_count)) 
		{
            return false;
        }

        /*TODO*/

        return true;
    }

    return false;
}

bool c_mp4_file::convert_mp4_next_chunk(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t          *cr;
    convert_mp4_chunk_entry_t     *ce, *nce;
    long 						new_chunk;

    if (t->chunks == NULL) 
	{
        return true;
    }

    cr = &t->cursor;

    if (cr->chunk_pos >= t->chunks->entry_count) 
	{
        printf("mp4: track#%d chunk[%d/%d] overflow",
                       (int)t->id, (int)cr->chunk_pos,
                       (int)t->chunks->entry_count);

        return false;
    }

    ce = &t->chunks->entries[cr->chunk_pos];

    cr->chunk_count++;

    if (cr->chunk_count >= convert_r32(ce->samples_per_chunk)) 
	{
        cr->chunk_count = 0;
        cr->chunk++;

        if (cr->chunk_pos + 1 < t->chunks->entry_count) 
		{
            nce = ce + 1;
            if (cr->chunk >= convert_r32(nce->first_chunk)) 
			{
                cr->chunk_pos++;
                ce = nce;
            }
        }

        new_chunk = 1;

    } 
	else
	{
        new_chunk = 0;
    }

    if (new_chunk)
	{
        return convert_mp4_update_offset(t);
    }

    return true;
}

bool c_mp4_file::convert_mp4_update_offset(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t          *cr;
    uint32_t  chunk;

    cr = &t->cursor;

    if (cr->chunk < 1)
	{
        return false;
    }

    chunk = cr->chunk - 1;

    if (t->offsets)
	{
        if (chunk >= t->offsets->entry_count) 
		{
            return false;
        }

        cr->offset = (off_t) convert_r32(t->offsets->entries[chunk]);
        cr->size = 0;

        return true;
    }

    if (t->offsets64)
	{
        if (chunk >= t->offsets64->entry_count) 
		{
            return false;
        }

        cr->offset = (off_t) convert_r64(t->offsets64->entries[chunk]);
        cr->size = 0;

        return true;
    }

    return false;
}

bool c_mp4_file::convert_mp4_next_key(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t          *cr;
    uint32_t                       *ke;

    cr = &t->cursor;

    if (t->keys == NULL)
	{
        return true;
    }

    if (cr->key)
	{
        cr->key_pos++;
    }

    if (cr->key_pos >= t->keys->entry_count)
	{
        cr->key = 0;
        return true;
    }

    ke = &t->keys->entries[cr->key_pos];
    cr->key = (cr->pos + 1 == convert_r32(*ke));

#if 0
    printf("mp4: track#%d key[%d/%d][%d/%d]=%s\n",
                   (int)t->id, (int)cr->key_pos,
                   (int)convert_r32(t->keys->entry_count),
                   (int)cr->pos, (int)convert_r32(*ke),
                   (int)cr->key ? "match" : "miss");
#endif

    return true;
}

bool c_mp4_file::convert_mp4_next_time(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t      *cr;
    convert_mp4_time_entry_t  *te;

    if (t->times == NULL)
	{
        return false;
    }

    cr = &t->cursor;

    if (cr->time_pos >= t->times->entry_count) 
	{
        cout << "mp4: track#" << t->id << "time[" << cr->time_pos << "/" << 
			t->times->entry_count << "] overflow" << endl;

        return false;
    }

    te = &t->times->entries[cr->time_pos];

    cr->timestamp += convert_r32(te->sample_delta);

    cr->not_first = 1;

    cr->time_count++;
    cr->pos++;

    if (cr->time_count >= convert_r32(te->sample_count))
	{
        cr->time_pos++;
        cr->time_count = 0;
    }

    return true;
}

bool c_mp4_file::convert_mp4_next_delay(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t          *cr;
    convert_mp4_delay_entry_t     *de;

    cr = &t->cursor;

    if (t->delays == NULL) 
	{
        return true;
    }

    if (cr->delay_pos >= t->delays->entry_count) 
	{
        return true;
    }

    cr->delay_count++;
    de = &t->delays->entries[cr->delay_pos];

    if (cr->delay_count >= convert_r32(de->sample_count)) 
	{
        cr->delay_pos++;
        de++;
        cr->delay_count = 0;
    }

    if (cr->delay_pos >= t->delays->entry_count) 
	{
        return true;
    }

    cr->delay = convert_r32(de->sample_offset);

    return true;
}

bool c_mp4_file::convert_mp4_seek(long timestamp)
{
    convert_mp4_ctx_t     *ctx = get_ctx();
    convert_mp4_track_t   *t;
    uint32_t               n;

    if (ctx == NULL) 
	{
        return true;
    }

    for (n = 0; n < ctx->ntracks; ++n) 
	{
        t = &ctx->tracks[n];

        if (t->type != conv_packet_video)
		{
            continue;
        }

        convert_mp4_seek_track(t, timestamp);

        timestamp = convert_mp4_to_rtmp_timestamp(t, t->cursor.timestamp);

        break;
    }

    for (n = 0; n < ctx->ntracks; ++n) 
	{
        t = &ctx->tracks[n];

        if (t->type == conv_packet_video) 
		{
            continue;
        }

        convert_mp4_seek_track(&ctx->tracks[n], timestamp);
    }

    ctx->start_timestamp = timestamp;

    return convert_mp4_reset();
}

bool c_mp4_file::convert_mp4_reset()
{
    convert_mp4_ctx_t     *ctx = get_ctx();
    convert_mp4_cursor_t  *cr;
    convert_mp4_track_t   *t;
    uint32_t              n;

    if (ctx == NULL) 
	{
        return true;
    }

    t = &ctx->tracks[0];
    for (n = 0; n < ctx->ntracks; ++n, ++t) 
	{
        cr = &t->cursor;
        cr->not_first = 0;
    }

    return true;
}

bool c_mp4_file::convert_mp4_seek_time(convert_mp4_track_t *t, uint32_t timestamp)
{
    convert_mp4_cursor_t      *cr;
    convert_mp4_time_entry_t  *te;
    uint32_t                    dt;

    if (t->times == NULL) 
	{
        return false;
    }

    cr = &t->cursor;

    te = t->times->entries;

    while (cr->time_pos < t->times->entry_count) 
	{
        dt = convert_r32(te->sample_delta) * convert_r32(te->sample_count);

        if (cr->timestamp + dt >= timestamp) 
		{
            if (te->sample_delta == 0) 
			{
                return false;
            }

            cr->time_count = (timestamp - cr->timestamp) /
                             convert_r32(te->sample_delta);
            cr->timestamp += convert_r32(te->sample_delta) * cr->time_count;
            cr->pos += cr->time_count;

            break;
        }

        cr->timestamp += dt;
        cr->pos += convert_r32(te->sample_count);
        cr->time_pos++;
        te++;
    }

    if (cr->time_pos >= t->times->entry_count) 
	{
        return  false;
    }

    return true;
}

bool c_mp4_file::convert_mp4_seek_key(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t      *cr;
    uint32_t                   *ke;
    long 						dpos;

    cr = &t->cursor;

    if (t->keys == NULL)
	{
        return true;
    }

    while (cr->key_pos < t->keys->entry_count)
	{
        if (convert_r32(t->keys->entries[cr->key_pos]) > cr->pos) 
		{
            break;
        }

        cr->key_pos++;
    }

    if (cr->key_pos >= t->keys->entry_count) 
	{
        return true;
    }

    ke = &t->keys->entries[cr->key_pos];
    /*cr->key = (cr->pos + 1 == convert_r32(*ke));*/

    /* distance to the next keyframe */
    dpos = convert_r32(*ke) - cr->pos - 1;
    cr->key = 1;

    /* TODO: range version needed */
    for (; dpos > 0; --dpos) 
	{
        convert_mp4_next_time(t);
    }

/*    cr->key = (cr->pos + 1 == convert_r32(*ke));*/

    return true;
}

bool c_mp4_file::convert_mp4_seek_chunk(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t          *cr;
    convert_mp4_chunk_entry_t     *ce, *nce;
    unsigned long pos, dpos, dchunk;

    cr = &t->cursor;

    if (t->chunks == NULL || t->chunks->entry_count == 0)
	{
        cr->chunk = 1;
        return true;
    }

    ce = t->chunks->entries;
    pos = 0;

    while (cr->chunk_pos + 1 < t->chunks->entry_count) 
	{
        nce = ce + 1;

        dpos = (convert_r32(nce->first_chunk) -
                convert_r32(ce->first_chunk)) *
                convert_r32(ce->samples_per_chunk);

        if (pos + dpos > cr->pos) 
		{
            break;
        }

        pos += dpos;
        ce++;
        cr->chunk_pos++;
    }

    if (ce->samples_per_chunk == 0) 
	{
        return false;
    }

    dchunk = (cr->pos - pos) / convert_r32(ce->samples_per_chunk);

    cr->chunk = convert_r32(ce->first_chunk) + dchunk;
    cr->chunk_pos = (ce - t->chunks->entries);
    cr->chunk_count = (cr->pos - pos - dchunk *
                                    convert_r32(ce->samples_per_chunk));

    return convert_mp4_update_offset(t);
}

bool c_mp4_file::convert_mp4_seek_size(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t      *cr;
    unsigned long pos;

    cr = &t->cursor;

    if (cr->chunk_count > cr->pos) 
	{
        return false;
    }

    if (t->sizes) 
	{
        if (t->sizes->sample_size) 
		{
            cr->size = convert_r32(t->sizes->sample_size);

            cr->offset += cr->size * cr->chunk_count;

            return true;
        }

        if (cr->pos >= convert_r32(t->sizes->sample_count)) 
		{
            return false;
        }

        for (pos = 1; pos <= cr->chunk_count; ++pos) 
		{
            cr->offset += convert_r32(t->sizes->entries[cr->pos - pos]);
        }

        cr->size_pos = cr->pos;
        cr->size = convert_r32(t->sizes->entries[cr->size_pos]);

        return true;
    }

    if (t->sizes2) 
	{
        if (cr->size_pos >= convert_r32(t->sizes2->sample_count)) 
		{

            return false;
        }

        cr->size_pos = cr->pos;

        /* TODO */
        return true;
    }

    return false;
}

bool c_mp4_file::convert_mp4_seek_track(convert_mp4_track_t *t, long timestamp)
{
    convert_mp4_cursor_t          *cr;

    cr = &t->cursor;
    conv_zero(cr,sizeof(*cr));

    if (!convert_mp4_seek_time( t, convert_mp4_from_rtmp_timestamp( t, timestamp))  ||
        !convert_mp4_seek_key(t) ||
        !convert_mp4_seek_chunk(t)||
        !convert_mp4_seek_size(t) ||
        !convert_mp4_seek_delay(t))
    {
        return false;
    }

    cr->valid = 1;
    return true;
}

bool c_mp4_file::convert_mp4_seek_delay(convert_mp4_track_t *t)
{
    convert_mp4_cursor_t      *cr;
    convert_mp4_delay_entry_t *de;
    uint32_t                    pos, dpos;

    cr = &t->cursor;

    if (t->delays == NULL) 
	{
        return true;
    }

    pos = 0;
    de = t->delays->entries;

    while (cr->delay_pos < t->delays->entry_count) 
	{
        dpos = convert_r32(de->sample_count);

        if (pos + dpos > cr->pos) 
		{
            cr->delay_count = cr->pos - pos;
            cr->delay = convert_r32(de->sample_offset);
            break;
        }

        cr->delay_pos++;
        pos += dpos;
        de++;
    }

    if (cr->delay_pos >= t->delays->entry_count) 
	{
        return true;
    }

    return true;
}

static bool convert_mp4_parse_ds(c_conv_base * base,u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_ds(pos,last);
}

static bool convert_mp4_parse_dc(c_conv_base * base,u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_dc(pos,last);
}

static bool convert_mp4_parse_es(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_es(pos,last);
}


static bool convert_mp4_parse_esds(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_esds(pos,last); 
}

static bool convert_mp4_parse_stco(c_conv_base* base,u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_stco(pos,last); 
}

static bool convert_mp4_parse_co64(c_conv_base* base,u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_co64(pos,last); 
}

static bool convert_mp4_parse_stsc(c_conv_base* base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_stsc(pos,last);
}

static bool convert_mp4_parse_stz2(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_stz2(pos,last);
}

static bool convert_mp4_parse_stsz(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_stsz(pos,last);
}

static bool convert_mp4_parse_stss(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_stss(pos,last);
}

static bool convert_mp4_parse_ctts(c_conv_base * base,u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_ctts(pos,last);
}

static bool convert_mp4_parse_stts(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_stts(pos,last);
}

static bool convert_mp4_parse(c_conv_base * base,u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse(pos,last);
}

static bool convert_mp4_parse_trak(c_conv_base *base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_trak(pos,last);
}

static bool convert_mp4_parse_mdhd(c_conv_base *base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_mdhd(pos,last);
}

static bool convert_mp4_parse_hdlr(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_hdlr(pos,last);
}

static bool convert_mp4_parse_stsd(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file *)base)->mp4_parse_stsd(pos,last);
}


static bool convert_mp4_parse_avc1(c_conv_base * base, u_char *pos, u_char *last)
{
    return ((c_mp4_file*)base)->mp4_parse_video(pos, last, CONVERT_VIDEO_H264);
}


static bool convert_mp4_parse_mp4v(c_conv_base *base, u_char *pos, u_char *last)
{
    return ((c_mp4_file*)base)->mp4_parse_video(pos, last, CONVERT_VIDEO_H264);
}

static bool convert_mp4_parse_avcC(c_conv_base * base, u_char *pos, u_char *last)
{
	return ((c_mp4_file*)base)->mp4_parse_avcC(pos,last);
}

static bool convert_mp4_parse_mp3(c_conv_base * base, u_char *pos, u_char *last)
{
    return ((c_mp4_file*)base)->mp4_parse_audio(pos, last, CONVERT_AUDIO_MP3);
}

static bool convert_mp4_parse_nmos(c_conv_base *base, u_char *pos, u_char *last)
{
    return ((c_mp4_file*)base)->mp4_parse_audio(pos, last, CONVERT_AUDIO_NELLY);
}


static bool convert_mp4_parse_spex(c_conv_base * base, u_char *pos, u_char *last)
{
    return ((c_mp4_file*)base)->mp4_parse_audio(pos, last, CONVERT_AUDIO_SPEEX);
}

static bool convert_mp4_parse_mp4a(c_conv_base * base, u_char *pos, u_char *last)
{
    return ((c_mp4_file*)base)->mp4_parse_audio(pos, last, CONVERT_AUDIO_MP3);
}

