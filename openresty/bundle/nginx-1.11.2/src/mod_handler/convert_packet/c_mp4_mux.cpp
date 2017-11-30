/*
 * =====================================================================================
 *
 *       Filename:  c_mp4_mux.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  02/07/15 19:55:33
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (490479164@qq.com), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include "c_mp4_mux.h"
#include <arpa/inet.h>
#include <limits.h>

void c_mp4_muxer::build_mem_writer(conv_in_out_packe_t * node,conv_mem_writer * pb)
{
    pb->pos = pb->start = node->p;
    pb->end = pb->pos + node->si;
    pb->si = node->si;
}

conv_in_out_packe_t * c_mp4_muxer::mux( const conv_in_out_packe_t *in, const conv_codec_ctx_t & ctx,int & ret)
{
    if(m_moov_end)
    {
    }
    else
    {
        write_packet(in,true);
        ret = 1;
    }
    return NULL;
}

void c_mp4_muxer::updtae_keyframes_pos()
{
    conv_size_t n = 0;
    conv_av_stream * v = &m_av[conv_packet_video - conv_packet_audio];
    m_node_opt.clear_keyframes();
    for(;n <v->entry;++n)
    {
        if(v->cluster[n].flags & MOV_SYNC_SAMPLE)
        {
            conv_frame_info keyframe;
            keyframe.pos = v->cluster[n].ppos + m_moov_pos;
            keyframe.stamp = v->cluster[n].dts;
            m_node_opt.push_keyframe(&keyframe);
        }
    }
}
conv_in_out_packe_t * c_mp4_muxer::mux_header(const conv_codec_ctx_t & ctx,long stamp)
{
    conv_in_out_packe_t * node = NULL;
    if(m_moov_end)
    {
        /*暂时还是放在最前面,因为放在后面也还是需要遍历大小*/
    }
    else
    {
        conv_mem_writer pb;
        for(int n = 1; n < 4; ++n)
        {
            node = m_node_opt.get_node(get_adout_mp4_header_size() * n);
            build_mem_writer(node,&pb);
            u_char * pos = pb.pos;
            write_ftyp(&pb,&ctx);
            write_moov(&pb);
            write_mdat(&pb);
            conv_size_t shift = pb.pos - pos;
            m_moov_pos = shift;
            u_char * end = pb.pos;
            /*write again*/
            for(int n = 0; n < 2;++n)
            {
                m_av[n].data_offset = shift;
                if(m_av[n].last_stco)
                {
                    conv_skip_field(&pb,m_av[n].last_stco);
                    write_stco(&pb, &m_av[n]);
                    m_av[n].last_stco = NULL;
                }
            }
            conv_skip_field(&pb,end);
            if(pb.pos - pb.start == 0)
            {
                cout << "may be memory can't enough" << endl;
                m_node_opt.free_node(node);
                continue;
            }
            node->si = pb.pos - pb.start;
            node->stamp = stamp;
            node->type = conv_packet_header;
            break;
        }
        updtae_keyframes_pos();
#if CONV_WRITE_TEST_FILE 
        if(m_test)
        {
            fwrite(node->p,pb.pos - pb.start,1,m_test);
        }
#endif
    }
    return node;
}

int c_mp4_muxer::write_ftyp(conv_mem_writer * dst,const conv_codec_ctx_t * ctx)
{
    u_char * pos = dst->pos;
    int has_h264 = 0;

    if (ctx->codec_video == CONVERT_VIDEO_H264)
    {
            has_h264 = 1;
    }

    write_start_box(dst, "ftyp");

    /* major brand */
    conv_wfourcc(dst, "isom");
    conv_write_field_32(dst, 512);

    conv_wfourcc(dst, "isom");
    conv_wfourcc(dst, "iso2");
    if (has_h264)
    {
        conv_wfourcc(dst, "avc1");
    }

    conv_wfourcc(dst, "mp41");
    
    return update_box_size(dst,pos); 
}

conv_size_t c_mp4_muxer::update_box_size(conv_mem_writer * dst, u_char * pos)
{
    u_char * cur_pos = dst->pos;
    conv_skip_field(dst,pos);
    conv_write_field_32(dst,cur_pos - pos);
    conv_skip_field(dst,cur_pos);
    assert(cur_pos > pos);
    return cur_pos - pos;
} 

int c_mp4_muxer::write_start_box(conv_mem_writer * dst,const char box[4])
{
    conv_write_field_32(dst, 0); /* size */
    conv_wfourcc(dst, box);
    return 1;
}

int c_mp4_muxer::write_mvhd(conv_mem_writer * dst)
{
    int max_track_id = 2;//a v
    int version = 0;
    
    u_char * pos = dst->pos;
    write_start_box(dst,"mvhd");
    conv_write_field_8(dst, version);
    conv_write_field_24(dst,0); /* flags */
    if (version == 1) 
    {
        conv_write_field_64(dst, 0);
        conv_write_field_64(dst, 0);
    } 
    else 
    {
        /* creation time */
        conv_write_field_32(dst,0);
        /* modification time */
        conv_write_field_32(dst,0);
    }
    conv_write_field_32(dst, 1000);
    int64_t max_duration = conv_max(m_av[CONV_A_INDEX].track_duration,m_av[CONV_V_INDEX].track_duration);
    (version == 1) ? conv_write_field_64(dst, max_duration) : conv_write_field_32(dst, max_duration); /* duration of longest track */

    conv_write_field_32(dst, 0x00010000); /* reserved (preferred rate) 1.0 = normal */
    conv_write_field_16(dst, 0x0100); /* reserved (preferred volume) 1.0 = normal */
    conv_write_field_16(dst, 0); /* reserved */
    conv_write_field_32(dst, 0); /* reserved */
    conv_write_field_32(dst, 0); /* reserved */

    /* Matrix structure */
    write_matrix(dst, 1, 0, 0, 1, 0, 0);

    conv_write_field_32(dst,0); /* reserved (preview time) */
    conv_write_field_32(dst,0); /* reserved (preview duration) */
    conv_write_field_32(dst,0); /* reserved (poster time) */
    conv_write_field_32(dst,0); /* reserved (selection time) */
    conv_write_field_32(dst,0); /* reserved (selection duration) */
    conv_write_field_32(dst,0); /* reserved (current time) */
    conv_write_field_32(dst,max_track_id + 1); /* Next track id */
    update_box_size(dst,pos);
    return 0x6c;
}

int c_mp4_muxer::write_matrix(conv_mem_writer *buf, 
    uint32_t a, uint32_t b, uint32_t c,
    uint32_t d, uint32_t tx, uint32_t ty)
{
/*
 * transformation matrix
 * |a  b  u|
 * |c  d  v|
 * |tx ty w|
 */
    conv_write_field_32(buf, a << 16);  /* 16.16 format */
    conv_write_field_32(buf, b << 16);  /* 16.16 format */
    conv_write_field_32(buf, 0);        /* u in 2.30 format */
    conv_write_field_32(buf, c << 16);  /* 16.16 format */
    conv_write_field_32(buf, d << 16);  /* 16.16 format */
    conv_write_field_32(buf, 0);        /* v in 2.30 format */
    conv_write_field_32(buf, tx << 16); /* 16.16 format */
    conv_write_field_32(buf, ty << 16); /* 16.16 format */
    conv_write_field_32(buf, 1 << 30);  /* w in 2.30 format */
    return 1;
}

/*
 * Handler reference atom
 * 用来告诉播放器怎么解释媒体数据
 * 说明media atom会包含说明类型的数据,例如音频或者视频.
 * */
int c_mp4_muxer::write_hdlr(conv_mem_writer * pb,conv_packet_type_t type)
{
    const char *hdlr, *descr = NULL, *hdlr_type = NULL;
    u_char * pos = pb->pos;

    hdlr      = "dhlr";
    hdlr_type = "url ";
    descr     = "DataHandler";

    if (type == conv_packet_video) 
    {
        hdlr_type = "vide";
        descr     = "VideoHandler";
    } 
    else if (type == conv_packet_audio)
    {
        hdlr_type = "soun";
        descr     = "SoundHandler";
    } 

    write_start_box(pb,"hdlr");

    conv_write_field_32(pb, 0); /* Version & flags */

    conv_write_data(pb, hdlr, 4); /* handler */
    conv_wfourcc(pb, hdlr_type); /* handler type */

    conv_write_field_32(pb, 0); /* reserved */
    conv_write_field_32(pb, 0); /* reserved */
    conv_write_field_32(pb, 0); /* reserved */

    conv_write_data(pb, descr, strlen(descr)+1);

    return update_box_size(pb, pos);
}

int c_mp4_muxer::write_mdhd(conv_mem_writer * pb,conv_packet_type_t type)
{
    conv_av_stream * av = &m_av[type - conv_packet_audio];
    int version = av->track_duration< INT32_MAX ? 0 : 1;
    u_char * pos = pb->pos;

    write_start_box(pb,"mdhd");
    conv_write_field_8(pb, version);
    conv_write_field_24(pb, 0); /* flags */
    if (version == 1) 
    {
        conv_write_field_64(pb, 0);
        conv_write_field_64(pb, 0);
    } else {
        conv_write_field_32(pb, 0); /* creation time */
        conv_write_field_32(pb, 0); /* modification time */
    }
    /*
     * A time value that indicates the time scale for this media—that is,
     * the number of time units that pass per second in its time coordinate system.
     * ffmpeg中视频是计算出来的,比如16000
     * 这个timescale只要duration与timescle对上就可以了,
     * 比如timescale是1000,duration的最后的时间除以timescale就是实际的值.
     * nginx中的写死的就死1000,暂时使用1000
     * */
    conv_write_field_32(pb, 1000); /* time scale (sample rate for audio) */

    if (!av->entry)
        (version == 1) ? conv_write_field_64(pb, 0) : conv_write_field_32(pb, 0);
    else
        (version == 1) ? conv_write_field_64(pb, av->track_duration) : conv_write_field_32(pb, av->track_duration); /* duration */
    conv_write_field_16(pb, 0x55c4); /* language */
    conv_write_field_16(pb, 0); /* reserved (quality) */

    update_box_size(pb,pos);
    return 32;
}

int c_mp4_muxer::write_vmhd(conv_mem_writer * pb)
{
    conv_write_field_32(pb, 0x14); /* size (always 0x14) */
    conv_wfourcc(pb, "vmhd");
    conv_write_field_32(pb, 0x01); /* version & flags */
    conv_write_field_64(pb, 0); /* reserved (graphics mode = copy) */
    return 0x14;
}

int c_mp4_muxer::write_smhd(conv_mem_writer * pb)
{
    conv_write_field_32(pb, 16); /* size */
    conv_wfourcc(pb, "smhd");
    conv_write_field_32(pb, 0); /* version & flags */
    conv_write_field_16(pb, 0); /* reserved (balance, normally = 0) */
    conv_write_field_16(pb, 0); /* reserved */
    return 16;
}

int c_mp4_muxer::write_dref(conv_mem_writer * pb)
{
    conv_write_field_32(pb, 28); /* size */
    conv_wfourcc(pb, "dref");
    conv_write_field_32(pb, 0); /* version & flags */
    conv_write_field_32(pb, 1); /* entry count */

    conv_write_field_32(pb, 0xc); /* size */
    //FIXME add the alis and rsrc atom
    conv_wfourcc(pb, "url ");
    conv_write_field_32(pb, 1); /* version & flags */

    return 28;
}

int c_mp4_muxer::write_dinf(conv_mem_writer * pb)
{
    u_char * pos = pb->pos;
    write_start_box(pb,"dinf");
    write_dref(pb);
    return update_box_size(pb, pos);
}

int c_mp4_muxer::mov_write_avcc_tag(conv_mem_writer * pb)
{
    u_char * pos = pb->pos;

    write_start_box(pb,"avcC");
    conv_write_data(pb, m_codec_ctx->video_config.p, m_codec_ctx->video_config.si);
    return update_box_size(pb, pos);
}

int c_mp4_muxer::mov_write_video_tag(conv_mem_writer * pb)
{
    u_char * pos = pb->pos;

    /*only support h264*/
    write_start_box(pb, "avc1");

    conv_write_field_32(pb, 0); /* Reserved */
    conv_write_field_16(pb, 0); /* Reserved */
    conv_write_field_16(pb, 1); /* Data-reference index */

    conv_write_field_16(pb, 0); /* Codec stream version */
    conv_write_field_16(pb, 0); /* Codec stream revision (=0) */

    conv_write_field_32(pb, 0); /* Reserved */
    conv_write_field_32(pb, 0); /* Reserved */
    conv_write_field_32(pb, 0); /* Reserved */

    conv_write_field_16(pb, m_codec_ctx->w); /* Video width */
    conv_write_field_16(pb, m_codec_ctx->h); /* Video height */
    conv_write_field_32(pb, 0x00480000); /* Horizontal resolution 72dpi */
    conv_write_field_32(pb, 0x00480000); /* Vertical resolution 72dpi */
    conv_write_field_32(pb, 0); /* Data size (= 0) */
    conv_write_field_16(pb, 1); /* Frame count (= 1) */

    /* FIXME not sure, ISO 14496-1 draft where it shall be set to 0 */
    conv_write_field_8(pb, 0); 
    char compressor_name[31] = {'\0'};
    conv_write_data(pb,compressor_name,31);

    conv_write_field_16(pb, 0x18); /* Reserved */
    conv_write_field_16(pb, 0xffff); /* Reserved */

    if (m_codec_ctx->codec_video == CONVERT_VIDEO_H265)
    {
        /*封装h265*/
    }
    else if (m_codec_ctx->codec_video == CONVERT_VIDEO_H264) 
    {
        mov_write_avcc_tag(pb);
    } 
    else if (m_codec_ctx->codec_video == CONVERT_VIDEO_ON2_VP6||
             m_codec_ctx->codec_video == CONVERT_VIDEO_ON2_VP6_ALPHA) 
    {
        /* Don't write any potential extradata here - the cropping
         * is signalled via the normal width/height fields. */
    } 

    return update_box_size(pb, pos);
}

int c_mp4_muxer::put_descr(conv_mem_writer *pb, int tag, unsigned int size)
{
    int i = 3;
    conv_write_field_8(pb, tag);
    for (; i > 0; i--)
        conv_write_field_8(pb, (size >> (7 * i)) | 0x80);
    conv_write_field_8(pb, size & 0x7F);
    return 33;
}

int c_mp4_muxer::write_esds(conv_mem_writer * pb)
{
    u_char * pos = pb->pos;
    int decoder_specific_info_len = m_codec_ctx->audio_config.si ? 5 + m_codec_ctx->audio_config.si : 0;

    write_start_box(pb,"esds");
    conv_write_field_32(pb, 0); // Version

    // ES descriptor
    put_descr(pb, 0x03, 3 + 5+13 + decoder_specific_info_len + 5+1);
    /*audio track id 2*/
    conv_write_field_16(pb, 2);
    conv_write_field_8(pb, 0x00); // flags (= no flags)

    // DecoderConfig descriptor
    put_descr(pb, 0x04, 13 + decoder_specific_info_len);

    // Object type indication
    if ((m_codec_ctx->codec_audio == CONVERT_AUDIO_MP3) && m_codec_ctx->samplerate > 24000)
        conv_write_field_8(pb, 0x6B); // 11172-3
    else
        conv_write_field_8(pb, 0x40);

    // the following fields is made of 6 bits to identify the streamtype (4 for video, 5 for audio)
    // plus 1 bit to indicate upstream and 1 bit set to 1 (reserved)
    conv_write_field_8(pb, 0x15); // flags (= Audiostream)

    conv_write_field_24(pb, 0); // Buffersize DB

    // maxbitrate (FIXME should be max rate in any 1 sec window)
    conv_write_field_32(pb, 0x0001F151);
    conv_write_field_32(pb, 0x0001F14D);

    if (m_codec_ctx->audio_config.si > 0) 
    {
        // DecoderSpecific info descriptor
        put_descr(pb, 0x05, m_codec_ctx->audio_config.si);
        conv_write_data(pb, m_codec_ctx->audio_config.p, m_codec_ctx->audio_config.si);
    }

    // SL descriptor
    put_descr(pb, 0x06, 1);
    conv_write_field_8(pb, 0x02);
    return update_box_size(pb, pos);
}

int c_mp4_muxer::mov_write_audio_tag(conv_mem_writer * pb)
{
    u_char * pos = pb->pos;
    write_start_box(pb, "mp4a");

    conv_write_field_32(pb, 0); /* Reserved */
    conv_write_field_16(pb, 0); /* Reserved */
    conv_write_field_16(pb, 1); /* Data-reference index, XXX  == 1 */

    /* SoundDescription */
    conv_write_field_16(pb, 0); /* Version */
    conv_write_field_16(pb, 0); /* Revision level */
    conv_write_field_32(pb, 0); /* Reserved */

    /* reserved for mp4/3gp */
    conv_write_field_16(pb, m_codec_ctx->nchannels ? m_codec_ctx->nchannels : 2);
    conv_write_field_16(pb, m_codec_ctx->samplesize ? m_codec_ctx->samplesize * 8 : 16);
    conv_write_field_16(pb, 0);
    conv_write_field_16(pb, 0); /* packet size (= 0) */

    conv_write_field_16(pb, m_codec_ctx->samplerate  <= UINT16_MAX ?  m_codec_ctx->samplerate : 0);
    conv_write_field_16(pb, 0); /* Reserved */

    write_esds(pb);

    return update_box_size(pb, pos);
}

/*
 * Sample description atom
 * 写音视频头
 * */
int c_mp4_muxer::write_stsd(conv_mem_writer * pb,conv_packet_type_t type)
{
    u_char * pos = pb->pos;
    write_start_box(pb,"stsd");
   
    conv_write_field_32(pb, 0); /* version & flags */
    conv_write_field_32(pb, 1); /* entry count */

    if (type == conv_packet_video)
        mov_write_video_tag(pb);
    else if (type == conv_packet_audio)
        mov_write_audio_tag(pb);

    return update_box_size(pb, pos);
}

typedef struct MOVStts {
    int count;
    int duration;
} MOVStts;

int c_mp4_muxer::get_cluster_duration(conv_av_stream *track, int cluster_idx)
{
    int64_t next_dts;

    if (cluster_idx >= track->entry)
        return 0;

    if (cluster_idx + 1 == track->entry)
        next_dts = track->track_duration + track->start_dts;
    else
        next_dts = track->cluster[cluster_idx + 1].dts;

    next_dts -= track->cluster[cluster_idx].dts;

    assert(next_dts >= 0);
    assert(next_dts <= INT_MAX);

    return next_dts;
}
int c_mp4_muxer::write_stts(conv_mem_writer * pb,conv_packet_type_t type,conv_av_stream * track)
{
    MOVStts *stts_entries;
    uint32_t entries = -1;
    int i;

    if (type == conv_packet_audio && !track->audio_vbr) 
    {
        stts_entries = new MOVStts; /* one entry */
        stts_entries[0].count = track->entry;
        stts_entries[0].duration = 1;
        entries = 1;
    } 
    else 
    {
        stts_entries = track->entry ?  new MOVStts[track->entry] :NULL;
        for (i = 0; i < track->entry; i++) 
        {
            int duration = get_cluster_duration(track, i);
            if (i && duration == stts_entries[entries].duration) 
            {
                stts_entries[entries].count++; /* compress */
            } 
            else 
            {
                entries++;
                stts_entries[entries].duration = duration;
                stts_entries[entries].count = 1;
            }
        }
        entries++; /* last one */
    }
    u_char * pos = pb->pos;
    write_start_box(pb, "stts");

    conv_write_field_32(pb, 0); /* version & flags */
    conv_write_field_32(pb, entries); /* entry count */

    for (i = 0; (uint32_t)i < entries; i++) 
    {
        conv_write_field_32(pb, stts_entries[i].count);
        conv_write_field_32(pb, stts_entries[i].duration);
    }
    delete []stts_entries;
    return update_box_size(pb,pos);
}

/*
 * 关键帧box
 * */
int c_mp4_muxer::write_stss(conv_mem_writer * pb,conv_av_stream * track,int flag)
{
    u_char * curpos, *entryPos;
    int i, index = 0;
    u_char * pos = pb->pos;
    write_start_box(pb, flag == MOV_SYNC_SAMPLE ? "stss" : "stps");

    conv_write_field_32(pb, 0); // version & flags
    entryPos = pb->pos;
    conv_write_field_32(pb, track->entry); // entry count
    for (i = 0; i < track->entry; i++) 
    {
        if (track->cluster[i].flags & flag) 
        {
            conv_write_field_32(pb, i + 1);
            index++;
        }
    }
    curpos = pb->pos;
    conv_skip_field(pb, entryPos);
    conv_write_field_32(pb, index); // rewrite size
    conv_skip_field(pb, curpos);
    return update_box_size(pb, pos);
}

int c_mp4_muxer::write_ctts(conv_mem_writer * pb, conv_av_stream * track)
{
    MOVStts *ctts_entries;
    uint32_t entries = 0;
    uint32_t atom_size;
    uint32_t i;

    ctts_entries = new MOVStts[track->entry + 1];
    ctts_entries[0].count = 1;
    ctts_entries[0].duration = track->cluster[0].cts;

    for (i = 1; i < track->entry; i++) 
    {
        if (track->cluster[i].cts == ctts_entries[entries].duration) 
        {
            ctts_entries[entries].count++; /* compress */
        }
        else 
        {
            entries++;
            ctts_entries[entries].duration = track->cluster[i].cts;
            ctts_entries[entries].count = 1;
        }
    }
    entries++; /* last one */
    atom_size = 16 + (entries * 8);
    conv_write_field_32(pb, atom_size); /* size */
    conv_wfourcc(pb, "ctts");
    conv_write_field_32(pb, 0); /* version & flags */
    conv_write_field_32(pb, entries); /* entry count */
    for (i = 0; i < entries; i++) 
    {
        conv_write_field_32(pb, ctts_entries[i].count);
        conv_write_field_32(pb, ctts_entries[i].duration);
    }
    delete []ctts_entries;
    return atom_size;
}

int c_mp4_muxer::write_stsc(conv_mem_writer * pb, conv_av_stream * track)
{
    int index = 0,  i;
    unsigned int oldval = -1;
    u_char *entryPos, *curpos;

    u_char * pos = pb->pos;
    write_start_box(pb, "stsc");
    
    conv_write_field_32(pb, 0); // version & flags
    entryPos = pb->pos;
    conv_write_field_32(pb, track->chunkCount); // entry count
    for (i = 0; i < track->entry; i++) 
    {
        if (oldval != track->cluster[i].samples_in_chunk && track->cluster[i].chunkNum) 
        {
            conv_write_field_32(pb, track->cluster[i].chunkNum); // first chunk
            conv_write_field_32(pb, track->cluster[i].samples_in_chunk); // samples per chunk
            conv_write_field_32(pb, 0x1); // sample description index
            oldval = track->cluster[i].samples_in_chunk;
            index++;
        }
    }
    curpos = pb->pos;
    conv_skip_field(pb, entryPos);
    conv_write_field_32(pb, index); // rewrite size
    conv_skip_field(pb, curpos);

    return update_box_size(pb, pos);
}

int c_mp4_muxer::write_stsz(conv_mem_writer * pb,conv_av_stream * track)
{
    int equalChunks = 1;
    int i, j, entries = 0, tst = -1, oldtst = -1;

    u_char * pos = pb->pos;
    write_start_box(pb,"stsz");

    conv_write_field_32(pb, 0); /* version & flags */

    for (i = 0; i < track->entry; i++) 
    {
        tst = track->cluster[i].size / track->cluster[i].entries;
        if (oldtst != -1 && tst != oldtst)
            equalChunks = 0;
        oldtst = tst;
        entries += track->cluster[i].entries;
    }
    if (equalChunks && track->entry) 
    {
        int sSize = track->entry ? track->cluster[0].size / track->cluster[0].entries : 0;
        sSize = conv_max(1, sSize); // adpcm mono case could make sSize == 0
        conv_write_field_32(pb, sSize); // sample size
        conv_write_field_32(pb, entries); // sample count
    } 
    else 
    {
        conv_write_field_32(pb, 0); // sample size
        conv_write_field_32(pb, entries); // sample count
        for (i = 0; i < track->entry; i++) 
        {
            for (j = 0; j < (int)track->cluster[i].entries; j++) 
            {
                conv_write_field_32(pb, track->cluster[i].size /
                          track->cluster[i].entries);
            }
        }
    }
    return update_box_size(pb, pos);
}

int c_mp4_muxer::co64_required(const conv_av_stream *track)
{
    if (track->entry > 0 && track->cluster[track->entry - 1].ppos + track->data_offset > UINT32_MAX)
        return 1;
    return 0;
}
int c_mp4_muxer::write_stco(conv_mem_writer * pb, conv_av_stream* track)
{
    int i;
    int mode64 = co64_required(track); // use 32 bit size variant if possible
    u_char * pos = pb->pos;
    track->last_stco = pos;
    conv_write_field_32(pb, 0); /* size */
    if (mode64) 
        conv_wfourcc(pb, "co64");
    else 
        conv_wfourcc(pb, "stco");
    conv_write_field_32(pb, 0); /* version & flags */
    conv_write_field_32(pb, track->chunkCount); /* entry count */

    conv_size_t ppos;

    for (i = 0; i < track->entry; i++) 
    {
        if (!track->cluster[i].chunkNum)
            continue;

        ppos = track->cluster[i].ppos + track->data_offset;

        if (mode64 == 1)
            conv_write_field_64(pb, ppos);
        else
            conv_write_field_32(pb, ppos);
    }
    return update_box_size(pb, pos);
}

conv_size_t c_mp4_muxer::get_adout_mp4_header_size()
{
    conv_size_t base = 10240;
    for(int n = 0; n  < 2;++n)
    {
        base += m_av[n].entry * ( 2 * sizeof(MOVStts) + 4 + 12 + 4 + 8);
    }
    return base;
}
/*
 * Sample Table Atoms
 * 重要的box.
 * */
int c_mp4_muxer::write_stbl(conv_mem_writer * pb, conv_packet_type_t type)
{
    u_char * pos = pb->pos;
    write_start_box(pb,"stbl");

    conv_av_stream * track = &m_av[type-conv_packet_audio];

    write_stsd(pb, type);
    /* 按帧数预留出 * sizeof(MOVStts) */
    write_stts(pb, type,track);

    if ((type == conv_packet_video) && track->has_keyframes && track->has_keyframes < track->entry)
    {
        /*按关键帧预留出 * sizeof(int) */
        write_stss(pb, track, MOV_SYNC_SAMPLE);
    }
    if (type == conv_packet_video && track->has_cts)
    {
        /* 按帧数预留出 * sizeof(MOVStts) */
        write_ctts(pb, track);
    }
    /* 按帧数预留出 * 12 */
    write_stsc(pb, track);
    /* 按帧数预留出 * 4 */
    write_stsz(pb, track);
    /* 按帧数预留出 * 8 */
    write_stco(pb, track);
    return update_box_size(pb, pos);
}
/*
 * Media Information Atoms
 * */
int c_mp4_muxer::write_minf(conv_mem_writer *pb, conv_packet_type_t type)
{
    u_char * pos = pb->pos;
    write_start_box(pb,"minf");
    if (type == conv_packet_video)
        write_vmhd(pb);
    else if (type == conv_packet_audio)
        write_smhd(pb);

    write_dinf(pb);
    write_stbl(pb, type);
    return update_box_size(pb, pos);

}

int c_mp4_muxer::write_mdia(conv_mem_writer * pb ,conv_packet_type_t type)
{
    u_char * pos = pb->pos;
    write_start_box(pb,"mdia");
    write_mdhd(pb,type);
    write_hdlr(pb,type);
    write_minf(pb,type);
    return update_box_size(pb, pos);
}

int c_mp4_muxer::write_tkhd(conv_mem_writer * pb ,conv_packet_type_t type)
{
    int group   = type == conv_packet_video ? 0 : 1;
    conv_av_stream * av = &m_av[type - conv_packet_audio];
    int version = av->track_duration < INT32_MAX ? 0 : 1;
    int flags   = 3;
    u_char * pos = pb->pos;

    conv_write_field_32(pb, 0);
    conv_wfourcc(pb, "tkhd");
    conv_write_field_8(pb, version);
    conv_write_field_24(pb, flags);
    if (version == 1) 
    {
        conv_write_field_64(pb, 0);
        conv_write_field_64(pb, 0);
    } 
    else 
    {
        conv_write_field_32(pb, 0); /* creation time */
        conv_write_field_32(pb, 0); /* modification time */
    }
    conv_write_field_32(pb, group+1); /* track-id */
    conv_write_field_32(pb, 0); /* reserved */
    if(!av->entry)
        (version == 1) ? conv_write_field_64(pb, 0) : conv_write_field_32(pb, 0);
    else
        (version == 1) ? conv_write_field_64(pb, av->track_duration) : conv_write_field_32(pb, av->track_duration);

    conv_write_field_32(pb, 0); /* reserved */
    conv_write_field_32(pb, 0); /* reserved */
    conv_write_field_16(pb, 0); /* layer */
    conv_write_field_16(pb, group); /* alternate group) */
    /* Volume, only for audio */
    if (type == conv_packet_audio)
        conv_write_field_16(pb, 0x0100);
    else
        conv_write_field_16(pb, 0);
    conv_write_field_16(pb, 0); /* reserved */

    /* Matrix structure */
    /* 不旋转*/
    write_matrix(pb,  1,  0,  0,  1, 0, 0);
    /* Track width and height, for visual only */
    if (type == conv_packet_video)
    {
        conv_write_field_32(pb, (uint32_t) m_codec_ctx->w << 16);
        conv_write_field_32(pb, (uint32_t) m_codec_ctx->h << 16);
    } 
    else 
    {
        conv_write_field_32(pb, 0);
        conv_write_field_32(pb, 0);
    }
    update_box_size(pb, pos);
    return 0x5c;
}

int c_mp4_muxer::write_trak(conv_mem_writer *b,conv_packet_type_t type)
{
    u_char  *pos = b->pos;
    write_start_box(b, "trak");

    write_tkhd(b, type);
    write_mdia(b, type);

    update_box_size(b, pos);
    return 0;
}

/*用户数据,比如版本之类的*/
int c_mp4_muxer::write_udta(conv_mem_writer *b)
{
    return 0;
}

int c_mp4_muxer::write_moov(conv_mem_writer * dst)
{
    u_char  *pos = dst->pos;

    write_start_box(dst, "moov");

    build_chunks(&m_av[0]);
    build_chunks(&m_av[1]);

    write_mvhd(dst);

    write_trak(dst,conv_packet_video);
    write_trak(dst,conv_packet_audio);

    write_udta(dst);
    return update_box_size(dst, pos);
}

#define AV_RB16(x)                           \
    ((((const uint8_t*)(x))[0] << 8) |          \
      ((const uint8_t*)(x))[1])

#define MOV_INDEX_CLUSTER_SIZE 1024

int c_mp4_muxer::write_mdat(conv_mem_writer * pb)
{
    if (m_data_size + 8 <= UINT32_MAX) 
    {
        conv_write_field_32(pb, m_data_size + 8);
        conv_wfourcc(pb, "mdat");
    } 
    else 
    {
        /* special value: real atom size will be 64 bit value after
         * tag field */
        conv_write_field_32(pb, 1);
        conv_wfourcc(pb, "mdat");
        conv_write_field_64(pb, m_data_size + 16);
    }
    return 0;
}

void c_mp4_muxer::build_chunks(conv_av_stream *trk)
{
    if(trk->entry <= 0)
        return;

    int i;
    MOVIentry *chunk = &trk->cluster[0];
    uint64_t chunkSize = chunk->size;
    chunk->chunkNum = 1;
    if (trk->chunkCount)
        return;

    trk->chunkCount = 1;
    for (i = 1; i<trk->entry; i++)
    {
        if (chunk->ppos + chunkSize == trk->cluster[i].ppos &&
            chunkSize + trk->cluster[i].size < (1<<20))
        {
            chunkSize             += trk->cluster[i].size;
            chunk->samples_in_chunk += trk->cluster[i].entries;
        } 
        else 
        {
            trk->cluster[i].chunkNum = chunk->chunkNum+1;
            chunk=&trk->cluster[i];
            chunkSize = chunk->size;
            trk->chunkCount++;
        }
    }
}

int c_mp4_muxer::write_packet(const conv_in_out_packe_t * pkt,bool write)
{
    conv_size_t size = 0;
    const conv_in_out_packe_t * n = pkt;
    conv_av_stream *trk = &m_av[pkt->type - conv_packet_audio];

#if CONV_WRITE_TEST_FILE 
    if(write)
    {
#if 0
        cout << "pos = " << m_moov_pos + trk->cluster[trk->index].ppos  << " ,nalu:" << int(pkt->p[4] & 0x1f) << 
            " index=" << trk->index << " mp4 entry cout again " << trk->index << ",type " <<  pkt->type << ",size :" << size << 
            " , all entry " << trk->entry << endl;
#endif
        assert(ftell(m_test) == (long)trk->cluster[trk->index].ppos + m_moov_pos);
        ++trk->index;
    }
#endif

    for(;n != NULL;n=n->next)
    {
        size += n->si;
        write_single_packet(n,write);
    }

    if(write)
    {
        return 1;
    }

    unsigned int samples_in_chunk = 0;
    if (trk->entry) 
    {
        int64_t duration = pkt->stamp - trk->cluster[trk->entry - 1].dts;
        if (duration < 0 || duration > INT_MAX) 
        {
            cout << "Application provided duration: " << duration << " timestamp: " << pkt->stamp << "is out of range for mov/mp4 format" << endl;
        }
    }

    if (trk->sample_size)
        samples_in_chunk = size / trk->sample_size;
    else
        samples_in_chunk = 1;

    if (conv_packet_audio == pkt->type && m_codec_ctx->codec_audio == CONVERT_AUDIO_AAC && pkt->si > 2 && (AV_RB16(pkt->p) & 0xfff0) == 0xfff0) 
    {
        cout << "mp4 muxer:aac bitstream error" << endl;
    }

    MOVIentry node;
    trk->cluster.push_back(node);

    trk->cluster[trk->entry].ppos              = m_data_pos;
    trk->cluster[trk->entry].samples_in_chunk = samples_in_chunk;
    trk->cluster[trk->entry].chunkNum         = 0;
    trk->cluster[trk->entry].size             = size;
    trk->cluster[trk->entry].entries          = samples_in_chunk;
    trk->cluster[trk->entry].dts              = pkt->stamp;
    m_data_pos += size;

    if (trk->start_dts == AV_NOPTS_VALUE) 
    {
        trk->start_dts = pkt->stamp;
    }
    trk->track_duration = pkt->stamp - trk->start_dts;

#if 0
    cout << "mp4 entry cout " << trk->entry << ",type " <<  pkt->type << ",duration " << trk->track_duration << ",size :" << size << endl;
#endif

    if (pkt->cts)
        trk->has_cts = true;

    trk->cluster[trk->entry].cts   = pkt->cts;
    trk->cluster[trk->entry].flags = 0;

    if (pkt->key_frame) 
    {
        trk->cluster[trk->entry].flags = MOV_SYNC_SAMPLE;
        trk->has_keyframes++;
    }
    trk->entry++;
    trk->sample_count += samples_in_chunk;
    m_data_size += size;
    return 1;
}

int c_mp4_muxer::write_single_packet(const conv_in_out_packe_t * pkt,bool write)
{
    conv_size_t size = pkt->si;

    if(pkt->type == conv_packet_video)
    {
#define CONV_TEST_264 0
#if CONV_TEST_264 
        if(write)
        {
            static FILE * sfp = NULL;
            if(NULL == sfp)
            {
                sfp = fopen("test.264","wb");
            }
            fwrite(pkt->p,1,pkt->si,sfp);
        }
#endif
    }
    if(write)
    {
        if(pkt->type == conv_packet_video)
        {
            if(size >= 4)
            {
                if((*(pkt->p)) == 0x00 &&(*(pkt->p+1)) == 0x00 &&(*(pkt->p+2)) == 0x00 &&(*(pkt->p+3)) == 0x01)
                {
                    uint32_t* p = ((uint32_t*)&pkt->p[0]);
                    //大端,去掉头部四个字节
                    *p = htonl(pkt->si-4);
                }
            }
        }
        conv_in_out_packe_t  tpkt = *pkt;
        tpkt.next = NULL;
        m_node_opt.push_node(&tpkt,false);
#if CONV_WRITE_TEST_FILE 
        fwrite(pkt->p,1,size,m_test);
#endif
        return 1;
    }

    return 1;
}

