#ifndef __C_MP4_MUX__
#define __C_MP4_MUX__

#include <stdint.h>
#include "mem_writer.h"
#include "c_conv_base.h"

typedef struct MOVIentry {
    uint64_t     ppos;
    int64_t      dts;
    unsigned int size;
    unsigned int samples_in_chunk;
    unsigned int chunkNum;              ///< Chunk number if the current entry is a chunk start otherwise 0
    unsigned int entries;
    int          cts;
#define MOV_SYNC_SAMPLE         0x0001
#define MOV_PARTIAL_SYNC_SAMPLE 0x0002
    uint32_t     flags;
} MOVIentry;

#define AV_NOPTS_VALUE          ((int64_t)UINT64_C(0x8000000000000000))

struct conv_av_stream
{
    conv_size_t entry;
    vector<MOVIentry> cluster;
    int64_t  track_duration; 
    int64_t start_dts;
    bool has_cts;
    bool audio_vbr;
    conv_size_t has_keyframes;
    conv_size_t chunkCount;
    conv_size_t data_offset;
    conv_size_t sample_size;
    conv_size_t sample_count;
    u_char * last_stco;
    int64_t  index;
#if CONV_WRITE_TEST_FILE 
#endif
    conv_av_stream()
    {
        entry = 0;
        has_cts = false;
        audio_vbr = true;
        has_keyframes = 0;
        chunkCount = 0;
        data_offset = 0;
        sample_size = 0;
        start_dts = AV_NOPTS_VALUE;
        track_duration = 0;
        sample_count = 0;
        last_stco = NULL;
        index = 0;
#if CONV_WRITE_TEST_FILE 
#endif
    }
};

class c_mp4_muxer
{
public:
    c_mp4_muxer()
    {
        m_pos_mux = 0;
        m_codec_ctx = NULL;
        m_moov_end = false;
        m_data_size = 0;
        m_data_pos = 0;
#if CONV_WRITE_TEST_FILE 
        m_test = fopen("test.mp4","wb");
#endif
        m_moov_pos = 0;
    }
    ~c_mp4_muxer()
    {
#if CONV_WRITE_TEST_FILE 
        if(m_test)
            fclose(m_test);
        m_test = NULL;
#endif
    }
	conv_in_out_packe_t * mux_header(const conv_codec_ctx_t & ctx,long stamp);
    conv_in_out_packe_t * mux(const conv_in_out_packe_t *in,const conv_codec_ctx_t & ctx,int & ret);
    void set_node_opt(const conv_node_opt_s * n){m_node_opt = *n;}
    void set_codec_ctx(const conv_codec_ctx_t * ctx){m_codec_ctx = ctx;}
    int write_packet(const conv_in_out_packe_t * pkt,bool write);
private:
	void mux_mp4v2( const conv_in_out_packe_t *in, const conv_codec_ctx_t & ctx);
    int write_ftyp(conv_mem_writer * dst,const conv_codec_ctx_t * ctx);
    conv_size_t update_box_size(conv_mem_writer * dst,u_char * pos);
    int write_moov(conv_mem_writer * dst);
    int write_start_box(conv_mem_writer* dst, const char box[4]);
    int write_mvhd(conv_mem_writer * dst);
    int write_matrix(conv_mem_writer* buf, uint32_t a, uint32_t b, uint32_t c,
    uint32_t d, uint32_t tx, uint32_t ty);
    int write_trak(conv_mem_writer *b,conv_packet_type_t type);
    int write_udta(conv_mem_writer *b);
    int write_tkhd(conv_mem_writer * pb ,conv_packet_type_t type);
    int write_mdia(conv_mem_writer * pb ,conv_packet_type_t type);
    int write_mdhd(conv_mem_writer * pb,conv_packet_type_t type);
    int write_hdlr(conv_mem_writer * pb,conv_packet_type_t type);
    int write_minf(conv_mem_writer *pb, conv_packet_type_t type);
    int write_vmhd(conv_mem_writer * pb);
    int write_smhd(conv_mem_writer * pb);
    int write_dinf(conv_mem_writer * pb);
    int write_dref(conv_mem_writer * pb);
    int write_stbl(conv_mem_writer * pb, conv_packet_type_t type);
    int write_stsd(conv_mem_writer * pb,conv_packet_type_t type);
    int mov_write_video_tag(conv_mem_writer * pb);
    int mov_write_audio_tag(conv_mem_writer * pb);
    int mov_write_avcc_tag(conv_mem_writer * pb);
    int write_esds(conv_mem_writer * pb);
    int put_descr(conv_mem_writer *pb, int tag, unsigned int size);
    int write_stts(conv_mem_writer * pb,conv_packet_type_t type,conv_av_stream * track);
    int write_stss(conv_mem_writer * pb,conv_av_stream * track,int flag);
    int write_ctts(conv_mem_writer * pb, conv_av_stream * track);
    int write_stsc(conv_mem_writer * pb, conv_av_stream * track);
    int write_stsz(conv_mem_writer * pb,conv_av_stream * track);
    int get_cluster_duration(conv_av_stream *track, int cluster_idx);
    int write_stco(conv_mem_writer * pb, conv_av_stream* track);
    int co64_required(const conv_av_stream *track);
    int write_single_packet(const conv_in_out_packe_t * pkt,bool write);
    int write_mdat(conv_mem_writer * pb);
    void build_mem_writer(conv_in_out_packe_t * node,conv_mem_writer * pb);
    void build_chunks(conv_av_stream *trk);
    conv_size_t get_adout_mp4_header_size();
    void updtae_keyframes_pos();
private:
    conv_size_t  m_pos_mux;
    conv_node_opt_s m_node_opt;
    const conv_codec_ctx_t * m_codec_ctx;
    bool m_moov_end;
    conv_size_t m_data_size;
#define CONV_A_INDEX 0 
#define CONV_V_INDEX 1
    conv_av_stream m_av[2];/*0 audo 1 video*/
    conv_size_t m_data_pos;
#if CONV_DEBUG
    FILE * m_test;
#endif
    conv_size_t m_moov_pos;
};

#endif
