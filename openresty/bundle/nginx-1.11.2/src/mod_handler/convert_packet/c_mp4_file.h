#ifndef _C_MP4_FILE__
#define _C_MP4_FILE__

#include "c_conv_base.h"
#include "c_mp4_mux.h"

#pragma pack(push,4)

/* disable zero-sized array warning by msvc */

typedef struct {
    uint32_t                            first_chunk;
    uint32_t                            samples_per_chunk;
    uint32_t                            sample_descrption_index;
} convert_mp4_chunk_entry_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    convert_mp4_chunk_entry_t          entries[0];
} convert_mp4_chunks_t;


typedef struct {
    uint32_t                            sample_count;
    uint32_t                            sample_delta;
} convert_mp4_time_entry_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    convert_mp4_time_entry_t           entries[0];
} convert_mp4_times_t;


typedef struct {
    uint32_t                            sample_count;
    uint32_t                            sample_offset;
} convert_mp4_delay_entry_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    convert_mp4_delay_entry_t          entries[0];
} convert_mp4_delays_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    uint32_t                            entries[0];
} convert_mp4_keys_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            sample_size;
    uint32_t                            sample_count;
    uint32_t                            entries[0];
} convert_mp4_sizes_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            field_size;
    uint32_t                            sample_count;
    uint32_t                            entries[0];
} convert_mp4_sizes2_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    uint32_t                            entries[0];
} convert_mp4_offsets_t;


typedef struct {
    uint32_t                            version_flags;
    uint32_t                            entry_count;
    uint64_t                            entries[0];
} convert_mp4_offsets64_t;


#if (NGX_WIN32)
#pragma warning(pop)
#endif
#pragma pack(pop)


typedef struct {
    uint32_t                            timestamp;
    off_t                               offset;
    size_t                              size;
    int                           key;
    uint32_t                            delay;

    unsigned                            not_first:1;
    unsigned                            valid:1;

    uint32_t                          pos;

    uint32_t                          key_pos;

    uint32_t                          chunk;
    uint32_t                          chunk_pos;
    uint32_t                          chunk_count;

    uint32_t                          time_pos;
    uint32_t                          time_count;

    uint32_t                          delay_pos;
    uint32_t                          delay_count;

    uint32_t                          size_pos;
} convert_mp4_cursor_t;


typedef struct {
    uint32_t                          id;

    conv_packet_type_t                type;
    int                               codec;
    int                               time_scale;
    uint64_t                          duration;

    u_char                             *header;
    size_t                              header_size;
    unsigned                            header_sent:1;

    convert_mp4_times_t               *times;
    convert_mp4_delays_t              *delays;
    convert_mp4_keys_t                *keys;
    convert_mp4_chunks_t              *chunks;
    convert_mp4_sizes_t               *sizes;
    convert_mp4_sizes2_t              *sizes2;
    convert_mp4_offsets_t             *offsets;
    convert_mp4_offsets64_t           *offsets64;
    convert_mp4_cursor_t               cursor;
} convert_mp4_track_t;

typedef struct {
    convert_mp4_track_t               tracks[2];
    convert_mp4_track_t               *track;
    uint32_t                          ntracks;

    uint32_t                          width;
    uint32_t                          height;
    uint32_t                          nchannels;
    uint32_t                          sample_size;
    uint32_t                          sample_rate;

    int                           atracks, vtracks;
    int                           aindex, vindex;

    uint32_t                            start_timestamp;
} convert_mp4_ctx_t;

/*
 * 复用与解复用可以再抽象出来,这里暂时没有进行分离.
 * */
class c_mp4_file : public c_conv_base
{
public:
	c_mp4_file(void);
	~c_mp4_file(void);

	virtual bool demux(c_conv_base * mux,conv_size_t start_frame,int gop);
	virtual conv_in_out_packe_t * mux_header(const conv_codec_ctx_t & ctx,long stamp)
    {
        m_mp4_mux.set_node_opt(&m_node_opt);
        return m_mp4_mux.mux_header(ctx,stamp);
    }
    virtual conv_in_out_packe_t * mux(const conv_in_out_packe_t *in,const conv_codec_ctx_t & ctx,int & ret)
    {
        return m_mp4_mux.mux(in,ctx,ret);
    }

    virtual int  advace_process(conv_in_out_packe_t * pkt,const conv_codec_ctx_t * ctx)
    {
        m_mp4_mux.set_codec_ctx(ctx);
        return m_mp4_mux.write_packet(pkt,false);
    }

	convert_mp4_ctx_t * get_ctx(){return &m_ctx;}  
	virtual bool get_codec_ctx(conv_codec_ctx_t * ctx);
	
    virtual void need_rebuild_header(){m_b_build_header = false;}

	bool mp4_parse(u_char * pos,u_char * last);
	bool mp4_parse_trak(u_char *pos, u_char *last);
	bool mp4_parse_hdlr(u_char * pos,u_char * last);
	bool mp4_parse_video(u_char *pos, u_char *last,int codec);
	bool mp4_parse_mdhd(u_char *pos, u_char *last);
	bool mp4_parse_avcC(u_char *pos, u_char *last);
	bool mp4_parse_stsd(u_char * pos,u_char * last);
	bool mp4_parse_audio(u_char *pos, u_char *last,int codec);
	bool mp4_parse_stts(u_char *pos, u_char *last);
	bool mp4_parse_ctts(u_char *pos, u_char *last);
	bool mp4_parse_stss(u_char *pos, u_char *last);
	bool mp4_parse_stsz(u_char *pos, u_char *last);
	bool mp4_parse_stz2(u_char *pos, u_char *last);
	bool mp4_parse_stsc(u_char *pos, u_char *last);
	bool mp4_parse_stco(u_char *pos, u_char *last);
	bool mp4_parse_co64(u_char *pos, u_char *last);
	bool mp4_parse_esds(u_char *pos, u_char *last);
	bool mp4_parse_descr(u_char *pos, u_char *last);
	bool mp4_parse_es(u_char *pos, u_char *last);
	bool mp4_parse_dc(u_char *pos, u_char *last);
	bool mp4_parse_ds(u_char *pos, u_char *last);
	bool mp4_parse_frame(int gop = 0);
    bool push_keyframe(const conv_frame_info * node);
    bool clear_keyframe();
    virtual int  demux_keyframes();
protected:
    bool advance_read(){return true;}

private:
	inline uint16_t convert_r16(uint16_t n)
	{
		return (n << 8) | (n >> 8);
	}
	inline uint32_t convert_r32(uint32_t n)
	{
		return (n << 24) | ((n << 8) & 0xff0000) | ((n >> 8) & 0xff00) | (n >> 24);
	}
	inline uint64_t convert_r64(uint64_t n)
	{
		return (uint64_t) convert_r32((uint32_t) n) << 32 | convert_r32((uint32_t) (n >> 32));
	}
	inline uint32_t convert_mp4_to_rtmp_timestamp(convert_mp4_track_t *t, uint64_t ts)
	{
		return (uint32_t) (ts * 1000 / t->time_scale);
	}
	inline uint32_t convert_mp4_from_rtmp_timestamp(convert_mp4_track_t *t, uint32_t ts)
	{
		return (uint64_t) ts * t->time_scale / 1000;
	}

	void print_box_tag(uint32_t *tag);

	bool parse_moov(Size & offset,Size & size,Size & shift);
	bool mp4_next(convert_mp4_track_t  *t);
	bool convert_mp4_next_time(convert_mp4_track_t *t);
	bool convert_mp4_next_key(convert_mp4_track_t *t);
	bool convert_mp4_next_chunk(convert_mp4_track_t *t);
	bool convert_mp4_update_offset(convert_mp4_track_t *t);
	bool convert_mp4_next_size(convert_mp4_track_t *t);
	bool convert_mp4_next_delay(convert_mp4_track_t *t);
	bool convert_mp4_seek(long timestamp);
	bool convert_mp4_seek_track(convert_mp4_track_t *t, long timestamp);
	bool convert_mp4_reset();
	bool convert_mp4_seek_time(convert_mp4_track_t *t, uint32_t timestamp);
	bool convert_mp4_seek_key(convert_mp4_track_t *t);
	bool convert_mp4_seek_chunk(convert_mp4_track_t *t);
	bool convert_mp4_seek_size(convert_mp4_track_t *t);
	bool convert_mp4_seek_delay(convert_mp4_track_t *t);
	const char * switch_box_to_printf(uint32_t * tag);
    bool set_keyframes();
private:
    convert_mp4_ctx_t         m_ctx;
    u_char *m_pdata;
    c_mp4_muxer m_mp4_mux;
    Size    m_moov_oft;
};

#endif
