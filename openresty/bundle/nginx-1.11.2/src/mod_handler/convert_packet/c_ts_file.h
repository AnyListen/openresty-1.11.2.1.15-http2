#ifndef __C_TS_FILE__
#define __C_TS_FILE__

#include "c_conv_base.h"

typedef struct conv_mpegts_frame_s{
    uint64_t    pts;
    uint64_t    dts;
    uint32_t    pid;
    uint32_t    sid;
    uint32_t    cc;
    unsigned    key:1;
	conv_mpegts_frame_s()
	{
		pts = dts = pid = sid = cc = 0;
		key = 0;
	}
} conv_mpegts_frame_t;

#define AV_RB16(x)                           \
    ((((const uint8_t*)(x))[0] << 8) |          \
      ((const uint8_t*)(x))[1])

#define AV_RB32(x)                                \
    (((uint32_t)((const uint8_t*)(x))[0] << 24) |    \
               (((const uint8_t*)(x))[1] << 16) |    \
               (((const uint8_t*)(x))[2] <<  8) |    \
                ((const uint8_t*)(x))[3])

typedef struct SectionHeader {
    uint8_t tid;
    uint16_t id;
    uint8_t version;
    uint8_t sec_num;
    uint8_t last_sec_num;
} SectionHeader;

#define 	MKTAG(a, b, c, d)   ((a) | ((b) << 8) | ((c) << 16) | ((unsigned)(d) << 24))

#define FFERRTAG(a, b, c, d) (-(int)MKTAG(a, b, c, d))
#define AVERROR_EOF                FFERRTAG( 'E','O','F',' ') ///< End of file

#define AVERROR(e) (-(e))   ///< Returns a negative error code from a POSIX error code, to return from library functions.
#define AVUNERROR(e) (-(e)) ///< Returns a POSIX error code from a library function error return value.

#define FFMAX(a,b) ((a) > (b) ? (a) : (b))
#define FFMAX3(a,b,c) FFMAX(FFMAX(a,b),c)
#define FFMIN(a,b) ((a) > (b) ? (b) : (a))
#define FFMIN3(a,b,c) FFMIN(FFMIN(a,b),c)

#define AV_PKT_FLAG_KEY     0x0001 ///< The packet contains a keyframe
#define AV_PKT_FLAG_CORRUPT 0x0002 ///< The packet content is corrupted

#define AVFMTCTX_NOHEADER      0x0001 /**< signal that no header is present
                                         (streams are added dynamically) */
#define AVERROR_INVALIDDATA  -1
#define TS_FEC_PACKET_SIZE 204
#define TS_DVHS_PACKET_SIZE 192
#define TS_PACKET_SIZE 188
#define TS_MAX_PACKET_SIZE 204

#define NB_PID_MAX 8192
#define MAX_SECTION_SIZE 4096

/* pids */
#define PAT_PID                 0x0000
#define SDT_PID                 0x0011

/* table ids */
#define PAT_TID   0x00
#define PMT_TID   0x02
#define M4OD_TID  0x05
#define SDT_TID   0x42

#define STREAM_TYPE_VIDEO_MPEG1     0x01
#define STREAM_TYPE_VIDEO_MPEG2     0x02
#define STREAM_TYPE_AUDIO_MPEG1     0x03
#define STREAM_TYPE_AUDIO_MPEG2     0x04
#define STREAM_TYPE_PRIVATE_SECTION 0x05
#define STREAM_TYPE_PRIVATE_DATA    0x06
#define STREAM_TYPE_AUDIO_AAC       0x0f
#define STREAM_TYPE_AUDIO_AAC_LATM  0x11
#define STREAM_TYPE_VIDEO_MPEG4     0x10
#define STREAM_TYPE_VIDEO_H264      0x1b
#define STREAM_TYPE_VIDEO_HEVC      0x24 //Definition of 0x24 HEVC video MPEG TS stream type
#define STREAM_TYPE_VIDEO_CAVS      0x42
#define STREAM_TYPE_VIDEO_VC1       0xea
#define STREAM_TYPE_VIDEO_DIRAC     0xd1

#define STREAM_TYPE_AUDIO_AC3       0x81
#define STREAM_TYPE_AUDIO_DTS       0x82
#define STREAM_TYPE_AUDIO_TRUEHD    0x83

enum MpegTSFilterType {
    MPEGTS_PES,
    MPEGTS_SECTION,
    MPEGTS_PCR,
};

typedef struct MpegTSFilter MpegTSFilter;
typedef int PESCallback (MpegTSFilter *f, const uint8_t *buf, int len,
                         int is_start, int64_t pos);

typedef struct MpegTSPESFilter {
    PESCallback *pes_cb;
    void *opaque;
} MpegTSPESFilter;

typedef void SectionCallback (MpegTSFilter *f, const uint8_t *buf, int len);

typedef void SetServiceCallback (void *opaque, int ret);

typedef struct MpegTSSectionFilter {
    int section_index;
    int section_h_size;
    uint8_t *section_buf;
    unsigned int check_crc : 1;
    unsigned int end_of_section_reached : 1;
    SectionCallback *section_cb;
    void *opaque;
} MpegTSSectionFilter;
#define MAX_PIDS_PER_PROGRAM 64
struct Program {
    unsigned int id; // program id/service id
    unsigned int nb_pids;
    unsigned int pids[MAX_PIDS_PER_PROGRAM];

    /** have we found pmt for this program */
    int pmt_found;
};

struct MpegTSFilter {
    int pid;
    int es_id;
    int last_cc; /* last cc code (-1 if first packet) */
    int64_t last_pcr;
    enum MpegTSFilterType type;
    union {
        MpegTSPESFilter pes_filter;
        MpegTSSectionFilter section_filter;
    } u;
};
struct MpegTSContext {
    /* user data */
//    AVFormatContext *stream;
    /** raw packet size, including FEC if present */
    int raw_packet_size;

    int size_stat[3];
    int size_stat_count;
#define SIZE_STAT_THRESHOLD 10

    int64_t pos47_full;

    /** if true, all pids are analyzed to find streams */
    int auto_guess;

    /** compute exact PCR for each transport stream packet */
    int mpeg2ts_compute_pcr;

    /** fix dvb teletext pts                                 */
    int fix_teletext_pts;

    int64_t cur_pcr;    /**< used to estimate the exact PCR */
    int pcr_incr;       /**< used to estimate the exact PCR */

    /* data needed to handle file based ts */
    /** stop parsing loop */
    int stop_parse;
    /** packet containing Audio/Video data */
 //   AVPacket *pkt;
    /** to detect seek */
    int64_t last_pos;

    int skip_changes;
    int skip_clear;

    /******************************************/
    /* private mpegts data */
    /* scan context */
    /** structure to keep track of Program->pids mapping */
    unsigned int nb_prg;
    struct Program *prg;

    int8_t crc_validity[NB_PID_MAX];
    /** filters for various streams specified by PMT + for the PAT and PMT */
    MpegTSFilter *pids[NB_PID_MAX];
    int current_pid;
    int ctx_flags;
	FileProvider * pb;
};

/* enough for PES header + length */
#define PES_START_SIZE  6
#define PES_HEADER_SIZE 9
#define MAX_PES_HEADER_SIZE (9 + 255)

enum MpegTSState {
    MPEGTS_HEADER = 0,
    MPEGTS_PESHEADER,
    MPEGTS_PESHEADER_FILL,
    MPEGTS_PAYLOAD,
    MPEGTS_SKIP,
};

typedef struct PESContext {
    int pid;
    int pcr_pid; /**< if -1 then all packets containing PCR are considered */
    int stream_type;
    MpegTSContext *ts;
#if 0
    AVFormatContext *stream;
    AVStream *st;
    AVStream *sub_st; /**< stream for the embedded AC3 stream in HDMV TrueHD */
#endif
    enum MpegTSState state;
    /* used to get the format */
    int data_index;
    int flags; /**< copied to the AVPacket flags */
    int total_size;
    int pes_header_size;
    int extended_stream_id;
    int64_t pts, dts;
    int64_t ts_packet_pos; /**< position of first TS packet of this PES packet */
    uint8_t header[MAX_PES_HEADER_SIZE];
    conv_in_out_packe_t *buffer;
#if 0
    SLConfigDescr sl;
#endif
} PESContext;

class c_ts_file:public c_conv_base
{
public:
	c_ts_file(void);
	virtual ~c_ts_file(void);

	virtual conv_in_out_packe_t * mux_header (const conv_codec_ctx_t & ctx,long stamp);
	virtual conv_in_out_packe_t * mux(const conv_in_out_packe_t *in,const conv_codec_ctx_t & ctx,int & ret);
	virtual bool demux(c_conv_base * mux,conv_size_t start_frame,int gop);
    virtual bool advance_read(){return true;}
    virtual int  advace_process(conv_in_out_packe_t * pkt,const conv_codec_ctx_t * ctx);
    virtual void need_rebuild_header(){m_b_build_header = false;}
private:
	bool conv_mpegts_write_header(u_char * p ,conv_size_t si,int64_t stamp);
	u_char * conv_mpegts_write_pcr(u_char *p, uint64_t pcr);
	u_char * conv_mpegts_write_pts(u_char *p, uint32_t fb, uint64_t pts);
	bool conv_mpegts_write_frame(conv_in_out_packe_t ** out, conv_mpegts_frame_t *f,conv_chain_t * cl,long stamp);
	conv_in_out_packe_t * conv_hls_video(const conv_in_out_packe_t * in,const conv_codec_ctx_t & ctx);
    conv_in_out_packe_t * conv_hls_update_fragment(uint64_t ts, uint32_t flush_rate,bool boundary);
	bool conv_hls_flush_audio(conv_in_out_packe_t ** out);
	void set_buf_by_packet(const conv_in_out_packe_t * in,conv_buf_t * out);
	conv_in_out_packe_t * mux_video(const conv_in_out_packe_t * in,const conv_codec_ctx_t & ctx);
	conv_in_out_packe_t * mux_audio(const conv_in_out_packe_t * in,const conv_codec_ctx_t & ctx);

	int mpegts_read_header(MpegTSContext * ts);
	int analyze(const uint8_t *buf, int size, int packet_size, int *index);
	int get_packet_size(const uint8_t *buf, int size);
	MpegTSFilter *mpegts_open_filter(MpegTSContext *ts, unsigned int pid,enum MpegTSFilterType type);
	MpegTSFilter *mpegts_open_section_filter(MpegTSContext *ts,
                                                unsigned int pid,
                                                SectionCallback *section_cb,
                                                void *opaque,
                                                int check_crc);
	int handle_packets(MpegTSContext *ts, int nb_packets);
	int read_packet(MpegTSContext *ts,FileProvider *pb, uint8_t *buf, int raw_packet_size,const uint8_t **data);
	int mpegts_resync(MpegTSContext *ts,FileProvider * pb);
	void reanalyze(MpegTSContext *ts,FileProvider * pb);
	int handle_packet(MpegTSContext *ts, const uint8_t *packet);
	int discard_pid(MpegTSContext *ts, unsigned int pid);
	PESContext *add_pes_stream(MpegTSContext *ts, int pid, int pcr_pid);
	MpegTSFilter *mpegts_open_pes_filter(MpegTSContext *ts, unsigned int pid,
                                            PESCallback *pes_cb,
                                            void *opaque);
	void write_section_data(MpegTSContext *ts, MpegTSFilter *tss1,const uint8_t *buf, int buf_size, int is_start);
	int  parse_pcr(int64_t *ppcr_high, int *ppcr_low, const uint8_t *packet);
    void conv_hls_close_frag();
    conv_in_out_packe_t * open_frag(int64_t stamp);
    bool is_frag(const conv_in_out_packe_t * in);
private:
	uint32_t m_video_cc;
	uint32_t m_audio_cc;
    conv_buf_t m_aframe;
    uint64_t m_frag_ts;
	uint64_t m_aframe_pts;
	uint32_t m_aframe_num;
	uint32_t m_aframe_base; 
	uint32_t m_sync;
    uint64_t  m_slice_length;
	conv_chain_t m_sps;
	conv_chain_t m_pps;
	conv_chain_t m_sei;
};

#endif
