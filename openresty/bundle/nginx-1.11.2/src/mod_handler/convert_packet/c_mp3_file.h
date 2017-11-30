#ifndef __C_MP3_H
#define __C_MP3_H

#include "c_conv_base.h"

#define ID3v2_HEADER_SIZE 10
/**
 * Default magic bytes for ID3v2 header: "ID3"
 */
#define ID3v2_DEFAULT_MAGIC "ID3"

#define MPA_DECODE_HEADER \
    int frame_size; \
    int error_protection; \
    int layer; \
    int sample_rate; \
    int sample_rate_index; /* between 0 and 8 */ \
    int bit_rate; \
    int nb_channels; \
    int mode; \
    int mode_ext; \
    int lsf;

typedef struct MPADecodeHeader {
  MPA_DECODE_HEADER
} MPADecodeHeader;

struct ParseContext{
    uint8_t *buffer;
    int index;
    int last_index;
    unsigned int buffer_size;
    uint32_t state;             ///< contains the last few bytes in MSB order
    int frame_start_found;
    int overread;               ///< the number of bytes which where irreversibly read from the next frame
    int overread_index;         ///< the index into ParseContext.buffer of the overread bytes
    uint64_t state64;           ///< contains the last 8 bytes in MSB order
    ParseContext()
    {
        buffer = NULL;
        index = last_index = 0;
        buffer_size = 0;
        state = 0;
        frame_start_found = 0;
        overread = overread_index = 0;
        state64 = 0;
    }
} ;

struct MpegAudioParseContext {
    ParseContext pc;
    int frame_size;
    uint32_t header;
    int header_count;
    int no_bitrate;
    MpegAudioParseContext()
    {
        frame_size = 0;
        header = 0;
        header_count = 0;
        no_bitrate = 0;
    }
};


struct MP3DecContext{
    int64_t filesize;
    int xing_toc;
    int start_pad;
    int end_pad;
    int usetoc;
    unsigned frames; /* Total number of frames in file */
    unsigned header_filesize;   /* Total number of bytes in the stream */
    int is_cbr;
    MP3DecContext()
    {
        filesize = 0;
        xing_toc = 0;
        start_pad = 0;
        end_pad = 0;
        usetoc = 0;
        frames = 0;
        header_filesize = 0;
    }
} ;

class c_mp3_file : public c_conv_base
{
public:
	c_mp3_file(void);
	virtual ~c_mp3_file();
	virtual bool init(conv_char_t * psrc,conv_size_t si,conv_packet_pt pt,void * user);
	virtual bool demux(c_conv_base * mux,conv_size_t start_frame,int gop);
	virtual conv_in_out_packe_t * mux_header (const conv_codec_ctx_t & ctx,long stamp){return NULL;}
	virtual conv_in_out_packe_t * mux( const conv_in_out_packe_t *in, const conv_codec_ctx_t & ctx,int & ret){return NULL;}
private:
    bool id3v2_read_internal(const char *magic/*ID3*/,int64_t max_search_size);
    int  ff_id3v2_match(const uint8_t *buf, const char *magic);
    void id3v2_parse( int len, uint8_t version, uint8_t flags);
    int  mp3_parse_vbr_tags(int64_t base);
    int  avpriv_mpa_decode_header2(uint32_t head, int *sample_rate, int *channels, int *frame_size, int *bit_rate,int * codec_id);
    int  avpriv_mpegaudio_decode_header(MPADecodeHeader *s, uint32_t header);
    int  mp3_parse_info_tag(MPADecodeHeader *c, uint32_t spf);
    void mp3_parse_vbri_tag(int64_t base);
    int  mpegaudio_parse(uint8_t **poutbuf, int *poutbuf_size, uint8_t *buf, int buf_size);
    int  ff_combine_frame(ParseContext *pc, int next, uint8_t **buf, int *buf_size);
private:
    /*
     * header()
     * {
     * syncword      12
     * ID             1
     * layer          2
     * protection_bit 1
     * bitrate_index  4
     * sampling_frequency 2
     * ....
     * }
     *
     * */
    /* fast header check for resync */
    inline int ff_mpa_check_header(uint32_t header)
    {
        /* header */
        if ((header & 0xffe00000) != 0xffe00000)
            return -1;
        /* layer check */
        if ((header & (3<<17)) == 0)
            return -1;
        /* bit rate */
        if ((header & (0xf<<12)) == 0xf<<12)
            return -1;
        /* frequency */
        if ((header & (3<<10)) == 3<<10)
            return -1;
        return 0;
    }
private:
    MP3DecContext m_mp3;
    MpegAudioParseContext m_parse;
};

#endif
