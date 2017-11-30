/*
 * =====================================================================================
 *
 *       Filename:  c_mp3_file.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  02/14/2015 11:17:19 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (490479164@qq.com), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "c_mp3_file.h"
#include "mem.h"
#include <arpa/inet.h>


static const uint16_t avpriv_mpa_bitrate_tab[2][3][15] = {
    { {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 },
      {0, 32, 48, 56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, 384 },
      {0, 32, 40, 48,  56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320 } },
    { {0, 32, 48, 56,  64,  80,  96, 112, 128, 144, 160, 176, 192, 224, 256},
      {0,  8, 16, 24,  32,  40,  48,  56,  64,  80,  96, 112, 128, 144, 160},
      {0,  8, 16, 24,  32,  40,  48,  56,  64,  80,  96, 112, 128, 144, 160}
    }
};

static const uint16_t avpriv_mpa_freq_tab[3] = { 44100, 48000, 32000 };

/*******************************************************/
/* layer 2 tables */

static const int ff_mpa_sblimit_table[5] = { 27 , 30 , 8, 12 , 30 };

static const int ff_mpa_quant_steps[17] = {
    3,     5,    7,    9,    15,
    31,    63,  127,  255,   511,
    1023,  2047, 4095, 8191, 16383,
    32767, 65535
};

/* we use a negative value if grouped */
static const int ff_mpa_quant_bits[17] = {
    -5,  -7,  3, -10, 4,
     5,  6,  7,  8,  9,
    10, 11, 12, 13, 14,
    15, 16
};

/* encoding tables which give the quantization index. Note how it is
   possible to store them efficiently ! */
static const unsigned char alloc_table_1[] = {
 4,  0,  2,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
 4,  0,  2,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
 4,  0,  2,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 16,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 16,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 16,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 16,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 16,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 16,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 16,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 3,  0,  1,  2,  3,  4,  5, 16,
 2,  0,  1, 16,
 2,  0,  1, 16,
 2,  0,  1, 16,
 2,  0,  1, 16,
 2,  0,  1, 16,
 2,  0,  1, 16,
 2,  0,  1, 16,
};

static const unsigned char alloc_table_3[] = {
 4,  0,  1,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
 4,  0,  1,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
};

static const unsigned char alloc_table_4[] = {
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
 4,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 3,  0,  1,  3,  4,  5,  6,  7,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
 2,  0,  1,  3,
};

static const unsigned char * const ff_mpa_alloc_tables[5] =
{ alloc_table_1, alloc_table_1, alloc_table_3, alloc_table_3, alloc_table_4, };

c_mp3_file::c_mp3_file(void)
{
}

c_mp3_file::~c_mp3_file()
{
}

bool c_mp3_file::init(conv_char_t * psrc,conv_size_t si,conv_packet_pt pt,void * user)
{
    return c_conv_base::init(psrc,si,pt,user);
}

#define MPA_HEADER_SIZE 4

/* header + layer + bitrate + freq + lsf/mpeg25 */
#define SAME_HEADER_MASK \
   (0xffe00000 | (3 << 17) | (3 << 10) | (3 << 19))

#define END_NOT_FOUND (-100)

/**
 * @ingroup lavc_decoding
 * Required number of additionally allocated bytes at the end of the input bitstream for decoding.
 * This is mainly needed because some optimized bitstream readers read
 * 32 or 64 bit at once and could read over the end.<br>
 * Note: If the first 23 bits of the additional bytes are not 0, then damaged
 * MPEG bitstreams could cause overread and segfault.
 */
#define FF_INPUT_BUFFER_PADDING_SIZE 32

int c_mp3_file::ff_combine_frame(ParseContext *pc, int next, uint8_t **buf, int *buf_size)
{
    /* Copy overread bytes from last frame into buffer. */
    for (; pc->overread > 0; pc->overread--)
        pc->buffer[pc->index++] = pc->buffer[pc->overread_index++];

    /* flush remaining if EOF */
    if (!*buf_size && next == END_NOT_FOUND)
        next = 0;

    pc->last_index = pc->index;

    /* copy into buffer end return */
    if (next == END_NOT_FOUND) 
    {
        void *new_buffer = conv_fast_realloc(pc->buffer, &pc->buffer_size,
                                           *buf_size + pc->index +
                                           FF_INPUT_BUFFER_PADDING_SIZE);

        if (!new_buffer) {
            pc->index = 0;
            return -1;
        }
        pc->buffer = (u_char *)new_buffer;
        memcpy(&pc->buffer[pc->index], *buf, *buf_size);
        pc->index += *buf_size;
        return -1;
    }

    *buf_size          =
    pc->overread_index = pc->index + next;

    /* append to buffer */
    if (pc->index) {
        void *new_buffer = conv_fast_realloc(pc->buffer, &pc->buffer_size,
                                           next + pc->index +
                                           FF_INPUT_BUFFER_PADDING_SIZE);
        if (!new_buffer) {
            pc->overread_index =
            pc->index = 0;
            return -1;
        }
        pc->buffer = (u_char *)new_buffer;
        if (next > -FF_INPUT_BUFFER_PADDING_SIZE)
            memcpy(&pc->buffer[pc->index], *buf,
                   next + FF_INPUT_BUFFER_PADDING_SIZE);
        pc->index = 0;
        *buf      = pc->buffer;
    }

    /* store overread bytes */
    for (; next < 0; next++) {
        pc->state   = pc->state   << 8 | pc->buffer[pc->last_index + next];
        pc->state64 = pc->state64 << 8 | pc->buffer[pc->last_index + next];
        pc->overread++;
    }

    if (pc->overread) {
    }

    return 0;
}

int c_mp3_file::mpegaudio_parse(uint8_t **poutbuf, int *poutbuf_size, uint8_t *buf, int buf_size)
{
    MpegAudioParseContext *s = &m_parse;
    ParseContext *pc = &s->pc;
    uint32_t state= pc->state;
    int i;
    int next= END_NOT_FOUND;

    for(i=0; i<buf_size; )
    {
        if(s->frame_size)
        {
            int inc= FFMIN(buf_size - i, s->frame_size);
            i += inc;
            s->frame_size -= inc;
            state = 0;

            if(!s->frame_size){
                next= i;
                break;
            }
        }
        else
        {
            while(i<buf_size)
            {
                int ret, sr, channels, bit_rate, frame_size;
                int codec_id = 0;

                state= (state<<8) + buf[i++];

                ret = avpriv_mpa_decode_header2(state, &sr, &channels, &frame_size, &bit_rate, &codec_id);
                if (ret < 4) 
                {
                    if (i > 4)
                        s->header_count = -2;
                }
                else 
                {
                    int header_threshold = m_codec_ctx->codec_audio != 0 && m_codec_ctx->codec_audio != codec_id;
                    if((state&SAME_HEADER_MASK) != (s->header&SAME_HEADER_MASK) && s->header)
                        s->header_count= -3;
                    s->header= state;
                    s->header_count++;
                    s->frame_size = ret-4;

                    if (s->header_count > header_threshold) {
                        m_codec_ctx->samplerate= sr;
                        m_codec_ctx->nchannels = channels;
                        m_codec_ctx->codec_audio = codec_id;
                        if (s->no_bitrate || !m_codec_ctx->bit_rate) {
                            s->no_bitrate = 1;
                            m_codec_ctx->bit_rate += (bit_rate - m_codec_ctx->bit_rate) / (s->header_count - header_threshold);
                        }
                    }
                    break;
                }
            }
        }
    }

    pc->state= state;
    if (ff_combine_frame(pc, next, &buf, &buf_size) < 0) {
        *poutbuf = NULL;
        *poutbuf_size = 0;
        return buf_size;
    }

    *poutbuf = buf;
    *poutbuf_size = buf_size;
    return next;
}

bool c_mp3_file::demux(c_conv_base * mux,conv_size_t start_frame,int gop)
{
    m_mux = mux;

    if(!id3v2_read_internal(ID3v2_DEFAULT_MAGIC ,0))
        return false;

    int64_t off = m_io->tell();
    if (mp3_parse_vbr_tags(off) < 0)
        m_io->seek_poisx(off, SEEK_SET);

    m_codec_ctx->codec_audio = CONVERT_AUDIO_MP3;

    int64_t stamp = 0;
    int64_t last_index = 0;
    int test = 0;
    while(!m_io->feof())
    {
        uint8_t buf[1024];
        int ret = m_io->readex(buf,sizeof(buf));
        uint8_t * out = NULL;
        int       si = 0;
        uint8_t * data = buf;
        while(ret > 0)
        {
            mpegaudio_parse(&out, &si, data, ret);

            if(si == 0)
            {
                last_index = ret;
                cout << "remain size:" << ret << endl;
                break;
            }

            if(last_index)
            {
                int dif = (si - last_index);
                ret -= dif;
                data += dif;
                last_index = 0;
            }
            else
            {
                ret -= si;
                data += si;
            }

            cout << "mp3 size:" << si << ",index:" << test++ << endl;
            conv_in_out_packe_t * node = get_node(si);
            node->stamp = stamp;
            node->type = conv_packet_audio;
            memcpy(node->p,out,si);
            node->si = si;

            assert(node->p[0] == 0xff);
            assert((node->p[1] & 0xe0) == 0xe0);

            stamp +=  1152 * 1000000 / m_codec_ctx->samplerate;
            push_node(node,true);
        }
    }
    return true;
}

int c_mp3_file::ff_id3v2_match(const uint8_t *buf, const char *magic)
{
    return  buf[0]         == magic[0] &&
            buf[1]         == magic[1] &&
            buf[2]         == magic[2] &&
            buf[3]         != 0xff     &&
            buf[4]         != 0xff     &&
           (buf[6] & 0x80) == 0        &&
           (buf[7] & 0x80) == 0        &&
           (buf[8] & 0x80) == 0        &&
           (buf[9] & 0x80) == 0;
}

void c_mp3_file::id3v2_parse( int len, uint8_t version, uint8_t flags)
{
    int64_t end = m_io->tell() + len;

    /* Footer preset, always 10 bytes, skip over it */
    if (version == 4 && flags & 0x10)
        end += 10;

    m_io->seek(end);
    return;
}

bool c_mp3_file::id3v2_read_internal(const char *magic,int64_t max_search_size)
{
    int len, ret;
    uint8_t buf[ID3v2_HEADER_SIZE];
    int found_header;
    int64_t start, off;
    bool rret = false;

    if (max_search_size && max_search_size < ID3v2_HEADER_SIZE)
        return false;

    start = m_io->tell();

    do {
        /* save the current offset in case there's nothing to read/skip */
        off = m_io->tell();
        if (max_search_size && off - start >= max_search_size - ID3v2_HEADER_SIZE) 
        {
            m_io->seek(off);
            break;
        }

        ret = m_io->readex(buf, ID3v2_HEADER_SIZE);
        if (ret != ID3v2_HEADER_SIZE) 
        {
            m_io->seek(off);
            break;
        }
        found_header = ff_id3v2_match(buf, magic);
        if (found_header) 
        {
            /* parse ID3v2 header */
            len = ((buf[6] & 0x7f) << 21) |
                  ((buf[7] & 0x7f) << 14) |
                  ((buf[8] & 0x7f) << 7) |
                   (buf[9] & 0x7f);
            id3v2_parse(len,buf[3], buf[5]);
            rret = true;
        } 
        else 
        {
            m_io->seek(off);
        }
    } while (found_header);
    return rret;
}

#define XING_FLAG_FRAMES 0x01
#define XING_FLAG_SIZE   0x02
#define XING_FLAG_TOC    0x04
#define XING_FLAC_QSCALE 0x08

#define XING_TOC_COUNT 100

int c_mp3_file::mp3_parse_info_tag(MPADecodeHeader *c, uint32_t spf)
{
    uint32_t v;

    MP3DecContext *mp3 = &m_mp3;
    static const int64_t xing_offtbl[2][2] = {{32, 17}, {17,9}};

    /* Check for Xing / Info tag */
    m_io->seek_poisx(xing_offtbl[c->lsf == 1][c->nb_channels == 1],SEEK_CUR);
    v = m_io->rb32();
    mp3->is_cbr = v == MKBETAG('I', 'n', 'f', 'o');
    if (v != MKBETAG('X', 'i', 'n', 'g') && !mp3->is_cbr)
        return 0;

    assert(0);
    return 1;
    /*不支持可变码率的MP3*/
}

void c_mp3_file::mp3_parse_vbri_tag(int64_t base)
{
    uint32_t v;
    MP3DecContext *mp3 = &m_mp3;

    /* Check for VBRI tag (always 32 bytes after end of mpegaudio header) */
    m_io->seek_poisx(base + 4 + 32, SEEK_SET);
    v = m_io->rb32();
    if (v == MKBETAG('V', 'B', 'R', 'I')) 
    {
        /* Check tag version */
        if (m_io->rb16() == 1) {
            /* skip delay and quality */
            m_io->seek_poisx(4,SEEK_CUR);
            mp3->header_filesize = m_io->rb32();
            mp3->frames = m_io->rb32();
        }
    }
}

/**
 * Try to find Xing/Info/VBRI tags and compute duration from info therein
 */
#define MPA_STEREO  0
#define MPA_JSTEREO 1
#define MPA_DUAL    2
#define MPA_MONO    3
int c_mp3_file::mp3_parse_vbr_tags(int64_t base)
{
    uint32_t v, spf;
    MPADecodeHeader c;
    int vbrtag_size = 0;
    MP3DecContext *mp3 = &m_mp3;

    v = m_io->rb32();
    if(ff_mpa_check_header(v) < 0)
      return -1;

    if (avpriv_mpegaudio_decode_header(&c, v) == 0)
        vbrtag_size = c.frame_size;
    if(c.layer != 3)
        return -1;

    spf = c.lsf ? 576 : 1152; /* Samples per frame, layer 3 */

    mp3_parse_info_tag(&c, spf);
    mp3_parse_vbri_tag(base);

    if (!mp3->frames && !mp3->header_filesize)
        return -1;

    /* Skip the vbr tag frame */
    m_io->seek_poisx(base + vbrtag_size, SEEK_SET);

    return 0;
}

int c_mp3_file::avpriv_mpegaudio_decode_header(MPADecodeHeader *s, uint32_t header)
{
    int sample_rate, frame_size, mpeg25, padding;
    int sample_rate_index, bitrate_index;
    if (header & (1<<20)) 
    {
        s->lsf = (header & (1<<19)) ? 0 : 1;
        mpeg25 = 0;
    } 
    else 
    {
        s->lsf = 1;
        mpeg25 = 1;
    }

    s->layer = 4 - ((header >> 17) & 3);
    /* extract frequency */
    sample_rate_index = (header >> 10) & 3;
    if (sample_rate_index >= (int)FF_ARRAY_ELEMS(avpriv_mpa_freq_tab))
        sample_rate_index = 0;
    sample_rate = avpriv_mpa_freq_tab[sample_rate_index] >> (s->lsf + mpeg25);
    sample_rate_index += 3 * (s->lsf + mpeg25);
    s->sample_rate_index = sample_rate_index;
    s->error_protection = ((header >> 16) & 1) ^ 1;
    s->sample_rate = sample_rate;

    bitrate_index = (header >> 12) & 0xf;
    padding = (header >> 9) & 1;
    //extension = (header >> 8) & 1;
    s->mode = (header >> 6) & 3;
    s->mode_ext = (header >> 4) & 3;
    //copyright = (header >> 3) & 1;
    //original = (header >> 2) & 1;
    //emphasis = header & 3;

    if (s->mode == MPA_MONO)
        s->nb_channels = 1;
    else
        s->nb_channels = 2;

    if (bitrate_index != 0) {
        frame_size = avpriv_mpa_bitrate_tab[s->lsf][s->layer - 1][bitrate_index];
        s->bit_rate = frame_size * 1000;
        switch(s->layer) {
        case 1:
            frame_size = (frame_size * 12000) / sample_rate;
            frame_size = (frame_size + padding) * 4;
            break;
        case 2:
            frame_size = (frame_size * 144000) / sample_rate;
            frame_size += padding;
            break;
        default:
        case 3:
            frame_size = (frame_size * 144000) / (sample_rate << s->lsf);
            frame_size += padding;
            break;
        }
        s->frame_size = frame_size;
    } else {
        /* if no frame size computed, signal it */
        return 1;
    }

#if defined(DEBUG)
    printf("layer%d, %d Hz, %d kbits/s, ", 
           s->layer, s->sample_rate, s->bit_rate);
    if (s->nb_channels == 2) {
        if (s->layer == 3) {
            if (s->mode_ext & MODE_EXT_MS_STEREO)
                printf("ms-");
            if (s->mode_ext & MODE_EXT_I_STEREO)
                printf("i-");
        }
        printf("stereo");
    } else {
        printf("mono");
    }
    printf("\n");
#endif
    return 0;
}

int c_mp3_file::avpriv_mpa_decode_header2(uint32_t head, int *sample_rate, int *channels, int *frame_size, int *bit_rate,int * codec_id)
{
    MPADecodeHeader s1, *s = &s1;

    if (ff_mpa_check_header(head) != 0)
        return -1;

    if (avpriv_mpegaudio_decode_header(s, head) != 0) {
        return -1;
    }

    switch(s->layer) {
    case 1:
        *codec_id = CONVERT_AUDIO_MP1;
        *frame_size = 384;
        break;
    case 2:
        *codec_id = CONVERT_AUDIO_MP2;
        *frame_size = 1152;
        break;
    default:
    case 3:
        *codec_id = CONVERT_AUDIO_MP3;
        if (s->lsf)
            *frame_size = 576;
        else
            *frame_size = 1152;
        break;
    }

    *sample_rate = s->sample_rate;
    *channels = s->nb_channels;
    *bit_rate = s->bit_rate;
    return s->frame_size;
}
