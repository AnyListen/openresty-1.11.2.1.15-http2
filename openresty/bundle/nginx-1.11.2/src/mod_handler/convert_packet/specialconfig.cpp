/*
 * =====================================================================================
 *
 *       Filename:  specialconfig.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月08日 13时24分03秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (490479164@qq.com), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "spcialconfig.h"
#include "c_conv_base.h"

static int s_rates [] = { 96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350, 0 };

int index_to_samplerate(int index)
{
	if(index >= (int)sizeof(s_rates) / (int)sizeof(int))
		return 0;
	return s_rates[index];
}

int  audio_specific_config (u_char objectType,int samplerate, int channels, u_char *p)
{
	u_char count = 0;
	for (count = 0; s_rates[count] != samplerate; count++)
	{
		if (s_rates [count] == 0)
			return 0;
	}
	p[0] = ((objectType << 3) | (count >> 1));
	p[1] = (((count) & 0x01) << 7) | (channels << 3);
	return 2;
}

#pragma pack(1)
struct SFlvAVCConfigHeader
{
	//版本号 0x1
	char configurationVersion;
	//sps的第一个数据
	char AVCProfileIndication;
	//sps的第二个数据
	char profile_compatibility;
	//sps的第三个数据
	char AVCLevelIndication;
	//NALUnitLeght的长度 该值一般为ff
	//前6为保留 为111111
	char lenghtSizeMinusOne;
	//sps的个数
	//前3位保留 为111
	//后五位为sps的个数
	char numOfSequenceParameterSets;
	//sps_size + sps数据
	//sps_size为2个字节
	char * sps;
	int nspsLenght;

	//pps的个数
	char numOfPictureParameterSets;
	//pps_size + sps数据
	//pps_size为2个字节
	char * pps;
	int  nppsLenghth;
};
#pragma pack()

static int CopyDataToNewMemWithSize(u_char * dst,const u_char * src,int srcLength)
{
	short sSize = srcLength;
	sSize = BigEndian_16(sSize);
	memcpy(dst,&sSize,sizeof(short));
	memcpy(dst + sizeof(short),src,srcLength);
	return  srcLength + sizeof(short);
}

int  write_video_specific_Config(u_char * pBuf,int nBufLen,const u_char * sps,int nspsLength,const u_char * pps,int nppsLength)
{
	//写配置信息
	if(nBufLen < 5 + 1 + 2 + nspsLength + 1 + 2 + nspsLength)
		return 0;

	u_char * psrc = pBuf;
	*pBuf++ = 0x1;
	*pBuf++ = sps[1];
	*pBuf++ = sps[2];
	*pBuf++ = sps[3];
	*pBuf++ = 0xff;

	*pBuf++ = 0xE1;
	pBuf += CopyDataToNewMemWithSize(pBuf,sps,nspsLength);

	if(nppsLength > 0)
	{
		*pBuf++ = 0x1;
		pBuf += CopyDataToNewMemWithSize(pBuf,pps,nppsLength);
	}
	else
	{
		*pBuf++ = 0;
	}
	return pBuf - psrc;
}

bool convert_copy(void* out,u_char ** in,int size,u_char * last)
{
	if(*in + size > last)
		return false;
	if(out != NULL)
	{
		memcpy(out,*in,size);
	}
	*in += size;
	return true;
}

void * convert_rmemcpy(void *dst, const void* src, size_t n)
{
	u_char     *d, *s;

	d = (u_char*)dst;
	s = (u_char*)src + n - 1;

	while(s >= (u_char*)src) 
	{
		*d++ = *s--;
	}

	return dst;
}

bool conv_parse_aac_header(const conv_str_t * audio_config, uint32_t *objtype, uint32_t *srindex, uint32_t *chconf)
{
    u_char           *p;
	u_char            b0, b1;

    p = (u_char*)audio_config->p;
	u_char * last = p + audio_config->si;

    if (!convert_copy(&b0, &p, 1, last) ) 
	{
        return false;
    }

    if (!convert_copy(&b1, &p, 1, last)) 
	{
        return false;
    }

    *objtype = b0 >> 3;
    if (*objtype == 0 || *objtype == 0x1f) 
	{
        cout << "hls: unsupported adts object type:" << *objtype << endl;
        return false;
    }

    if (*objtype > 4) 
	{
        /*
         * Mark all extended profiles as LC
         * to make Android as happy as possible.
         */
        *objtype = 2;
    }

    *srindex = ((b0 << 1) & 0x0f) | ((b1 & 0x80) >> 7);
    if (*srindex == 0x0f) 
	{
		cout << "hls: unsupported adts sample rate:" << *srindex;
        return false;
    }

    *chconf = (b1 >> 3) & 0x0f;

    return true;
}

conv_in_out_packe_t *  conv_append_sps_pps(long stamp,conv_str_t * video_config,class c_conv_base * base)
{
    u_char                    *p;
    int8_t                    nnals;
    uint16_t                  len, rlen;
    int                       n;

    u_char * in = video_config->p;
	conv_size_t si = video_config->si;
	u_char * last = in + si;

    if (in == NULL) 
	{
        return NULL;
    }

    p = in;

    /*
     * Skip bytes:
     * - version
     * - profile
     * - compatibility
     * - level
     * - nal bytes
     */

    if (!convert_copy(NULL, &p, 5,last ))
	{
        return NULL;
    }

    /* number of SPS NALs */
    if (!convert_copy(&nnals, &p, 1, last))
	{
        return NULL;
    }

    nnals &= 0x1f; /* 5lsb */
    /* SPS */
	conv_in_out_packe_t * header = NULL; 
	conv_in_out_packe_t ** plast = &header; 
    for (n = 0; ; ++n) 
	{
        for (; nnals; --nnals)
		{
            /* NAL length */

            if (!convert_copy(&rlen, &p, 2, last))
			{
                return header;
            }

            convert_rmemcpy(&len, &rlen, 2);
            /* NAL body */
			conv_in_out_packe_t * node = base->get_node(4+len);
            *plast = node;
            plast = &node->next;
			node->stamp = stamp;
			node->type = conv_packet_video;
			char nalu[4] = {0,0,0,1};
			memcpy(node->p,nalu,4);

            if (!convert_copy(node->p+4, &p, len, last))
			{
				base->free_node(node);
                return header;
            }
#if CONV_WRITE_TEST_FILE
			{
#if 0
				if(NULL == s_h264)
				{
					s_h264 = fopen("test.h264","wb");
				}
				fwrite(nalu,4,1,s_h264);
				fwrite(node->p,node->si,1,s_h264);
#endif
			}
#endif
		}

        if (n == 1)
		{
            break;
        }

        /* number of PPS NALs */
        if (!convert_copy(&nnals, &p, 1,last)) 
		{
            return header;
        }
    }

    return header;
}

