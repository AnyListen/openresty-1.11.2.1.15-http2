#ifndef __C_FLV_FILE
#define __C_FLV_FILE

#include "c_conv_base.h"
#include "spcialconfig.h"

using namespace std;

typedef struct _SAudioFram
{
	int nChannels;//1为单通道 2为双通道
	int samplerate;
	u_char * pDataBuf;
	unsigned int nBufLen;
	long stamp;//如果为-1 则内部获取时间戳
	u_char objectType;//1 or 2
    u_char SoundSize;/* 1=8bit, 2=16bit */
    int           dataType;/*codec id*/
    int           audio_config;/*0 config ,1 data*/
	_SAudioFram()
	{
		nChannels = 0;
		samplerate = 0;
		pDataBuf = NULL;
		nBufLen = 0;
		stamp = 0;
		objectType = 0;
		SoundSize = 0;
		dataType = 0;
		audio_config = 0;
	}
}SAudioFrame;

typedef struct _SVideoFrame
{
	u_char *pDataBuf;
	uint32_t  nDataLen;
	bool bIsKeyFrame;
	long stamp;
	_SVideoFrame()
	{
		pDataBuf = NULL;
		nDataLen = 0;
		bIsKeyFrame = false;
		stamp = 0;
	}
}SVideoFrame;

typedef struct _SBuildFileHeader
{
	SVideoFrame * sps;
	SVideoFrame * pps;
	SAudioFrame * audio;
	int 	      width;
	int 		  height; 
	int 		  fps;
    unsigned int  video_data_rate;
    unsigned int  audio_data_rate;
    conv_str_t    aac_header;
	conv_str_t    avc_header;
    conv_str_t    meta_data;
	_SBuildFileHeader()
	{
		sps = NULL;
		pps = NULL;
		audio = NULL;
		width = height = fps = video_data_rate = audio_data_rate = 0;
	}
}SBuildFileHeader;

typedef struct _AMFHeaderOutPos
{
	int n_duration_pos;
	int n_filesize_pos;
}AMFHeaderOutPos;

typedef int		int_4;
typedef short	short_2;

#pragma pack(1)
struct SFlvHeader
{
	char szFLV[3];
	char szVersion;
	char streamInfo;
	int_4 nHeaderSize;
};

struct SFlvTagHeader
{
	char  tagHeaderType;//音频为0x8 视频为0x9  脚本为0x12
	char  tagDataLength[3];//数据区长度
	u_char  Timestamp[4];//时间戳 最后一个字节为扩展时间戳
	char  StreamID[3];//Always 0
};

struct SFlvTagWithPreSize
{
	int_4 nPreTagSize; //上一个tag的大小
	SFlvTagHeader tagHeader;
};

struct SFlvAMFHeader
{
	char amf1type;//第一个amf的类型 一般是0x02.表示字符串
	short_2 stringLength;//一般是0x0a
	char * pData;//后面为数据 一般为"onMetaData"
	char amf2type;//第二份amf2的类型 一般是0x08 表示数组
	int_4 arraySize;//数组元素的个数

};
//double 类型
struct SFlvAMFArrayNode
{
	char nameLength[2];//数组元素名的长度
	string Name;//元素名
	char type;//类型 00
	double data;//数据
};

struct SFlvAMFBOOLArraryNode
{
	char nameLength[2];//数组元素名的长度
	string Name;//元素名
	char type;//类型 01
	char data;//数据
};

struct SFlvVideoTagHeader
{
	/*
		//前四位为Frame Type 
		1 = key frame (for AVC, a seekable frame)
		2 = inter frame (for AVC, a non-seekable frame)
		3 = disposable inter frame (H.263 only)
		4 = generated key frame (reserved for server use only)
		5 = video info/command frame 
		后四位为CodecID
		2 = Sorenson H.263
		3 = Screen video
		4 = On2 VP6
		5 = On2 VP6 with alpha channel
		6 = Screen video version 2
		7 = AVC 
	*/
	char Type;//我们这里为0x17为关键字 27为一般帧
	/*
		0 = AVC sequence header sps
		1 = AVC NALU
		2 = AVC end of sequence (lower level NALU sequence ender is 
		not required or supported)
	*/
	char AVCPacketType;
	/*
		IF AVCPacketType == 1
			Composition time offset 
		ELSE
			0
	*/
	char compositiontime[3];
};

struct SH264_SPS_PPS
{
	u_char * sps;
	int n_sps_len;
	u_char * pps;
	int n_pps_len;
};

#pragma pack()

struct FlvNeedParam
{
	int n_fps;
	int n_width;
	int n_height;
	int audiosamplerate;
    unsigned int video_data_rate;
    unsigned int audio_data_rate;
	bool bNeedDurationAndFileSize;
    bool bHasAudio ;
    bool bHasVideo ;
    FlvNeedParam()
    {
        n_fps = n_width = n_height = audiosamplerate = 0;
        bNeedDurationAndFileSize = false;
        bHasAudio = bHasVideo = false;
        video_data_rate = 0;
        audio_data_rate = 0;
    }
};

struct FlvTagHeadertParam
{
    int  n_tag_size_pos;
    int  tag_type;
    long stamp;
    bool bVideo;
    FlvTagHeadertParam(bool bIsVideo,long s):
        n_tag_size_pos(0),
        tag_type(-1),
        stamp(s),
        bVideo(bIsVideo){
        }
};

typedef int ngx_int_t;
typedef unsigned int ngx_uint_t;
typedef unsigned char u_char;
#define caoc_pf printf

#define NGX_OK     0
#define NGX_ERROR -1

class c_flv_file:public c_conv_base
{
public:
	c_flv_file(void);
	virtual ~c_flv_file(void);

	virtual conv_in_out_packe_t * mux_header (const conv_codec_ctx_t & ctx,long stamp);
    virtual conv_in_out_packe_t * mux(const conv_in_out_packe_t *in,const conv_codec_ctx_t & ctx,int & ret);
	virtual bool demux(c_conv_base * mux,conv_size_t start_frame,int gop);
    virtual int  demux_keyframes();
private:
	inline bool flv_right_bigger(int left,int right)
	{
		if(left < right)
		{
			perror("flv:dst size is smaller\n");
			return true;
		}
		return false;
	}

	inline void flv_put_num_to_buf(OUT u_char szNum[],const char * psrc,int dstLenght)
	{
		if(conv_big_endian_test())
		{
			for (int n = 0; n < dstLenght; ++n)
			{
				szNum[n] = psrc[n];
			}
		}
		else
		{
			for (int n = 0; n < dstLenght; ++n)
			{
				szNum[n] = psrc[dstLenght -1 - n];
			}
		}
	}

	inline int flv_mem_cp(void *dst,const void * src,int size)
	{
		memcpy(dst,src,size);
		return size;
	}

private:
	int flv_build_header( u_char *pdst, int ndstlen, const conv_codec_ctx_t* pData, OUT AMFHeaderOutPos * out);
	int write_flv_header_mem(u_char * szHeader,int nLength,bool bHasAudio,bool bHasVideo);
	int write_flv_metadata_mem(u_char * szMetadata,int nLength,const FlvNeedParam * pflv,AMFHeaderOutPos * pOut);
	int write_flv_amf_header(u_char * dst,int ndstlen,const SFlvAMFHeader & amfHeader);
	int CreateMetaDataNode(const char * szName,bool data,SFlvAMFBOOLArraryNode &node);
	int CreateMetaDataNode(const char * szName,double data,SFlvAMFArrayNode &node);
	int CreatMetaDataNodeCommon(const char * szName,char nameLength[2],string & name );
	int WriteFrameTagsHeader(u_char * buf,int nlen,FlvTagHeadertParam &out);
	int WriteLastTagSize(u_char * pbuf,int nlen,int_4 lastTagSize);
	int flv_build_video_frame_header( u_char * pdst, int ndstlen, int b_is_key_frame, int stamp, uint32_t cts, int frame_size);
	int write_nalu_header( u_char * pDstDataBuf, int ndstlen, int b_is_key_frame, int frame_size, uint32_t cts);
	int WriteAudioFrameTagData(u_char * pdst,int ndst,const SAudioFrame * pFrame);
	int WriteAudioFrameTagData_NotAAC(u_char * pdst,int ndst,const SAudioFrame * pFrame);
	int WriteAudioFrameTagHeader_NotAAC(u_char * pdst,int ndst,const SAudioFrame * pFrame);
	int flv_build_audio_frame(u_char *pdst,int ndstlen,const SAudioFrame * pFrame);
	int WriteAAChdr(const SAudioFrame *frame,u_char *p,bool force_config = false);
	int WrtiteMetaDataNode(u_char * buf,int nLength,const SFlvAMFBOOLArraryNode &node);
	int WrtiteMetaDataNode(u_char * buf,int nLength,const SFlvAMFArrayNode &node);
	int flv_build_video_frame( const conv_in_out_packe_t & in, OUT conv_in_out_packe_t ** out);
	int flv_build_audio_frame( const conv_in_out_packe_t & in, const conv_codec_ctx_t & ctx, OUT conv_in_out_packe_t ** out);
	bool parse_header();
	bool parse_frame(bool only_metadata = false,conv_size_t start_frame = 0,int gop = 0);
	int ngx_get_rtmp_type_from_flv_type(u_char fmt);
	int ngx_http_pull_parse_audio_config(u_char *pc,int len);
    void parse_flv_script_tag(u_char * p,u_char * pend);
    int amf_parse_object(u_char ** p,u_char * pend,const char * key,int depth);
    int amf_get_string(u_char **p, char *buffer, int buffsize);
    int parse_keyframes_index(u_char ** p,u_char * pend);
    bool advance_read_frames(bool force);
    uint32_t conv_cts(u_char * pcts,int si);
    void append_sps_pps(conv_in_out_packe_t ** plast,conv_in_out_packe_t * node);
private:
    bool m_has_video;
    bool m_has_audio;
    bool m_parse_header;
    bool m_parse_audio_header;
    string m_audio_config;
    string m_video_config;
    bool m_first_prase;
    bool m_parse_metadata;
    bool m_meta_has_keyframes;
};


#endif
