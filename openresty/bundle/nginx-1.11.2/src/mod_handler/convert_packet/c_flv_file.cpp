/*
 * =====================================================================================
 *
 *       Filename:  c_flv_file.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月07日 15时00分06秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (), 
 *   Organization:  490479164@qq.com
 *
 * =====================================================================================
 */
#include "c_flv_file.h"
#include "mem_reader.h"

#define CONV_FLV_HEADER_SIZE 13

//tag时间戳第四位是扩展位
//ffmpeg中是7f TagStamp[3] = v & 0x7f
#define FLVFILE_COPYSTAMP(stamp,TagStamp)\
{\
	long v = stamp;\
	TagStamp [2] = (u_char)(v & 0xFF);\
	v >>= 8;\
	TagStamp [1] = (u_char)(v & 0xFF);\
	v >>= 8;\
	TagStamp [0] = (u_char)(v & 0xFF);\
	v >>= 8;\
	TagStamp [3] = (u_char)(v & 0xFF);\
}

#define putIntToThreeChar(szThree,data) flv_put_num_to_buf(szThree,(const char*)&data,3)
#define putDoubleToEightChar(szEight,data) flv_put_num_to_buf(szEight,(const char*)&data,8)

#define FLV_VIDEOTAG_HEADER_SIZE 24
#define FLV_AUDIOTAG_HEADER_SIZE 19
#define FLV_MAX_TAGSIZE 20
#define FLV_TAIL_SIZE 4

c_flv_file::c_flv_file()
{
    m_parse_header = m_has_audio = m_has_video = false;
    m_parse_audio_header = false;
    m_first_prase = true;
    m_parse_metadata = false;
    m_meta_has_keyframes = false;
}

c_flv_file::~c_flv_file()
{

}

#define FLVFILE_COPYSTAMP_INT(nstamp,stamp)\
        nstamp = (u_char)stamp[3] << 24 | (u_char)stamp[0] << 16 | (u_char)stamp[1] << 8 | (u_char)stamp[2]

#pragma pack(1)
typedef struct 
{
    char  tag_header_type;//音频为0x8 视频为0x9  脚本为0x12
    char  tag_data_length[3];//数据区长度 no include header size
    u_char  timestamp[4];//时间戳 最后一个字节为扩展时间戳
    char  stream_id[3];//Always 0
}conv_flv_tag_header_t;
#pragma pack()

int c_flv_file::ngx_get_rtmp_type_from_flv_type(u_char fmt)
{
    static ngx_uint_t  sample_rates[] = { 5512, 11025, 22050, 44100 };

    m_codec_ctx->codec_audio = (fmt & 0xf0) >> 4;

    m_codec_ctx->nchannels = (fmt & 0x01) + 1;
    m_codec_ctx->samplesize = (fmt & 0x02) ? 2 : 1;

	size_t sap = (fmt & 0x0c) >> 2;
	if(sap  >= sizeof(sample_rates))
		return NGX_ERROR;
	m_codec_ctx->samplerate= sample_rates[sap];
	if(m_codec_ctx->codec_audio == 0)
		m_codec_ctx->codec_audio = CONVERT_AUDIO_UNCOMPRESSED;
    return 1;
}

int c_flv_file::ngx_http_pull_parse_audio_config(u_char *pc,int len)
{
    ngx_get_rtmp_type_from_flv_type(pc[0]);
    if((pc[0] & 0xF0) != 0xA0)
    {
        //no aac
        caoc_pf("parse not aac audio tag\n");
        return 1;
    }
    if(pc[1] != 0)
        return 0;

	m_codec_ctx->codec_audio = CONVERT_AUDIO_AAC;
    caoc_pf("parse aac audio tag\n");
	uint32_t srindex;
	conv_str_t  audio_config;
	audio_config.p = pc + 2;
	audio_config.si = len - 2;
	conv_parse_aac_header(&audio_config, (uint32_t*)&m_codec_ctx->aac_profile, &srindex, (uint32_t*)&m_codec_ctx->nchannels);
	m_codec_ctx->samplerate = index_to_samplerate(srindex);
    m_audio_config = string((const char*)pc+2,len-2); 
	m_codec_ctx->audio_config.p = (u_char *)m_audio_config.c_str();
	m_codec_ctx->audio_config.si = len - 2;
	return 2;
}

uint32_t c_flv_file::conv_cts(u_char * pcts,int si)
{
    uint32_t cts = 0;
    memcpy(&cts,pcts,si);
    return  ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) | (cts & 0x0000FF00);
}

void c_flv_file::append_sps_pps(conv_in_out_packe_t ** plast,conv_in_out_packe_t * node)
{
    conv_in_out_packe_t * h264_header = NULL;
    h264_header = conv_append_sps_pps(node->stamp,&m_codec_ctx->video_config,this);
    if(h264_header != NULL)
    {
        *plast = h264_header;
        for(;h264_header->next != NULL;h264_header=h264_header->next){}
        h264_header->next = node;
    }
}

bool c_flv_file::advance_read_frames(bool force)
{
    if(!force)
    {
        bool                            advance = false;
        if(m_first_prase)
        {
            m_first_prase = false;
            if(m_mux)
            {
                advance = m_mux->advance_read();
            }
        }
        else 
            return true;

        if(!advance)
            return true;
    }

	Size                            si;
	conv_flv_tag_header_t           header;
	conv_flv_tag_header_t           *ph = &header;
    int                             data_size;
    ngx_int_t                       stamp;
	conv_in_out_packe_t            *node = NULL;
    
    conv_size_t opos = m_io->tell();
    m_io->seek(CONV_FLV_HEADER_SIZE);
    bool parse_audio_header = false;
    bool first_video = true;
    conv_size_t tag_pos = 0;

    while(1)
    {
        tag_pos = m_io->tell();
        if(!m_io->read(ph,sizeof(*ph),si))
            break;

        if(si < (Size)sizeof(conv_flv_tag_header_t))
            break;	

        conv_swicth_int(ph->tag_data_length,sizeof(ph->tag_data_length),&data_size);
        FLVFILE_COPYSTAMP_INT(stamp,ph->timestamp);

        /*
         * 4  flv的tail的4个字节的上个tag的长度. 
         *
         * 5   264的flv格式前面5个字节
         * 4   264的前面4字节的长度
         * 1   nalu头
         * */
        int get_size = first_video ? data_size + 4 : 5 + 4 + 1;
        int statr_pos = tag_pos + sizeof(*ph);
        node = get_node(get_size);

        node->stamp = stamp;

        if(!m_io->readex(node->p,get_size))
        {
            free_node(node);
            break;
        }

        int oft = 0;
        //      cout << "flv tag:" << (int)ph->tag_header_type << "size:" << data_size << endl;
        switch(ph->tag_header_type /*& 0x1f*/)
        {
            case 0x08:
                {
                    /*需要多读出2位
                     *aduio
                     * */
                    if(!parse_audio_header || ((node->p[0] & 0xF0) == 0xA0 && node->p[1] == 0))
                    {
                        parse_audio_header = true;
                        if((node->p[0] & 0xF0) != 0xA0)
                        {
                            oft += 1;
                        }
                        else 
                        {
                            oft += 2;
                            m_codec_ctx->codec_audio = CONVERT_AUDIO_AAC;
                        }
                    }
                    else
                    {
                        oft += 1;
                    }

                    if(oft == 1)
                    {
                        if(m_codec_ctx->codec_audio == CONVERT_AUDIO_AAC)
                            oft += 1;
                        node->p += oft;
                        node->type = conv_packet_audio;
                        node->si = data_size - oft;
                    }
                    m_io->seek_poisx(data_size + sizeof(int) - get_size,SEEK_CUR);
                }
                break;
            case 0x09:
                {
                    //video
                    oft +=  5;//only h264
                    u_char * pstart = node->p + oft;
                    first_video = false;
                    if(*(pstart - 4) != 0x00)
                    {
                        node->type = conv_packet_video;
                        Size frame_si = data_size - oft;
                        node->cts = conv_cts(pstart - 3,3);
                        int64_t nalu_size = 0;
                        char ftype = (pstart[-5] & 0xf0) >> 4;
                        conv_in_out_packe_t *pheader = node;
                        conv_in_out_packe_t ** plast = &pheader;
                        int bkeyframe = (ftype == 1);
                        for(;frame_si > 0;)
                        {
                            conv_swicth_int(pstart,4,&nalu_size);
                            frame_si -= nalu_size;
                            frame_si -= 4;
                            node->si = nalu_size + 4;
                            node->p = pstart;
                            if((pstart[4] & 0x1f) == 5)
                            {
                                bkeyframe = 1;
                                if(!m_meta_has_keyframes)
                                {
                                    m_keyframes.push_back(conv_frame_info(tag_pos,stamp));
                                }
                                append_sps_pps(plast,node);
                            }
                            node->key_frame = bkeyframe;
                            m_io->seek_poisx(nalu_size-1,SEEK_CUR);
                            if(frame_si)
                            {
                                conv_in_out_packe_t *node2 = get_node(5);
                                pstart = node2->p;
                                *node2 = *node;
                                node2->next = NULL;
                                node->next = node2;
                                plast = &node->next;
                                node = node2;
                                if(!m_io->readex(pstart,5))
                                {
                                    break;
                                }
                            }
                        }
                        node = pheader;
                        m_io->seek_poisx(4,SEEK_CUR);
                        if(node)
                            node->key_frame = bkeyframe;
                    }
                    else
                    {
                        caoc_pf("nalu sequence stamp = %i\n",stamp);
                        if(data_size > 5)
                        {
                            m_video_config = string((const char*)pstart,data_size - 5); 
                            m_codec_ctx->video_config.p = (u_char*)m_video_config.c_str();
                            m_codec_ctx->video_config.si = data_size - 5;
                        }
                        m_io->seek_poisx(statr_pos + data_size + 4,SEEK_SET);
                    }
                }
                break;
            case 0x12:
                {
                    //script
                    parse_flv_script_tag(node->p,node->p + data_size);
                    first_video = m_has_video;
                }
                break;
            default:
                {
                    caoc_pf("unkonw flv data type %d\n",(int)ph->tag_header_type);
                }
                break;
        }
        if(!force)
        {
            if(node->type == conv_packet_audio || node->type == conv_packet_video)
                m_mux->advace_process(node,m_codec_ctx);
        }
        free_node(node);
    }
    m_io->seek(opos);
    return true;
}

bool c_flv_file::parse_frame(bool only_metadata,conv_size_t start_frame,int gop)
{
	Size                            si;
	conv_flv_tag_header_t            header;
	conv_flv_tag_header_t            *ph = &header;
    int                             data_size;
    ngx_int_t                       stamp;
    Size                            max_read = -1;
    bool                            nolimit = true;
    int                             find_av_header = 0;
	conv_in_out_packe_t            *node = NULL;

	get_codec_ctx(NULL);
	m_codec_ctx->codec_video = CONVERT_VIDEO_H264;

    advance_read_frames(false);

    conv_size_t pos = 0;    
    if(m_keyframes.size() > 0)
    {
        if(start_frame >= (conv_size_t)m_keyframes.size())
            return false;

        if(0 == start_frame)
            pos = CONV_FLV_HEADER_SIZE;
        else
            pos = m_keyframes[start_frame].pos;
        m_io->seek_poisx(pos,SEEK_SET);

        if(gop > 0)
        {
            Size                            end = -1;
            if(start_frame < (conv_size_t)m_keyframes.size() - 1)
                end = m_keyframes[start_frame+1].pos;
            else if(start_frame >= (conv_size_t)m_keyframes.size())
                return false;

            max_read = end - pos;
            nolimit = false;
        }
    }
    else if(only_metadata)
    {
        nolimit = true;
        find_av_header = 10;/*找前10帧*/
    }
    else
    {
        m_io->seek(CONV_FLV_HEADER_SIZE);
    }

    while(nolimit || (!nolimit && max_read > 0))
    {
        if(!m_io->read(ph,sizeof(*ph),si))
            break;
        max_read -= si;

        if(si < (Size)sizeof(conv_flv_tag_header_t))
            break;	

        conv_swicth_int(ph->tag_data_length,sizeof(ph->tag_data_length),&data_size);

        //tag_all_size = sizeof(conv_flv_tag_header_t) + data_size + sizeof(int);
        FLVFILE_COPYSTAMP_INT(stamp,ph->timestamp);

        node = get_node(data_size + sizeof(int));
        node->stamp = stamp;

        if(!m_io->readex(node->p,data_size + sizeof(int)))
        {
            free_node(node);
            return false;
        }
        max_read -= (data_size + 4);

        int oft = 0;
        //cout << "flv tag:" << (int)ph->tag_header_type << "size:" << data_size << endl;
        switch(ph->tag_header_type /*& 0x1f*/)
        {
            case 0x08:
                {
                    //aduio
                    if(!m_parse_audio_header || ((node->p[0] & 0xF0) == 0xA0 && node->p[1] == 0))
                    {
                        m_parse_audio_header = true;
                        oft += ngx_http_pull_parse_audio_config(node->p,data_size);
                    }
                    else
                    {
                        oft += 1;
                    }

                    if(only_metadata)
                    {
                        if(m_codec_ctx->video_config.si && m_codec_ctx->audio_config.si)
                            goto end_parse;
                        --find_av_header;
                        if(find_av_header < 0)
                            goto end_parse;
                        break;
                    }

                    if(oft == 1)
                    {
                        if(m_codec_ctx->codec_audio == CONVERT_AUDIO_AAC)
                            oft += 1;

                        node->p += oft;
                        node->type = conv_packet_audio;
                        node->si = data_size - oft;
                    }
                }
                break;
            case 0x09:
                {
                    //video
                    oft +=  5;//only h264

                    u_char * pstart = node->p + oft;
                    if(*(pstart - 4) == 0x00)
                    {
                        if(m_codec_ctx->video_config.si == 0)
                        {
                            caoc_pf("nalu sequence stamp = %i\n",stamp);
                            m_video_config = string((const char*)pstart,data_size - 5); 
                            m_codec_ctx->video_config.p = (u_char*)m_video_config.c_str();
                            m_codec_ctx->video_config.si = data_size - 5;
                        }
                    }
                    else
                    {
                        if(only_metadata)
                        {
                            if(m_codec_ctx->video_config.si && m_codec_ctx->audio_config.si)
                                goto end_parse;

                            --find_av_header;
                            if(find_av_header < 0)
                                goto end_parse;

                            break;
                        }

                        node->type = conv_packet_video;
                        u_char * h264_end = node->p + data_size;;
                        node->cts = conv_cts(pstart - 3,3);
                        int type = 0;
                        int nalu_size = 0;
                        char ftype = (pstart[-5] & 0xf0) >> 4;
                        conv_in_out_packe_t *pheader = node;
                        conv_in_out_packe_t ** plast = &pheader;
                        int bkeyframe = (ftype == 1);
                        bool b_append_sps_pps = false;
                        for(;pstart < h264_end;)
                        {
                            conv_swicth_int(pstart,4,&nalu_size);
                            node->p = pstart;
                            pstart[0] = 0;
                            pstart[1] = 0;
                            pstart[2] = 0;
                            pstart[3] = 1;
                            type  = pstart[4] & 0x1f;
                            pstart += 4;
                            pstart += nalu_size;
                            node->si = pstart - node->p;

                            if(type == 7 || type == 8)
                            {
                                b_append_sps_pps = true;
                            }
                            if(type == 5)
                            {
                                bkeyframe = 1;
                                /*否则对于IDR里有sps和pps的,画面会花*/
                                if(!b_append_sps_pps)
                                {
                                    append_sps_pps(plast,node);
                                   b_append_sps_pps = true;
                                }
                            }
                            node->key_frame = bkeyframe;
                            if(pstart < h264_end)
                            {
                                conv_in_out_packe_t *node2 = get_node(sizeof(void*));
                                *node2 = *node;
                                node2->next = NULL;
                                node2->p = pstart;
                                node->next = node2;
                                plast = &node->next;
                                node = node2;
                            }
                        }
                        node = pheader;
                        if(node)
                            node->key_frame = bkeyframe;
                    }
                    break;
                }
                break;
            case 0x12:
                    //script
                    parse_flv_script_tag(node->p,node->p + data_size);
                break;
            default:
                {
                    caoc_pf("unkonw flv data type %d\n",(int)ph->tag_header_type);
                }
                break;
        }
        if(node->type == conv_packet_audio || node->type == conv_packet_video)
            push_node(node,true);
        else
            free_node(node);
    }
	return true;
end_parse:
    free_node(node);
	return true;
}

bool c_flv_file::demux(c_conv_base * mux,conv_size_t start_frame,int gop)
{
	m_mux = mux;
	if(!parse_header())
		return false;
	return parse_frame(false,start_frame,gop);
}

bool c_flv_file::parse_header()
{
    if(m_parse_header) return true;

	char hdr[3] = {'\0'};
    m_io->read_poisx((u_char *) &hdr, sizeof(hdr), 0);
	if(hdr[0] != 'F' || hdr[1] != 'L' || hdr[2] != 'V')
	{
		caoc_pf("not flv\n");
		return false;
	}
	m_io->seek(CONV_FLV_HEADER_SIZE );
    m_parse_header = true;
	return true;
}

conv_in_out_packe_t * c_flv_file::mux_header (const conv_codec_ctx_t & ctx,long stamp)
{
	conv_size_t len = ctx.audio_config.si + ctx.video_config.si + 3*(FLV_MAX_TAGSIZE + FLV_TAIL_SIZE) + 1024/*meta data*/;
	conv_in_out_packe_t * node = get_node(len);

	node->si = flv_build_header(node->p,node->si,&ctx,NULL);
    node->type = conv_packet_header;
	if(0 == node->si)
	{
		free_node(node);
		return NULL;
	}
	return node;
}

conv_in_out_packe_t * c_flv_file::mux(const conv_in_out_packe_t *in,const conv_codec_ctx_t & ctx,int & ret)
{
	conv_in_out_packe_t * node = NULL;
	switch (in->type)
	{
		case conv_packet_video:
			flv_build_video_frame(*in,&node);
			break;
		case conv_packet_audio:
			flv_build_audio_frame(*in,ctx,&node);
			break;
		default:
			cout << "unkonow type in flv" << endl;
			break;
	}
    ret = node == NULL ? 0 : 1;
	return node;
}

int   c_flv_file::flv_build_header( u_char *pdst, int ndstlen, const conv_codec_ctx_t * pData, OUT AMFHeaderOutPos * out)
{
	FlvNeedParam flv;
    flv.bHasAudio = pData->codec_audio > 0;
    flv.bHasVideo = pData->codec_video > 0;
	int nsize = write_flv_header_mem(pdst,ndstlen,flv.bHasAudio,flv.bHasVideo);
    int nlastsize = nsize;

    if(flv.bHasAudio)
    {
	    flv.audiosamplerate = pData->samplerate;
        flv.audio_data_rate = pData->audio_data_rate;
    }
    else
    {
        perror("flv: no audio\n");
    }
    if(flv.bHasVideo)
    {
        flv.n_fps = pData->fps;
        flv.n_width = pData->w;
        flv.n_height = pData->h;
        flv.video_data_rate = pData->video_data_rate;
        printf("flv: have video\n");
    }
    else
    {
        perror("flv:no video\n");
    }
	flv.bNeedDurationAndFileSize = out != NULL ? true : false;
    if(NULL == pData->meta.p)
	    nsize += write_flv_metadata_mem(pdst + nsize,ndstlen-nsize,&flv,out);
    else
    {
        if(ndstlen - nsize > 4)
        {
            pdst[nsize++] = 0;
            pdst[nsize++] = 0;
            pdst[nsize++] = 0;
            pdst[nsize++] = 0;
        }
        else
        {
		    perror("flv:buf size is small when set first tag pre size\n");
        }
        if(ndstlen - nsize > (int)pData->meta.si)
        {
            memcpy(pdst + nsize,pData->meta.p,pData->meta.si);
            nsize += pData->meta.si;
        }
        else
        {
		    perror("flv:buf size is small when copy meta data\n");
        }
    }
	if(out != NULL)
	{
		out->n_duration_pos += nlastsize;
		out->n_filesize_pos += nlastsize;
	}
	if(pData->video_config.p != NULL)
	{
		FlvTagHeadertParam param(true,0);
	    int n_last_size = nsize;	
		nsize += WriteFrameTagsHeader(pdst + nsize ,ndstlen-nsize,param);
		int nTagDataLenghth = 5;
		*(pdst+nsize) = 0x17;
		*(pdst+nsize+1) = 0;
		*(pdst+nsize+2) = 0;
		*(pdst+nsize+3) = 0;
		*(pdst+nsize+4) = 0;
		nsize += 5;
		nTagDataLenghth += pData->video_config.si;
		if(pData->video_config.si > (conv_size_t)(ndstlen - nsize))
		{
			perror("flv:mem flow\n");
			return 0;
		}
		memcpy(pdst+nsize,pData->video_config.p,pData->video_config.si);

		nsize += pData->video_config.si;
		nsize += WriteLastTagSize(pdst + nsize,ndstlen-nsize,sizeof(SFlvTagHeader) + nTagDataLenghth);
		putIntToThreeChar(pdst +n_last_size +  param.n_tag_size_pos,nTagDataLenghth);
	}
	if(pData->audio_config.p != NULL)
	{
		FlvTagHeadertParam out(false,0);
		int n_last_size = nsize;	
		nsize += WriteFrameTagsHeader(pdst+nsize,ndstlen-nsize,out);
		SAudioFrame pFrame;
		pFrame.samplerate = pData->samplerate;
		pFrame.audio_config = 0;
		
		int nTagLength = WriteAAChdr(&pFrame,pdst+nsize,true);
		nsize += nTagLength;
		//写tag数据
		if(pData->audio_config.si > (conv_size_t)(ndstlen - nsize))
		{
			perror("flv:copy aac header error\n");
			return 0;
		}

		memcpy(pdst+nsize,pData->audio_config.p,pData->audio_config.si);
		nsize += pData->audio_config.si;
		nTagLength += pData->audio_config.si;

		nsize += WriteLastTagSize(pdst+nsize,ndstlen-nsize,sizeof(SFlvTagHeader) + nTagLength);
		putIntToThreeChar(pdst+n_last_size+out.n_tag_size_pos,nTagLength);
	}
	return nsize;
}

int  c_flv_file::WriteFrameTagsHeader(u_char * buf,int nlen,FlvTagHeadertParam &out)
{
	if(flv_right_bigger(nlen,sizeof(SFlvTagHeader)))
		return 0;

    if(out.tag_type == -1)
        *buf = out.bVideo ? 0x09 : 0x08;
    else
        *buf = (u_char)out.tag_type;

	out.n_tag_size_pos = sizeof(char);
	buf += 4;
	FLVFILE_COPYSTAMP(out.stamp,buf)
	*(buf+4) = 0;
	*(buf+5) = 0;
	*(buf+6) = 0;
	return sizeof(SFlvTagHeader);
}

int c_flv_file::WriteLastTagSize(u_char * pbuf,int nlen,int_4 lastTagSize)
{
	int_4 nPreTagSize = lastTagSize;
	nPreTagSize = BigEndian_32(nPreTagSize);
	if(flv_right_bigger(nlen,sizeof(nPreTagSize)))
		return 0;
	return flv_mem_cp(pbuf,&nPreTagSize,sizeof(nPreTagSize));
}

int  c_flv_file::write_nalu_header(
        u_char * pDstDataBuf,
        int ndstlen,
        int b_is_key_frame,
        int frame_size,
        uint32_t cts
        )
{
	if(flv_right_bigger(ndstlen,sizeof(SFlvVideoTagHeader)+ sizeof(int_4)))
		return 0;

	if(b_is_key_frame)
		*pDstDataBuf = 0x17;
	else
		*pDstDataBuf = 0x27;
	
	*(pDstDataBuf+1) = 0x1;//nalu

	*(pDstDataBuf+2) = cts >> 16 ;
	*(pDstDataBuf+3) = (cts >> 8) & 0xFF;
	*(pDstDataBuf+4) = cts & 0xFF;

	int nWritenSize = 5;
	int_4 nNaluSize = BigEndian_32(frame_size);

	nWritenSize += flv_mem_cp(pDstDataBuf+nWritenSize,&nNaluSize,sizeof(nNaluSize));
	
	return nWritenSize;
}

int c_flv_file::flv_build_audio_frame(
		const conv_in_out_packe_t & in,
		const conv_codec_ctx_t & ctx,
		OUT conv_in_out_packe_t ** out)
{
	conv_in_out_packe_t * pout = get_node(FLV_MAX_TAGSIZE + in.si + FLV_TAIL_SIZE);
	int si = 0;
	SAudioFrame frame;
	frame.stamp = in.stamp;
	frame.samplerate = ctx.samplerate;
	frame.SoundSize = ctx.samplesize;
	frame.nChannels = ctx.nchannels;
	frame.nBufLen = in.si;
	frame.pDataBuf = in.p;
	frame.dataType = ctx.codec_audio;
	frame.audio_config = 0;

	si += flv_build_audio_frame(pout->p,pout->si,&frame);
	pout->si = si;
    pout->type = conv_packet_audio;
	*out = pout;

	return si;
}

int c_flv_file::flv_build_video_frame(
		const conv_in_out_packe_t & in,
		OUT conv_in_out_packe_t ** out)
{
    const conv_in_out_packe_t * next = &in;
    conv_in_out_packe_t ** last = out;
    for(;next != NULL;next=next->next)
    {
        int nalu_type = next->p[4] & 0x1f;
        /*
         * 多写进去 6 和 9 , ffplay会提示较多的错误,但是可以播放 
         * */
        if(7 == nalu_type || 8 == nalu_type || 9 == nalu_type || 6 == nalu_type)
            continue;

        int si = 0;
        conv_size_t dsi = next->si - 4;
        conv_in_out_packe_t * pout = get_node(FLV_MAX_TAGSIZE + dsi + FLV_TAIL_SIZE);
        si += flv_build_video_frame_header(pout->p,pout->si,next->key_frame,next->stamp,next->cts,dsi);
        if(si > FLV_MAX_TAGSIZE)
        {
            free_node(pout);
            return 0;
        }

        si += flv_mem_cp(pout->p + si, next->p+4,dsi);
        si += WriteLastTagSize(pout->p + si,pout->si - si,si);
        pout->type = conv_packet_video;
        pout->si = si;
        *last = pout;
        last = &(pout->next);
    }
	return 1;
}

//return tag size
//pre_size = tag_size + frame_size 
int c_flv_file::flv_build_video_frame_header(
        u_char * pdst,
        int ndstlen,
        int b_is_key_frame,
        int stamp,
        uint32_t cts,
        int frame_size)
{
	FlvTagHeadertParam out(true,stamp);
	//11 bytes
	int nSize = WriteFrameTagsHeader(pdst,ndstlen,out);

	//写tag数据
	//9 bytes
	int nTagDataLenghth = write_nalu_header(pdst+nSize,
			ndstlen-nSize,
			b_is_key_frame,
			frame_size,
            cts);
	nSize += nTagDataLenghth;
	nTagDataLenghth += frame_size;
	putIntToThreeChar(pdst+out.n_tag_size_pos,nTagDataLenghth);
	return nSize;
}

int c_flv_file::WriteAudioFrameTagHeader_NotAAC(u_char * pdst,int ndst,const SAudioFrame * pFrame)
{
	if(flv_right_bigger(ndst,1))
		return 0;

    u_char firstc = 0;

    firstc |= (pFrame->dataType << 4) & 0xF0;

    //{ 5512, 11025, 22050, 44100 };
    if(pFrame->samplerate <= 11025)
        firstc |= 0x04;
    else if(pFrame->samplerate <= 22050)
        firstc |= 0x08;
    else if(pFrame->samplerate >= 44100)
        firstc |= 0x0c;

    if(pFrame->SoundSize == 2)
    {
        firstc |= 0x02;
    }

    if(pFrame->nChannels == 2)
    {
        firstc |= 0x01;
    }

    pdst[0]  = firstc; 
    return 1;
}

int c_flv_file::WriteAudioFrameTagData_NotAAC(u_char * pdst,int ndst,const SAudioFrame * pFrame)
{
	if(flv_right_bigger(ndst,1+pFrame->nBufLen))
		return 0;

	int nTagDataSize = WriteAudioFrameTagHeader_NotAAC(pdst,ndst,pFrame);

	//write data
    if(pFrame->pDataBuf != NULL)
	    nTagDataSize += flv_mem_cp(pdst + nTagDataSize,pFrame->pDataBuf,pFrame->nBufLen);	

	return nTagDataSize;
}

int c_flv_file::WriteAudioFrameTagData(u_char * pdst,int ndst,const SAudioFrame * pFrame)
{
	if(flv_right_bigger(ndst,4+pFrame->nBufLen))
		return 0;
	int nTagDataSize = WriteAAChdr(pFrame,pdst);
	//write data
	if(0 == pFrame->audio_config)
		nTagDataSize += flv_mem_cp(pdst + nTagDataSize,pFrame->pDataBuf,pFrame->nBufLen);	
	return nTagDataSize;
}

int c_flv_file::write_flv_header_mem(u_char * szHeader,int nLength,bool bHasAudio,bool bHasVideo)
{
	if(flv_right_bigger(nLength, sizeof(SFlvHeader)))
		return 0;

	SFlvHeader *header = (SFlvHeader*)szHeader;
	memcpy(header->szFLV,"FLV",3);
	header->szVersion = 0x01;
	//写流信息
    header->streamInfo = 0x0;
	if(bHasVideo)
		header->streamInfo = 0x01;
    if(bHasAudio)	
		header->streamInfo |= 0x04;
	//Header长度
	header->nHeaderSize = sizeof(SFlvHeader);
	header->nHeaderSize = BigEndian_32(header->nHeaderSize);
	return sizeof (SFlvHeader);
}

int c_flv_file::WrtiteMetaDataNode(u_char * buf,int nLength,const SFlvAMFArrayNode &node)
{
	if(flv_right_bigger(nLength,sizeof(node.nameLength)))
		return 0;
	int n_ret_sie = 0;
	n_ret_sie = flv_mem_cp(buf,node.nameLength,sizeof(node.nameLength));
		
	if(flv_right_bigger(nLength,n_ret_sie + strlen(node.Name.c_str())))
		return 0;
	n_ret_sie += flv_mem_cp(buf+n_ret_sie,node.Name.c_str(),strlen(node.Name.c_str()));

	if(flv_right_bigger(nLength,n_ret_sie + sizeof(node.type)))
		return 0;
	n_ret_sie += flv_mem_cp(buf+n_ret_sie,&node.type,sizeof(node.type));

	if(flv_right_bigger(nLength,n_ret_sie + sizeof(double)))
		return 0;
	putDoubleToEightChar(buf+n_ret_sie,node.data);

	return n_ret_sie + sizeof(double);
}

int c_flv_file::WrtiteMetaDataNode(u_char * buf,int nLength,const SFlvAMFBOOLArraryNode &node)
{
	if(flv_right_bigger(nLength,sizeof(node.nameLength)))
		return 0;
	int n_ret_sie = 0;
	n_ret_sie = flv_mem_cp(buf,node.nameLength,sizeof(node.nameLength));

	if(flv_right_bigger(nLength,n_ret_sie + strlen(node.Name.c_str())))
		return 0;
	n_ret_sie += flv_mem_cp(buf+n_ret_sie,node.Name.c_str(),strlen(node.Name.c_str()));

	if(flv_right_bigger(nLength,n_ret_sie + sizeof(node.type)))
		return 0;
	n_ret_sie += flv_mem_cp(buf+n_ret_sie,&node.type,sizeof(node.type));

	if(flv_right_bigger(nLength,n_ret_sie + sizeof(node.data)))
		return 0;
    n_ret_sie += flv_mem_cp(buf+n_ret_sie,&node.data,sizeof(node.data));
	return n_ret_sie;
}

int c_flv_file::CreatMetaDataNodeCommon(const char * szName,char nameLength[2],string & name )
{
	int nSize = 0;
	short_2 nNameLenght = strlen(szName);
	nSize += nNameLenght;
	name = szName;

	nNameLenght = BigEndian_16(nNameLenght);
	memcpy(nameLength,&nNameLenght,sizeof(short_2));
	nSize += sizeof(short_2);
	return nSize;
}

int c_flv_file::CreateMetaDataNode(const char * szName,double data,SFlvAMFArrayNode &node)
{
	int nSize = CreatMetaDataNodeCommon(szName,node.nameLength,node.Name);

	node.type = 0x0;//double类型
	nSize += sizeof(node.type);

	node.data = data;
	nSize += sizeof(node.data);
	return nSize;
}

int c_flv_file::CreateMetaDataNode(const char * szName,bool data,SFlvAMFBOOLArraryNode &node)
{
	int nSize = CreatMetaDataNodeCommon(szName,node.nameLength,node.Name);

	node.type = 0x1;//bool 类型
	nSize += sizeof(node.type);

	node.data = data ? 1 : 0;
	nSize += sizeof(node.data);
	return nSize;
}

int  c_flv_file::write_flv_metadata_mem(u_char * szMetadata,int nLength,const FlvNeedParam * pflv,AMFHeaderOutPos * pOut)
{
	SFlvTagWithPreSize tagWithHeager;
	int mem_flag = 0;
	int nDataLenghtPos = sizeof(tagWithHeager.nPreTagSize)+ sizeof(tagWithHeager.tagHeader.tagHeaderType);

	tagWithHeager.nPreTagSize = 0x0;
	tagWithHeager.tagHeader.tagHeaderType = 0x12;//脚本 记录视频信息

	memset(tagWithHeager.tagHeader.tagDataLength,0,sizeof(tagWithHeager.tagHeader.tagDataLength));
	memset(tagWithHeager.tagHeader.Timestamp,0,sizeof(tagWithHeager.tagHeader.Timestamp));
	memset(&tagWithHeager.tagHeader.StreamID,0,sizeof(tagWithHeager.tagHeader.StreamID));
	
	if(flv_right_bigger(nLength,sizeof(tagWithHeager)))
		return 0;
	mem_flag += flv_mem_cp(szMetadata,&tagWithHeager,sizeof(tagWithHeager));

	//tag data
	int last_size = mem_flag;
	int nMetaDataSize = 0;
	SFlvAMFHeader amfHeader;
	amfHeader.amf1type = 0x02;
	amfHeader.stringLength = 0x0a;
	amfHeader.pData = (char*)"onMetaData";
	amfHeader.amf2type = 0x08;	
	if(pflv->bNeedDurationAndFileSize)
		amfHeader.arraySize = 0xd;//这个根据下面几个SFlvAMFArrayNode决定
	else
		amfHeader.arraySize = 0xb;//这个根据下面几个SFlvAMFArrayNode决定

    if(!pflv->bHasAudio)
        amfHeader.arraySize -= 2;//audiocodecid, sampleate , audiodatarate
    
    if(!pflv->bHasVideo)
        amfHeader.arraySize -= 5;//width,height,videocodecid,videorate,framerate

	mem_flag += write_flv_amf_header(szMetadata+mem_flag,nLength-mem_flag,amfHeader);
	
	SFlvAMFArrayNode node;

	if(pflv->bNeedDurationAndFileSize)
	{
		CreateMetaDataNode("duration",0.0,node);
		mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);
		if(pOut)	
		{
			pOut->n_duration_pos = mem_flag - sizeof(double);
		}
	}
	SFlvAMFBOOLArraryNode nodeBool;
	CreateMetaDataNode("hasVideo",pflv->bHasVideo,nodeBool);
	mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,nodeBool);

	CreateMetaDataNode("hasAudio",pflv->bHasAudio,nodeBool);
	mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,nodeBool);

	CreateMetaDataNode("hasMetadata",1,nodeBool);
	mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,nodeBool);
    
    if(pflv->bHasVideo)
    {
        CreateMetaDataNode("width",pflv->n_width,node);
        mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);

        CreateMetaDataNode("height",pflv->n_height,node);
        mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);

        CreateMetaDataNode("videodatarate",pflv->video_data_rate,node);
        mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);

        CreateMetaDataNode("framerate",pflv->n_fps,node);
        mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);
        
        //7是h264编码 现在只支持h264的封装
        CreateMetaDataNode("videocodecid",0x7,node);
        mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);
    }
	
	if(pflv->bNeedDurationAndFileSize)
	{
		CreateMetaDataNode("filesize",0,node);
		mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);
		if(pOut)	
		{
			pOut->n_filesize_pos = mem_flag - sizeof(double);
		}
	}

    if(pflv->bHasAudio)
    {
        CreateMetaDataNode("audiocodecid",0xA,node);
        mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);

        CreateMetaDataNode("audiosamplerate ",pflv->audiosamplerate,node);
        mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);

        CreateMetaDataNode("audiosamplesize ",16,node);
        mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);

        //CreateMetaDataNode("audiodatarate",pflv->audio_data_rate,node);
        //mem_flag += WrtiteMetaDataNode(szMetadata+mem_flag,nLength-mem_flag,node);
    }
	szMetadata[mem_flag] = 0x09;//end
	++mem_flag;

	nMetaDataSize = mem_flag - last_size;
	putIntToThreeChar(szMetadata+nDataLenghtPos,nMetaDataSize);

	tagWithHeager.nPreTagSize = nMetaDataSize + sizeof(SFlvTagHeader);
	tagWithHeager.nPreTagSize =BigEndian_32(tagWithHeager.nPreTagSize);
	if(flv_right_bigger(nLength-mem_flag,sizeof(tagWithHeager.nPreTagSize)))
		return 0;
	mem_flag += flv_mem_cp(szMetadata+mem_flag,&tagWithHeager.nPreTagSize,sizeof(tagWithHeager.nPreTagSize));
	return mem_flag;
}

int c_flv_file::write_flv_amf_header(u_char * dst,int ndstlen,const SFlvAMFHeader & amfHeader)
{
	int nMetaDataSize = 0;
	if(flv_right_bigger(ndstlen,sizeof(amfHeader.amf1type)))
		return 0;

	nMetaDataSize += flv_mem_cp(dst,&amfHeader.amf1type,sizeof(amfHeader.amf1type));
	
	if(flv_right_bigger(ndstlen,sizeof(amfHeader.stringLength)+nMetaDataSize))
		return 0;
	short_2 stringLength = BigEndian_16(amfHeader.stringLength);
	nMetaDataSize += flv_mem_cp(dst+nMetaDataSize,&stringLength,sizeof(amfHeader.stringLength));

	if(flv_right_bigger(ndstlen,amfHeader.stringLength+nMetaDataSize))
		return 0;
	nMetaDataSize += flv_mem_cp(dst+nMetaDataSize,amfHeader.pData,amfHeader.stringLength);

	if(flv_right_bigger(ndstlen,sizeof(amfHeader.amf2type)+nMetaDataSize))
		return 0;
	nMetaDataSize += flv_mem_cp(dst+nMetaDataSize,&amfHeader.amf2type,sizeof(amfHeader.amf2type));

	if(flv_right_bigger(ndstlen,sizeof(amfHeader.arraySize)+nMetaDataSize))
		return 0;
	int_4 arraySize = BigEndian_32(amfHeader.arraySize);
	nMetaDataSize += flv_mem_cp(dst+nMetaDataSize,&arraySize,sizeof(amfHeader.arraySize));

	return nMetaDataSize;
}

int c_flv_file::flv_build_audio_frame(u_char *pdst,int ndstlen,const SAudioFrame * pFrame)
{
    if(pFrame->dataType != CONVERT_AUDIO_AAC && pFrame->pDataBuf == NULL)
    {
        return 0;
    }

	FlvTagHeadertParam out(false,pFrame->stamp);
	int nSize = WriteFrameTagsHeader(pdst,ndstlen,out);

	//写tag数据
	int nTagDataLenghth = 0;
    if(CONVERT_AUDIO_AAC == pFrame->dataType)
    {
        nTagDataLenghth = WriteAudioFrameTagData(pdst+nSize,ndstlen-nSize,pFrame);
    }
    else
    {
        nTagDataLenghth = WriteAudioFrameTagData_NotAAC(pdst+nSize,ndstlen-nSize,pFrame);
    }

	nSize += nTagDataLenghth;	
	nSize += WriteLastTagSize(pdst+nSize,ndstlen-nSize,sizeof(SFlvTagHeader) + nTagDataLenghth);
	putIntToThreeChar(pdst+out.n_tag_size_pos,nTagDataLenghth);
	return nSize;
}

int c_flv_file::WriteAAChdr(const SAudioFrame *frame,u_char *p,bool force_config)
{
    if(frame->samplerate == 5500)
    {
        p[0] = 0x00;
    }
    if(frame->samplerate <= 11025)
    {
        p[0] = 0x04;
    }
    else if(frame->samplerate <= 22050)
    {
        p[0] = 0x08;
    }
    else if(frame->samplerate >= 44100)
    {
        p[0] = 0x0c;
    }

	if(frame->audio_config == 0)
	{
		p[0] |= 0xA3; // AAC audio, need these codes first
		force_config ? p[1] = 0x0 : p[1] = 0x01;
		return  2;
	}
	else
	{
		int c = audio_specific_config(frame->objectType,frame->samplerate,frame->nChannels,p+2);

		p[0] |= 0xA3; // AAC audio, need these codes first
		p[1] = 0x0;
		return  2+c;
	}
}

int  c_flv_file::demux_keyframes()
{
	if(!parse_header())
		return 0;
	parse_frame(true);
    return m_keyframes.size();
}

void c_flv_file::parse_flv_script_tag(u_char * p,u_char * pend)
{
    if(m_parse_metadata)
        return;

    if(conv_read_8(&p,pend) != 0x2)
        return;

    int                      amf_string_size;
    conv_swicth_int(p,2,&amf_string_size);
    p += 2;

    if(amf_string_size == 10 && strncasecmp((const char *)p,"onMetaData",amf_string_size) == 0)
    {
        printf("array onMetaData\n");
    }
    else
        return;
    p += amf_string_size;
    amf_parse_object(&p,pend,"onMetaData",0);
    m_parse_metadata = true;

    if(m_keyframes.size() == 0)
    {
        advance_read_frames(true);
    }
    else
    {
        m_meta_has_keyframes = true;
    }
}

#define AMF_END_OF_OBJECT         0x09
typedef enum {
    AMF_DATA_TYPE_NUMBER      = 0x00,
    AMF_DATA_TYPE_BOOL        = 0x01,
    AMF_DATA_TYPE_STRING      = 0x02,
    AMF_DATA_TYPE_OBJECT      = 0x03,
    AMF_DATA_TYPE_NULL        = 0x05,
    AMF_DATA_TYPE_UNDEFINED   = 0x06,
    AMF_DATA_TYPE_REFERENCE   = 0x07,
    AMF_DATA_TYPE_MIXEDARRAY  = 0x08,
    AMF_DATA_TYPE_OBJECT_END  = 0x09,
    AMF_DATA_TYPE_ARRAY       = 0x0a,
    AMF_DATA_TYPE_DATE        = 0x0b,
    AMF_DATA_TYPE_LONG_STRING = 0x0c,
    AMF_DATA_TYPE_UNSUPPORTED = 0x0d,
} AMFDataType;

int c_flv_file::amf_get_string(u_char **p, char *buffer, int buffsize)
{
    int length ;
    conv_swicth_int((*p),2,&length);
    (*p) += 2;
    if (length >= buffsize) 
    {
        (*p) += length;
        return -1;
    }

    memcpy(buffer, *p,length);

    buffer[length] = '\0';
    (*p) += length;

    return length;
}

#define KEYFRAMES_TAG            "keyframes"
#define KEYFRAMES_TIMESTAMP_TAG  "times"
#define KEYFRAMES_BYTEOFFSET_TAG "filepositions"

int c_flv_file::parse_keyframes_index(u_char ** p,u_char * pend)
{
    unsigned int timeslen = 0, fileposlen = 0, i;
    char str_val[256];
    int64_t *times         = NULL;
    int64_t *filepositions = NULL;
    int ret                = 0;
    u_char * initial_pos    = *p;

    while ((*p) < pend - 2 && amf_get_string(p, str_val, sizeof(str_val)) > 0) 
    {
        int64_t **current_array;
        unsigned int arraylen;

        // Expect array object in context
        if (conv_read_8(p,pend) != AMF_DATA_TYPE_ARRAY)
            break;

        arraylen = conv_read_32(p,pend);
        if (arraylen>>28)
            break;

        if (!strcmp(KEYFRAMES_TIMESTAMP_TAG , str_val) && !times) 
        {
            current_array = &times;
            timeslen      = arraylen;
        } 
        else if (!strcmp(KEYFRAMES_BYTEOFFSET_TAG, str_val) && !filepositions) 
        {
            current_array = &filepositions;
            fileposlen    = arraylen;
        } 
        else
            // unexpected metatag inside keyframes, will not use such
            // metadata for indexing
            break;

        if (!(*current_array = new int64_t[arraylen])) 
        {
            ret = 0;
            goto finish;
        }

        for (i = 0; i < arraylen && *p < pend - 1; i++) 
        {
            if (conv_read_8(p,pend) != AMF_DATA_TYPE_NUMBER)
                goto invalid;
            current_array[0][i] = conv_char2double(p,pend);
        }
        if (times && filepositions) 
        {
            // All done, exiting at a position allowing amf_parse_object
            // to finish parsing the object
            ret = 0;
            break;
        }
    }

    if (timeslen == fileposlen && fileposlen>1) 
    {
        /*丢弃视频头*/
        for (i = 1; i < fileposlen; i++) 
        {
            printf("key frame pos = %p,time = %ld\n",(void*)filepositions[i], (long)times[i] * 1000);
            conv_frame_info info;
            info.pos = filepositions[i];
            info.stamp = times[i] * 1000;
            m_keyframes.push_back(info);
        }
    } 
    else 
    {
invalid:
        printf("Invalid keyframes object, skipping.\n");
    }

finish:
    if(times) delete []times; 
    if(filepositions) delete []filepositions;
    *p = initial_pos;
    return ret;
}

int c_flv_file::amf_parse_object(u_char ** p,u_char * pend,const char * key,int depth)
{
    char str_val[1024];
    int amf_type = conv_read_8(p,pend);
    double num_val = 0;

    switch (amf_type) 
    {
    case AMF_DATA_TYPE_NUMBER:
        num_val = conv_char2double(p,pend);
        break;
    case AMF_DATA_TYPE_BOOL:
        num_val = conv_read_8(p,pend);
        break;
    case AMF_DATA_TYPE_STRING:
        if (amf_get_string(p, str_val, sizeof(str_val)) < 0)
            return -1;
        break;
    case AMF_DATA_TYPE_OBJECT:
        if (key && !strcmp(KEYFRAMES_TAG, key) && depth == 1)
        {
            if (parse_keyframes_index(p,pend) < 0)
                printf("Keyframe index parsing failed\n");
        }

        while ((*p) < pend- 2 && amf_get_string(p, str_val, sizeof(str_val)) > 0)
            if (amf_parse_object(p,pend, str_val, depth + 1) < 0)
                return -1;     // if we couldn't skip, bomb out.
        if (conv_read_8(p,pend) != AMF_END_OF_OBJECT)
            return -1;
        break;
    case AMF_DATA_TYPE_NULL:
    case AMF_DATA_TYPE_UNDEFINED:
    case AMF_DATA_TYPE_UNSUPPORTED:
        break;     // these take up no additional space
    case AMF_DATA_TYPE_MIXEDARRAY:
        *p += 4;     // skip 32-bit max array index
        while (*p < pend - 2 && amf_get_string(p, str_val, sizeof(str_val)) > 0)
            // this is the only case in which we would want a nested
            // parse to not skip over the object
            if (amf_parse_object(p, pend, str_val, depth + 1) < 0)
                return -1;
        if (conv_read_8(p,pend) != AMF_END_OF_OBJECT)
            return -1;
        break;
    case AMF_DATA_TYPE_ARRAY:
    {
        unsigned int arraylen, i;
        arraylen = conv_read_32(p,pend);

        for (i = 0; i < arraylen && *p < pend - 1; i++)
            if (amf_parse_object(p, pend, NULL, depth + 1) < 0)
                return -1;      // if we couldn't skip, bomb out.
    }
    break;
    case AMF_DATA_TYPE_DATE:
        *p += (8 + 2);  // timestamp (double) and UTC offset (int16)
        break;
    default:                    // unsupported type, we couldn't skip
        return -1;
    }

    if (key) 
    {
        // stream info doesn't live any deeper than the first object
        if (depth == 1) 
        {
            /*
             * hasVideo-type:1-value:1
             * hasAudio-type:1-value:1
             * */
            cout << key << "-" << "type:" << amf_type << "-value:" << num_val << endl;
            if(!strcasecmp("duration",key))
            {
                m_duration = num_val;
            }
            else if((!strcasecmp("HasVideo",key)) || (!strcasecmp("videocodecid",key)))
            {
                m_has_video = (int)num_val;
            }
            else if((!strcasecmp("HasAudio",key)) || (!strcasecmp("audiocodecid",key)))
            {
                m_has_audio = (int)num_val;
            }
            else if(!strcasecmp("framerate",key))
            {
                m_codec_ctx->fps = num_val;
            }
            else if(!strcasecmp("width",key))
            {
                m_codec_ctx->w = num_val;
            }
            else if(!strcasecmp("height",key))
            {
                m_codec_ctx->h = num_val;
            }
        }
    }

    return 0;
}
