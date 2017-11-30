/*
 * =====================================================================================
 *
 *       Filename:  test.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月04日 11时55分25秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  caochao (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include "convert_packet.h"
#include <stdio.h>

static int s_ts = false;

static conv_char_t * fread_file(const char * file,off_t  & si)
{
	FILE  * fp  = fopen(file,"rb");
	if(NULL == fp)
	{
		printf("oepn file:%s failed\n",file);
		return NULL;
	}
	fseek(fp,0,SEEK_END);
	si = ftell(fp);
	fseek(fp,0,SEEK_SET);
	conv_char_t * p = new conv_char_t[si];
	fread(p,si,1,fp);
	fclose(fp);
	return p;
}

struct packet_param_s
{
	const char * filename;
	const char * h264filename;
};

static void write_packets(const conv_in_out_packe_t * packet,FILE * fp)
{
	const conv_in_out_packe_t * next = packet;
	for(;next != NULL;next = next->next)
	{
		fwrite(next->p,next->si,1,fp);
	}
}

/*
 * #EXTM3U
 * #EXT-X-VERSION:3
 * #EXT-X-MEDIA-SEQUENCE:0
 * #EXT-X-TARGETDURATION:3
 * #EXTINF:3,
 * zuqiu.flv.ts
 *
 * */
static void write_m3u8_tail(long max_duration,string & str,FILE * fp)
{
    const char * format = "#EXT-X-TARGETDURATION:%ld\n";
    char text[4096];
    int si = snprintf(text,sizeof(text),format,max_duration/1000+1);
    fwrite(text,si,1,fp);
    str += "#EXT-X-ENDLIST\n";
    fwrite(str.c_str(),str.length(),1,fp);
}

static void write_m3u8(int duration,const char * filename,string & str)
{
    const char * format =         
        "#EXTINF:%d,\n"
        "%s\n";

    char text[4096];
    snprintf(text,sizeof(text),format,duration / 1000+1,filename);
    str += text;
}

static void write_m3u8_header(FILE * fp)
{
    const char * m3u8_header = "#EXTM3U\n"
        "#EXT-X-VERSION:3\n"
        "#EXT-X-MEDIA-SEQUENCE:0\n";
    fwrite(m3u8_header,strlen(m3u8_header),1,fp);
}

static conv_size_t get_conv_packet(void * user,const conv_in_out_packe_t * packet,int demux)
{
	packet_param_s * p = (packet_param_s*)user;
	if(packet && packet->type == conv_packet_unuse)
		return 1;

    static FILE * m3u8 = NULL;
    static long start_stamp = 0;
    static long max_stamp = 0;
    static string m3u8str;

    if(s_ts && NULL == m3u8)
    {
        char name[1024];
        snprintf(name,sizeof(name),"%s.m3u8",p->filename);
        m3u8 = fopen(name,"wb");
        write_m3u8_header(m3u8);
    }
	if(demux)
	{
		static FILE  * h264 = NULL;

		if(packet == NULL)
		{
			if(h264 != NULL)
			{
				fclose(h264);
				h264 = NULL;
			}
			return 1;
		}

		if(packet->type == conv_packet_video && p->h264filename != NULL)
		{
			if(NULL == h264)
			{
				h264 = fopen(p->h264filename,"wb");
			}
            if(h264 != NULL)
			write_packets(packet,h264);
		}
		return 1;
	}

	static FILE * flv = NULL;
	if(packet == NULL)
	{
        if(flv) fclose(flv);
        if(m3u8)
        {
            write_m3u8_tail(max_stamp,m3u8str,m3u8);
            fclose(m3u8);
        }
		flv = NULL;
        m3u8 = NULL;
		return 1;
	}

    if(start_stamp == 0)
        start_stamp = packet->stamp;

    if(flv == NULL || packet->frag != 0)
    {
        char name[1024];
        static int index = 0;
        if(flv != NULL)
        {
            fclose(flv);
            const char * pf = strrchr(p->filename,'/');
            if(pf != NULL)
                ++pf;
            else
                pf = p->filename;

            snprintf(name,sizeof(name),"%s-%d.ts",pf,index-1);
            long dif = packet->stamp - start_stamp;
            printf("packet stamp = %ld\n",packet->stamp);
            if(dif > max_stamp)
                max_stamp = dif;
            write_m3u8(dif,name,m3u8str);
            start_stamp = 0;
        }

        if(s_ts)
        {
            snprintf(name,sizeof(name),"%s-%d.ts",p->filename,index++);
        }
        else
        {
            snprintf(name,sizeof(name),"%s",p->filename);
        }
        flv = fopen(name,"wb");
    }
	write_packets(packet,flv);
	return 1;
}

static conv_packet_type get_pakcet_type(const char * filename)
{
    if(strstr(filename,".ts") != NULL)
    {
        return conv_ts;
    }
    else if(strstr(filename,".flv") != NULL)
    {
        return conv_flv;
    }
    else if(strstr(filename,".fhv") != NULL)
    {
        return conv_flv;
    }
    else if(strstr(filename,".mp4") != NULL)
    {
        return conv_mp4;
    }
    else if(strstr(filename,".mp3") != NULL)
    {
        return conv_mp3;
    }
    return conv_unknow;
}
int main(int argc,char *argv[])
{
    if(argc < 3)
    {
        printf("./convert_packet in.file out.file\n");
        return 0;
    }
	off_t size = 0;
	//conv_char_t * p = fread_file(argv[1],size);
	//if(NULL == p)
	//	return 0;
	
	packet_param_s param;
	conv_handler_t h;
#if 0
	param.filename = "test.flv"	;
	param.h264filename = "test.264";
	h  = conv_create_convert( conv_mp4, conv_flv, p, size,get_conv_packet,(void*)&param);
	conv_destory_convert(h);
#endif
    conv_packet_type src = get_pakcet_type(argv[1]);
    if(src == conv_unknow)
    {
        printf("argv[1] : %s is error\n",argv[1]);
        return 0;
    }
	param.filename = argv[2];
    conv_packet_type dst = get_pakcet_type(argv[2]);
    if(dst == conv_unknow)
    {
        dst = conv_ts;
        s_ts = true;
    }
	param.h264filename = NULL;
	h = conv_create_convert( src, dst, (u_char*)argv[1], 0,get_conv_packet,(void*)&param,1,NULL);
	conv_destory_convert(h);

	//delete []p;
	return 0;
}
