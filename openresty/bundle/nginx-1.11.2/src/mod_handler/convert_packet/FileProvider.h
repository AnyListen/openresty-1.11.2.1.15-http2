#ifndef __C_FILE_PROVIDER
#define __C_FILE_PROVIDER
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mem_reader.h"

//! file operation mode flags
enum Mode {
	MODE_UNDEFINED, //!< undefined
	MODE_READ,      //!< file may be read
	MODE_MODIFY,    //!< file may be read/written
	MODE_CREATE,    //!< file will be created/truncated for read/write
	MODE_READ_MEM,  //READ MEM
	MODE_WRITE_MEM
};

//! type used to represent all file sizes and offsets
typedef int64_t Size;

class FileProvider
{

public:
    virtual ~FileProvider() { }

    virtual bool open( const char * name, Size t ,Mode mode  ) = 0;
    virtual bool seek( Size pos ) = 0;
	virtual bool seek_poisx(Size pos,int whence) = 0;
    virtual bool read( void* buffer, Size size, Size& nin) = 0;
	virtual Size read_poisx(void * buffer,Size size,Size oft) = 0;
	virtual Size readex(void * buffer,Size si) = 0;
	virtual char read8() = 0;
	virtual bool feof() = 0;
    virtual bool write( const void* buffer, Size size, Size& nout, Size maxChunkSize ) = 0;
    virtual bool close() = 0;
	virtual Size tell() = 0;
    virtual Size get_size() = 0;
public:
    unsigned int rb16()
    {
        unsigned int val;
        val = read8() << 8;
        val |= read8();
        return val;
    }

    unsigned int rb24()
    {
        unsigned int val;
        val = rb16() << 8;
        val |= read8();
        return val;
    }
    unsigned int rb32()
    {
        unsigned int val;
        val = rb16() << 16;
        val |= rb16();
        return val;
    }
protected:
    FileProvider() { }
};

class DiskFileProvider : public FileProvider
{
public:
    DiskFileProvider()
    {
        m_fp = NULL;
    }
    virtual ~DiskFileProvider()
    {
        close();
    }

	bool open( const char * name, Size t ,Mode mode )
	{
		if (mode != MODE_READ)
		{
			return false;
		}
        m_fp = fopen(name,"rb");
        if(m_fp)
        {
            fseek(m_fp,0,SEEK_END);
            m_size = ftell(m_fp);
            fseek(m_fp,0,SEEK_SET);
        }
		return m_fp != NULL;
	}

	bool seek( Size pos )
	{
        return seek_poisx(pos,SEEK_SET);
	}

	bool seek_poisx(Size pos,int whence)
	{
        return fseek(m_fp,pos,whence) >= 0;
	}

	Size read_poisx(void *buffer,Size size,Size oft)
	{
		if(!seek(oft))
			return 0;
		Size ret;
		if(!read(buffer,size,ret))
			return 0;

		return ret;
	}

	bool read( void* buffer, Size size, Size& nin)
	{
        nin = fread(buffer,1,size,m_fp);
		return nin > 0;
	}

	Size readex(void * buffer,Size si)
	{
		Size re = 0;
		if(!read(buffer,si,re))
			return 0;
		return re;
	}

	char read8()
	{
		if(feof())
			return -1;

        char c;
        Size nin = 0;
	    read( &c, 1, nin);
        return c;
	}

	bool feof()
	{
        return ::feof(m_fp) > 0;
	}

	Size tell()
	{
		return ftell(m_fp);
	}

	bool write( const void* buffer, Size size, Size& nout, Size maxChunkSize )
	{
		return false;
	}

	bool close()
	{
        if(m_fp)
            fclose(m_fp);
        m_fp = NULL;
		return true;
	}

    Size get_size()
    {
        return m_size;
    }
private:
    FILE * m_fp;
    Size m_size;
};

class MemFileProvider : public FileProvider
{
public:
	MemFileProvider()
	{
		init();
	}

	bool open( const char * name, Size t ,Mode mode )
	{
		if (mode != MODE_READ_MEM && mode != MODE_WRITE_MEM)
		{
			return false;
		}
		m_size = t;
		m_data = name;
		return true;
	}

	bool seek( Size pos )
	{
		if(pos > m_size)
			return false;

		m_pos = pos;
		return true;
	}

	bool seek_poisx(Size pos,int whence)
	{
		switch(whence)
		{
			case SEEK_SET:
				return seek(pos);
			case SEEK_CUR:
				return seek(m_pos + pos);
			case SEEK_END:
				return seek(m_size + pos);
			default:
				return false;
		}
		return false;
	}

	Size read_poisx(void *buffer,Size size,Size oft)
	{
		if(!seek(oft))
			return 0;
		Size ret;
		if(!read(buffer,size,ret))
			return 0;

		return ret;
	}

	bool read( void* buffer, Size size, Size& nin)
	{
		nin = size > (m_size - m_pos) ? m_size - m_pos : size;
		if (nin < 0)
		{
			return false;
		}
		
		memcpy(buffer,m_data+m_pos,nin);
		m_pos += nin;
		return true;
	}

	Size readex(void * buffer,Size si)
	{
		Size re = 0;
		if(!read(buffer,si,re))
			return 0;
		return re;
	}

	char read8()
	{
		if(feof())
			return -1;

		return m_data[m_pos++];
	}

	bool feof()
	{
		if(m_pos >= m_size)
			return true;
		return false;
	}

	Size tell()
	{
		return m_pos;
	}

	bool write( const void* buffer, Size size, Size& nout, Size maxChunkSize )
	{
		return false;
	}

	bool close()
	{
		init();
		return true;
	}
    Size get_size()
    {
        return m_size;
    }
private:
	void init()
	{
		m_pos = m_size = 0;
		m_data = NULL;
	}
private:
	const char*    m_data;//when read ,this data is out data,must't free caoc
	Size           m_size;
	Size		   m_pos;
	Mode           m_mode;
};

#endif
