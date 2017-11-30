#ifndef __CODEC__ID
#define __CODEC__ID

/* Audio codecs */
enum {
    /* Uncompressed codec id is actually 0,
     * but we use another value for consistency */
    CONVERT_AUDIO_UNCOMPRESSED     = 16,
    CONVERT_AUDIO_ADPCM            = 1,
    CONVERT_AUDIO_MP3              = 2,
    CONVERT_AUDIO_LINEAR_LE        = 3,
    CONVERT_AUDIO_NELLY16          = 4,
    CONVERT_AUDIO_NELLY8           = 5,
    CONVERT_AUDIO_NELLY            = 6,
    CONVERT_AUDIO_G711A            = 7,
    CONVERT_AUDIO_G711U            = 8,
    CONVERT_AUDIO_AAC              = 10,
    CONVERT_AUDIO_SPEEX            = 11,
    CONVERT_AUDIO_MP3_8            = 14,
    CONVERT_AUDIO_DEVSPEC          = 15,

    CONVERT_AUDIO_MP1              = 17,           
    CONVERT_AUDIO_MP2              = 18          
};


/* Video codecs */
enum {
    CONVERT_VIDEO_JPEG             = 1,
    CONVERT_VIDEO_SORENSON_H263    = 2,
    CONVERT_VIDEO_SCREEN           = 3,
    CONVERT_VIDEO_ON2_VP6          = 4,
    CONVERT_VIDEO_ON2_VP6_ALPHA    = 5,
    CONVERT_VIDEO_SCREEN2          = 6,
    CONVERT_VIDEO_H264             = 7,
    CONVERT_VIDEO_H265             = 8
};


#endif
