#ifndef _NGX_SHA512_H_INCLUDED_
#define _NGX_SHA512_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
/**
 * \brief          SHA-512 context structure
 */
typedef struct
{
    uint64_t total[2];          /*!< number of bytes processed  */
    uint64_t state[8];          /*!< intermediate digest state  */
    u_char buffer[128];  /*!< data block being processed */
    int is384;                  /*!< 0 => SHA-512, else SHA-384 */
}ngx_sha512_context;

/**
 * \brief          Initialize SHA-512 context
 *
 * \param ctx      SHA-512 context to be initialized
 */
void ngx_sha512_init( ngx_sha512_context *ctx );

/**
 * \brief          Clear SHA-512 context
 *
 * \param ctx      SHA-512 context to be cleared
 */
void ngx_sha512_free( ngx_sha512_context *ctx );

/**
 * \brief          Clone (the state of) a SHA-512 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void ngx_sha512_clone( ngx_sha512_context *dst,
                           const ngx_sha512_context *src );

/**
 * \brief          SHA-512 context setup
 *
 * \param ctx      context to be initialized
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void ngx_sha512_starts( ngx_sha512_context *ctx, int is384 );

/**
 * \brief          SHA-512 process buffer
 *
 * \param ctx      SHA-512 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void ngx_sha512_update( ngx_sha512_context *ctx, const u_char *input,
                    size_t ilen );

/**
 * \brief          SHA-512 final digest
 *
 * \param ctx      SHA-512 context
 * \param output   SHA-384/512 checksum result
 */
void ngx_sha512_finish( ngx_sha512_context *ctx, u_char output[64] );


/**
 * \brief          Output = SHA-512( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SHA-384/512 checksum result
 * \param is384    0 = use SHA512, 1 = use SHA384
 */
void ngx_sha512( const u_char *input, size_t ilen,
             u_char output[64], int is384 );


void ngx_sha512_process( ngx_sha512_context *ctx, const u_char data[128] );

#endif
