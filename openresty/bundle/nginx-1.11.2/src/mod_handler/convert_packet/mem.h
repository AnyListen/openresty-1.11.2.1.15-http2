#ifndef __MEM_H
#define __MEM_H

#include "c_conv_base.h"

void *conv_realloc(void *ptr, size_t size);

void * conv_fast_realloc(void *ptr, unsigned int *size, size_t min_size);

void *conv_malloc(size_t size);
#endif
