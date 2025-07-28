#pragma once

#include "Includes.h"

#define VIZOR_MAGIC_CHARS { 'V', 'i', 'z', 'r' } // 'Vzr!' magic signature
#define VIZOR_POOL_TAG 'Vizr' // The signature of the tag
#define VIZOR_TAG_SIZE sizeof(VIZOR_TAG) // The size of the VIZOR_TAG structure

typedef struct _VIZOR_TAG {
	const char Signature[4];// 'Vizr' signature
	const DOUBLE Version; // Version of the driver (1.0)
	ULONG Size; // Size of the tag structure
	ULONG Flags; // Reserved for future use
} VIZOR_TAG, * PVIZOR_TAG;

extern VIZOR_TAG VizorTag;