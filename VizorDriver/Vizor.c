#include "Vizor.h"

VIZOR_TAG VizorTag = {
	.Signature = VIZOR_MAGIC_CHARS,
	.Version = 1.0, // Version 1.0
	.Size = 0,
	.Flags = 0 // Reserved for future use
};


static_assert(sizeof(VizorTag) == VIZOR_TAG_SIZE, "VIZOR_TAG size mismatch");