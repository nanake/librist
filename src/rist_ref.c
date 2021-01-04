#include "rist_ref.h"
#include <stdlib.h>
#include <stdbool.h>

struct rist_ref *rist_ref_create(void *data)
{
	struct rist_ref *ref = malloc(sizeof(*ref));
	if (!ref)
		return NULL;
	ref->ptr = data;
	atomic_init(&ref->refcnt, 1);
	return ref;
}

void rist_ref_inc(struct rist_ref *ref)
{
	atomic_fetch_add(&ref->refcnt, 1);
}

bool rist_ref_iswritable(struct rist_ref *ref)
{
	return atomic_load(&ref->refcnt) == 1 && ref->ptr;
}
