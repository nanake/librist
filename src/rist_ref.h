#include "common/attributes.h"
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>

struct rist_ref {
	atomic_int refcnt;
	const void *ptr;
};

RIST_PRIV bool rist_ref_iswritable(struct rist_ref *ref);
RIST_PRIV struct rist_ref *rist_ref_create(void *data);
RIST_PRIV void rist_ref_inc(struct rist_ref *ref);
