#ifndef LIBRIST_CRYPTO_SRP_CONSTANTS_H
#define LIBRIST_CRYPTO_SRP_CONSTANTS_H


#include <librist/common.h>
typedef enum
{
	LIBRIST_SRP_NG_512,
	LIBRIST_SRP_NG_768,
    LIBRIST_SRP_NG_1024,
    LIBRIST_SRP_NG_2048,
    LIBRIST_SRP_NG_4096,
    LIBRIST_SRP_NG_8192
} librist_srp_ng_e;

#define LIBRIST_SRP_NG_DEFAULT LIBRIST_SRP_NG_2048

//Marked as public because we want to use it in ristsrppassword. NOT (yet) intended for public use, so zero API/ABI guarantees/promises.
RIST_API int librist_get_ng_constants(librist_srp_ng_e ng_pair, const char **n, const char **g);

#endif /* LIBRIST_CRYPTO_SRP_CONSTANTS_H */
