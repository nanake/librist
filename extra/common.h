/* librist. Copyright 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 */

#ifndef RIST_EXTRA_COMMON_H
#define RIST_EXTRA_COMMON_H

/* __BEGIN_DECLS should be used at the beginning of your declarations,
   so that C++ compilers don't mangle their names.  Use __END_DECLS at
   the end of C declarations. */
#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

__BEGIN_DECLS

/* Reference: http://gcc.gnu.org/wiki/Visibility */
#if defined(_WIN32) || defined(__CYGWIN__)
# define RIST_PRIV
#else /* defined(_WIN32) || defined(__CYGWIN__) */
# if __GNUC__ >= 4
#  define RIST_PRIV  __attribute__ ((visibility ("hidden")))
# else /* __GNUC__ >= 4 */
#  define RIST_PRIV
# endif /* __GNUC__ >= 4 */
#endif /* defined(_WIN32) || defined(__CYGWIN__) */

#ifdef _WIN32
# define RIST_PACKED_STRUCT(sname,sbody) \
__pragma( pack(push, 1) ) \
struct sname sbody; \
__pragma( pack(pop) )
#else
# define RIST_PACKED_STRUCT(sname,sbody) \
struct __attribute__((packed)) sname sbody;
#endif

/* Branch prediction */
#ifdef __GNUC__
# define RIST_LIKELY(p)   __builtin_expect(!!(p), 1)
# define RIST_UNLIKELY(p) __builtin_expect(!!(p), 0)
#else
# define RIST_LIKELY(p)   (!!(p))
# define RIST_UNLIKELY(p) (!!(p))
#endif

#ifdef __GNUC__
# define RIST_FALLTHROUGH __attribute__((fallthrough))
#endif

__END_DECLS

#endif
