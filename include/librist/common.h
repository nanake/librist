/*
 * Copyright © 2020, librist authors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RIST_COMMON_H
#define RIST_COMMON_H

/* Reference: http://gcc.gnu.org/wiki/Visibility */
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(rist_EXPORTS)
#if defined(__GNUC__)
#define RIST_API __attribute__((dllexport))
#else /* defined(__GNUC__) */
/* Note: actually gcc seems to also supports this syntax. */
#define RIST_API __declspec(dllexport)
#endif /* defined(__GNUC__) */
#else  /* defined(rist_EXPORTS) */
#if defined(__GNUC__)
#define RIST_API __attribute__((dllimport))
#else
/* Note: actually gcc seems to also supports this syntax. */
#define RIST_API __declspec(dllimport)
#endif
#endif /* defined(rist_EXPORTS) */
#else  /* defined(_WIN32) || defined(__CYGWIN__) */
#if __GNUC__ >= 4
#define RIST_API __attribute__((visibility("default")))
#else /* __GNUC__ >= 4 */
#define RIST_API
#endif /* __GNUC__ >= 4 */
#endif /* defined(_WIN32) || defined(__CYGWIN__) */
#endif
