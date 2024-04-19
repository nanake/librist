# librist. Copyright (c) 2019 SipRadius LLC. All right reserved.
# Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
# Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
# SPDX-License-Identifier: BSD-2-Clause

project('libRIST', 'c',
	version: '0.2.10',
	default_options: ['c_std=c99', 'warning_level=3', 'libdir=lib'],
        meson_version: '>= 0.51.0')

cc = meson.get_compiler('c')
# Configuration data for config.h
cdata = configuration_data()

#librist ABI version, libtool rules (taken from https://github.com/pvanhoof/dir-examples)
#If the library source code has changed at all since the last update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
#If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
#If any interfaces have been added since the last public release, then increment age.
#If any interfaces have been removed or changed since the last public release, then set age to 0.
librist_abi_current = 7
librist_abi_revision = 1
librist_abi_age = 3
librist_soversion = librist_abi_current - librist_abi_age
librist_version = '@0@.@1@.@2@'.format(librist_abi_current - librist_abi_age, librist_abi_age, librist_abi_revision)

# libRIST version
#API follows semver rules:
#MAJOR version when you make incompatible API changes,
#MINOR version when you add functionality in a backwards-compatible manner, and
#PATCH not used (doesn't make sense for API version, remains here for backwards compat)

librist_api_version_major = 4
librist_api_version_minor = 4
librist_api_version_patch = 0

librist_src_root = meson.current_source_dir()

deps = []
platform_files = []
inc = []
inc += include_directories('.', 'src', 'include/librist', 'include', 'contrib')

#builtin_lz4 = get_option('builtin_lz4')
builtin_cjson = get_option('builtin_cjson')
builtin_mbedtls = get_option('builtin_mbedtls')
use_mbedtls = get_option('use_mbedtls')
use_nettle = get_option('use_nettle')
use_gnutls = get_option('use_gnutls')

if not use_gnutls
	if use_nettle
		warning('use_nettle is deprecated, use use_gnutls')
	endif
	use_gnutls = use_nettle
endif

cdata.set10('ALLOW_INSECURE_IV_FALLBACK', get_option('allow_insecure_iv_fallback'))

required_library = false
if not get_option('fallback_builtin')
	required_library = true
endif

should_install = true
if meson.is_subproject()
	should_install = false
endif

have_pthreads = cc.has_header('pthread.h')
have_clock_gettime = false

threads = []
test_args = []
if host_machine.system() == 'windows'
	deps += [
		cc.find_library('ws2_32'),
		cc.find_library('iphlpapi')
	]

windows_version_test = '''
#include <windef.h>
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
# error _WIN32_WINNT toolchain default not high enough
#endif
'''
	if not cc.compiles(windows_version_test, name: '_WIN32_WINNT includes Vista')
		add_project_arguments(['-D_WIN32_WINNT=0x0600'], language: 'c')
	endif

	if get_option('default_library') != 'static'
		add_project_arguments(['-DLIBRIST_BUILDING_DLL'], language: 'c')
	endif
	if get_option('have_mingw_pthreads')
		if have_pthreads
			threads = dependency('threads')
			deps += threads
			cdata.set('HAVE_PTHREADS', 1)
			have_clock_gettime =  cc.has_function('clock_gettime', prefix : '#include <time.h>', args : test_args, dependencies: threads)
		endif
	else
		have_pthreads = false
	endif
	add_project_arguments(['-DWIN32_LEAN_AND_MEAN'], language: 'c')
	add_project_arguments(['-D__USE_MINGW_ANSI_STDIO=1'], language: 'c')
	add_project_arguments(['-D_CRT_NONSTDC_NO_DEPRECATE'], language: 'c')
	add_project_arguments(['-D_CRT_SECURE_NO_WARNINGS'], language: 'c')
	add_project_arguments(cc.get_supported_arguments(['-wd4996', '-wd4324']), language: 'c')
	#Windows meson tends to break on pkgconfig/Cmake finding, so use builtin libraries
	librist_soversion = ''
else
	if host_machine.system() == 'linux' or host_machine.system() == 'android'
		test_args += '-D_GNU_SOURCE'
		add_project_arguments('-D_GNU_SOURCE', language: 'c')
		if cc.check_header('linux/if_alg.h')
			add_project_arguments(['-DLINUX_CRYPTO'], language: 'c')
			platform_files += 'contrib/linux-crypto.c'
		endif
		checkgetif = '''
#include <ifaddrs.h>

void test(void) {
	struct ifaddrs *ifaddr = NULL;
	getifaddrs(&ifaddr);
}
'''
		hasgetifaddrs = cc.compiles(checkgetif)
		if not hasgetifaddrs and host_machine.system() == 'android'
			platform_files += 'compat/android/ifaddrs.c'
			inc += include_directories('compat/android')
		endif
	elif host_machine.system() == 'darwin'
		test_args += '-D_DARWIN_C_SOURCE'
		add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
	elif host_machine.system() == 'gnu'
		test_args += '-D_GNU_SOURCE'
		add_project_arguments('-D_GNU_SOURCE', language: 'c')
	endif
	librist_soversion = librist_soversion
	have_clock_gettime = cc.has_function('clock_gettime', prefix : '#include <time.h>', args : test_args)
	if not have_clock_gettime and host_machine.system() != 'darwin'
		lib_rt = cc.find_library('rt', required: false)
		have_clock_gettime = cc.has_function('clock_gettime', prefix : '#include <time.h>', args : test_args, dependencies : lib_rt)
		if not have_clock_gettime
			error('clock_gettime not found')
		endif
		deps += [ lib_rt ]
	endif
	add_project_arguments(['-Wshadow', '-pedantic-errors'], language: 'c')
	add_project_arguments(cc.get_supported_arguments([
		'-Wundef',
		'-Werror=vla',
		'-Wno-maybe-uninitialized',
		'-Wno-missing-field-initializers',
		'-Wno-unused-parameter',
		'-Wshorten-64-to-32',
		'-Wunused-parameter',
		'-Wmaybe-uninitialized',
		'-Wno-error=deprecated-declarations'
		]), language : 'c')
	threads = [ dependency('threads') ]
	if host_machine.system() != 'freebsd'
	  add_project_arguments(cc.get_supported_arguments([
            '-Watomic-implicit-seq-cst']), language: 'c')
	endif
	deps += threads
endif

cdata.set10('HAVE_CLOCK_GETTIME', have_clock_gettime)
cdata.set10('HAVE_PTHREADS', have_pthreads)

sock_un_h = cc.has_header('sys/un.h')
cdata.set10('HAVE_SOCK_UN_H', sock_un_h)
microhttpd = dependency('libmicrohttpd', required: false)
cdata.set10('HAVE_LIBMICROHTTPD', microhttpd.found())
if microhttpd.found()
	code = '''
#include <microhttpd.h>
static enum MHD_Result test(void) {
	return MHD_NO;
}'''
	cdata.set10('MICROHTTPD_HAS_RESULT_ENUM',cc.compiles(code, dependencies: [microhttpd], name: 'libmicrohttpd has MHD_Result enum'))
	code = '''
#include <microhttpd.h>
static void test(void) {
	MHD_start_daemon(MHD_USE_AUTO_INTERNAL_THREAD, 0, NULL, NULL, NULL, NULL, MHD_OPTION_END);
}'''
	cdata.set10('MICROHTTPD_HAS_AUTO_INTERNAL_THREAD',cc.compiles(code, dependencies: [microhttpd], name: 'libmicrohttpd has MHD_USE_AUTO_INTERNAL_THREAD flag'))
endif
compile_prometheus = sock_un_h or microhttpd.found()
cdata.set10('HAVE_PROMETHEUS_SUPPORT', compile_prometheus)

if cc.has_argument('-fvisibility=hidden')
    add_project_arguments('-fvisibility=hidden', language: 'c')
else
    warning('Compiler does not support -fvisibility=hidden, all symbols will be public!')
endif

# Header checks
stdatomic_dependency = []
if not cc.check_header('stdatomic.h')
    if cc.get_id() == 'msvc'
        # we have a custom replacement for MSVC
        stdatomic_dependency = declare_dependency(
            include_directories : include_directories('compat/msvc'),
        )
    elif cc.compiles('''int main() { int v = 0; return __atomic_fetch_add(&v, 1, __ATOMIC_SEQ_CST); }''',
                     name : 'GCC-style atomics', args : test_args)
        stdatomic_dependency = declare_dependency(
            include_directories : include_directories('compat/gcc'),
        )
    else
        error('Atomics not supported')
    endif
endif

#On ubuntu cjson does not come with pkgconfig files, hence the extended checking.
if not builtin_cjson
	cjson_lib = dependency('libcjson', required: false)
	if not cjson_lib.found()
		cjson_lib = cc.find_library('cjson', required: required_library, has_headers: ['cjson/cJSON.h'])
		if not cjson_lib.found()
			builtin_cjson = true
		endif
	endif
endif
if builtin_cjson
	message('Using builtin cJSON library')
	cjson_lib = declare_dependency( compile_args : '-DCJSON_HIDE_SYMBOLS',
									sources: 'contrib/contrib_cJSON/cjson/cJSON.c',
									include_directories : include_directories('contrib/contrib_cJSON'))
endif

if get_option('use_tun')
	if host_machine.system() == 'linux' and cc.check_header('linux/if_tun.h')
		add_project_arguments(['-DUSE_TUN'], language: 'c')
	else
		error('TUN only supported on linux at this moment')
	endif
endif

crypto_deps = []

mbedcrypto_lib_found = false
if use_mbedtls
	message('Building mbedtls')
	subdir('contrib/mbedtls')

	crypto_deps += mbedcrypto_lib
elif use_gnutls
	crypto_deps = [dependency('nettle'), dependency('hogweed')]
	test_mini_gmp = '''
#include <nettle/bignum.h>
#if !NETTLE_USE_MINI_GMP
	#error "Need to link gmp"
#endif
'''
	if not cc.compiles(test_mini_gmp, name: 'Nettle with mini-gmp?', dependencies: crypto_deps)
		crypto_deps += dependency('gmp')
	endif
	crypto_deps += dependency('gnutls')#Just for random numbers at the moment :/
endif
deps += crypto_deps

subdir('include')

filter_obj = false
objcopy = find_program('objcopy', native: true, required: false)

if get_option('allow_obj_filter') and cc.get_id() == 'clang'
	error('allow_obj_filter doesn\'t work with clang due to it not supporting pre-linking')
endif

if get_option('allow_obj_filter') and get_option('default_library') != 'shared' and not get_option('b_lto')
	if objcopy.found()
		message('Using objcopy to localize symbols in static library')
		filter_obj = true
	else
		error('objcopy not found, unable to localize symbols in static library')
	endif
endif

if not mbedcrypto_lib_found and not use_gnutls
	platform_files += [
		'contrib/aes.c',
		'contrib/sha256.c',
		'contrib/fastpbkdf2.c',
	]
endif

have_srp = mbedcrypto_lib_found or use_gnutls

if have_srp
    platform_files += 'src/proto/eap.c'
	platform_files += 'src/crypto/srp_constants.c'
	platform_files += 'src/crypto/srp.c'
	platform_files += 'src/crypto/random.c'
endif

cdata.set10('HAVE_MBEDTLS', mbedcrypto_lib_found)
cdata.set10('HAVE_NETTLE', use_gnutls and not mbedcrypto_lib_found)
# Generate config.h
config_file = configure_file(output: 'config.h', configuration: cdata)

librist = library('librist',
	'src/crypto/crypto.c',
	'src/crypto/psk.c',
	'src/proto/gre.c',
	'src/proto/rtp.c',
	'src/proto/rist_time.c',
	'src/flow.c',
	'src/logging.c',
	'src/network.c',
	'src/rist.c',
	'src/rist-common.c',
	'src/rist_ref.c',
	'src/rist-thread.c',
	'src/mpegts.c',
	'src/peer.c',
	'src/udp.c',
	'src/stats.c',
	'src/udpsocket.c',
	'src/libevsocket.c',
	'contrib/stdio-shim.c',
	'contrib/time-shim.c',
	'contrib/pthread-shim.c',
	config_file,
	platform_files,
	rev_target,
	include_directories: inc,
	dependencies: [
		deps,
		stdatomic_dependency,
		cjson_lib,
	],
	name_prefix : '',
	version: librist_version,
	soversion: librist_soversion,
	prelink: filter_obj,
	install: should_install)

objcopy_fake_file = ''
if filter_obj
	lib_target = librist
	if get_option('default_library') == 'both'
		lib_target = librist.get_static_lib()
	endif
	objcopy_fake_file = custom_target('librist',
		input: lib_target,
		output: 'librist.is-stripped',
		capture: true,
		command: [
			objcopy,
			'--localize-hidden',
			'-w',
			'--localize-symbol=!rist*',
			'--localize-symbol=!librist*',
			'--localize-symbol=!udpsocket*',
			'--localize-symbol=!evsocket*',
			'--localize-symbol=*',
			'@INPUT@',
		],
		build_by_default: true,
	)
endif

pkg_mod = import('pkgconfig')
pkg_mod.generate(
	libraries: librist,
	version: meson.project_version(),
	name: 'librist',
	description: 'Reliable Internet Stream Transport (RIST)',
)

if get_option('static_analyze')
	run_target('cppcheck', command : ['cppcheck',
									  '--quiet',
									  '--std=c99',
									  '--suppressions-list=' + join_paths(librist_src_root, 'common/configs/cppcheck-suppressions.txt'),
									  '--project=' + join_paths(meson.build_root(),
									  'compile_commands.json')])
	run_target('analyze', command: ['bash', join_paths(librist_src_root, 'common/scripts/analyze.sh')])
endif

librist_dep = declare_dependency(include_directories: inc, link_with : librist)

if get_option('built_tools')
	message('Building tools')
	subdir('tools')
endif

if get_option('test')
	subdir('test')
endif
