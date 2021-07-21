# librist. Copyright (c) 2019 SipRadius LLC. All right reserved.
# Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
# Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
# SPDX-License-Identifier: BSD-2-Clause

project('libRIST', 'c',
	version: '0.2.6',
	default_options: ['c_std=c99', 'warning_level=3', 'libdir=lib'],
        meson_version: '>= 0.51.0')

cc = meson.get_compiler('c')
# Configuration data for config.h
cdata = configuration_data()

#librist ABI verion, libtool rules (taken from https://github.com/pvanhoof/dir-examples)
#If the library source code has changed at all since the last update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
#If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
#If any interfaces have been added since the last public release, then increment age.
#If any interfaces have been removed or changed since the last public release, then set age to 0.
librist_abi_current = 5
librist_abi_revision = 4
librist_abi_age = 1
librist_soversion = librist_abi_current - librist_abi_age
librist_version = '@0@.@1@.@2@'.format(librist_abi_current - librist_abi_age, librist_abi_age, librist_abi_revision)

# libRIST version
#API follows semver rules:
#MAJOR version when you make incompatible API changes,
#MINOR version when you add functionality in a backwards-compatible manner, and
#PATCH not used (doesn't make sense for API version, remains here for backwards compat)

librist_api_version_major = 4
librist_api_version_minor = 1
librist_api_version_patch = 1

librist_src_root = meson.current_source_dir()

deps = []
platform_files = []
contrib_libs = []
inc = []
inc += include_directories('.', 'src', 'include/librist', 'include', 'contrib')

#builtin_lz4 = get_option('builtin_lz4')
builtin_cjson = get_option('builtin_cjson')
builtin_mbedtls = get_option('builtin_mbedtls')
use_mbedtls = get_option('use_mbedtls')
cdata.set10('ALLOW_INSECURE_IV_FALLBACK', get_option('allow_insecure_iv_fallback'))

required_library = false
if not get_option('fallback_builtin')
	required_library = true
endif

should_install = true
if meson.is_subproject()
	should_install = false
endif

threads = []
test_args = []
if host_machine.system() == 'windows'
	deps += [ cc.find_library('ws2_32') ]
	add_project_arguments(['-D_WIN32_WINNT=0x0601'], language: 'c')
	if get_option('default_library') != 'static'
		add_project_arguments(['-DLIBRIST_BUILDING_DLL'], language: 'c')
	endif
	if get_option('have_mingw_pthreads')
		if cc.has_header('pthread.h')
			threads = cc.find_library('winpthread', static: true)
			deps += threads
			add_project_arguments(['-DHAVE_PTHREAD_H'], language: 'c')
			cdata.set('HAVE_PTHREADS', 1)
		endif
	endif
	add_project_arguments(['-DWIN32_LEAN_AND_MEAN'], language: 'c')
	add_project_arguments(['-D__USE_MINGW_ANSI_STDIO=1'], language: 'c')
	add_project_arguments(cc.get_supported_arguments(['-wd4996', '-wd4324']), language: 'c')
	#Windows meson tends to break on pkgconfig/Cmake finding, so use builtin libraries
	librist_soversion = ''
else
	if host_machine.system() == 'linux'
		test_args += '-D_GNU_SOURCE'
		add_project_arguments('-D_GNU_SOURCE', language: 'c')
		if cc.check_header('linux/if_alg.h')
			add_project_arguments(['-DLINUX_CRYPTO'], language: 'c')
			platform_files += 'contrib/linux-crypto.c'
		endif
	elif host_machine.system() == 'darwin'
		test_args += '-D_DARWIN_C_SOURCE'
		add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
	endif
	librist_soversion = librist_soversion
	if cc.has_function('clock_gettime', prefix : '#include <time.h>', args : test_args)
		cdata.set('HAVE_CLOCK_GETTIME', 1)
	elif host_machine.system() != 'darwin'
		lib_rt = cc.find_library('rt', required: false)
		if not cc.has_function('clock_gettime', prefix : '#include <time.h>', args : test_args, dependencies : lib_rt)
		error('clock_gettime not found')
		endif
		deps += [ lib_rt ]
		cdata.set('HAVE_CLOCK_GETTIME', 1)
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
	cjson_lib = dependency('cJSON', required: false)
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

if use_mbedtls
	message('Building mbedtls')
	subdir('contrib/mbedtls')
endif

subdir('include')

filter_obj = false
objcopy = find_program('objcopy', native: true, required: false)

if get_option('allow_obj_filter') and get_option('default_library') != 'shared' and not get_option('b_lto')
	if objcopy.found()
		message('Using objcopy to localize symbols in static library')
		filter_obj = true
	else
		warning('objcopy not found, unable to localize symbols in static library')
	endif
endif

librist = library('librist',
	'src/crypto/crypto.c',
	'src/crypto/psk.c',
	'src/flow.c',
	'src/logging.c',
	'src/rist.c',
	'src/rist-common.c',
	'src/rist_ref.c',
	'src/mpegts.c',
	'src/udp.c',
	'src/stats.c',
	'src/udpsocket.c',
	'src/libevsocket.c',
	'contrib/aes.c',
	'contrib/sha256.c',
	'contrib/fastpbkdf2.c',
	'contrib/stdio-shim.c',
	'contrib/time-shim.c',
	'contrib/pthread-shim.c',
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
									  '--suppressions-list=' + join_paths(meson.source_root(), 'common/configs/cppcheck-suppressions.txt'),
									  '--project=' + join_paths(meson.build_root(),
									  'compile_commands.json')])
	run_target('analyze', command: ['bash', join_paths(meson.source_root(), 'common/scripts/analyze.sh')])
endif

librist_dep = declare_dependency(include_directories: inc, link_with : librist)

# Generate config.h
config_h_target = configure_file(output: 'config.h', configuration: cdata)

if get_option('built_tools')
	message('Building tools')
	subdir('tools')
endif

if get_option('test')
	subdir('test')
endif
