# librist. Copyright 2019 SipRadius LLC. All right reserved.
# Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
# Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>

project('libRIST', 'c',
	version: '0.2',
	default_options: ['c_std=c99', 'warning_level=3', 'libdir=lib'],
        meson_version: '>= 0.47.0')

cc = meson.get_compiler('c')


# libRIST version
#If the internal source has changed, increase minor
#If any interfaces have been added, removed, or changed since the last update, increment major and minor to 0.
#If any interfaces have been added since the last public release, then increment minor.
#If any interfaces have been removed or changed since the last public release, then set micro to 0.
librist_api_version_major = 3
librist_api_version_minor = 0
librist_api_version_patch = 0
librist_version = '@0@.@1@.@2@'.format(librist_api_version_major, librist_api_version_minor, librist_api_version_patch)
librist_soversion = librist_api_version_major - librist_api_version_patch

librist_src_root = meson.current_source_dir()

deps = []
platform_files = []
contrib_libs = []
inc = include_directories('.', 'include/librist', 'include', 'contrib')

builtin_lz4 = get_option('builtin_lz4')
builtin_cjson = get_option('builtin_cjson')

if host_machine.system() == 'windows'
	deps += [ meson.get_compiler('c').find_library('ws2_32') ]
	add_project_arguments(['-D_WIN32_WINNT=0x0601'], language: 'c')
	if get_option('default_library') != 'static'
		add_project_arguments(['-DLIBRIST_BUILDING_DLL'], language: 'c')
	endif
	add_project_arguments(['-DWIN32_LEAN_AND_MEAN'], language: 'c')
	add_project_arguments(['-D__USE_MINGW_ANSI_STDIO=1'], language: 'c')
	add_project_arguments(cc.get_supported_arguments(['-wd4996', '-wd4324']), language: 'c')
	#Windows meson tends to break on pkgconfig/Cmake finding, so use builtin libraries
	builtin_cjson = true
	builtin_lz4 = true
else
	add_project_arguments(['-Wshadow', '-pedantic-errors'], language: 'c')
	add_project_arguments(cc.get_supported_arguments([
		'-Wundef',
		'-Werror=vla',
		'-Wno-maybe-uninitialized',
		'-Wno-missing-field-initializers',
		'-Wno-unused-parameter',
		'-Wshorten-64-to-32',
		'-Watomic-implicit-seq-cst',
		'-Wunused-parameter',
		'-Wmaybe-uninitialized'
		]), language : 'c')
endif

if cc.has_argument('-fvisibility=hidden')
    add_project_arguments('-fvisibility=hidden', language: 'c')
else
    warning('Compiler does not support -fvisibility=hidden, all symbols will be public!')
endif

test_args = []
threads = []
if host_machine.system() == 'linux'
    test_args += '-D_GNU_SOURCE'
	add_project_arguments(['-D_GNU_SOURCE'], language: 'c')
	threads = [ dependency('threads') ]
	deps += threads
	lib_rt = cc.find_library('rt', required: false)
	deps += [ lib_rt ]
	if cc.check_header('linux/if_alg.h')
		add_project_arguments(['-DLINUX_CRYPTO'], language: 'c')
		platform_files += 'contrib/linux-crypto.c'
	endif
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

if host_machine.system() == 'windows'
	librist_soversion = ''
else 
	librist_soversion = librist_soversion
endif

#On ubuntu cjson does not come with pkgconfig files, hence the extended checking.
if not builtin_cjson
	cjson_lib = dependency('cJSON', required: false)
	if not cjson_lib.found()
		cjson_lib = cc.find_library('cjson', required: false)
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

if not builtin_lz4
	lz4_lib = dependency('liblz4', required: false)
	if not lz4_lib.found()
		builtin_lz4 = true
	endif
endif
if builtin_lz4
	message('Using builtin lz4 library')
	lz4_lib = declare_dependency( compile_args : '-DLZ4LIB_VISIBILITY=',
								  sources: ['contrib/lz4/lz4.c',
											'contrib/lz4/lz4frame.c',
											'contrib/lz4/lz4hc.c',
											'contrib/lz4/xxhash.c',],
								  include_directories: include_directories('contrib/lz4'))
endif

subdir('include')

librist = library('librist',
	'src/crypto.c',
	'src/flow.c',
	'src/logging.c',
	'src/rist.c',
	'src/rist-common.c',
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
		lz4_lib,
	],
	name_prefix : '',
	version: librist_version,
	soversion: librist_soversion,
	install: true)

if get_option('built_tools')
	message('Building tools')
	subdir('tools')
endif

if get_option('test')
	subdir('test')
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
