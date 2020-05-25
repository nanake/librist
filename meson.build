# librist. Copyright 2019 SipRadius LLC. All right reserved.
# Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
# Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>

project('rist', 'c',
	version: '0.1',
	default_options: ['c_std=c99', 'warning_level=3'])

cc = meson.get_compiler('c')

deps = []
platform_files = []
inc = include_directories('include', 'contrib')

subproject = meson.is_subproject()

if host_machine.system() == 'windows'
	deps += [ meson.get_compiler('c').find_library('ws2_32') ]
	add_project_arguments(['-Drist_EXPORTS'], language: 'c')
	add_project_arguments(['-DWIN32_LEAN_AND_MEAN'], language: 'c')
else
	add_project_arguments(['-Wshadow', '-pedantic-errors'], language: 'c')
	if meson.get_compiler('c').get_id() == 'clang'
		add_project_arguments(['-Watomic-implicit-seq-cst'], language: 'c')
	endif
endif

test_args = []
if host_machine.system() == 'linux'
    test_args += '-D_GNU_SOURCE'
	add_project_arguments(['-D_GNU_SOURCE'], language: 'c')
	deps += [ dependency('threads') ]
	lib_rt = cc.find_library('rt', required: false)
	deps += [ lib_rt ]
	platform_files += 'contrib/linux-crypto.c'
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


librist = library('rist',
	'src/crypto.c',
	'src/flow.c',
	'src/log.c',
	'src/rist.c',
	'src/rist-common.c',
	'src/udp.c',
	'src/stats.c',
	'src/udpsocket.c',
	'contrib/aes.c',
	'contrib/sha256.c',
	'contrib/fastpbkdf2.c',
	'contrib/libevsocket.c',
	'contrib/stdio-shim.c',
	'contrib/time-shim.c',
	'contrib/pthread-shim.c',
	'contrib/lz4/lz4.c',
	'contrib/lz4/lz4frame.c',
	'contrib/lz4/lz4hc.c',
	'contrib/lz4/xxhash.c',
	platform_files,
	include_directories: inc,
	dependencies: [
		deps,
		stdatomic_dependency
	],
	install: true)

install_headers('include/librist.h')
install_headers('include/librist_udpsocket.h')

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
