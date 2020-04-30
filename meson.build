# librist. Copyright 2019 SipRadius LLC. All right reserved.
# Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
# Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>

project('rist', 'c',
	version: '0.1',
	default_options: ['c_std=c99', 'warning_level=3'])

cc = meson.get_compiler('c')

deps = []
platform_files = []
inc = include_directories('inc', 'extra')

add_global_arguments(['-Drist_EXPORTS'], language: 'c')
add_global_arguments(['-Wshadow', '-pedantic-errors'], language: 'c')

if host_machine.system() == 'windows'
	deps += [ meson.get_compiler('c').find_library('ws2_32') ]
	add_global_arguments(['-DWIN32_LEAN_AND_MEAN'], language: 'c')
endif

if host_machine.system() == 'linux'
	add_global_arguments(['-D_GNU_SOURCE'], language: 'c')
	deps += [ dependency('threads') ]
	lib_rt = cc.find_library('rt', required: false)
	deps += [ lib_rt ]
	platform_files += 'extra/linux-crypto.c'
endif

librist = library('rist',
	'src/crypto.c',
	'src/flow.c',
	'src/log.c',
	'src/rist.c',
	'src/rist-common.c',
	'src/udp.c',
	'src/stats.c',
	'extra/aes.c',
	'extra/sha256.c',
	'extra/fastpbkdf2.c',
	'extra/libevsocket.c',
	'extra/network.c',
	'extra/stdio-shim.c',
	'extra/time-shim.c',
	'extra/pthread-shim.c',
	'extra/lz4/lz4.c',
	'extra/lz4/lz4frame.c',
	'extra/lz4/lz4hc.c',
	'extra/lz4/xxhash.c',
	platform_files,
	include_directories: inc,
	dependencies: deps,
	install: true)

install_headers('inc/librist.h')

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
									  '--suppressions-list=' + join_paths(meson.source_root(), 'configs/cppcheck-suppressions.txt'),
									  '--project=' + join_paths(meson.build_root(),
									  'compile_commands.json')])
	run_target('analyze', command: ['bash', join_paths(meson.source_root(), 'scripts/analyze.sh')])
endif
