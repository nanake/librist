

tools_deps = []
if host_machine.system() == 'windows'
	tools_deps += ['../contrib/getopt-shim.c']
endif

executable('mpeg2rist',
	['mpeg2rist.c', tools_deps],
	link_with : [librist],
	include_directories: inc,
	install: true)

executable('rist2mpeg',
	['rist2mpeg.c', tools_deps],
	link_with : [librist],
	include_directories: inc,
	install: true)

executable('rist2rist',
        ['rist2rist.c', tools_deps],
        link_with : [librist],
		include_directories: inc,
        install: true)
