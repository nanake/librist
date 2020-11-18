

tools_deps = []
if host_machine.system() == 'windows'
	tools_deps += ['../contrib/getopt-shim.c']
endif

tools_deps += [	'../contrib/pthread-shim.c']

srp_shared = []
tools_dependencies = []
if use_mbedtls
	srp_shared += 'srp_shared.c'
	tools_dependencies += mbedcrypto_lib
endif




executable('ristsender',
	['ristsender.c',srp_shared, tools_deps],
	link_with : [librist],
	dependencies: [
		threads,
		stdatomic_dependency,
		tools_dependencies
	],
	include_directories: inc,
	install: true)

executable('ristreceiver',
	['ristreceiver.c', srp_shared, tools_deps],
	link_with : [librist],
	dependencies: [tools_dependencies],
	include_directories: inc,
	install: true)

executable('rist2rist',
        ['rist2rist.c', tools_deps],
        link_with : [librist],
		include_directories: inc,
        install: true)
if use_mbedtls
	executable('ristsrppasswd',
			['ristsrppasswd.c', '../contrib/srp.c', tools_deps],
			link_with : [librist],
			dependencies: [mbedcrypto_lib],
			include_directories: inc,
			install: true)
endif