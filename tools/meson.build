
tools_dependencies = []
tools_deps = []
if host_machine.system() == 'windows'
	tools_deps += ['../contrib/getopt-shim.c']
	tools_dependencies += [ cc.find_library('ws2_32') ]
endif

tools_deps += [	'../contrib/time-shim.c']
tools_deps += [	'../contrib/pthread-shim.c']

srp_shared = []
if use_mbedtls
	srp_shared += 'srp_shared.c'
	tools_dependencies += mbedcrypto_lib
endif




executable('ristsender',
	['ristsender.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	link_with : [librist],
	dependencies: [
		threads,
		stdatomic_dependency,
		tools_dependencies
	],
	include_directories: inc,
	install: true)

executable('ristreceiver',
	['ristreceiver.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	link_with : [librist],
	dependencies: [tools_dependencies],
	include_directories: inc,
	install: true)

executable('rist2rist',
	['rist2rist.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	link_with : [librist],
	dependencies: [tools_dependencies],
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