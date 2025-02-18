# librist. Copyright (c) 2020 SipRadius LLC. All right reserved.
# Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
# SPDX-License-Identifier: BSD-2-Clause

tools_dependencies = []
tools_deps = []
if host_machine.system() == 'windows'
	tools_deps += ['../contrib/getopt-shim.c']
	tools_dependencies += [ cc.find_library('ws2_32') ]
endif

tools_deps += [	'../contrib/time-shim.c']
tools_deps += [	'../contrib/pthread-shim.c']

if filter_obj
	tools_deps += [objcopy_fake_file ]
endif

srp_shared = []
if have_srp
	srp_shared += 'srp_shared.c'
	tools_dependencies += crypto_deps
endif

if compile_prometheus
	prometheuslib = static_library('prometheus', 'prometheus-exporter.c', include_directories: inc)
	prometheus_dep = declare_dependency(link_with: prometheuslib, include_directories: include_directories('.'), dependencies: microhttpd)
	tools_dependencies += prometheus_dep
endif

executable('ristsender',
	['ristsender.c', 'yamlparse.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	dependencies: [
		librist_dep,
		threads,
		stdatomic_dependency,
		tools_dependencies,
	],
	include_directories: inc,
	install: should_install)

executable('ristreceiver',
	['ristreceiver.c', 'yamlparse.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	dependencies: [
		librist_dep,
		tools_dependencies,
		threads,
	],

	include_directories: inc,
	install: should_install)

executable('rist2rist',
	['rist2rist.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	dependencies: [
		tools_dependencies,
		threads,
		librist_dep,
	],
	include_directories: inc,
	install: should_install)

executable('udp2udp',
	['udp2udp.c', 'yamlparse.c', 'oob_shared.c', srp_shared, tools_deps, rev_target],
	dependencies: [
		tools_dependencies,
		threads,
		librist_dep,
	],
	include_directories: inc,
	install: should_install)

if mbedcrypto_lib_found or use_nettle
	executable('ristsrppasswd',
			['ristsrppasswd.c', tools_deps],
			dependencies: [
				librist_dep,
				crypto_deps,
			],
			include_directories: inc,
			install: should_install)
endif
