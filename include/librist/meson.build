# librist. Copyright (c) 2020 SipRadius LLC. All right reserved.
# SPDX-License-Identifier: BSD-2-Clause

version_h_data = configuration_data()

version_h_data.set('LIBRIST_API_VERSION_MAJOR', librist_api_version_major)
version_h_data.set('LIBRIST_API_VERSION_MINOR', librist_api_version_minor)
version_h_data.set('LIBRIST_API_VERSION_PATCH', librist_api_version_patch)
version_h_target = configure_file(input: 'version.h.in',
								  output: 'version.h',
								  configuration: version_h_data)

if should_install
	install_headers('librist.h', 
					'udpsocket.h',
					'common.h',
					'headers.h',
					'logging.h',
					version_h_target, subdir: 'librist')

	if use_mbedtls
		install_headers('librist_srp.h', subdir: 'librist')
	endif
endif