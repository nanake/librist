cmocka = meson.get_compiler('c').find_library('cmocka', required: false)

if cmocka.found()
	if have_srp
		srp_unit = executable('srp_unit', rev_target,
								'srp_examples.c',
								'../../../contrib/pthread-shim.c',
								'../../../src/crypto/random.c',
								include_directories : inc,
								dependencies : [threads, cmocka,crypto_deps],
		)

		test('srp_unit_test', srp_unit, suite:['unit'])
	endif
endif