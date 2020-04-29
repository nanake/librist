risttest_sources = [
    'example-test.c'
]

risttest_deps = [
    meson.get_compiler('c').find_library('cmocka')
]

risttest_lib_deps = [
    librist
]

risttest = executable('risttest', 
    risttest_sources, 
    include_directories : inc,
    dependencies : [risttest_deps,test_deps], 
    link_with : [risttest_lib_deps, test_dep_libs])

test('rist test', risttest)
