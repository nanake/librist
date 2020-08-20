risttest_sources = [
    'example-test.c'
]
cmocka = meson.get_compiler('c').find_library('cmocka', required: false)
risttest_deps = [
    cmocka
]

risttest_lib_deps = [
    librist
]
comockatests = cmocka.found()
if cmocka.found()
    
    risttest = executable('risttest',
                            risttest_sources,
                            include_directories : inc,
                            dependencies : [risttest_deps,test_deps],
                            link_with : [risttest_lib_deps, test_dep_libs])
                            
endif

test_send_receive = executable('test_send_receive', 
                                'test_send_receive.c',
								'../../contrib/pthread-shim.c',
                                include_directories: inc,
                                link_with: librist,
                                dependencies: [
                                    threads
                                ])


if comockatests
    test('rist test', risttest)
endif

###Simple profile tests
#Unicast
test('Simple profile unicast', test_send_receive, args: ['0', 'rist://@127.0.0.1:1234', 'rist://127.0.0.1:1234', '0'])
test('Simple profile unicast packet loss 10%', test_send_receive, args: ['0', 'rist://@127.0.0.1:2234', 'rist://127.0.0.1:2234', '10'])
test('Simple profile unicast packet loss 30%', test_send_receive, args: ['0', 'rist://@127.0.0.1:3234', 'rist://127.0.0.1:3234', '30'])
#test('Simple profile unicast packet loss 35%', test_send_receive, args: ['0', 'rist://@127.0.0.1:4234', 'rist://127.0.0.1:4234', '35'], is_parallel : false)
#Multicast (needs lo interface otherwise it breaks!)
#Somehow broken need to investigate!
test('Simple profile multicast', test_send_receive, args: ['0', 'rist://@239.0.0.1:1234', 'rist://239.0.0.1:1234', '0'])
test('Simple profile multicast packet loss 10%', test_send_receive, args: ['0', 'rist://@239.0.0.2:1234', 'rist://239.0.0.2:1234', '10'])
#test('Simple profile multicast packet loss 30%', test_send_receive, args: ['0', 'rist://@239.0.0.3:1234?miface=lo', 'rist://239.0.0.3:1234?miface=lo', '30'])
#test('Simple profile multicast packet loss 35%', test_send_receive, args: ['0', 'rist://@239.0.0.4:1234?miface=lo', 'rist://239.0.0.4:1234?miface=lo', '35'], is_parallel : false)

###Main profile tests:
#Sender connecting to receiver
test('Main profile receive: server mode, sender: client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:4001', 'rist://127.0.0.1:4001', '0'])
test('Main profile receive: server mode, sender: client mode packet loss 10%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4002', 'rist://127.0.0.1:4002', '10'])
test('Main profile receive: server mode, sender: client mode packet loss 30%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4003', 'rist://127.0.0.1:4003', '30'])
#test('Main profile receive: server mode, sender: client mode packet loss 35%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4004', 'rist://127.0.0.1:4004', '35'], is_parallel : false)
#Receiver connecting to sender
test('Main profile receive: client mode, sender: server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:5001', 'rist://@127.0.0.1:5001', '0'])
test('Main profile receive: client mode, sender: server mode packet loss 10%', test_send_receive, args: ['1', 'rist://127.0.0.1:5002', 'rist://@127.0.0.1:5002', '10'])
test('Main profile receive: client mode, sender: server mode packet loss 30%', test_send_receive, args: ['1', 'rist://127.0.0.1:5003', 'rist://@127.0.0.1:5003', '30'])
#test('Main profile receive: client mode, sender: server mode packet loss 35%', test_send_receive, args: ['1', 'rist://127.0.0.1:5004', 'rist://@127.0.0.1:5004', '35'], is_parallel : false)
#Encryption: TODO