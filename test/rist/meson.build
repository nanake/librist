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
                                    threads,
									stdatomic_dependency
                                ])


if comockatests
    test('rist test', risttest)
endif

###Simple profile tests
#Unicast
test('Simple profile unicast', test_send_receive, args: ['0', 'rist://@127.0.0.1:1234', 'rist://127.0.0.1:1234', '0'])
test('Simple profile unicast packet loss 10%', test_send_receive, args: ['0', 'rist://@127.0.0.1:2234', 'rist://127.0.0.1:2234', '10'])
test('Simple profile unicast packet loss 25%', test_send_receive, args: ['0', 'rist://@127.0.0.1:3234', 'rist://127.0.0.1:3234', '25'])
#Multicast
#Somehow broken need to investigate!
test('Simple profile multicast', test_send_receive, args: ['0', 'rist://@239.0.0.1:1234', 'rist://239.0.0.1:1234', '0'])
test('Simple profile multicast packet loss 10%', test_send_receive, args: ['0', 'rist://@239.0.0.2:1234', 'rist://239.0.0.2:1234', '10'])
#test('Simple profile multicast packet loss 25%', test_send_receive, args: ['0', 'rist://@239.0.0.3:1234?miface=lo', 'rist://239.0.0.3:1234?miface=lo', '25'])

###Main profile tests:
#Sender connecting to receiver
test('Main profile receive: server mode, sender: client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:4001', 'rist://127.0.0.1:4001', '0'])
test('Main profile receive: server mode, sender: client mode packet loss 10%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4002', 'rist://127.0.0.1:4002', '10'])
test('Main profile receive: server mode, sender: client mode packet loss 25%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4003', 'rist://127.0.0.1:4003', '25'])
#Receiver connecting to sender
test('Main profile receive: client mode, sender: server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:5001', 'rist://@127.0.0.1:5001', '0'])
test('Main profile receive: client mode, sender: server mode packet loss 10%', test_send_receive, args: ['1', 'rist://127.0.0.1:5002', 'rist://@127.0.0.1:5002', '10'])
test('Main profile receive: client mode, sender: server mode packet loss 25%', test_send_receive, args: ['1', 'rist://127.0.0.1:5003', 'rist://@127.0.0.1:5003', '25'])
#Encryption: TODO
test('Main profile encryption: receive: server mode, sender: client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:6001?secret=12345678&aes-type=128', 'rist://127.0.0.1:6001?secret=12345678&aes-type=128', '0'])
test('Main profile encryption: receive client mode, sender: server mode ', test_send_receive, args: ['1', 'rist://127.0.0.1:6002?secret=12345678&aes-type=128', 'rist://@127.0.0.1:6002?secret=12345678&aes-type=128', '0'])
#Encryption tests where 1 side has enabled encryption these should fail
test('Main profile encryption: receive: server mode unencrupted, sender: client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:6003', 'rist://127.0.0.1:6003?secret=12345678&aes-type=128', '0'], should_fail: true)
test('Main profile encryption: receive: server mode, sender: client mode unencrypted', test_send_receive, args: ['1', 'rist://@127.0.0.1:6004?secret=12345678&aes-type=128', 'rist://127.0.0.1:6004', '0'], should_fail: true)
test('Main profile encryption: client mode unencrypted, sender: server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:6005', 'rist://@127.0.0.1:6005?secret=12345678&aes-type=128', '0'], should_fail: true)
test('Main profile encryption: client mode, sender: server mode unencrypted', test_send_receive, args: ['1', 'rist://127.0.0.1:6006?secret=12345678&aes-type=128', 'rist://@127.0.0.1:6006', '0'], should_fail: true)
