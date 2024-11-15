# librist. Copyright (c) 2020 SipRadius LLC. All right reserved.
# SPDX-License-Identifier: BSD-2-Clause

subdir('unit')

extra_sources = ['../../contrib/time-shim.c','../../contrib/pthread-shim.c']

if filter_obj
	extra_sources += [objcopy_fake_file ]
endif


test_send_receive = executable('test_send_receive',
                                'test_send_receive.c',
                                extra_sources,
                                include_directories: inc,
                                link_with: librist,
                                dependencies: [
                                    threads,
                                    tools_dependencies,
									stdatomic_dependency
                                ])


###Simple profile tests
#Unicast
test('Simple profile unicast', test_send_receive, args: ['0', 'rist://@127.0.0.1:1234', 'rist://127.0.0.1:1234', '0'], suite: ['simple', 'unicast'])
test('Simple profile unicast packet loss 10%', test_send_receive, args: ['0', 'rist://@127.0.0.1:2234', 'rist://127.0.0.1:2234', '10'],suite: ['simple', 'unicast'])
test('Simple profile unicast packet loss 25%', test_send_receive, args: ['0', 'rist://@127.0.0.1:3234', 'rist://127.0.0.1:3234', '25'],suite: ['simple', 'unicast'])
if (host_machine.system() != 'darwin')
    #Multicast
    test('Simple profile multicast', test_send_receive, args: ['0', 'rist://@239.0.0.1:1236?rtt-max=10&rtt-min=1', 'rist://239.0.0.1:1236?rtt-max=10&rtt-min=1', '0'],suite: ['simple', 'multicast'])
    test('Simple profile multicast packet loss 10%', test_send_receive, args: ['0', 'rist://@239.0.0.2:2236?rtt-max=10&rtt-min=1', 'rist://239.0.0.2:2236?rtt-max=10&rtt-min=1', '10'],suite: ['simple', 'multicast'])
    test('Simple profile multicast packet loss 25%', test_send_receive, args: ['0', 'rist://@239.0.0.3:3236?rtt-max=10&rtt-min=1', 'rist://239.0.0.3:3236?rtt-max=10&rtt-min=1', '25'],suite: ['simple', 'multicast'])
endif

###Main profile tests:
#Null Packet Deletion
test('Main profile NPD receive server mode, sender client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:3501?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:3501?rtt-max=10&rtt-min=1', '0', '1'], suite: ['main', 'unicast', 'server', 'NPD'])
test('Main profile NPD receive client mode, sender server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:3502?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:3502?rtt-max=10&rtt-min=1', '0', '1'], suite: ['main', 'unicast', 'client', 'NPD'])
#Sender connecting to receiver
test('Main profile receive server mode, sender client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:4001?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:4001?rtt-max=10&rtt-min=1', '0'],suite: ['main', 'unicast', 'server'])
test('Main profile receive server mode, sender client mode packet loss 10%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4002?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:4002?rtt-max=10&rtt-min=1', '10'],suite: ['main', 'unicast', 'server'])
test('Main profile receive server mode, sender client mode packet loss 25%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4003?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:4003?rtt-max=10&rtt-min=1', '25'],suite: ['main', 'unicast', 'server'])
#Receiver connecting to sender
test('Main profile receive client mode, sender server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:5001?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:5001?rtt-max=10&rtt-min=1', '0'],suite: ['main', 'unicast', 'client'])
test('Main profile receive client mode, sender server mode packet loss 10%', test_send_receive, args: ['1', 'rist://127.0.0.1:5002?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:5002?rtt-max=10&rtt-min=1', '10'],suite: ['main', 'unicast', 'client'])
test('Main profile receive client mode, sender server mode packet loss 25%', test_send_receive, args: ['1', 'rist://127.0.0.1:5003?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:5003?rtt-max=10&rtt-min=1', '25'],suite: ['main', 'unicast', 'client'])
#Encryption: TODO
test('Main profile encryption receive server mode, sender client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:6001?secret=12345678&aes-type=128', 'rist://127.0.0.1:6001?secret=12345678&aes-type=128', '0'],suite: ['main', 'unicast', 'server', 'encryption'])
test('Main profile encryption receive client mode, sender server mode ', test_send_receive, args: ['1', 'rist://127.0.0.1:6002?secret=12345678&aes-type=128', 'rist://@127.0.0.1:6002?secret=12345678&aes-type=128', '0'],suite: ['main', 'unicast', 'client', 'encryption'])
test('Main profile encryption receive client mode, sender server mode AES256 ', test_send_receive, args: ['1', 'rist://127.0.0.1:6007?secret=12345678&aes-type=256', 'rist://@127.0.0.1:6007?secret=12345678&aes-type=256', '0'],suite: ['main', 'unicast', 'client', 'encryption'])
#Encryption tests where 1 side has enabled encryption these should fail
test('Main profile encryption receive server mode unencrypted, sender client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:6003', 'rist://127.0.0.1:6003?secret=12345678&aes-type=128', '0'], should_fail: true)
test('Main profile encryption receive server mode, sender client mode unencrypted', test_send_receive, args: ['1', 'rist://@127.0.0.1:6004?secret=12345678&aes-type=128', 'rist://127.0.0.1:6004', '0'], should_fail: true)
test('Main profile encryption client mode unencrypted, sender server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:6005', 'rist://@127.0.0.1:6005?secret=12345678&aes-type=128', '0'], should_fail: true)
test('Main profile encryption client mode, sender server mode unencrypted', test_send_receive, args: ['1', 'rist://127.0.0.1:6006?secret=12345678&aes-type=128', 'rist://@127.0.0.1:6006', '0'], should_fail: true)
#Test SRP Auth
if have_srp
	test('Main profile encryption receive client mode, sender server mode, SRP auth', test_send_receive, args: ['1', 'rist://127.0.0.1:6008?secret=12345678&aes-type=128&username=testuser&password=testpassword', 'rist://@127.0.0.1:6008?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'],suite: ['main', 'unicast', 'server', 'encryption', 'srp'], should_fail: false)
	test('Main profile encryption receive client mode, sender server mode, SRP auth, client no SRP', test_send_receive, args: ['1', 'rist://127.0.0.1:6009?secret=12345678&aes-type=128', 'rist://@127.0.0.1:6009?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'], suite: ['main', 'unicast', 'server', 'encryption', 'srp'], should_fail: true)
	test('Main profile encryption receive client mode, sender server mode, SRP auth, server no SRP', test_send_receive, args: ['1', 'rist://127.0.0.1:6010?secret=12345678&aes-type=128&username=testuser&password=testpassword', 'rist://@127.0.0.1:6010?secret=12345678&aes-type=128', '0'], suite: ['main', 'unicast', 'server', 'encryption', 'srp'], should_fail: true)
	test('Main profile encryption receive client mode, sender server mode, SRP auth, password mismatch', test_send_receive, args: ['1', 'rist://127.0.0.1:6011?secret=12345678&aes-type=128&username=testuser&password=wrongpassword', 'rist://@127.0.0.1:6011?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'],suite: ['main', 'unicast', 'server', 'encryption', 'srp'], should_fail: true)
endif
