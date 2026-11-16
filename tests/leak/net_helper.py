#!/usr/bin/env python3
"""Helper for the hermetic network cases (tests/leak/net_cases.sh).

Standard library only. Three groups of subcommands:

  serve READY UNIX_PATH    host side: the listeners and the DNS server the
                           cases talk to, on addresses net_cases.sh has
                           created (192.0.2.1, 192.0.2.2, 127.0.0.1)
  ls-get ID FIELD          host side: one field of a session from
                           `hisn ls --json` on stdin (dir, state,
                           network, workspace.id)
  journal-count K=V ...    host side: number of journal records on stdin
                           (JSON lines) matching every K=V
  journal-flood PORT       host side: single and summarized record counts
  journal-dump             host side: the network records, one per line
  in-*                     inside a session: one probe each; prints one
                           result line, or `FAIL: <reason>` and exits 1
                           (in-tcp, in-resolve and in-refused serve the
                           real-network step of host-verify-network.sh)
"""

import hashlib
import json
import os
import socket
import statistics
import sys
import threading
import time

LISTEN_IP = '192.0.2.1'
DNS_IP = '192.0.2.2'
BLACKHOLE = ('192.0.2.98', 18181)
TCP_PORTS = (18080, 18090, 18102, 18103, 18110, 18120)
HOST_LOOPBACK_PORT = 18070
GREETING = b'HERMETIC-OK'
ENETUNREACH = 101
EACCES = 13
ECONNREFUSED = 111
ETIMEDOUT = 110


def fail(reason):
    print(f'FAIL: {reason}')
    sys.exit(1)


# ---------------------------------------------------------------- host side


def _greet_forever(sock, greeting):
    while True:
        conn, _ = sock.accept()
        try:
            conn.sendall(greeting)
        except OSError:
            pass
        conn.close()


def _dns_answer(query):
    """The reply for `query`, or None to stay silent.

    Names starting with `drop` are never answered, names starting with
    `nx` get NXDOMAIN, every other A query resolves to LISTEN_IP and
    every other type gets an empty NOERROR.
    """
    if len(query) < 17:
        return None
    i = 12
    labels = []
    while query[i]:
        labels.append(query[i + 1:i + 1 + query[i]])
        i += 1 + query[i]
    end = i + 5
    name = b'.'.join(labels).lower()
    question = query[12:end]
    qtype = int.from_bytes(query[end - 4:end - 2], 'big')
    if name.startswith(b'drop'):
        return None
    if name.startswith(b'nx'):
        return query[:2] + b'\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00' + question
    if qtype != 1:
        return query[:2] + b'\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00' + question
    answer = (b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
              + socket.inet_aton(LISTEN_IP))
    return (query[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
            + question + answer)


def _dns_udp(sock):
    while True:
        query, addr = sock.recvfrom(4096)
        reply = _dns_answer(query)
        if reply:
            sock.sendto(reply, addr)


def _dns_tcp(sock):
    while True:
        conn, _ = sock.accept()
        conn.settimeout(5)
        try:
            size = int.from_bytes(conn.recv(2), 'big')
            reply = _dns_answer(conn.recv(size))
            if reply:
                conn.sendall(len(reply).to_bytes(2, 'big') + reply)
        except OSError:
            pass
        conn.close()


def serve(ready_path, unix_path):
    """Bind everything, then create `ready_path` and serve forever."""
    threads = []

    def listen(family, address):
        sock = socket.socket(family, socket.SOCK_STREAM)
        if family != socket.AF_UNIX:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
        sock.listen(256)
        return sock

    try:
        for port in TCP_PORTS:
            threads.append((_greet_forever,
                            (listen(socket.AF_INET, (LISTEN_IP, port)),
                             GREETING)))
        threads.append((_greet_forever,
                        (listen(socket.AF_INET,
                                ('127.0.0.1', HOST_LOOPBACK_PORT)),
                         b'HOST-LOOPBACK')))
        threads.append((_greet_forever,
                        (listen(socket.AF_UNIX, unix_path), b'HOST-UNIX')))
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((DNS_IP, 53))
        threads.append((_dns_udp, (udp,)))
        threads.append((_dns_tcp, (listen(socket.AF_INET, (DNS_IP, 53)),)))
    except OSError as e:
        fail(f'helper cannot bind its listeners: {e}')
    for target, args in threads:
        threading.Thread(target=target, args=args, daemon=True).start()
    with open(ready_path, 'w', encoding='ascii') as f:
        f.write('ready\n')
    while True:
        time.sleep(3600)


def ls_get(session, field):
    for s in json.load(sys.stdin).get('sessions', []):
        if s.get('id') == session:
            value = s
            for part in field.split('.'):
                value = value.get(part) if isinstance(value, dict) else None
            print('' if value is None else value)
            return
    print('')


def _records():
    out = []
    for line in sys.stdin:
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _field(record, key):
    if key in ('kind', 'session'):
        return record.get(key)
    return record.get('data', {}).get(key)


def journal_count(conditions):
    wanted = [c.split('=', 1) for c in conditions]
    count = 0
    for record in _records():
        for key, value in wanted:
            got = _field(record, key)
            if (value == 'null') != (got is None):
                break
            if got is not None and str(got) != value:
                break
        else:
            count += 1
    print(count)


def journal_flood(port):
    """Counts for the flood case: records written one by one for `port`,
    and the allow total of the summaries written after the first one."""
    target = f'{LISTEN_IP}:{port}'
    singles = 0
    summarized = 0
    first = None
    for record in _records():
        if (record['kind'] == 'network/connect'
                and record['data'].get('target') == target):
            singles += 1
            if first is None:
                first = record['wseq']
        elif record['kind'] == 'network/summary' and first is not None:
            summarized += record['data'].get('allow', 0)
    print(f'singles={singles} summarized={summarized}')


def journal_dump():
    for record in _records():
        if record['kind'].startswith('network/'):
            print(json.dumps(record, sort_keys=True))


# ------------------------------------------------------- inside a session


def _connect_errno(family, kind, address, timeout=10):
    """errno of connect(), 0 on success."""
    sock = socket.socket(family, kind)
    sock.settimeout(timeout)
    try:
        sock.connect(address)
        return 0
    except OSError as e:
        return e.errno if e.errno is not None else -1
    finally:
        sock.close()


def _greeting_from(port):
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect((LISTEN_IP, port))
    data = sock.recv(100)
    sock.close()
    return data


def in_connect(port):
    data = _greeting_from(port)
    if data != GREETING:
        fail(f'connected, but read {data!r}')
    print('CONNECT-OK')


def in_main(port, out_path):
    """The session's main command: one connect, then stay alive."""
    try:
        result = 'MAIN-OK ' + _greeting_from(port).decode()
    except OSError as e:
        result = f'MAIN-ERR {e}'
    with open(out_path + '.tmp', 'w', encoding='ascii') as f:
        f.write(result + '\n')
    os.rename(out_path + '.tmp', out_path)
    time.sleep(3600)


def in_dns():
    with open('/etc/resolv.conf', encoding='ascii') as f:
        resolv = f.read()
    if resolv != 'nameserver 127.0.0.1\n':
        fail(f'/etc/resolv.conf is {resolv!r}')
    with open('/etc/nsswitch.conf', encoding='ascii') as f:
        if 'hosts: files dns\n' not in f.read():
            fail('/etc/nsswitch.conf has no "hosts: files dns" line')
    info = socket.getaddrinfo('hermetic.test', 18080, socket.AF_INET,
                              socket.SOCK_STREAM)
    address = info[0][4]
    if address != (LISTEN_IP, 18080):
        fail(f'hermetic.test resolved to {address}')
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect(address)
    if sock.recv(100) != GREETING:
        fail('resolved and connected, but the greeting is wrong')
    print('L94-OK')


def _dns_query(name, ident):
    question = b''.join(
        bytes([len(p)]) + p.encode() for p in name.split('.'))
    return (ident.to_bytes(2, 'big') + b'\x01\x00\x00\x01\x00\x00\x00\x00'
            b'\x00\x00' + question + b'\x00\x00\x01\x00\x01')


def in_dns_raw(name, how):
    """One query to the responder; prints `RCODE r ANSWERS n`.

    how: `udp` (sendto), `udp-connect` (connect() on the datagram
    socket, which is intercepted), or `tcp`.
    """
    query = _dns_query(name, 0x4242)
    server = ('127.0.0.1', 53)
    try:
        if how == 'tcp':
            sock = socket.socket()
            sock.settimeout(10)
            sock.connect(server)
            sock.sendall(len(query).to_bytes(2, 'big') + query)
            size = int.from_bytes(sock.recv(2), 'big')
            reply = sock.recv(size)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            if how == 'udp-connect':
                sock.connect(server)
                sock.send(query)
            else:
                sock.sendto(query, server)
            reply = sock.recv(4096)
    except OSError as e:
        fail(f'{how} query for {name}: {e}')
    if len(reply) < 12 or reply[:2] != query[:2]:
        fail(f'{how} query for {name}: malformed reply {reply!r}')
    print(f'RCODE {reply[3] & 15} ANSWERS {int.from_bytes(reply[6:8], "big")}')


def in_loopback():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 19001))
    server.listen(1)
    client = socket.socket()
    client.settimeout(10)
    client.connect(('127.0.0.1', 19001))
    accepted, _ = server.accept()
    accepted.sendall(b'ping')
    if client.recv(10) != b'ping':
        fail('loopback data did not arrive')
    print('L96-OK')


def in_unix(path):
    sock = socket.socket(socket.AF_UNIX)
    try:
        sock.connect(path)
    except FileNotFoundError:
        print('L97-OK')
        return
    except OSError as e:
        fail(f'connect to the host unix socket: {e} (want ENOENT)')
    fail('connected to a host unix socket')


def in_sendto():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.sendto(b'x', (LISTEN_IP, 18080))
        fail('UDP sendto to an outside address was sent')
    except OSError as e:
        if e.errno != ENETUNREACH:
            fail(f'UDP sendto: errno {e.errno} (want ENETUNREACH)')
    tcp = socket.socket()
    try:
        tcp.sendto(b'x', socket.MSG_FASTOPEN, (LISTEN_IP, 18080))
        fail('TCP fast-open sendto to an outside address was sent')
    except OSError as e:
        if e.errno != ENETUNREACH:
            fail(f'fast-open sendto: errno {e.errno} (want ENETUNREACH)')
    print('L98-OK')


def in_cloexec():
    """The close-on-exec flag of a socket survives the intercepted
    connect, set or unset (the descriptor is replaced underneath)."""
    import fcntl
    for inheritable in (False, True):
        sock = socket.socket()
        os.set_inheritable(sock.fileno(), inheritable)
        sock.settimeout(10)
        sock.connect((LISTEN_IP, 18080))
        cloexec = bool(fcntl.fcntl(sock, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        if cloexec == inheritable:
            fail(f'after connect FD_CLOEXEC is {cloexec}, '
                 f'socket was inheritable={inheritable}')
        sock.close()
    print('CLOEXEC-OK')


def in_nonblock():
    import fcntl
    import select
    sock = socket.socket()
    sock.setblocking(False)
    rc = sock.connect_ex((LISTEN_IP, 18080))
    if rc not in (0, 115):  # 115 = EINPROGRESS
        fail(f'non-blocking connect returned errno {rc}')
    if not select.select([], [sock], [], 10)[1]:
        fail('socket never became writable')
    error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if error:
        fail(f'SO_ERROR is {error}')
    if not fcntl.fcntl(sock, fcntl.F_GETFL) & os.O_NONBLOCK:
        fail('the socket lost O_NONBLOCK')
    if not select.select([sock], [], [], 10)[0] or sock.recv(100) != GREETING:
        fail('no greeting on the non-blocking socket')
    blocking = socket.socket()
    blocking.connect((LISTEN_IP, 18080))
    if fcntl.fcntl(blocking, fcntl.F_GETFL) & os.O_NONBLOCK:
        fail('a blocking socket came back non-blocking')
    print('L99-OK')


def in_dgram():
    rc = _connect_errno(socket.AF_INET, socket.SOCK_DGRAM, (LISTEN_IP, 18080))
    if rc != EACCES:
        fail(f'datagram connect: errno {rc} (want EACCES)')
    print('L104-OK')


def in_bind():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 19055))
    sock.settimeout(10)
    sock.connect((LISTEN_IP, 18080))
    if sock.recv(100) != GREETING:
        fail('bound socket connected, but the greeting is wrong')
    port = sock.getsockname()[1]
    if port == 19055:
        fail('the bound source port survived (documented as lost)')
    print('L105-OK')


def in_thread(port):
    """A connect from a thread other than the main one."""
    result = []

    def worker():
        try:
            result.append(_greeting_from(port))
        except OSError as e:
            result.append(e)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(20)
    if result != [GREETING]:
        fail(f'connect from a second thread: {result}')
    print('THREAD-OK')


def in_concurrent():
    """A connect that never completes must not delay another one."""
    slow_result = []

    def slow():
        slow_result.append(
            _connect_errno(socket.AF_INET, socket.SOCK_STREAM, BLACKHOLE, 60))

    slow_thread = threading.Thread(target=slow, daemon=True)
    slow_thread.start()
    time.sleep(0.5)
    if slow_result:
        fail(f'the blackhole connect returned at once: errno {slow_result}')
    start = time.monotonic()
    data = _greeting_from(18080)
    took = time.monotonic() - start
    if data != GREETING:
        fail('the fast connect read a wrong greeting')
    if took > 2.0:
        fail(f'the fast connect took {took:.2f} s behind a pending one')
    if slow_result or not slow_thread.is_alive():
        fail(f'the blackhole connect is not pending any more: {slow_result}')
    print('L106-OK')


PRIVATE_TARGETS = (
    (socket.AF_INET, '192.168.1.1'),
    (socket.AF_INET, '10.0.0.1'),
    (socket.AF_INET, '172.16.0.1'),
    (socket.AF_INET, '169.254.169.254'),
    (socket.AF_INET, '100.64.0.1'),
    (socket.AF_INET, '198.18.0.1'),
    (socket.AF_INET, '224.0.0.1'),
    (socket.AF_INET, '0.0.0.0'),
    (socket.AF_INET6, 'fd00::1'),
    (socket.AF_INET6, 'fec0::1'),
    (socket.AF_INET6, '::ffff:10.0.0.1'),
    (socket.AF_INET6, '::10.0.0.1'),
    (socket.AF_INET6, '64:ff9b::a00:1'),
    (socket.AF_INET6, '2002:a00:1::1'),
    (socket.AF_INET6, '2001:0:4136:e378:8000:63bf:3f57:fefe'),
)


def in_private():
    for family, address in PRIVATE_TARGETS:
        rc = _connect_errno(family, socket.SOCK_STREAM, (address, 80), 5)
        if rc != EACCES:
            fail(f'connect to {address}: errno {rc} (want EACCES)')
    # The host's loopback listener is not the sandbox's loopback.
    rc = _connect_errno(socket.AF_INET, socket.SOCK_STREAM,
                        ('127.0.0.1', HOST_LOOPBACK_PORT), 5)
    if rc != ECONNREFUSED:
        fail(f'host loopback port: errno {rc} (want ECONNREFUSED)')
    print('L107-OK')


def in_family():
    """Families other than INET/INET6/UNIX are refused."""
    netlink = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    try:
        netlink.connect((0, 0))
        fail('netlink connect was allowed')
    except OSError as e:
        if e.errno != EACCES:
            fail(f'netlink connect: errno {e.errno} (want EACCES)')
    try:
        vsock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    except OSError as e:
        # No vsock in this kernel: there is no connect to refuse.
        print(f'L109-OK netlink refused; vsock unavailable (errno {e.errno})')
        return
    try:
        vsock.connect((2, 1234))
        fail('vsock connect was allowed')
    except OSError as e:
        if e.errno != EACCES:
            fail(f'vsock connect: errno {e.errno} (want EACCES)')
    print('L109-OK netlink refused; vsock refused')


def in_dumpable(port):
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        fail('prctl(PR_SET_DUMPABLE, 0) failed')
    if libc.prctl(3, 0, 0, 0, 0) != 0:  # PR_GET_DUMPABLE
        fail('the process is still dumpable')
    data = _greeting_from(port)
    if data != GREETING:
        fail(f'non-dumpable connect read {data!r}')
    print('L110-OK')


def in_flood(port, count):
    for _ in range(count):
        sock = socket.socket()
        sock.connect((LISTEN_IP, port))
        sock.close()
    print('FLOOD-DONE')


def in_status():
    filters = '?'
    with open('/proc/self/status', encoding='ascii') as f:
        for line in f:
            if line.startswith('Seccomp_filters:'):
                filters = line.split()[1]
    names = ','.join(sorted(name for _, name in socket.if_nameindex()))
    print(f'FILTERS {filters} IFACES {names}')


def in_pending():
    """Stay in a connect() that never completes (L100)."""
    rc = _connect_errno(socket.AF_INET, socket.SOCK_STREAM, BLACKHOLE, 120)
    print(f'PENDING-RETURNED errno {rc}')


def in_leave_pending():
    """Main command of a session: leave a child in a connect() that never
    completes, then exit. The session must end without waiting for the
    connect deadline."""
    if os.fork() == 0:
        _connect_errno(socket.AF_INET, socket.SOCK_STREAM, BLACKHOLE, 120)
        os._exit(0)
    time.sleep(1)


def in_none():
    """network = "none": no route, no interception, no generated files."""
    rc = _connect_errno(socket.AF_INET, socket.SOCK_STREAM, (LISTEN_IP, 18080))
    if rc != ENETUNREACH:
        fail(f'connect in none: errno {rc} (want ENETUNREACH)')
    if os.path.lexists('/etc/resolv.conf'):
        fail('/etc/resolv.conf exists in a none session')
    try:
        with open('/etc/nsswitch.conf', 'rb') as f:
            digest = hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        digest = 'absent'
    print(f'NONE-OK nsswitch {digest}')


def in_timing():
    def run():
        start = time.perf_counter()
        for _ in range(100):
            sock = socket.socket()
            sock.connect((LISTEN_IP, 18080))
            sock.close()
        return (time.perf_counter() - start) * 1e6 / 100

    runs = [run() for _ in range(3)]
    print(f'TIMING median {statistics.median(runs):.1f} us/connect '
          f'(runs: {", ".join(f"{r:.1f}" for r in runs)})')


def in_tcp(host, port):
    """Real-network step: one TCP connect; prints the peer address."""
    sock = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)
    sock.settimeout(15)
    sock.connect((host, port))
    print(f'TCP-OK {sock.getpeername()[0]}:{sock.getpeername()[1]}')


def in_resolve(name):
    """Real-network step: resolve through the session's resolver."""
    info = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
    print(f'RESOLVE-OK {name} {info[0][4][0]}')


def in_refused(host, port):
    rc = _connect_errno(socket.AF_INET, socket.SOCK_STREAM, (host, port), 10)
    if rc != EACCES:
        fail(f'connect to {host}:{port}: errno {rc} (want EACCES)')
    print('REFUSED-OK')


def main(argv):
    if len(argv) < 2:
        fail('usage: net_helper.py SUBCOMMAND [ARGS...]')
    cmd, args = argv[1], argv[2:]
    commands = {
        'serve': lambda: serve(args[0], args[1]),
        'ls-get': lambda: ls_get(args[0], args[1]),
        'journal-count': lambda: journal_count(args),
        'journal-flood': lambda: journal_flood(int(args[0])),
        'journal-dump': journal_dump,
        'in-connect': lambda: in_connect(int(args[0])),
        'in-main': lambda: in_main(int(args[0]), args[1]),
        'in-dns': in_dns,
        'in-dns-raw': lambda: in_dns_raw(args[0], args[1]),
        'in-loopback': in_loopback,
        'in-unix': lambda: in_unix(args[0]),
        'in-sendto': in_sendto,
        'in-nonblock': in_nonblock,
        'in-cloexec': in_cloexec,
        'in-dgram': in_dgram,
        'in-bind': in_bind,
        'in-concurrent': in_concurrent,
        'in-thread': lambda: in_thread(int(args[0])),
        'in-private': in_private,
        'in-family': in_family,
        'in-dumpable': lambda: in_dumpable(int(args[0])),
        'in-flood': lambda: in_flood(int(args[0]), int(args[1])),
        'in-status': in_status,
        'in-pending': in_pending,
        'in-leave-pending': in_leave_pending,
        'in-none': in_none,
        'in-timing': in_timing,
        'in-tcp': lambda: in_tcp(args[0], int(args[1])),
        'in-resolve': lambda: in_resolve(args[0]),
        'in-refused': lambda: in_refused(args[0], int(args[1])),
    }
    if cmd not in commands:
        fail(f'unknown subcommand {cmd}')
    try:
        commands[cmd]()
    except OSError as e:
        fail(f'{cmd}: {e}')


if __name__ == '__main__':
    main(sys.argv)
