Another Proxy
=============

Quick and dirty local DNS resolver and HTTP/HTTPS proxy that forwards requests over SOCKS5 (think: SSH -D9050).
```
Usage of anotherproxy:
  -httpproxy string
        Address:port for local HTTP proxy (default "127.0.0.1:8080")
  -localdns string
        Address:port for local DNS requests (default "127.0.0.1:53")
  -remotedns string
        Address:port of upstream DNS servers (comma seperated for multiple values) (default "8.8.8.8:53,8.8.4.4:53")
  -socks5 string
        SOCKS5 address:port
```

e.g.,
```
./anotherproxy -socks5="127.0.0.1:9050" \
-httpproxy="192.168.1.5:8080" \
-localdns="192.168.1.5:53"
```

## Install notes
```
sudo setcap 'cap_net_bind_service=+ep' $GOPATH/bin/anotherproxy
```

:heart: Major thanks to github.com/miekg/dns and github.com/elazarl/goproxy
