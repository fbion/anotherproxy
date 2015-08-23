Another DNS Proxy
=================

Quick and dirty way to provide a local DNS resolver that forwards requests over SOCKS5 (think: SSH).
```
Usage of ./anotherdnsproxy:
  -address string
    	Address to listen to (TCP and UDP) (default "127.0.0.1:53")
  -dns string
    	DNS server (default "8.8.8.8:53")
  -runtests
    	Run internal tests
  -socks5 string
    	SOCKS5 address and port
```
e.g.,
```bash$ ./anotherdnsproxy -socks5=:9123```

<3 to github.com/miekg/dns
