Another Proxy
=============

Quick and dirty local DNS resolver and HTTP/HTTPS proxy that forwards requests over SOCKS5 (think: SSH -D9050).
```
Usage of anotherproxy:
  -alsologtostderr
        log to standard error as well as files
  -httpproxy string
        Address:port for local HTTP proxy (default "127.0.0.1:8080")
  -localdns string
        Address:port for local DNS requests (default "127.0.0.1:53")
  -log_backtrace_at value
        when logging hits line file:N, emit a stack trace (default :0)
  -log_dir string
        If non-empty, write log files in this directory
  -logtostderr
        log to standard error instead of files
  -remotedns string
        Address:port of upstream DNS servers (comma seperated for multiple values) (default "8.8.8.8:53,8.8.4.4:53")
  -socks5 string
        SOCKS5 address:port
  -stderrthreshold value
        logs at or above this threshold go to stderr
  -v value
        log level for V logs
  -vmodule value
        comma-separated list of pattern=N settings for file-filtered logging
```

e.g.,
```
./anotherproxy -socks5="127.0.0.1:9050" \
-httpproxy="192.168.1.5:8080" \
-localdns="192.168.1.5:53" \
-v=2
```

## Install notes
```
sudo setcap 'cap_net_bind_service=+ep' $GOPATH/bin/anotherproxy
```

:heart: Major thanks to github.com/miekg/dns and github.com/elazarl/goproxy
