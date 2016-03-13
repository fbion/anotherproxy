// Quick and dirty DNS resolver with SOCKS5 proxy support
package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"net/http"
	"runtime"
	"time"
)

/*

Other miekg/dns implementations:
- https://github.com/d2g/dnsforwarder
- https://github.com/googollee/dnsproxy/blob/master/client.go
- https://github.com/DJDNS/djdns

TODO: print some DNS stats every 5min?

*/

var (
	_localDNS    = flag.String("localdns", "127.0.0.1:53", "Address:port for local DNS requests")
	_socks5Proxy = flag.String("socks5", "", "SOCKS5 address:port")
	_httpProxy   = flag.String("httpproxy", "127.0.0.1:8080", "Address:port for local HTTP proxy")
	_remoteDNS   = flag.String("remotedns", "8.8.8.8:53", "Address:port of upstream DNS server")
)

func isTransfer(req *dns.Msg) bool {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeIXFR, dns.TypeAXFR:
			return true
		}
	}
	return false
}

type proxyResponse struct {
	*dns.Msg
	err error
}

type proxyRequest struct {
	*dns.Msg
	response chan proxyResponse
}

func proxyWorkerFunc(req *dns.Msg, dlr *dialer) (*dns.Msg, error) {
	// timer expiration (+1) and DNS write/read completes (+1) == 2
	done := make(chan proxyResponse, 2)

	go func() {
		// dial() can block for a few seconds;
		// actual duration can be queried by getsockopt()
		conn, err := dlr.Dial()
		if err != nil {
			done <- proxyResponse{nil, err}
			return
		}

		defer func() {
			if err := conn.Close(); err != nil {
				log.Printf("conn.Close() error: %v", err.Error())
			}
		}()

		if isTransfer(req) {
			err := errors.New("need to handle transfers!")
			done <- proxyResponse{nil, err}
			return

			/*
				// from: https://github.com/StalkR/dns-reverse-proxy
				if transport != "tcp" {
					log.Printf("ERROR: isTransfer==true and transport==", transport)
					dns.HandleFailed(w, req)
					return
				}
				t := new(dns.Transfer)
				c, err := t.In(req, addr)
				if err != nil {
					log.Print("ERROR: " + err.Error())
					dns.HandleFailed(w, req)
					return
				}
				if err = t.Out(w, req, c); err != nil {
					log.Print("ERROR: " + err.Error())
					dns.HandleFailed(w, req)
					return
				}
				return
			*/
		}

		dnsConn := &dns.Conn{Conn: conn}
		if err := dnsConn.WriteMsg(req); err != nil {
			done <- proxyResponse{nil, err}
			return
		}

		resp, err := dnsConn.ReadMsg()
		if err != nil {
			done <- proxyResponse{nil, err}
			return

		} else if resp.Id != req.Id {
			err := fmt.Errorf("ERROR: resp.Id %v != req.Id %v", resp.Id, req.Id)
			done <- proxyResponse{nil, err}
			return
		}
		resp.RecursionAvailable = true
		done <- proxyResponse{resp, nil}
	}()

	select {
	case <-time.After(10 * time.Second):
		err := errors.New("general timeout")
		return nil, err

	case r := <-done:
		return r.Msg, r.err
	}
}

func proxyWorker(c chan proxyRequest, d *dialer) {
	for req := range c {
		resp, err := proxyWorkerFunc(req.Msg, d)
		req.response <- proxyResponse{resp, err}
	}
}

func route(w dns.ResponseWriter, req *dns.Msg, jobQueue chan proxyRequest) {
	if len(req.Question) == 0 {
		log.Print("ERROR: len(req.Question)==0")
		dns.HandleFailed(w, req)
		return
	}

	responseChan := make(chan proxyResponse, 0)
	jobQueue <- proxyRequest{req, responseChan}
	x := <-responseChan
	close(responseChan)

	if x.err != nil {
		log.Printf("ERROR: %s on request %q", x.err, req)
		dns.HandleFailed(w, req)
		return
	}

	// assuming miekg/dns handles possible indefinite write blocking
	if err := w.WriteMsg(x.Msg); err != nil {
		log.Printf("ERROR WriteMsg(): %s on request %q", x.err, req)
		dns.HandleFailed(w, req)
		return
	}
	////log.Print(x.Msg.String())
}

type dialer struct {
	dnsServer   string
	socks5Proxy string
}

func (d *dialer) Dial() (net.Conn, error) {
	if d.socks5Proxy == "" {
		return proxy.Direct.Dial("tcp", d.dnsServer)
	}
	dialer, err := proxy.SOCKS5("tcp", d.socks5Proxy, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", d.dnsServer)
}

type server struct {
	jobQueue         chan<- proxyRequest
	udpServer        *dns.Server
	tcpServer        *dns.Server
	httpProxyServer  *goproxy.ProxyHttpServer
	httpProxyAddress string

	// Track and report all errors
}

/*
// BUG: Server can't fully release resources and shutdown cleanly, as HTTP Proxy subsystem doesn't have shutdown API
func (s *server) Shutdown() error {
	var errors []error
	if err := s.udpServer.Shutdown(); err != nil {
		errors = append(errors, err)
	}
	if err := s.tcpServer.Shutdown(); err != nil {
		errors = append(errors, err)
	}
	// TODO: shutdown http proxy, too!  don't know how to do this right now.

	if len(errors) > 0 {
		return errors[0]
	}
	return nil
}
*/

func (s *server) ListenAndServe() error {
	resChan := make(chan error, 4)
	go func() {
		resChan <- s.udpServer.ListenAndServe()
	}()
	go func() {
		resChan <- s.tcpServer.ListenAndServe()
	}()
	go func() {
		resChan <- http.ListenAndServe(s.httpProxyAddress, s.httpProxyServer)
	}()

	// Runtime test
	go func() {
		// Don't have elegant way to know when udp-dns/tcp-dns/http-proxy have started, so wait...
		time.Sleep(2 * time.Second)

		m := new(dns.Msg)
		m.SetQuestion("miek.nl.", dns.TypeSOA)

		c := new(dns.Client)
		r, _, err := c.Exchange(m, s.udpServer.Addr)
		if err == nil {
			if r != nil && r.Rcode != dns.RcodeSuccess {
				err = fmt.Errorf("invalid answer: %q", r)
			}
		}
		if err != nil {
			log.Printf("Quick test passed of %q", m.String())
		}
		resChan <- err
	}()

	// Return first error early, don't block on all subsystems returning
	for i := 0; i < cap(resChan); i++ {
		if err := <-resChan; err != nil {
			// ignore other potential errors in resChan
			return err
		}
	}
	return nil
}

func newServer(localDNS, remoteDNS, httpProxy, socks5Proxy string, numWorkers int) (*server, error) {
	if socks5Proxy == "" {
		return nil, errors.New("No SOCKS5 proxy specified")
	}
	if httpProxy == "" {
		return nil, errors.New("No HTTP proxy specified")
	}

	log.Printf("Using SOCKS5 proxy %v", socks5Proxy)
	log.Printf("Local DNS address %v", localDNS)
	log.Printf("Upstream DNS %v", remoteDNS)
	log.Printf("HTTP proxy address %v", httpProxy)

	dns_dialer := &dialer{remoteDNS, socks5Proxy}
	http_dialer, err := proxy.SOCKS5("tcp", socks5Proxy, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	jobQueue := make(chan proxyRequest, numWorkers)
	for i := 0; i < numWorkers; i++ {
		go proxyWorker(jobQueue, dns_dialer)
	}

	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		route(w, req, jobQueue)
	})

	// default read/write timeouts are 2s
	udpServer := &dns.Server{
		Addr:    localDNS,
		Net:     "udp",
		Handler: serveMux,
	}
	tcpServer := &dns.Server{
		Addr:    localDNS,
		Net:     "tcp",
		Handler: serveMux,
	}

	httpProxyServer := goproxy.NewProxyHttpServer()
	httpProxyServer.Tr = &http.Transport{
		Dial: http_dialer.Dial,
	}
	httpProxyServer.ConnectDial = http_dialer.Dial

	httpProxyServer.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			//r.Header.Set("X-Foo", "BarBaz")
			return r, nil
		},
	)

	s := &server{
		jobQueue:         jobQueue,
		udpServer:        udpServer,
		tcpServer:        tcpServer,
		httpProxyServer:  httpProxyServer,
		httpProxyAddress: httpProxy,
	}
	//runtime.SetFinalizer(s, (*server).Shutdown)
	return s, nil
}

// TODO: round robin remote DNS support?  i.e. use 8.8.8.8 and 8.8.4.4?
// TODO: failover DNS support?  i.e., 8.8.8.8 doesn't work, so use 8.8.4.4?
// TODO: singleflight optimization?

// Test with:
// bash$ nslookup github.com. @127.0.0.1
func main() {
	flag.Parse()
	numWorkers := runtime.NumCPU() * 4
	s, err := newServer(*_localDNS, *_remoteDNS, *_httpProxy, *_socks5Proxy, numWorkers)
	if err != nil {
		log.Fatal(err)
	}

	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
