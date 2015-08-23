// Quick and dirty DNS resolver with SOCKS5 proxy support
package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

/*

Other miekg/dns implementations:
- https://github.com/d2g/dnsforwarder
- https://github.com/googollee/dnsproxy/blob/master/client.go
- https://github.com/DJDNS/djdns

TODO: print some stats every 5min?
*/

var (
	_address     = flag.String("address", "127.0.0.1:53", "Address to listen to (TCP and UDP)")
	_socks5Proxy = flag.String("socks5", "", "SOCKS5 address and port")
	_dnsServer   = flag.String("dns", "8.8.8.8:53", "DNS server")
	_runTests    = flag.Bool("runtests", false, "Run internal tests")
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
		log.Print("ERROR: " + x.err.Error())
		dns.HandleFailed(w, req)
		return
	}

	// assuming miekg/dns handles possible indefinite write blocking
	if err := w.WriteMsg(x.Msg); err != nil {
		log.Print("ERROR:" + err.Error())
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
	jobQueue  chan<- proxyRequest
	udpServer *dns.Server
	tcpServer *dns.Server
	//// Errors []error?  and errorMu?  addError() func that deals with mutex?
	//// and Errors() function to get errors?...
	//// track last 100 errors by default
}

func (s *server) Shutdown() error {
	err := s.udpServer.Shutdown()
	e2 := s.tcpServer.Shutdown()
	if err != nil {
		return err
	}
	return e2
}

func (s *server) ListenAndServe() error {
	var wg sync.WaitGroup
	wg.Add(2)
	errors := make(chan error, 2)
	go func() {
		defer wg.Done()
		if err := s.udpServer.ListenAndServe(); err != nil {
			errors <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := s.tcpServer.ListenAndServe(); err != nil {
			errors <- err
		}
	}()
	wg.Wait()
	select {
	case err := <-errors:
		// ignore possible second error
		return err
	default:
		return nil
	}
}

func newServer(address, dnsServer, socks5Proxy string, numWorkers int) *server {
	log.Printf("Local address %v", address)
	log.Printf("DNS server %v", dnsServer)

	if socks5Proxy == "" {
		log.Printf("Using direct connect (no SOCKS5 proxy specified)")
	} else {
		log.Printf("Using SOCKS5 proxy %v", socks5Proxy)
	}

	dlr := &dialer{dnsServer, socks5Proxy}

	jobQueue := make(chan proxyRequest, numWorkers)
	for i := 0; i < numWorkers; i++ {
		go proxyWorker(jobQueue, dlr)
	}

	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		route(w, req, jobQueue)
	})

	// default read/write timeouts are 2s
	udpServer := &dns.Server{
		Addr:    address,
		Net:     "udp",
		Handler: serveMux,
	}
	tcpServer := &dns.Server{
		Addr:    address,
		Net:     "tcp",
		Handler: serveMux,
	}

	s := &server{
		jobQueue:  jobQueue,
		udpServer: udpServer,
		tcpServer: tcpServer,
	}
	// ignore errors; would get 'server not started' error if client never kicks
	// off server.
	runtime.SetFinalizer(s, (*server).Shutdown)
	return s
}

func runTests(s *server) error {
	errors := make(chan error, 1)
	go func() {
		errors <- s.ListenAndServe()
	}()

	// HACK/TODO: replace with onstartup notifier hooks so we know when server has started
	log.Print("testing...")
	time.Sleep(1 * time.Second)

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeSOA)

	c := new(dns.Client)
	r, _, err := c.Exchange(m, s.udpServer.Addr)
	if err != nil {
		return err
	}
	if r != nil && r.Rcode != dns.RcodeSuccess {
		err := fmt.Errorf("failed to get an valid answer\n%v", r)
		return err
	}
	select {
	case err := <-errors:
		return err
	default:
		log.Print("success!")
		return nil
	}
}

// TODO: round robin remote DNS support?  i.e. use 8.8.8.8 and 8.8.4.4?
// TODO: failover DNS support?  i.e., 8.8.8.8 doesn't work, so use 8.8.4.4?
// TODO: singleflight optimization?

// Test with:
// bash$ nslookup github.com. 127.0.0.1
func main() {
	flag.Parse()
	numWorkers := runtime.NumCPU() * 4
	s := newServer(*_address, *_dnsServer, *_socks5Proxy, numWorkers)
	if *_runTests {
		if err := runTests(s); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
