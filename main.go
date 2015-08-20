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
	"runtime"
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
	address     = flag.String("address", "127.0.0.1:53", "Address to listen to (TCP and UDP)")
	socks5Proxy = flag.String("socks5", "", "SOCKS5 address and port")
	dnsServer   = flag.String("dns", "8.8.8.8:53", "DNS server")
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

func dial() (net.Conn, error) {
	if *socks5Proxy == "" {
		return proxy.Direct.Dial("tcp", *dnsServer)
	}
	dialer, err := proxy.SOCKS5("tcp", *socks5Proxy, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", *dnsServer)
}

func proxyWorkerFunc2(req *dns.Msg) (*dns.Msg, error) {
	// timer expiration (+1) and DNS write/read completes (+1) == 2
	done := make(chan proxyResponse, 2)

	go func() {
		// dial() can block (think: getsockopt)
		conn, err := dial()
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
		/*
			// is this necessary? what effect does it have?
			resp.RecursionAvailable = true
		*/
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

func proxyWorker(c chan proxyRequest) {
	for req := range c {
		resp, err := proxyWorkerFunc2(req.Msg)
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

// TODO: use the server pattern so we can shut it down for tests..
// TODO: tests!
// TODO: round robin remote DNS support?  i.e. use 8.8.8.8 and 8.8.4.4?
// TODO: failover DNS support?  i.e., 8.8.8.8 doesn't work, so use 8.8.4.4?
// TODO: singleflight optimization?

// Test with:
// bash$ nslookup github.com. 127.0.0.1
func main() {
	flag.Parse()

	log.Printf("Local address %v", *address)
	log.Printf("DNS server %v", *dnsServer)

	if *socks5Proxy == "" {
		log.Printf("Using direct connect (no SOCKS5 proxy specified)")
	} else {
		log.Printf("Using SOCKS5 proxy %v", *socks5Proxy)
	}

	numWorkers := runtime.NumCPU() * 4
	jobQueue := make(chan proxyRequest, numWorkers)
	for i := 0; i < numWorkers; i++ {
		go proxyWorker(jobQueue)
	}

	// default read/write timeouts are 2s
	udpServer := &dns.Server{
		Addr: *address,
		Net:  "udp",
	}
	tcpServer := &dns.Server{
		Addr: *address,
		Net:  "tcp",
	}
	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		route(w, req, jobQueue)
	})

	go func() {
		log.Fatal(udpServer.ListenAndServe())
	}()
	log.Fatal(tcpServer.ListenAndServe())
}
