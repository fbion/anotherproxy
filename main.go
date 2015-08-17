package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"log"
	"runtime"
	"time"
)

/*

Other miekg/dns implementations:
- https://github.com/d2g/dnsforwarder
- https://github.com/googollee/dnsproxy/blob/master/client.go

TODO: print some stats every 5min?

*/

var (
	address      = flag.String("address", "127.0.0.1:53", "Address to listen to (TCP and UDP)")
	socks5Proxy  = flag.String("socks5", "", "SOCKS5 address and port")
	proxySideDNS = flag.String("proxydns", "8.8.8.8:53", "Proxy-side DNS server")
)

var (
	_proxyChan chan proxyRequest
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
	req          *dns.Msg
	responseChan chan proxyResponse
}

func proxyWorkerFunc(done chan proxyResponse, req *dns.Msg) {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9123", nil, proxy.Direct)
	if err != nil {
		done <- proxyResponse{nil, err}
		return
	}
	proxyCon, err := dialer.Dial("tcp", *proxySideDNS)
	if err != nil {
		done <- proxyResponse{nil, err}
		return
	}
	defer func() {
		if err = proxyCon.Close(); err != nil {
			panic(err)
		}
	}()

	if isTransfer(req) {
		err := errors.New("isTransfer==true! handle this!")
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

	co := &dns.Conn{Conn: proxyCon}
	if err := co.WriteMsg(req); err != nil {
		done <- proxyResponse{nil, err}
		return
	}
	resp, err := co.ReadMsg()
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
}

func proxyWorker(c chan proxyRequest) {
	for req := range c {
		/*
			edge-case: it's possible two responses can be sent IF our timer expires,
			and the DNS exchange actually finishes after..  we only need to relay
			the first, the second will be GC'd
		*/
		done := make(chan proxyResponse, 2)
		go proxyWorkerFunc(done, req.req)

		select {
		case <-time.After(10 * time.Second):
			err := errors.New("some kind of timeout!")
			req.responseChan <- proxyResponse{nil, err}
		case r := <-done:
			req.responseChan <- r
		}
	}
}

// TODO: Consider singleflight!
func route(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		log.Print("ERROR: len(req.Question)==0")
		dns.HandleFailed(w, req)
		return
	}

	responseChan := make(chan proxyResponse, 0)
	_proxyChan <- proxyRequest{req, responseChan}
	x := <-responseChan
	close(responseChan)

	if x.err != nil {
		log.Print("ERROR: " + x.err.Error())
		dns.HandleFailed(w, req)
		return
	}

	if err := w.WriteMsg(x.Msg); err != nil {
		log.Print("ERROR:" + err.Error())
		dns.HandleFailed(w, req)
		return
	}
	////log.Print(x.Msg.String())
}

// Test with:
// bash$ nslookup github.com. 127.0.0.1
func main() {
	flag.Parse()

	if *socks5Proxy == "" {
		log.Fatal("-socks5 is required")
	}

	numWorkers := runtime.NumCPU() * 4
	_proxyChan = make(chan proxyRequest, numWorkers)
	for i := 0; i < numWorkers; i++ {
		go proxyWorker(_proxyChan)
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
	dns.HandleFunc(".", route)
	go func() {
		log.Fatal(udpServer.ListenAndServe())
	}()
	log.Fatal(tcpServer.ListenAndServe())
}
