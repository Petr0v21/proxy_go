package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"tunnel-proxy/tunnel"
)

var (
	activeMux atomic.Value // *tunnel.ServerMux
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Expose tunnel server (agent connects here)
	go runTunnelServer(":9000")

	// Expose proxies publicly (make sure you firewall this in real VPS)
	go runHTTPProxy(":8080")
	go runSOCKS5(":1080")

	select {}
}

func runTunnelServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("tunnel listen error: %v", err)
	}
	log.Printf("Tunnel server listening on %s", addr)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("tunnel accept error: %v", err)
			continue
		}

		// Replace active agent connection (lab: only one)
		if v := activeMux.Load(); v != nil {
			_ = v.(*tunnel.ServerMux).Close()
		}

		m := tunnel.NewServerMux(c)
		activeMux.Store(m)
		log.Printf("Agent connected from %s", c.RemoteAddr())
	}
}

func getMux() (*tunnel.ServerMux, error) {
	v := activeMux.Load()
	if v == nil {
		return nil, errors.New("no agent connected")
	}
	m := v.(*tunnel.ServerMux)
	if !m.Alive() {
		return nil, errors.New("agent not alive")
	}
	return m, nil
}

// -------------------- HTTP proxy (CONNECT + plain HTTP) --------------------

func runHTTPProxy(addr string) {
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           http.HandlerFunc(httpHandler),
	}
	log.Printf("HTTP proxy on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	mux, err := getMux()
	if err != nil {
		http.Error(w, "No agent connected", http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodConnect {
		handleHTTPConnect(w, r, mux)
		return
	}

	// Plain HTTP proxy request (absolute-form) or origin-form.
	handleHTTPForward(w, r, mux)
}

func handleHTTPConnect(w http.ResponseWriter, r *http.Request, mux *tunnel.ServerMux) {
	target := r.Host // host:port

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	up, err := mux.Dial(ctx, target)
	if err != nil {
		http.Error(w, "Dial via agent failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer up.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(up, clientConn); errCh <- e }()
	go func() { _, e := io.Copy(clientConn, up); errCh <- e }()
	<-errCh
}

func handleHTTPForward(w http.ResponseWriter, r *http.Request, mux *tunnel.ServerMux) {
	// For plain HTTP proxying we can use Transport with a custom DialContext.
	// Important: we must convert request into a client request:
	// - RequestURI must be empty
	// - URL must contain Scheme/Host (absolute) or we derive it from Host header
	// - hop-by-hop headers must be removed
	ctx := r.Context()

	req := r.Clone(ctx)
	req.RequestURI = ""

	// Determine destination.
	// If client uses proxy absolute-form, Go parses it into URL with Scheme/Host.
	// If client uses origin-form ("/path"), URL.Host may be empty; use Host header.
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	req.Host = req.URL.Host

	removeHopByHopHeaders(req.Header)

	tr := &http.Transport{
		Proxy: nil,
		// Network will be "tcp" (for http) most of the time.
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			// addr is "host:port". If port is missing, add default.
			host, port, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				// Might be missing port; assume 80
				host = addr
				port = "80"
			}
			target := net.JoinHostPort(host, port)
			return mux.Dial(dctx, target)
		},
		DisableCompression:  false,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   false, // keep it simple for the lab
		ResponseHeaderTimeout: 30 * time.Second,
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		http.Error(w, "Upstream request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	// Remove headers listed in "Connection" header too.
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		// Replace to be safe; typical proxy behavior.
		dst.Del(k)
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// -------------------- SOCKS5 proxy (no auth, CONNECT only) --------------------

func runSOCKS5(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("socks listen error: %v", err)
	}
	log.Printf("SOCKS5 proxy on %s", addr)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("socks accept error: %v", err)
			continue
		}
		go handleSocksConn(c)
	}
}

func handleSocksConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(c)

	// Greeting: VER, NMETHODS, METHODS
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		return
	}
	if h[0] != 0x05 {
		return
	}
	n := int(h[1])
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	// Choose no-auth if offered
	chosen := byte(0xFF)
	for _, m := range methods {
		if m == 0x00 {
			chosen = 0x00
			break
		}
	}
	_, _ = c.Write([]byte{0x05, chosen})
	if chosen == 0xFF {
		return
	}

	// Request: VER, CMD, RSV, ATYP
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	cmd := req[1]
	atyp := req[3]
	if cmd != 0x01 {
		_ = socksReply(c, 0x07) // Command not supported
		return
	}

	host, port, err := socksReadAddr(br, atyp)
	if err != nil {
		_ = socksReply(c, 0x08)
		return
	}

	mux, err := getMux()
	if err != nil {
		_ = socksReply(c, 0x01)
		return
	}

	target := net.JoinHostPort(host, port)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	up, err := mux.Dial(ctx, target)
	if err != nil {
		_ = socksReply(c, 0x04) // Host unreachable (approx)
		return
	}
	defer up.Close()

	_ = c.SetDeadline(time.Time{})

	// Success reply: VER REP RSV ATYP BND.ADDR BND.PORT (we send 0.0.0.0:0)
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(up, c); errCh <- e }()
	go func() { _, e := io.Copy(c, up); errCh <- e }()
	<-errCh
}

func socksReply(c net.Conn, rep byte) error {
	// Minimal: 0.0.0.0:0
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func socksReadAddr(r *bufio.Reader, atyp byte) (host string, port string, err error) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // DOMAIN
		l, e := r.ReadByte()
		if e != nil {
			return "", "", e
		}
		b := make([]byte, int(l))
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	default:
		return "", "", errors.New("unsupported atyp")
	}

	pb := make([]byte, 2)
	if _, err = io.ReadFull(r, pb); err != nil {
		return
	}
	p := binary.BigEndian.Uint16(pb)
	port = fmt.Sprintf("%d", p)

	host = strings.TrimSpace(host)
	return
}
