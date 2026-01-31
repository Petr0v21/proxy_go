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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"
)

// -------------------- Config --------------------

const (
	httpAddr  = "127.0.0.1:8080"
	socksAddr = "127.0.0.1:1080"
)

// -------------------- Main --------------------

func main() {
	// Shared logger prefix
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// HTTP proxy server
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           http.HandlerFunc(httpProxyHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// SOCKS5 server
	socksSrv := &Socks5Server{
		ListenAddr: socksAddr,
	}

	// Run both servers
	errCh := make(chan error, 2)

	go func() {
		log.Printf("HTTP proxy listening on http://%s\n", httpAddr)
		errCh <- httpSrv.ListenAndServe()
	}()

	go func() {
		log.Printf("SOCKS5 proxy listening on %s\n", socksAddr)
		errCh <- socksSrv.ListenAndServe()
	}()

	// Graceful shutdown on Ctrl+C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	select {
	case sig := <-stop:
		log.Printf("signal: %v, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		_ = socksSrv.Close()
	case err := <-errCh:
		// http.ListenAndServe returns http.ErrServerClosed on Shutdown; treat as normal
		if !errors.Is(err, http.ErrServerClosed) && err != nil {
			log.Fatalf("server error: %v\n", err)
		}
	}
}

// -------------------- HTTP Proxy (HTTP + CONNECT) --------------------

func httpProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleHTTPConnect(w, r)
		return
	}
	handleHTTPForward(w, r)
}

func handleHTTPConnect(w http.ResponseWriter, r *http.Request) {
	// CONNECT host:port
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to connect to target", http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Tunnel established
	_, _ = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Bi-directional copy
	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(targetConn, clientConn); errCh <- e }()
	go func() { _, e := io.Copy(clientConn, targetConn); errCh <- e }()
	<-errCh
}

func handleHTTPForward(w http.ResponseWriter, r *http.Request) {
	// Build absolute URL if needed
	outURL := r.URL
	if !outURL.IsAbs() {
		scheme := "http"
		outURL = &url.URL{
			Scheme:   scheme,
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
	}

	// Create outgoing request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusBadRequest)
		return
	}

	// Copy headers but drop hop-by-hop headers (basic correctness)
	copyHeadersDropHopByHop(outReq.Header, r.Header)

	transport := &http.Transport{
		Proxy: nil, // Avoid chaining via env proxy by accident
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 20 * time.Second,
		ForceAttemptHTTP2:     false, // Keep it simple for lab
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers/status/body
	copyHeadersDropHopByHop(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, bufio.NewReader(resp.Body))
}

func copyHeadersDropHopByHop(dst, src http.Header) {
	// RFC 7230 hop-by-hop headers
	hop := map[string]bool{
		"connection":          true,
		"proxy-connection":    true,
		"keep-alive":          true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"te":                  true,
		"trailer":             true,
		"transfer-encoding":   true,
		"upgrade":             true,
	}

	// Also remove headers listed in "Connection: ..."
	if v := src.Get("Connection"); v != "" {
		for _, f := range strings.Split(v, ",") {
			hop[strings.ToLower(strings.TrimSpace(f))] = true
		}
	}

	for k, vv := range src {
		if hop[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// -------------------- SOCKS5 (no auth, CONNECT only) --------------------

type Socks5Server struct {
	ListenAddr string
	ln         net.Listener
}

func (s *Socks5Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return err
	}
	s.ln = ln

	for {
		c, err := ln.Accept()
		if err != nil {
			// If closed, exit
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("socks accept error: %v\n", err)
			continue
		}
		go s.handleConn(c)
	}
}

func (s *Socks5Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Socks5Server) handleConn(c net.Conn) {
	defer c.Close()

	// Protect handshake
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	if err := socks5HandshakeNoAuth(c); err != nil {
		return
	}

	_ = c.SetDeadline(time.Time{})

	if err := socks5HandleRequestConnectOnly(c); err != nil {
		return
	}
}

func socks5HandshakeNoAuth(c net.Conn) error {
	// Client greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return errors.New("not SOCKS5")
	}
	n := int(hdr[1])
	if n <= 0 || n > 255 {
		return errors.New("invalid NMETHODS")
	}

	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	// Choose "no auth" if offered
	chosen := byte(0xFF)
	for _, m := range methods {
		if m == 0x00 {
			chosen = 0x00
			break
		}
	}

	// Server choice: VER, METHOD
	if _, err := c.Write([]byte{0x05, chosen}); err != nil {
		return err
	}
	if chosen == 0xFF {
		return errors.New("no acceptable auth method")
	}
	return nil
}

func socks5HandleRequestConnectOnly(c net.Conn) error {
	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return errors.New("invalid request version")
	}
	cmd := hdr[1]
	atyp := hdr[3]

	if cmd != 0x01 { // CONNECT
		_ = socks5Reply(c, 0x07, atyp, nil) // Command not supported
		return errors.New("only CONNECT supported")
	}

	host, port, err := socks5ReadDst(c, atyp)
	if err != nil {
		_ = socks5Reply(c, 0x08, atyp, nil) // Address type not supported
		return err
	}

	target := net.JoinHostPort(host, port)

	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		_ = socks5Reply(c, 0x04, atyp, nil) // Host unreachable (approx)
		return err
	}
	defer up.Close()

	// Reply success with BND.ADDR/BND.PORT = upstream local addr
	bndAtyp, bndAddrPort := socks5PackLocalBind(up.LocalAddr())
	if err := socks5Reply(c, 0x00, bndAtyp, bndAddrPort); err != nil {
		return err
	}

	// Tunnel
	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(up, c); errCh <- e }()
	go func() { _, e := io.Copy(c, up); errCh <- e }()
	<-errCh
	return nil
}

func socks5ReadDst(r io.Reader, atyp byte) (host string, port string, err error) {
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
		lb := make([]byte, 1)
		if _, err = io.ReadFull(r, lb); err != nil {
			return
		}
		l := int(lb[0])
		db := make([]byte, l)
		if _, err = io.ReadFull(r, db); err != nil {
			return
		}
		host = string(db)

	default:
		return "", "", errors.New("unsupported ATYP")
	}

	pb := make([]byte, 2)
	if _, err = io.ReadFull(r, pb); err != nil {
		return
	}
	p := binary.BigEndian.Uint16(pb)
	port = fmt.Sprintf("%d", p)
	return
}

func socks5Reply(c net.Conn, rep byte, atyp byte, addrPort []byte) error {
	// Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	if addrPort == nil {
		// Provide minimal "0.0.0.0:0" for IPv4
		atyp = 0x01
		addrPort = []byte{0, 0, 0, 0, 0, 0}
	}
	_, err := c.Write(append([]byte{0x05, rep, 0x00, atyp}, addrPort...))
	return err
}

func socks5PackLocalBind(a net.Addr) (atyp byte, addrPort []byte) {
	tcpAddr, ok := a.(*net.TCPAddr)
	if !ok {
		// Fallback: 0.0.0.0:0
		return 0x01, []byte{0, 0, 0, 0, 0, 0}
	}

	ip := tcpAddr.IP
	port := uint16(tcpAddr.Port)

	if ip.To4() != nil {
		atyp = 0x01
		addrPort = make([]byte, 0, 6)
		addrPort = append(addrPort, ip.To4()...)
		addrPort = append(addrPort, byte(port>>8), byte(port))
		return
	}

	atyp = 0x04
	addrPort = make([]byte, 0, 18)
	addrPort = append(addrPort, ip.To16()...)
	addrPort = append(addrPort, byte(port>>8), byte(port))
	return
}
