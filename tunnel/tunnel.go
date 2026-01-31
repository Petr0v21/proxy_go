package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type FrameType byte

const (
	FOpen     FrameType = 0x01
	FOpenOK   FrameType = 0x02
	FOpenFail FrameType = 0x03
	FData     FrameType = 0x04
	FClose    FrameType = 0x05
	FPing     FrameType = 0x06
	FPong     FrameType = 0x07
)

const (
	headerLen    = 1 + 4 + 4 // type + streamID + payloadLen
	maxFrameData = 1 << 20   // 1MB per frame (lab default)
)

type frame struct {
	t   FrameType
	id  uint32
	pld []byte
}

func writeFrame(w io.Writer, f frame) error {
	if len(f.pld) > maxFrameData {
		return fmt.Errorf("payload too large: %d", len(f.pld))
	}
	h := make([]byte, headerLen)
	h[0] = byte(f.t)
	binary.BigEndian.PutUint32(h[1:5], f.id)
	binary.BigEndian.PutUint32(h[5:9], uint32(len(f.pld)))

	if _, err := w.Write(h); err != nil {
		return err
	}
	if len(f.pld) > 0 {
		_, err := w.Write(f.pld)
		return err
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var h [headerLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	t := FrameType(h[0])
	id := binary.BigEndian.Uint32(h[1:5])
	n := binary.BigEndian.Uint32(h[5:9])
	if n > maxFrameData {
		return frame{}, fmt.Errorf("payload too large: %d", n)
	}
	var p []byte
	if n > 0 {
		p = make([]byte, n)
		if _, err := io.ReadFull(r, p); err != nil {
			return frame{}, err
		}
	}
	return frame{t: t, id: id, pld: p}, nil
}

// -------------------- Multiplex: Server side API --------------------

type Dialer interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Alive() bool
	Close() error
}

type ServerMux struct {
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	writeMu  sync.Mutex
	streams  sync.Map // map[uint32]*srvStream
	nextID   uint32
	alive    atomic.Bool
	closeOnce sync.Once

	pingInterval time.Duration
}

func NewServerMux(conn net.Conn) *ServerMux {
	m := &ServerMux{
		conn:         conn,
		br:           bufio.NewReader(conn),
		bw:           bufio.NewWriter(conn),
		pingInterval: 10 * time.Second,
	}
	m.alive.Store(true)
	go m.readLoop()
	go m.pingLoop()
	return m
}

func (m *ServerMux) Alive() bool { return m.alive.Load() }

func (m *ServerMux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.alive.Store(false)
		err = m.conn.Close()
		// Close all streams
		m.streams.Range(func(k, v any) bool {
			s := v.(*srvStream)
			s.closeLocal()
			return true
		})
	})
	return err
}

func (m *ServerMux) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if !m.Alive() {
		return nil, errors.New("mux not alive")
	}

	id := atomic.AddUint32(&m.nextID, 1)
	s := newSrvStream(m, id, addr)
	m.streams.Store(id, s)

	// Send OPEN
	if err := m.send(frame{t: FOpen, id: id, pld: []byte(addr)}); err != nil {
		m.streams.Delete(id)
		s.closeLocal()
		return nil, err
	}

	// Wait OPEN_OK/FAIL or ctx cancel
	select {
	case err := <-s.openCh:
		if err != nil {
			m.streams.Delete(id)
			s.closeLocal()
			return nil, err
		}
		return s, nil
	case <-ctx.Done():
		_ = m.send(frame{t: FClose, id: id})
		m.streams.Delete(id)
		s.closeLocal()
		return nil, ctx.Err()
	}
}

func (m *ServerMux) send(f frame) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	if !m.Alive() {
		return errors.New("mux closed")
	}

	if err := writeFrame(m.bw, f); err != nil {
		return err
	}
	return m.bw.Flush()
}

func (m *ServerMux) readLoop() {
	defer m.Close()

	for {
		f, err := readFrame(m.br)
		if err != nil {
			return
		}

		switch f.t {
		case FPong:
			// ignore
		case FPing:
			_ = m.send(frame{t: FPong, id: 0})
		case FOpenOK, FOpenFail, FData, FClose:
			v, ok := m.streams.Load(f.id)
			if !ok {
				continue
			}
			s := v.(*srvStream)
			s.onFrame(f)
			if f.t == FClose {
				m.streams.Delete(f.id)
			}
		default:
			// Unknown frame type: close
			return
		}
	}
}

func (m *ServerMux) pingLoop() {
	t := time.NewTicker(m.pingInterval)
	defer t.Stop()

	for range t.C {
		if !m.Alive() {
			return
		}
		_ = m.send(frame{t: FPing, id: 0})
	}
}

// -------------------- Server stream net.Conn --------------------

type srvStream struct {
	mux   *ServerMux
	id    uint32
	addr  string

	pr *io.PipeReader
	pw *io.PipeWriter

	openCh chan error

	closed atomic.Bool
	once   sync.Once
}

func newSrvStream(mux *ServerMux, id uint32, addr string) *srvStream {
	pr, pw := io.Pipe()
	return &srvStream{
		mux:    mux,
		id:     id,
		addr:   addr,
		pr:     pr,
		pw:     pw,
		openCh: make(chan error, 1),
	}
}

func (s *srvStream) onFrame(f frame) {
	switch f.t {
	case FOpenOK:
		select {
		case s.openCh <- nil:
		default:
		}
	case FOpenFail:
		msg := "open failed"
		if len(f.pld) > 0 {
			msg = string(f.pld)
		}
		select {
		case s.openCh <- errors.New(msg):
		default:
		}
	case FData:
		// Write incoming data into pipe
		_, _ = s.pw.Write(f.pld)
	case FClose:
		s.closeLocal()
	}
}

func (s *srvStream) closeLocal() {
	s.once.Do(func() {
		s.closed.Store(true)
		_ = s.pw.Close()
		_ = s.pr.Close()
	})
}

// net.Conn interface

func (s *srvStream) Read(p []byte) (int, error)  { return s.pr.Read(p) }
func (s *srvStream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	// Send as DATA frames (chunk if needed)
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrameData {
			chunk = p[:maxFrameData]
		}
		if err := s.mux.send(frame{t: FData, id: s.id, pld: chunk}); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}
func (s *srvStream) Close() error {
	if s.closed.Load() {
		return nil
	}
	_ = s.mux.send(frame{t: FClose, id: s.id})
	s.mux.streams.Delete(s.id)
	s.closeLocal()
	return nil
}
func (s *srvStream) LocalAddr() net.Addr                { return dummyAddr("server-stream") }
func (s *srvStream) RemoteAddr() net.Addr               { return dummyAddr(s.addr) }
func (s *srvStream) SetDeadline(t time.Time) error      { return nil }
func (s *srvStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *srvStream) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "tunnel" }
func (d dummyAddr) String() string  { return string(d) }

// -------------------- Client side (phone agent) --------------------

type AgentMux struct {
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	writeMu  sync.Mutex
	streams  sync.Map // map[uint32]*agentStream
	alive    atomic.Bool
	closeOnce sync.Once
}

func NewAgentMux(conn net.Conn) *AgentMux {
	m := &AgentMux{
		conn: conn,
		br:   bufio.NewReader(conn),
		bw:   bufio.NewWriter(conn),
	}
	m.alive.Store(true)
	go m.readLoop()
	return m
}

func (m *AgentMux) Alive() bool { return m.alive.Load() }

func (m *AgentMux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.alive.Store(false)
		err = m.conn.Close()
		m.streams.Range(func(k, v any) bool {
			st := v.(*agentStream)
			st.closeBoth()
			return true
		})
	})
	return err
}

func (m *AgentMux) send(f frame) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if !m.Alive() {
		return errors.New("mux closed")
	}
	if err := writeFrame(m.bw, f); err != nil {
		return err
	}
	return m.bw.Flush()
}

func (m *AgentMux) readLoop() {
	defer m.Close()

	for {
		f, err := readFrame(m.br)
		if err != nil {
			return
		}

		switch f.t {
		case FPing:
			_ = m.send(frame{t: FPong, id: 0})
		case FOpen:
			addr := string(f.pld)
			st := newAgentStream(m, f.id, addr)
			m.streams.Store(f.id, st)
			go st.openAndRun()
		case FData, FClose:
			v, ok := m.streams.Load(f.id)
			if !ok {
				continue
			}
			st := v.(*agentStream)
			st.onFrame(f)
			if f.t == FClose {
				m.streams.Delete(f.id)
			}
		default:
			// ignore
		}
	}
}

type agentStream struct {
	mux  *AgentMux
	id   uint32
	addr string

	up net.Conn

	inCh chan []byte
	once sync.Once
}

func newAgentStream(m *AgentMux, id uint32, addr string) *agentStream {
	return &agentStream{
		mux:  m,
		id:   id,
		addr: addr,
		inCh: make(chan []byte, 64),
	}
}

func (s *agentStream) openAndRun() {
	// Dial outbound to internet
	up, err := net.DialTimeout("tcp", s.addr, 10*time.Second)
	if err != nil {
		_ = s.mux.send(frame{t: FOpenFail, id: s.id, pld: []byte(err.Error())})
		s.closeBoth()
		s.mux.streams.Delete(s.id)
		return
	}
	s.up = up

	_ = s.mux.send(frame{t: FOpenOK, id: s.id})

	// Remote -> tunnel
	go func() {
		defer func() {
			_ = s.mux.send(frame{t: FClose, id: s.id})
			s.closeBoth()
			s.mux.streams.Delete(s.id)
		}()

		buf := make([]byte, 32*1024)
		for {
			n, e := up.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if err := s.mux.send(frame{t: FData, id: s.id, pld: chunk}); err != nil {
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()

	// Tunnel -> remote
	for p := range s.inCh {
		if len(p) == 0 {
			continue
		}
		if _, err := up.Write(p); err != nil {
			break
		}
	}

	_ = s.mux.send(frame{t: FClose, id: s.id})
	s.closeBoth()
	s.mux.streams.Delete(s.id)
}

func (s *agentStream) onFrame(f frame) {
	switch f.t {
	case FData:
		// Backpressure: if channel is full, we drop and close
		select {
		case s.inCh <- f.pld:
		default:
			_ = s.mux.send(frame{t: FClose, id: s.id})
			s.closeBoth()
			s.mux.streams.Delete(s.id)
		}
	case FClose:
		s.closeBoth()
		s.mux.streams.Delete(s.id)
	}
}

func (s *agentStream) closeBoth() {
	s.once.Do(func() {
		close(s.inCh)
		if s.up != nil {
			_ = s.up.Close()
		}
	})
}

// Small helper to generate token (optional, for future)
func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
