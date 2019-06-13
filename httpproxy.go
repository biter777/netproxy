// (c) biter

package netproxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type httpProxy struct {
	user     string
	password string
	network  string
	addr     string
	forward  Dialer
	timeout  time.Duration
}

// ------------------------------------------------------------------

// bufferedConn is used when part of the data on a connection has already been
// read by a *bufio.Reader. Reads will first try and read from the
// *bufio.Reader and when everything has been read, reads will go to the
// underlying connection.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read first reads from the *bufio.Reader any data that has already been
// buffered. Once all buffered data has been read, reads go to the net.Conn.
func (bc *bufferedConn) Read(b []byte) (n int, err error) {
	if bc.reader.Buffered() > 0 {
		return bc.reader.Read(b)
	}
	return bc.Conn.Read(b)
}

// ------------------------------------------------------------------

func (s *httpProxy) dialAddr() string {
	if s.user == "" {
		return s.addr
	}

	addr := s.user
	if s.password != "" {
		addr = addr + ":" + s.password
	}

	return addr + "@" + s.addr
}

// ------------------------------------------------------------------

// Dial connects to the address addr on the given network via the HTTP/HTTPS proxy.
func (s *httpProxy) Dial(network, addr string) (net.Conn, error) {
	conn, err := s.forward.Dial(s.network, s.dialAddr())
	if err != nil {
		return nil, err
	}

	err = conn.SetDeadline(time.Now().Add(s.timeout))
	if err != nil {
		conn.Close()
		return nil, err
	}
	err = conn.SetReadDeadline(time.Now().Add(s.timeout)) 
	if err != nil {
		conn.Close()
		return nil, err
	}
	err = conn.SetWriteDeadline(time.Now().Add(s.timeout)) 
	if err != nil {
		conn.Close()
		return nil, err
	}

	if conn, err = s.connect(conn, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// ------------------------------------------------------------------

func (s *httpProxy) connect(conn net.Conn, target string) (net.Conn, error) {
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	err := connectReq.Write(conn)
	if err != nil {
		return conn, err
	}

	// Read in the response. http.ReadResponse will read in the status line, mime
	// headers, and potentially part of the response body. the body itself will
	// not be read, but kept around so it can be read later.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		return conn, err
	}
	if resp.StatusCode != http.StatusOK {
		return conn, fmt.Errorf("unable to proxy connection: %v", resp.Status)
	}

	// Return a bufferedConn that wraps a net.Conn and a *bufio.Reader. this
	// needs to be done because http.ReadResponse will buffer part of the
	// response body in the *bufio.Reader that was passed in. reads must first
	// come from anything buffered, then from the underlying connection otherwise
	// data will be lost.
	return &bufferedConn{
		Conn:   conn,
		reader: br,
	}, nil
}

// ------------------------------------------------------------------

// HTTPProxyDialer returns a Dialer that makes HTTP/HTTPS proxy connections to the given address
// with an optional username and password.
func HTTPProxyDialer(network, addr string, auth *Auth, forward Dialer, timeout time.Duration) (Dialer, error) {
	s := &httpProxy{
		network: network,
		addr:    addr,
		forward: forward,
		timeout: timeout, 
	}
	if auth != nil {
		s.user = auth.User
		s.password = auth.Password
	}

	return s, nil
}

// ------------------------------------------------------------------
// ------------------------------------------------------------------
