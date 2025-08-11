package dns

// A DNS client implementation, modelled after http.Client

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// A Client is a DNS client. If it currently empty.
type Client struct {
	// 	Transport RoundTripper Do the RoundTripper interface?
	*Transport
}

type Transport struct {
	// DialContext specifies the dial function for creating unencrypted TCP or UDP connections.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	TLSClientConfig *tls.Config
}

var DefaultTransport = &Transport{
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 3 * time.Second,
	}),
}

func defaultTransportDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return dialer.DialContext
}

// Exchange performs a synchronous UDP query. It sends the message m to the address
// contained in a and waits for a reply. Exchange does not retry a failed query, nor
// will it fall back to TCP in case of truncation. The message's Data byffer must have been written to by
// calling m.Pack() before calling Exchange.
//
// See client.Exchange for more information on setting larger buffer sizes.
func Exchange(ctx context.Context, m *Msg, network, address string) (r *Msg, err error) {
	client := Client{Transport: DefaultTransport}
	r, _, err = client.Exchange(ctx, m, network, address)
	return r, err
}

// Exchange performs a synchronous query. It sends the message m to the address
// contained in a and waits for a reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	m.Pack()
//	resp, rtt, err := c.Exchange(m, "127.0.0.1:53")
//
// If client does not have a transport [DefaultTransport] is used.
// Exchange does not retry a failed query, nor will it fall back to TCP in case of truncation.
//
// It is up to the caller to create a message that allows for larger responses to be returned. Specifically
// this means setting [Msg.Bufsize] that will advertise a larger buffer. Messages without an Bufsize will
// fall back to the historic limit of 512 octets (bytes).
//
// The full binary data is included in the (decoded) message r. Any TSIG or SIG(0) can still be performed on
// those octets.
func (c *Client) Exchange(ctx context.Context, m *Msg, network, address string) (r *Msg, rtt time.Duration, err error) {
	var conn net.Conn
	if c.Transport == nil {
		conn, err = DefaultTransport.DialContext(ctx, network, address)
	} else {
		conn, err = c.Transport.DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	return c.ExchangeWithConn(ctx, m, conn)
}

// ExchangeWithContext behaves like Exchange, but with a supplied connection.
func (c *Client) ExchangeWithConn(ctx context.Context, m *Msg, conn net.Conn) (r *Msg, rtt time.Duration, err error) {
	t := time.Now()
	if isPacketConn(conn) {
		if _, err := conn.Write(m.Data); err != nil {
			return nil, 0, err
		}

		r = new(Msg)
		if m.UDPSize > MinMsgSize {
			r.Data = make([]byte, m.UDPSize)
		} else {
			r.Data = make([]byte, MinMsgSize)
		}
		n, err := conn.Read(r.Data)
		if err != nil {
			return nil, time.Since(t), err
		}
		r.Data = r.Data[:n]

	} else {

		msg := make([]byte, 2+len(m.Data))
		binary.BigEndian.PutUint16(msg, uint16(len(m.Data)))
		copy(msg[2:], m.Data)
		if _, err := conn.Write(msg); err != nil {
			return nil, 0, err
		}

		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return nil, time.Since(t), err
		}

		r = new(Msg)
		r.Data = make([]byte, length)
		n, err := io.ReadFull(conn, r.Data)
		if err != nil {
			return r, time.Since(t), err
		}
		if int(length) > len(r.Data) {
			return r, time.Since(t), io.ErrShortBuffer
		}
		r.Data = r.Data[:n]
	}

	err = r.Unpack()
	return r, time.Since(t), err
}

func isPacketConn(c net.Conn) bool {
	if _, ok := c.(net.PacketConn); !ok {
		return false
	}

	if ua, ok := c.LocalAddr().(*net.UnixAddr); ok {
		return ua.Net == "unixgram" || ua.Net == "unixpacket"
	}
	return true
}
