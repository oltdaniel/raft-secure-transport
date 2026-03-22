// See https://github.com/hashicorp/raft/blob/main/tcp_transport_test.go

package raftsecure

import (
	"io"
	"net"
	"testing"

	"github.com/hashicorp/raft"
)

func TestTLSTransport_BadAddr(t *testing.T) {
	identity := newTestIdentity(t)

	_, err := NewTLSTransport("0.0.0.0:0", nil, identity, nil, 1, 0, io.Discard)
	if err != errNotAdvertisable {
		t.Fatalf("err: %v", err)
	}
}

func TestTLSTransport_EmptyAddr(t *testing.T) {
	identity := newTestIdentity(t)

	_, err := NewTLSTransport(":0", nil, identity, nil, 1, 0, io.Discard)
	if err != errNotAdvertisable {
		t.Fatalf("err: %v", err)
	}
}

func TestTLSTransport_WithAdvertise(t *testing.T) {
	identity := newTestIdentity(t)

	ips, err := net.LookupIP("localhost")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) == 0 {
		t.Fatalf("localhost did not resolve to any IPs")
	}

	addr := &net.TCPAddr{IP: ips[0], Port: 12345}
	trans, err := NewTLSTransport("0.0.0.0:0", addr, identity, nil, 1, 0, io.Discard)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer trans.Close()

	if trans.LocalAddr() != raft.ServerAddress(net.JoinHostPort(ips[0].String(), "12345")) {
		t.Fatalf("bad: %v", trans.LocalAddr())
	}
}

func newTestIdentity(t *testing.T) *Identity {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}
	return id
}
