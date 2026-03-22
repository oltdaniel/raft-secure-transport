package raftsecure

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/raft"
)

var (
	errNotAdvertisable = errors.New("local bind address is not advertisable")
	errNotTCP          = errors.New("local address is not a TCP address")
)

type PinnedPublicKeys struct {
	Pool   *x509.CertPool
	hashes map[[32]byte]struct{}
}

func NewPinnedPublicKeys(peers []*Identity) (*PinnedPublicKeys, error) {
	hashes := make(map[[32]byte]struct{}, len(peers))
	pool := x509.NewCertPool()

	for _, p := range peers {
		h, err := publicKeyHash(p.TLSCertificate.Leaf)
		if err != nil {
			return nil, fmt.Errorf("pinning peer identity: %w", err)
		}
		hashes[h] = struct{}{}

		pool.AddCert(p.TLSCertificate.Leaf)
	}
	return &PinnedPublicKeys{hashes: hashes, Pool: pool}, nil
}

// publicKeyHash returns a SHA-256 digest of the DER-encoded SubjectPublicKeyInfo.
func publicKeyHash(cert *x509.Certificate) ([32]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshalling public key: %w", err)
	}
	return sha256.Sum256(spki), nil
}

func (p *PinnedPublicKeys) Verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no certificate presented")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parsing peer certificate: %w", err)
	}
	h, err := publicKeyHash(cert)
	if err != nil {
		return fmt.Errorf("hashing peer public key: %w", err)
	}
	if _, ok := p.hashes[h]; !ok {
		return errors.New("peer public key not in pinned set")
	}
	return nil
}

type TLSStreamLayer struct {
	advertise      net.Addr
	listener       net.Listener
	configListener *tls.Config
	configDialer   *tls.Config
}

func NewTLSTransport(
	bindAddr string,
	advertise net.Addr,
	identity *Identity,
	peerIdentities []*Identity,
	maxPool int,
	timeout time.Duration,
	logOutput io.Writer,
) (*raft.NetworkTransport, error) {
	return newTLSTransport(bindAddr, advertise, identity, peerIdentities, func(stream raft.StreamLayer) *raft.NetworkTransport {
		return raft.NewNetworkTransport(stream, maxPool, timeout, logOutput)
	})
}

func newTLSTransport(
	bindAddr string,
	advertise net.Addr,
	identity *Identity,
	peerIdentities []*Identity,
	transportCreator func(raft.StreamLayer) *raft.NetworkTransport,
) (*raft.NetworkTransport, error) {
	// Generate pinned public keys for peer verification
	pinned, err := NewPinnedPublicKeys(peerIdentities)
	if err != nil {
		return nil, fmt.Errorf("creating pinned public keys: %w", err)
	}

	// Generate tls config
	tlsConfigListener := generateTLSConfigListener(identity, pinned)
	tlsConfigDialer := generateTLSConfigDialer(identity, pinned)

	// Try to bind
	list, err := tls.Listen("tcp", bindAddr, tlsConfigListener)
	if err != nil {
		return nil, err
	}

	// Create stream
	stream := &TLSStreamLayer{
		advertise:      advertise,
		listener:       list,
		configListener: tlsConfigListener,
		configDialer:   tlsConfigDialer,
	}

	// Verify that we have a usable advertise address
	addr, ok := stream.Addr().(*net.TCPAddr)
	if !ok {
		_ = list.Close()
		return nil, errNotTCP
	}
	if addr.IP == nil || addr.IP.IsUnspecified() {
		_ = list.Close()
		return nil, errNotAdvertisable
	}

	// Create the network transport
	trans := transportCreator(stream)
	return trans, nil
}

func generateTLSConfigListener(identity *Identity, pinned *PinnedPublicKeys) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{identity.TLSCertificate},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinned.Verify,
	}
}

func generateTLSConfigDialer(identity *Identity, pinned *PinnedPublicKeys) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{identity.TLSCertificate},
		RootCAs:               pinned.Pool,
		VerifyPeerCertificate: pinned.Verify,
	}
}

// Dial implements the StreamLayer interface.
func (t *TLSStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", string(address), t.configDialer)
}

// Accept implements the net.Listener interface.
func (t *TLSStreamLayer) Accept() (c net.Conn, err error) {
	return t.listener.Accept()
}

// Close implements the net.Listener interface.
func (t *TLSStreamLayer) Close() (err error) {
	return t.listener.Close()
}

// Addr implements the net.Listener interface.
func (t *TLSStreamLayer) Addr() net.Addr {
	// Use an advertise addr if provided
	if t.advertise != nil {
		return t.advertise
	}
	return t.listener.Addr()
}
