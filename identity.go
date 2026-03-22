package raftsecure

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	pemBlockTypeCertificate = "CERTIFICATE"
	pemBlockTypePrivateKey  = "PRIVATE KEY"
)

type Identity struct {
	TLSCertificate tls.Certificate
	Certificate    *x509.Certificate
	PublicKey      ed25519.PublicKey
	privateKey     ed25519.PrivateKey
}

func NewIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		BasicConstraintsValid: true,

		// Tolerance in regards to clock skew of nodes
		NotBefore: now.Add(-time.Minute),
		// See: RFC 5280 (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5)
		// Cite: "To indicate that a certificate has no well-defined expiration date, the notAfter SHOULD be assigned the GeneralizedTime value of 99991231235959Z."
		NotAfter: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),

		// Limit key usage to digital signature and TLS auth to prevent misuse if leaked
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},

		// Mark as CA, as each node operates as its onw root of trust, and nodes trust each other directly via public key pinning rather than a shared CA
		IsCA: true,

		// Limit SANs to allow for built-in certificate verification to succeed.
		// TODO: Make configurable and allow DNSNames
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: pemBlockTypeCertificate, Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemBlockTypePrivateKey, Bytes: privDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &Identity{
		TLSCertificate: tlsCert,
		Certificate:    cert,
		PublicKey:      pub,
		privateKey:     priv,
	}, nil
}

func LoadIdentity(certPath, keyPath string) (*Identity, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, err
	}

	privKeyBlock, _ := pem.Decode(keyPEM)
	if privKeyBlock == nil || privKeyBlock.Type != pemBlockTypePrivateKey {
		return nil, errors.New("invalid private key PEM block")
	}

	pkcs8Key, err := x509.ParsePKCS8PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	privKey, ok := pkcs8Key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ed25519")
	}

	return &Identity{
		TLSCertificate: tlsCert,
		Certificate:    cert,
		PublicKey:      privKey.Public().(ed25519.PublicKey),
		privateKey:     privKey,
	}, nil
}

func (id *Identity) Save(certPath, keyPath string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: pemBlockTypeCertificate, Bytes: id.Certificate.Raw})
	privDER, err := x509.MarshalPKCS8PrivateKey(id.privateKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemBlockTypePrivateKey, Bytes: privDER})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}
