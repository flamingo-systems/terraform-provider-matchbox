package matchbox

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	matchbox "github.com/poseidon/matchbox/matchbox/client"
)

var (
	defaultTimeout = 25 * time.Second
)

type MatchboxClient struct {
	config *Config
	client *matchbox.Client
	mutex  sync.Mutex
}

func NewMatchBoxClient(config *Config) *MatchboxClient {
	return &MatchboxClient{
		config: config,
	}
}

func (c *MatchboxClient) Get() (*matchbox.Client, error) {
	// If the client is nil, it is uninitialized.
	if c.client == nil {
		// Try to lock the mutex to make sure that we're the only ones
		// writing to the client.
		c.mutex.Lock()
		defer c.mutex.Unlock()

		// It's possible that another goroutine initialized the client
		// while we were waiting to unlock, in which case we do nothing.
		if c.client != nil {
			return c.client, nil
		}

		client, err := initMatchboxClient(c.config)
		if err != nil {
			return nil, err
		}
		c.client = client
	}

	return c.client, nil
}

// Config configures a matchbox client.
type Config struct {
	// gRPC API endpoint
	Endpoint string
	// PEM encoded TLS CA and client credentials
	CA         []byte
	ClientCert []byte
	ClientKey  []byte
}

func initMatchboxClient(config *Config) (*matchbox.Client, error) {
	tlscfg, err := tlsConfig(config.CA, config.ClientCert, config.ClientKey)
	if err != nil {
		return nil, err
	}

	// matchbox.New calls newClient(), which is the function trying to call Matchbox gRPC straight away.
	return matchbox.New(&matchbox.Config{
		Endpoints:   []string{config.Endpoint},
		DialTimeout: defaultTimeout,
		TLS:         tlscfg,
	})
}

// tlsConfig returns a matchbox client TLS.Config.
// TODO: Update matchbox TLSInfo.ClientConfig to replace this.
func tlsConfig(ca, clientCert, clientKey []byte) (*tls.Config, error) {
	// certificate authority for verifying the server
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(ca)
	if !ok {
		return nil, errors.New("no PEM certificates were parsed")
	}

	// client certificate for authentication
	cert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// CA bundle the client should trust when verifying the server
		RootCAs: pool,
		// Client certificate to authenticate to the server
		Certificates: []tls.Certificate{cert},
	}, nil
}
