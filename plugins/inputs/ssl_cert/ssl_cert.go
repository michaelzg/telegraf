package ssl_cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

const sampleConfig = `
  ## List of local SSL files
  # files = []
  ## List of servers
  # servers = []
  ## Timeout for SSL connection
  # timeout = 5
`
const description = "Reads metrics from a SSL certificate"

// SSLCert holds the configuration of the plugin.
type SSLCert struct {
	Servers []string      `toml:"servers"`
	Files   []string      `toml:"files"`
	Timeout time.Duration `toml:"timeout"`

	// For tests
	CloseConn  bool
	UnsetCerts bool
}

// Description returns description of the plugin.
func (sc *SSLCert) Description() string {
	return description
}

// SampleConfig returns configuration sample for the plugin.
func (sc *SSLCert) SampleConfig() string {
	return sampleConfig
}

func getRemoteCert(server string, timeout time.Duration, closeConn bool, unsetCerts bool) (*x509.Certificate, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	ipConn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return nil, err
	}
	defer ipConn.Close()

	conn := tls.Client(ipConn, tlsCfg)
	defer conn.Close()

	if closeConn {
		conn.Close()
	}

	hsErr := conn.Handshake()
	if hsErr != nil {
		return nil, hsErr
	}

	certs := conn.ConnectionState().PeerCertificates

	if unsetCerts {
		certs = nil
	}

	if certs == nil || len(certs) < 1 {
		return nil, errors.New("couldn't get remote certificate")
	}

	return certs[0], nil
}

func getLocalCert(filename string) (*x509.Certificate, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func getMetrics(cert *x509.Certificate, now time.Time) map[string]interface{} {
	age := int(now.Sub(cert.NotBefore).Seconds())
	expiry := int(cert.NotAfter.Sub(now).Seconds())
	startdate := int(cert.NotBefore.Unix())
	enddate := int(cert.NotAfter.Unix())

	metrics := map[string]interface{}{
		"age":       age,
		"expiry":    expiry,
		"startdate": startdate,
		"enddate":   enddate,
	}

	return metrics
}

// Gather adds metrics and errors into the accumulator.
func (sc *SSLCert) Gather(acc telegraf.Accumulator) error {
	now := time.Now()

	for _, server := range sc.Servers {
		cert, err := getRemoteCert(server, sc.Timeout*time.Second, sc.CloseConn, sc.UnsetCerts)
		if err != nil {
			acc.AddError(fmt.Errorf("cannot get remote SSL cert '%s': %s", server, err))
			break
		}

		tags := map[string]string{
			"server": server,
		}

		fields := getMetrics(cert, now)

		acc.AddFields("ssl_cert", fields, tags)
	}

	for _, file := range sc.Files {
		cert, err := getLocalCert(file)
		if err != nil {
			acc.AddError(fmt.Errorf("cannot get local SSL cert '%s': %s", file, err))
			break
		}

		tags := map[string]string{
			"file": file,
		}

		fields := getMetrics(cert, now)

		acc.AddFields("ssl_cert", fields, tags)
	}

	return nil
}

func init() {
	inputs.Add("ssl_cert", func() telegraf.Input {
		return &SSLCert{
			Files:   []string{},
			Servers: []string{},
			Timeout: 5,
		}
	})
}
