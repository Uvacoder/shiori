package ldap

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"io/ioutil"

	"github.com/go-ldap/ldap"
	"github.com/sirupsen/logrus"
)

// Client is object that used to connect with LDAP server
type Client struct {
	Config Config
	Certs  *x509.CertPool
	conn   *ldap.Conn
}

// NewClient returns a LDAP client from given config
func NewClient(cfg Config) (*Client, error) {
	// Create initial clients and load certificates
	client := &Client{Config: cfg}
	client.Certs = x509.NewCertPool()

	for _, cert := range cfg.TLS.TrustedCertificates {
		data, err := ioutil.ReadFile(cert)
		if err != nil {
			logrus.Warnf("failed to read certificate %s: %v\n", cert, err)
			continue
		}

		if !client.Certs.AppendCertsFromPEM(data) {
			logrus.Warnf("failed to load certificate %s: %v\n", cert, err)
			continue
		}
	}

	// Connect to server
	err := client.connect()
	if err != nil {
		return client, fmt.Errorf("failed to connect to server: %v", err)
	}

	return client, nil
}

// Close closes client connection to LDAP server
func (cl *Client) Close() {
	cl.conn.Close()
}

// Search searches for a username in LDAP server
func (cl *Client) Search(username string, owner bool) (string, string, error) {
	loginField := cl.Config.Search.LoginField
	searchGroup := cl.Config.Search.VisitorGroupDN
	if owner {
		searchGroup = cl.Config.Search.OwnerGroupDN
	}

	return cl.search(username, searchGroup, loginField)
}

// VerifyDN connect, and verify the password with DN of identified user
func (cl *Client) VerifyDN(dn string, password string) error {
	err := cl.conn.Bind(dn, password)
	if err != nil {
		return fmt.Errorf("failed to bind DN: %v", err)
	}

	return nil
}

func (cl *Client) connect() error {
	// Dial the LDAP server
	ldapAddress := fmt.Sprintf("%s:%d", cl.Config.Host, cl.Config.Port)
	conn, err := ldap.Dial("tcp", ldapAddress)
	if err != nil {
		return fmt.Errorf("failed to bind LDAP: %v", err)
	}

	// If needed, start TLS
	if cl.Config.TLS.Enabled {
		var tlsConfig tls.Config

		if cl.Config.TLS.SkipCertVerification {
			logrus.Warnln("Connecting LDAP with TLS without certificate verification")
			tlsConfig = tls.Config{InsecureSkipVerify: true}
		} else {
			tlsConfig = tls.Config{
				ServerName:         cl.Config.Host,
				InsecureSkipVerify: false,
				RootCAs:            cl.Certs,
			}
		}

		err = conn.StartTLS(&tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to start TLS: %v", err)
		}
	} else {
		logrus.Warnln("Connecting LDAP without TLS")
	}

	// Bind with read only user
	err = conn.Bind(cl.Config.Bind.UserDN, cl.Config.Bind.Password)
	if err != nil {
		return fmt.Errorf("failed to bind LDAP: %v", err)
	}

	cl.conn = conn
	return nil
}

func (cl *Client) search(username string, group string, loginField string) (string, string, error) {
	// Generate search filter from username and group
	data := struct {
		Login string
		Group string
	}{username, group}

	tpl, err := template.New("filter").Parse(cl.Config.Search.Filter)
	if err != nil {
		return "", "", fmt.Errorf("failed to create user filter: %v", err)
	}

	filterBuf := bytes.NewBufferString("")
	err = tpl.Execute(filterBuf, data)
	if err != nil {
		return "", "", fmt.Errorf("failed to render user filter: %v", err)
	}

	// Generate search attribute
	attributes := []string{"dn"}
	if loginField != "" {
		attributes = append(attributes, loginField)
	}

	// Search user
	searchRequest := ldap.NewSearchRequest(
		cl.Config.Search.Base, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filterBuf.String(), // The filter to apply
		attributes,
		nil,
	)

	result, err := cl.conn.Search(searchRequest)
	if err != nil {
		return "", "", fmt.Errorf("failed to search user %s: %v", username, err)
	}

	if len(result.Entries) == 0 {
		return "", "", fmt.Errorf("user %s doesn't exist", username)
	}

	if len(result.Entries) > 1 {
		return "", "", fmt.Errorf("user %s has too many entries", username)
	}

	// Get DN of the user
	dn := result.Entries[0].DN
	if loginField != "" {
		username = result.Entries[0].GetAttributeValue(loginField)
	}

	return dn, username, nil
}
