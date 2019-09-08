package ldap

import (
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"
	"gopkg.in/go-playground/validator.v9"
)

// Config is the configuration for connecting to LDAP server.
// Usually loaded from file.
type Config struct {
	Version int          `validate:"gte=1,lte=1"`
	Host    string       `validate:"ip|hostname|fqdn"`
	Port    int          `validate:"gte=1,lte=65535"`
	TLS     TLSConfig    `validate:"required"`
	Bind    BindConfig   `validate:"required"`
	Search  SearchConfig `validate:"required"`
}

// TLSConfig specify TLS configuration for connecting to server
type TLSConfig struct {
	Enabled              bool     `validate:"omitempty"`
	SkipCertVerification bool     `validate:"omitempty"`
	TrustedCertificates  []string `validate:"required_without=SkipCertVerification"`
}

// BindConfig is the bind request that will be send to LDAP server
type BindConfig struct {
	UserDN   string `validate:"required"`
	Password string `validate:"required"`
}

// SearchConfig specify where client allowed to search in LDAP server
type SearchConfig struct {
	Base           string `validate:"required"`
	Filter         string `validate:"required"`
	OwnerGroupDN   string `validate:"omitempty"`
	VisitorGroupDN string `validate:"omitempty"`
	LoginField     string `validate:"required"`
}

// ParseConfig parses config from specified reader
func ParseConfig(r io.Reader) (Config, error) {
	// Create initial result
	cfg := Config{}

	// Parse input to TOML
	_, err := toml.DecodeReader(r, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("failed to parse LDAP config: %v", err)
	}

	// Validate config
	err = validator.New().Struct(cfg)
	if err != nil {
		return cfg, fmt.Errorf("failed to validate LDAP config: %v", err)
	}

	return cfg, nil
}

// ParseConfigFile parses config from file in specified path
func ParseConfigFile(path string) (Config, error) {
	// Open config file
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("failed to open LDAP config: %v", err)
	}
	defer f.Close()

	return ParseConfig(f)
}
