// Package config loads runtime configuration from flags and environment.
package config

import (
	"flag"
	"fmt"
	"net"
	"strings"
)

// Config is the process-wide configuration.
type Config struct {
	DataDir       string
	Listen        string
	TLSCert       string
	TLSKey        string
	InsecureHTTP  bool
	AdminPassword string
}

// Load parses args (without the program name) and falls back to getenv for
// values not supplied on the command line.
func Load(args []string, getenv func(string) string) (Config, error) {
	cfg := Config{
		DataDir: "./data",
		Listen:  "127.0.0.1:8080",
	}

	fs := flag.NewFlagSet("47c", flag.ContinueOnError)
	fs.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "directory for the database and reports")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "address:port for the web UI")
	fs.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS certificate for the web UI")
	fs.StringVar(&cfg.TLSKey, "tls-key", "", "TLS private key for the web UI")
	fs.BoolVar(&cfg.InsecureHTTP, "insecure-http", false, "allow binding a non-loopback address over plain HTTP")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if !set["data-dir"] {
		if v := getenv("47C_DATA_DIR"); v != "" {
			cfg.DataDir = v
		}
	}
	if !set["listen"] {
		if v := getenv("47C_LISTEN"); v != "" {
			cfg.Listen = v
		}
	}
	cfg.AdminPassword = getenv("ADMIN_PASSWORD")

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.DataDir) == "" {
		return fmt.Errorf("config: data directory is empty")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("config: invalid listen address %q: %w", c.Listen, err)
	}
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if loopback {
		return nil
	}
	if c.TLSCert != "" && c.TLSKey != "" {
		return nil
	}
	if c.InsecureHTTP {
		return nil
	}
	return fmt.Errorf("config: refusing to bind %q without TLS; pass --tls-cert/--tls-key or --insecure-http", c.Listen)
}
