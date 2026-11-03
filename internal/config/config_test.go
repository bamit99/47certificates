package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "./data" {
		t.Fatalf("DataDir = %q", cfg.DataDir)
	}
	if cfg.Listen != "127.0.0.1:8080" {
		t.Fatalf("Listen = %q", cfg.Listen)
	}
}

func TestLoadRejectsNonLoopbackWithoutTLS(t *testing.T) {
	_, err := Load([]string{"--listen", "0.0.0.0:8080"}, func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadAllowsNonLoopbackWithInsecureFlag(t *testing.T) {
	cfg, err := Load([]string{"--listen", "0.0.0.0:8080", "--insecure-http"}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureHTTP {
		t.Fatal("InsecureHTTP should be set")
	}
}

func TestLoadEnvFallback(t *testing.T) {
	env := map[string]string{"47C_DATA_DIR": "/srv/47c", "47C_LISTEN": "127.0.0.1:9000"}
	cfg, err := Load(nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/srv/47c" || cfg.Listen != "127.0.0.1:9000" {
		t.Fatalf("%+v", cfg)
	}
}
