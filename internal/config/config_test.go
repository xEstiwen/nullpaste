package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	for _, k := range []string{"NULLPASTE_ADDR", "NULLPASTE_DB_PATH", "NULLPASTE_MAXBYTES", "NULLPASTE_DEFAULT_TTL", "NULLPASTE_GC_INTERVAL"} {
		t.Setenv(k, "")
	}
	c := Load()
	if c.Addr != ":8080" || c.DBPath != "nullpaste.db" || c.MaxBytes != 256*1024 ||
		c.DefaultTTL != 7*24*time.Hour || c.GCInterval != time.Hour {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("NULLPASTE_ADDR", "127.0.0.1:9")
	t.Setenv("NULLPASTE_DB_PATH", "/data/x.db")
	t.Setenv("NULLPASTE_MAXBYTES", "2048")
	t.Setenv("NULLPASTE_DEFAULT_TTL", "2h")
	t.Setenv("NULLPASTE_GC_INTERVAL", "30s")
	c := Load()
	if c.Addr != "127.0.0.1:9" || c.DBPath != "/data/x.db" || c.MaxBytes != 2048 ||
		c.DefaultTTL != 2*time.Hour || c.GCInterval != 30*time.Second {
		t.Errorf("unexpected config: %+v", c)
	}
}

func TestLoadInvalidValuesFallBack(t *testing.T) {
	t.Setenv("NULLPASTE_MAXBYTES", "-5")
	t.Setenv("NULLPASTE_DEFAULT_TTL", "forever")
	t.Setenv("NULLPASTE_GC_INTERVAL", "0x")
	c := Load()
	if c.MaxBytes != 256*1024 || c.DefaultTTL != 7*24*time.Hour || c.GCInterval != time.Hour {
		t.Errorf("invalid input not rejected: %+v", c)
	}
}
