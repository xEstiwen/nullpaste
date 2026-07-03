package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr        string
	DBPath      string
	MaxBytes    int64
	DefaultTTL  time.Duration
	GCInterval  time.Duration
}

func Load() *Config {
	maxBytes, _ := strconv.ParseInt(os.Getenv("NULLPASTE_MAXBYTES"), 10, 64)
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}

	ttl := parseEnvDuration("NULLPASTE_DEFAULT_TTL", 7*24*time.Hour)
	gc := parseEnvDuration("NULLPASTE_GC_INTERVAL", time.Hour)

	return &Config{
		Addr:       getEnv("NULLPASTE_ADDR", ":8080"),
		DBPath:     getEnv("NULLPASTE_DB_PATH", "nullpaste.db"),
		MaxBytes:   maxBytes,
		DefaultTTL: ttl,
		GCInterval: gc,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
