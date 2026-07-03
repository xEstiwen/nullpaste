package model

import "time"

type Paste struct {
	ID        string    `json:"id"`
	Blob      []byte    `json:"-"` // encrypted container, never exposed as raw bytes to client via JSON
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Burn      bool      `json:"burn"`
	HasDuress bool      `json:"has_duress,omitempty"`
}

type CreateRequest struct {
	Blob      string `json:"blob"` // base64-encoded encrypted container
	TTL       string `json:"ttl"`  // "5m","1h","1d","7d","30d","never"
	Burn      bool   `json:"burn"`
	HasDuress bool   `json:"has_duress"`
}

type CreateResponse struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	DeleteToken string `json:"delete_token,omitempty"`
}

type ReadResponse struct {
	Blob      string `json:"blob"` // base64-encoded encrypted container
	ExpiresAt string `json:"expires_at,omitempty"`
	Burn      bool   `json:"burn"`
}
