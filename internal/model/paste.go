package model

import "time"

type Paste struct {
	ID        string    `json:"id"`
	Blob      []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Burn      bool      `json:"burn"`
	Burned    bool      `json:"-"`
	HasDuress bool      `json:"has_duress,omitempty"`
}

type CreateRequest struct {
	Blob      string      `json:"blob"`
	TTL       string      `json:"ttl"`
	Burn      interface{} `json:"burn"`
	HasDuress interface{} `json:"has_duress"`
}

func ParseBool(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "true" || val == "1" || val == "2"
	case float64:
		return val != 0
	}
	return false
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
