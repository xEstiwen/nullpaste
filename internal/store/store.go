package store

import (
	"time"

	"nullpaste/internal/model"
)

type Store interface {
	Create(p *model.Paste) (deleteToken string, err error)
	Get(id string) (*model.Paste, error)
	Delete(id string) error
	// Burn reports true for exactly one caller per paste
	Burn(id string) (bool, error)
	Sweep(before time.Time) (int, error)
	DeleteTokenValid(id, token string) bool
	Close() error
}
