package store

import (
	"nullpaste/internal/model"
	"time"
)

type Store interface {
	Create(p *model.Paste) (deleteToken string, err error)
	Get(id string) (*model.Paste, error)
	Delete(id string) error
	Sweep(before time.Time) (int, error)
	DeleteTokenValid(id, token string) bool
	Close() error
}
