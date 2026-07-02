# Nullpaste

Zero-knowledge paste servisi. Şifreleme tarayıcıda AES-GCM ile yapılır, sunucu sadece opak blob depolar.

## Hızlı Başlangıç

```bash
# Binary indir (veya derle)
go build -o nullpaste ./cmd/nullpaste

# Çalıştır
./nullpaste

# Tarayıcıda aç
open http://localhost:8080
```

## Özellikler

- Zero-knowledge mimari (içerik tarayıcıda şifrelenir, sunucu göremez)
- Duress şifresi ile reddedilebilir içerik
- Burn-after-read ve TTL ile otomatik silme
- Tek statik binary, SQLite ile sıfır bağımlılık
- Gizlilik öncelikli: IP/log tutulmaz
