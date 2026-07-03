# Nullpaste

> Sıfır-bilgi (zero-knowledge) paste servisi. Reddedilebilir şifreleme (plausible deniability).

İçerik tarayıcıda AES-GCM ile şifrelenir, sunucuya sadece şifreli metin gider. Sunucu **içeriği okuyamaz**, **anahtarları/şifreleri görmez**, **çözemez**. 

Duress (baskı) şifresi özelliği: bir şifre gerçek içeriği, diğer şifre sahte (decoy) içeriği gösterir. Sunucu hangisinin "gerçek" olduğunu ayırt edemez.

## Sunucuda Ne Var?

| Veri | Tutulur mu? | Açıklama |
|---|---|---|
| Şifreli içerik (AES-GCM) | Evet | Opak blob, sunucu okuyamaz |
| ID (128-bit rastgele) | Evet | Link için gerekli |
| Zaman damgaları | Evet | TTL otomatik silme için |
| Burn flag | Evet | Boolean, ilk okumada silinsin mi |
| Silme token'ı (SHA-256 hash) | Evet | Hash, düz metin değil |
| **IP adresi** | **Hayır** | Middleware'de silinir |
| **User-Agent** | **Hayır** | Loglanmaz, saklanmaz |
| **Şifre (password)** | **Hayır** | Sunucuya asla gönderilmez |
| **Şifreleme anahtarı** | **Hayır** | URL fragment'ta kalır, HTTP'e eklenmez |
| **Düz metin içerik** | **Hayır** | Yüklemeden önce şifrelenir |

## Özellikler

- **Sıfır-bilgi mimari** — şifreleme/çözme tarayıcıda, Web Crypto API ile
- **Duress şifresi** — ikinci şifreye ayrı sahte içerik tanımlama
- **Export/import ciphertext** — link yerine şifreli metni kopyala, server'sız çöz
- **Burn after read** — paste ilk okumada yok olur
- **TTL otomatik silme** — 5dk, 1sa, 1g, 7g, 30g, hiç
- **Gizlilik öncelikli** — IP loglanmaz, User-Agent saklanmaz
- **Tek binary** — SQLite gömülü, sıfır bağımlılık

## Hızlı Başlangıç

```bash
# Binary indir
curl -L -o nullpaste https://github.com/xEstiwen/nullpaste/releases/latest/download/nullpaste-linux-amd64
chmod +x nullpaste
./nullpaste

# Tarayıcıda aç
http://localhost:8080
```

## API

### Paste oluştur

```http
POST /api/paste
Content-Type: application/json

{
  "blob": "base64 şifreli konteyner",
  "ttl": "7d",
  "burn": false,
  "has_duress": false
}
```

### Paste oku

```http
GET /api/paste/:id
```

### Paste sil

```http
DELETE /api/paste/:id?token=<delete_token>
```

## Güvenlik Notları

- **Offline brute-force:** Blob'u ele geçiren saldırgan offline brute-force yapabilir. PBKDF2 600k iterasyon bunu yavaşlatır. Güçlü şifre kullanın.
- **Duress şifresi:** Kaynak kodu okuyan saldırgan iki ciphertext olduğunu görür, ama hangisinin "gerçek" olduğunu şifreler olmadan kanıtlayamaz.
- **Burn after read:** İlk GET'te içerik teslim edilir, ardından paste "yakıldı" olarak işaretlenir. İkinci GET'te 410 Gone döner.
- **IP log yok:** `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` header'ları tüm isteklerde silinir.
