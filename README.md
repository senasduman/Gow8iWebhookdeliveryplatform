# Webhook Delivery Platform

Go ile PostgreSQL tabanlı, güvenilir webhook teslimat MVP'si.

## Başlatma

Create a local `.env` from `.env.example`, replacing all placeholder values with generated random values. Do not commit `.env`:

```powershell
Copy-Item .env.example .env
```

Then start the stack:

```powershell
docker compose --env-file .env up --build
```

`POST /v1/events` için `Authorization: Bearer <api-key>` ve benzersiz `Idempotency-Key` gerekir. Organizasyon, endpoint ve API key kayıtlarını PostgreSQL'e ekledikten sonra event'ler aktif endpoint'lere asenkron olarak gönderilir.

Worker'lar `FOR UPDATE SKIP LOCKED` ile işleri paylaşır. Başarısız teslimatlar exponential backoff ile tekrar denenir; 2xx dışı yanıtlar ve ağ hataları başarısız sayılır. `GET /healthz`, `GET /readyz` ve Prometheus formatında `GET /metrics` uçları mevcuttur.

Migration dosyaları `migrations/`, API sözleşmesi `openapi.yaml` içindedir. CI; test, vet ve build çalıştırır.

## Management API

### Local bootstrap

The bootstrap token is supplied through `.env` and is valid only once. After a successful bootstrap, the database marks the bootstrap state consumed and further requests return `409`. The `key` field is only returned in the creation response:

```powershell
curl.exe -X POST http://localhost:8080/v1/bootstrap/organization `
  -H "X-Bootstrap-Token: <BOOTSTRAP_TOKEN>" `
  -H "Content-Type: application/json" `
  -d '{"name":"Acme","key_name":"bootstrap"}'
```

Sonraki yönetim çağrılarında `Authorization: Bearer <key>` kullanılır:

```powershell
$auth = @{ Authorization = "Bearer <key>" }
curl.exe -X POST http://localhost:8080/v1/api-keys -H "Authorization: Bearer <key>" `
  -H "Content-Type: application/json" -d '{"name":"deployments"}'
curl.exe http://localhost:8080/v1/api-keys -H "Authorization: Bearer <key>"
curl.exe -X POST http://localhost:8080/v1/webhook-endpoints -H "Authorization: Bearer <key>" `
  -H "Content-Type: application/json" `
  -d '{"url":"https://example.com/webhooks","secret":"replace-with-at-least-16-chars"}'
```

### Production provisioning

Production'da `BOOTSTRAP_TOKEN`, `API_KEY_PEPPER` ve `WEBHOOK_ENCRYPTION_KEY` secret manager'dan inject edilmelidir. Bootstrap endpoint'i ilk başarılı provisioning'den sonra veritabanında kapanır; token'ı yeniden kullanmak mümkün değildir. Token eksikse uygulama başlamaz ve endpoint public olarak açılmaz.

API key secretleri veritabanında yalnızca pepper'lı SHA-256 hash olarak tutulur. Webhook secret'ları API seviyesinde AES-256-GCM ile şifrelenmiş ciphertext olarak tutulur; nonce ciphertext ile birlikte saklanır ve plaintext yalnızca delivery worker belleğinde kısa süreli çözülür. Encryption key loglanmaz veya API yanıtlarına dahil edilmez.

## Webhook signature verification

Her delivery şu başlıkları içerir:

```text
X-Webhook-Timestamp: 1730000000
X-Webhook-Signature: v1=4f...
```

`v1` imzası HMAC-SHA256 ile şu byte dizisi üzerinde hesaplanır:

```text
<unix_timestamp>.<exact_raw_http_body>
```

Receiver, body'yi JSON parse/re-serialize etmeden önce imzayı doğrulamalı ve timestamp için kendi allowed window kontrolünü uygulamalıdır (örneğin +/- 5 dakika). Aynı delivery ID'nin tekrar işlenmesini de receiver idempotency ile engellemelidir.

Python receiver örneği:

```python
import hashlib, hmac, time

def verify_webhook(secret: bytes, timestamp: str, signature: str,
                   raw_body: bytes, tolerance_seconds: int = 300) -> bool:
    sent_at = int(timestamp)
    if abs(int(time.time()) - sent_at) > tolerance_seconds:
        return False
    version, received = signature.split("=", 1)
    if version != "v1":
        return False
    message = timestamp.encode("ascii") + b"." + raw_body
    expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(received, expected)
```

`X-Webhook-Secret` artık varsayılan olarak gönderilmez. Eski consumer'ların güvenli geçişi için geçici olarak `.env` içinde `WEBHOOK_LEGACY_SECRET_HEADER=true` ayarlanabilir; bu durumda HMAC başlıkları yine gönderilir ve eski header yalnızca migration süresince eklenir. Tüm receiver'lar HMAC doğrulamaya geçirildikten sonra bu bayrak `false` bırakılmalıdır. Yeni consumer'lar legacy header'a bağımlı olmamalıdır.

## Receiver example and delivery semantics

Çalışan minimal receiver örneği [examples/receiver](C:/Dev/Gow8WebhookDeliveryPlatform/examples/receiver) içindedir. `schema.sql`, `receiver_deliveries.delivery_id` üzerinde persistent `PRIMARY KEY` tanımlar. Receiver önce raw body üzerinde timestamp/HMAC doğrulaması yapar, sonra delivery kaydı ve örnek event kaydını aynı PostgreSQL transaction'ında yazar. Aynı `X-Delivery-ID` ikinci kez gelirse unique constraint nedeniyle event tekrar işlenmez ve `{"status":"duplicate"}` döner.

Örneği çalıştırmak için:

```powershell
psql $env:DATABASE_URL -f examples/receiver/schema.sql
$env:RECEIVER_WEBHOOK_SECRET = "<same-secret-configured-for-the-endpoint>"
go run ./examples/receiver
```

Webhook delivery en az bir kez teslimat semantiğine sahiptir: receiver timeout'u, bağlantı hatası veya 5xx response delivery'yi retryable yapar. Retry aynı logical `X-Delivery-ID` değerini taşır; her request kendi exact body'si ve timestamp'i ile imzalanır. Tam olarak bir kez teslim veya tam olarak bir kez işleme garanti edilmez. Receiver atomic deduplication ve business operation transaction'ı ile idempotent olmalıdır.

Timestamp penceresi replay riskini azaltır, ancak tek başına replay'i tamamen engellemez. Receiver allowed window yanında delivery ID deduplication uygulamalı ve saat senkronizasyonunu sağlamalıdır.

Key rotation için yeni key version metadata'sı ve kontrollü re-encryption job'ı gerekir. Eski plaintext şemadan geçişte `002_bootstrap_state` legacy `secret` kolonunu `secret_legacy` olarak ayırır; mevcut kayıtlar, eski key ve kontrollü bakım job'ı ile ciphertext'e çevrilmeden kullanılmamalıdır. Yeni kayıtlar yalnızca encrypted kolona yazılır.
