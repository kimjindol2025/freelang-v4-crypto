# FreeLang v4 Crypto Functions

## 제국의 방패: Hardened Security Runtime

FreeLang v4 언어용 암호화 내장 함수 5개 구현

### 함수 목록

| 함수 | 시그니처 | 알고리즘 | 용도 |
|------|---------|---------|------|
| `hash` | `hash(data, algo?) → str` | SHA-256/512 | 데이터 지문, 변조 감지 |
| `hmac` | `hmac(data, key, algo?) → str` | HMAC-SHA256/512 | 메시지 인증, 토큰 검증 |
| `encrypt` | `encrypt(plain, key) → Result<str>` | AES-256-GCM | 기밀 데이터 암호화 |
| `decrypt` | `decrypt(cipher, key) → Result<str>` | AES-256-GCM | 권한 기반 복호화 |
| `uuid` | `uuid() → str` | UUID v4 | 고유 리소스 식별자 |

### 보안 원칙

- **Constant-time 비교**: `crypto.timingSafeEqual` — 타이밍 공격 방지
- **Zero-fill on Drop**: `Buffer.fill(0)` — 메모리에서 키 흔적 제거
- **랜덤 IV**: 매 encrypt마다 새 12-byte IV — 재전송 공격 방지
- **GCM authTag**: 16-byte 인증 태그 — 무결성 + 변조 감지
- **정보 누출 최소화**: 복호화 실패 시 동일 에러 메시지

### 암호화 출력 형식

```
"<iv_hex>:<authTag_hex>:<ciphertext_hex>"
  iv      = 24자 hex (12 bytes)
  authTag = 32자 hex (16 bytes)
  cipher  = 평문 비례 hex
```

## 실행

```bash
npm install
npm test     # 48/48 테스트 통과
```

## 의존성

- FreeLang v4 (`../freelang-v4`)
- Node.js 내장 `crypto` 모듈
