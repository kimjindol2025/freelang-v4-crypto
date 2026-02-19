# 🔐 FreeLang v4 Cryptography & Security System

**Comprehensive Cryptography & Security for FreeLang v4**

완벽하게 테스트된 고급 암호화 및 보안 시스템입니다.

---

## ✨ 주요 기능

### 1️⃣ Hash Algorithms (MD5, SHA1, SHA256, SHA512)
- Multiple hash algorithm support
- Fast hashing with verification
- Constant-time comparison (timing attack prevention)

### 2️⃣ AES-256 Encryption (CBC/GCM)
- AES-256-CBC (Cipher Block Chaining)
- AES-256-GCM (Galois/Counter Mode with authentication)
- Key derivation from passwords
- Authenticated encryption with AAD

### 3️⃣ RSA 2048-bit Encryption & Signing
- Key pair generation
- OAEP & PKCS1 padding
- Digital signatures (SHA256/SHA512)
- Message verification

### 4️⃣ HMAC-SHA256 & HMAC-SHA512
- Message authentication codes
- Constant-time verification
- Support for both SHA256 and SHA512

### 5️⃣ PBKDF2 Key Derivation
- 100,000 iterations by default
- 256-bit key generation
- Password verification

### 6️⃣ Bcrypt Password Hashing
- Configurable rounds (default: 12)
- Async & sync variants
- Salt generation & verification

### 7️⃣ Argon2 Password Hashing
- Argon2i, Argon2d, Argon2id variants
- Configurable memory & time costs
- Modern password hashing standard

### 8️⃣ X509 Certificate Management
- Self-signed certificate generation
- Certificate parsing
- Expiration checking
- Validity verification

### 9️⃣ TLS/SSL Configuration
- Server & client TLS connections
- Session info retrieval
- Cipher & version support
- Certificate validation

### 🔟 System Statistics & Monitoring
- Operation tracking
- Average execution times
- Algorithm-specific metrics
- Performance reporting

---

## 📊 성능

| 항목 | 성능 |
|------|------|
| **MD5 해시** | < 1ms |
| **SHA256 해시** | < 2ms |
| **AES-256-CBC 암호화** | < 5ms |
| **RSA-2048 암호화** | 50-100ms |
| **Bcrypt (12 rounds)** | 200-500ms |
| **Argon2id** | 500-1000ms |

---

## 🎯 빠른 시작

### 설치

```bash
npm install
npm run build
```

### 기본 사용

```typescript
import cryptoSystem from './src/crypto-system';

// 1. SHA256 해싱
const hash = cryptoSystem.hash.sha256('hello world');
console.log(hash.hex);

// 2. AES-256-CBC 암호화
const key = cryptoSystem.aes.generateKey(256);
const encrypted = cryptoSystem.aes.encryptCBC('secret data', key);
const decrypted = cryptoSystem.aes.decryptCBC(encrypted, key);
console.log(decrypted.plaintext);

// 3. RSA 암호화 및 서명
const keyPair = cryptoSystem.rsa.generateKeyPair();
const signature = cryptoSystem.rsa.sign('message', keyPair.privateKey);
const verified = cryptoSystem.rsa.verify('message', signature, keyPair.publicKey);
console.log(verified.valid);

// 4. HMAC 인증
const hmac = cryptoSystem.hmac.sha256('data', 'secret');
const isValid = cryptoSystem.hmac.verify('data', hmac.signature, 'secret');

// 5. Bcrypt 비밀번호
const bcryptHash = cryptoSystem.kdf.bcryptSync('password123');
const isMatch = cryptoSystem.kdf.verifyBcryptSync('password123', bcryptHash.hash);

// 6. 인증서 생성
const cert = cryptoSystem.certificates.generateSelfSigned({
  commonName: 'example.com',
  organization: 'My Org',
  validityDays: 365
});

// 7. 통계 조회
const stats = cryptoSystem.getStatistics();
console.log(stats.totalHashOperations);
```

---

## 📋 API 레퍼런스

### Hash Algorithms

#### `hash.md5(data: string | Buffer): HashResult`
MD5 해시 (호환성용, 보안용 권장 안 함)

#### `hash.sha1(data: string | Buffer): HashResult`
SHA1 해시 (레거시용)

#### `hash.sha256(data: string | Buffer): HashResult`
SHA256 해시 (권장)

#### `hash.sha512(data: string | Buffer): HashResult`
SHA512 해시 (고보안용)

### AES Encryption

#### `aes.generateKey(keySize: 128 | 192 | 256): Buffer`
AES 키 생성

#### `aes.encryptCBC(plaintext: string, key: Buffer): AESEncrypted`
AES-256-CBC 암호화

#### `aes.decryptCBC(encrypted: AESEncrypted, key: Buffer): AESDecrypted`
AES-256-CBC 복호화

#### `aes.encryptGCM(plaintext: string, key: Buffer, aad?: string): AESEncrypted`
AES-256-GCM 암호화 (인증 포함)

#### `aes.decryptGCM(encrypted: AESEncrypted, key: Buffer): AESDecrypted`
AES-256-GCM 복호화 (인증 검증)

### RSA Encryption

#### `rsa.generateKeyPair(): RSAKeyPair`
RSA 2048-bit 키 쌍 생성

#### `rsa.encryptOAEP(plaintext: string, publicKey: string): RSAEncrypted`
RSA-OAEP 암호화 (권장)

#### `rsa.encryptPKCS1(plaintext: string, publicKey: string): RSAEncrypted`
RSA-PKCS1 암호화

#### `rsa.decrypt(encrypted: RSAEncrypted, privateKey: string): RSADecrypted`
RSA 복호화

#### `rsa.sign(message: string, privateKey: string): RSASignature`
RSA 디지털 서명

#### `rsa.verify(message: string, signature: RSASignature, publicKey: string): RSAVerified`
RSA 서명 검증

### HMAC

#### `hmac.sha256(message: string, secret: string): HMACResult`
HMAC-SHA256 생성

#### `hmac.sha512(message: string, secret: string): HMACResult`
HMAC-SHA512 생성

#### `hmac.verify(message: string, signature: string, secret: string): boolean`
HMAC 검증 (상수시간)

### KDF (Key Derivation Functions)

#### `kdf.pbkdf2(password: string): PBKDF2Result`
PBKDF2 키 파생 (100,000 iterations)

#### `kdf.bcryptSync(password: string, rounds?: number): BcryptResult`
Bcrypt 해싱 (동기)

#### `kdf.verifyBcryptSync(password: string, hash: string): boolean`
Bcrypt 검증 (동기)

#### `kdf.bcrypt(password: string, rounds?: number): Promise<BcryptResult>`
Bcrypt 해싱 (비동기)

#### `kdf.verifyBcrypt(password: string, hash: string): Promise<boolean>`
Bcrypt 검증 (비동기)

#### `kdf.argon2(password: string, algorithm?: string): Promise<Argon2Result>`
Argon2 해싱 (권장)

#### `kdf.verifyArgon2(password: string, hash: string): Promise<boolean>`
Argon2 검증

### Certificates

#### `certificates.generateSelfSigned(request: CertificateRequest): SignedCertificate`
자체 서명 인증서 생성

#### `certificates.isExpired(cert: string): boolean`
인증서 만료 확인

#### `certificates.getDaysUntilExpiration(cert: string): number`
만료까지의 일 수

### TLS/SSL

#### `tls.validateConfig(config: TLSConfig): boolean`
TLS 설정 검증

#### `tls.getSupportedVersions(): string[]`
지원되는 TLS 버전

#### `tls.getSupportedCiphers(): string[]`
지원되는 암호화 스위트

---

## 🧪 테스트

```bash
npm test

# 결과:
# Test Suites: 1 passed, 1 total
# Tests:       40 passed, 40 total
```

**테스트 항목**:
- ✅ MD5, SHA1, SHA256, SHA512 해싱
- ✅ AES-256-CBC 암호화/복호화
- ✅ AES-256-GCM 인증 암호화
- ✅ RSA 키 생성 및 암호화
- ✅ RSA 디지털 서명
- ✅ HMAC-SHA256/512 인증
- ✅ PBKDF2 키 파생
- ✅ Bcrypt (동기/비동기)
- ✅ Argon2 (현대 표준)
- ✅ X509 인증서 관리
- ✅ TLS/SSL 설정
- ✅ 시스템 통계 추적

---

## 🏗️ 내부 구조

### HashAlgorithms
Node.js crypto 모듈을 래핑한 해시 기능

### AESCipher
CBC/GCM 모드의 AES-256 암호화

### RSACipher
2048-bit RSA 암호화 및 서명

### HMAC
상수시간 비교를 포함한 HMAC 인증

### KDF
PBKDF2, Bcrypt, Argon2 구현

### CertificateManager
X509 인증서 생성 및 관리

### TLSManager
TLS/SSL 서버 및 클라이언트 설정

### CryptoSystem
모든 모듈의 통합 인터페이스

---

## 🔐 보안 고려사항

### 권장 알고리즘
- **해싱**: SHA256 이상 (MD5/SHA1은 호환성용만)
- **암호화**: AES-256-GCM (인증 포함)
- **키 유도**: Argon2id (최신 표준)
- **비밀번호**: Bcrypt 12 rounds 이상
- **서명**: RSA-2048 + SHA256

### 타이밍 공격 방어
- 모든 비교 연산은 상수시간 구현
- HMAC 검증은 타이밍 독립적

### 난수 생성
- crypto.randomBytes() 사용 (cryptographically secure)

---

## 📈 사용 사례

### Case 1: 사용자 인증
```typescript
// 비밀번호 저장
const userPassword = 'user_input_password';
const bcryptHash = cryptoSystem.kdf.bcryptSync(userPassword);
// DB에 bcryptHash.hash 저장

// 로그인 시 검증
const isValid = cryptoSystem.kdf.verifyBcryptSync(inputPassword, storedHash);
```

### Case 2: API 토큰 서명
```typescript
const keyPair = cryptoSystem.rsa.generateKeyPair();
const token = JSON.stringify({ userId: 123, exp: ... });
const signature = cryptoSystem.rsa.sign(token, keyPair.privateKey);
// 클라이언트에 {token, signature} 전달

// 검증
const verified = cryptoSystem.rsa.verify(token, signature, keyPair.publicKey);
```

### Case 3: 데이터 암호화 저장
```typescript
const sensitiveData = 'personal information';
const key = cryptoSystem.aes.generateKey(256);
const encrypted = cryptoSystem.aes.encryptGCM(sensitiveData, key);
// DB에 encrypted 저장, key는 안전한 곳에 보관
```

### Case 4: 메시지 인증
```typescript
const message = 'important data';
const sharedSecret = 'api_key';
const hmac = cryptoSystem.hmac.sha256(message, sharedSecret);
// 메시지와 함께 hmac.signature 전송

// 수신 측에서 검증
const isValid = cryptoSystem.hmac.verify(message, receivedHmac, sharedSecret);
```

---

## 💡 성능 최적화

### 비동기 작업
```typescript
// 느린 작업은 비동기로
const bcryptHash = await cryptoSystem.kdf.bcrypt(password);
const argon2Hash = await cryptoSystem.kdf.argon2(password);
```

### 통계 모니터링
```typescript
const stats = cryptoSystem.getStatistics();
console.log(`Average hash time: ${stats.averageHashTime}ms`);
```

---

## 🔗 저장소

**URL**: https://gogs.dclub.kr/kim/freelang-v4-crypto

---

## 📝 라이센스

MIT

---

**🎉 FreeLang v4 Cryptography System이 프로덕션 준비 완료되었습니다!**

10가지 암호화 기술로 보안을 강화하세요! 🔐
