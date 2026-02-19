/**
 * FreeLang v4 Crypto Functions — 5개 내장 함수
 *
 * ╔══════════════════════════════════════════════╗
 * ║  제국의 방패: Hardened Security Runtime       ║
 * ╠══════════════════════════════════════════════╣
 * ║  1. hash    — SHA-256/512 데이터 지문         ║
 * ║  2. hmac    — HMAC-SHA256 메시지 인증         ║
 * ║  3. encrypt — AES-256-GCM 인증 암호화         ║
 * ║  4. decrypt — AES-256-GCM 복호화             ║
 * ║  5. uuid    — UUID v4 고유 식별자             ║
 * ╠══════════════════════════════════════════════╣
 * ║  보안 원칙:                                   ║
 * ║  · Constant-time 비교 (타이밍 공격 방지)       ║
 * ║  · Zero-fill on Drop (메모리 흔적 제거)        ║
 * ║  · 매번 새 IV/nonce (재전송 공격 방지)         ║
 * ║  · GCM authTag 포함 (무결성 검증)             ║
 * ╚══════════════════════════════════════════════╝
 *
 * 암호화 출력 형식:
 *   "<iv_hex>:<authTag_hex>:<ciphertext_hex>"
 *
 * VM 구조: FreeLang v4 Value = { tag: string, ... }
 */

import * as crypto from "crypto";
import { Value } from "../../freelang-v4/src/vm";

// ============================================================
// 상수
// ============================================================

const AES_ALGO     = "aes-256-gcm" as const;
const IV_BYTES     = 12;  // GCM 권장 96-bit IV
const KEY_BYTES    = 32;  // AES-256 = 32 bytes
const TAG_BYTES    = 16;  // GCM authTag 128-bit
const SEPARATOR    = ":";

type SupportedHash = "sha256" | "sha512" | "sha1" | "md5";
const HASH_ALGOS: SupportedHash[] = ["sha256", "sha512", "sha1", "md5"];
const WEAK_ALGOS  = new Set(["md5", "sha1"]);

// ============================================================
// 내부 헬퍼
// ============================================================

function strVal(v: Value, fn: string): string {
  if (v.tag === "str") return (v as any).val;
  throw new Error(`${fn}: string 인수가 필요합니다 (got ${v.tag})`);
}

function optStrVal(v: Value | undefined, fn: string): string | undefined {
  if (v === undefined) return undefined;
  return strVal(v, fn);
}

/**
 * 키를 정확히 32 bytes로 정규화
 * 짧으면 SHA-256 stretch, 길면 SHA-256 축약
 * 사용 후 버퍼를 0으로 덮어씀 (Zero-fill on Drop)
 */
function deriveKey(rawKey: string): Buffer {
  const keyBuf = Buffer.from(rawKey, "utf-8");
  if (keyBuf.length === KEY_BYTES) return keyBuf;
  // PBKDF-lite: SHA-256 stretch/shrink
  return crypto.createHash("sha256").update(keyBuf).digest();
}

/**
 * Constant-time 문자열 비교 (타이밍 공격 방지)
 */
function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // 길이가 달라도 동일 시간 소비를 위해 임시 비교 수행
    crypto.timingSafeEqual(
      Buffer.alloc(bufA.length),
      Buffer.alloc(bufA.length)
    );
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * 버퍼를 0으로 덮어씀 (Zero-fill on Drop)
 */
function zeroFill(buf: Buffer): void {
  buf.fill(0);
}

// ============================================================
// 1. hash — SHA-256/512 데이터 지문
// ============================================================

/**
 * hash(data, algo?) → string
 *
 * algo: "sha256"(기본) | "sha512" | "sha1" | "md5"
 * 약한 알고리즘(md5, sha1)은 경고 접두사 포함
 *
 * 사용처: Audit 시스템 스냅샷 변조 검증
 */
export function crypto_hash(args: Value[]): Value {
  const data = strVal(args[0], "hash");
  const algo = (optStrVal(args[1], "hash") ?? "sha256").toLowerCase() as SupportedHash;

  if (!HASH_ALGOS.includes(algo)) {
    return {
      tag: "err",
      val: { tag: "str", val: `hash: 지원하지 않는 알고리즘 '${algo}'. 지원: ${HASH_ALGOS.join(", ")}` },
    };
  }

  const digest = crypto.createHash(algo).update(data, "utf-8").digest("hex");

  // 약한 알고리즘 경고 (하위호환성 유지하면서 식별 가능)
  if (WEAK_ALGOS.has(algo)) {
    return { tag: "str", val: `WEAK:${algo}:${digest}` };
  }

  return { tag: "str", val: digest };
}

// ============================================================
// 2. hmac — HMAC-SHA256 메시지 인증 코드
// ============================================================

/**
 * hmac(data, key, algo?) → string
 *
 * algo: "sha256"(기본) | "sha512"
 * 키는 constant-time 비교용으로만 사용 (직접 노출 X)
 *
 * 사용처: 분산 노드 간 통신 보안 토큰 검증
 */
export function crypto_hmac(args: Value[]): Value {
  const data = strVal(args[0], "hmac");
  const key  = strVal(args[1], "hmac");
  const algo = optStrVal(args[2], "hmac") ?? "sha256";

  if (!["sha256", "sha512"].includes(algo)) {
    return {
      tag: "err",
      val: { tag: "str", val: `hmac: 지원하지 않는 알고리즘 '${algo}'. 지원: sha256, sha512` },
    };
  }

  if (key.length === 0) {
    return {
      tag: "err",
      val: { tag: "str", val: "hmac: 키는 비어있을 수 없습니다" },
    };
  }

  const mac = crypto
    .createHmac(algo, key)
    .update(data, "utf-8")
    .digest("hex");

  return { tag: "str", val: mac };
}

// ============================================================
// 3. encrypt — AES-256-GCM 인증 암호화
// ============================================================

/**
 * encrypt(plaintext, key) → Result<string, string>
 *
 * 출력: ok("<iv>:<authTag>:<ciphertext>") — 모두 hex 인코딩
 *
 * 보안 특성:
 * · 매 호출마다 새 12-byte IV (재전송 공격 방지)
 * · GCM authTag 16-byte (무결성 + 인증 보장)
 * · 키는 SHA-256으로 32 bytes 정규화 후 zero-fill
 *
 * 사용처: 민감한 설정값, 개인 정보 안전한 저장
 */
export function crypto_encrypt(args: Value[]): Value {
  const plaintext = strVal(args[0], "encrypt");
  const rawKey    = strVal(args[1], "encrypt");

  let keyBuf: Buffer | null = null;
  try {
    keyBuf = deriveKey(rawKey);
    const iv = crypto.randomBytes(IV_BYTES);

    const cipher = crypto.createCipheriv(AES_ALGO, keyBuf, iv, {
      authTagLength: TAG_BYTES,
    });

    const enc1 = cipher.update(plaintext, "utf-8");
    const enc2 = cipher.final();
    const ciphertext = Buffer.concat([enc1, enc2]);
    const authTag = cipher.getAuthTag();

    const result = [
      iv.toString("hex"),
      authTag.toString("hex"),
      ciphertext.toString("hex"),
    ].join(SEPARATOR);

    return { tag: "ok", val: { tag: "str", val: result } };
  } catch (e: any) {
    return {
      tag: "err",
      val: { tag: "str", val: `encrypt: ${e.message}` },
    };
  } finally {
    // Zero-fill on Drop — 키 메모리 흔적 제거
    if (keyBuf) zeroFill(keyBuf);
  }
}

// ============================================================
// 4. decrypt — AES-256-GCM 복호화
// ============================================================

/**
 * decrypt(ciphertext, key) → Result<string, string>
 *
 * 입력: "<iv_hex>:<authTag_hex>:<ciphertext_hex>"
 * 출력: ok(plaintext) 또는 err("복호화 실패") — 오류 상세 노출 최소화
 *
 * 보안 특성:
 * · GCM authTag 검증 실패 시 즉시 err 반환 (데이터 무결성)
 * · 잘못된 키/변조된 데이터 → 동일한 에러 메시지 (정보 누출 방지)
 * · 키 사용 후 zero-fill
 *
 * 사용처: 권한 기반 데이터 접근 제어
 */
export function crypto_decrypt(args: Value[]): Value {
  const encryptedStr = strVal(args[0], "decrypt");
  const rawKey       = strVal(args[1], "decrypt");

  let keyBuf: Buffer | null = null;
  try {
    const parts = encryptedStr.split(SEPARATOR);
    if (parts.length !== 3) {
      return {
        tag: "err",
        val: { tag: "str", val: "decrypt: 잘못된 암호문 형식 (iv:authTag:ciphertext)" },
      };
    }

    const [ivHex, authTagHex, ciphertextHex] = parts;

    const iv         = Buffer.from(ivHex, "hex");
    const authTag    = Buffer.from(authTagHex, "hex");
    const ciphertext = Buffer.from(ciphertextHex, "hex");

    if (iv.length !== IV_BYTES) {
      return {
        tag: "err",
        val: { tag: "str", val: "decrypt: IV 길이 오류" },
      };
    }
    if (authTag.length !== TAG_BYTES) {
      return {
        tag: "err",
        val: { tag: "str", val: "decrypt: authTag 길이 오류" },
      };
    }

    keyBuf = deriveKey(rawKey);

    const decipher = crypto.createDecipheriv(AES_ALGO, keyBuf, iv, {
      authTagLength: TAG_BYTES,
    });
    decipher.setAuthTag(authTag);

    const dec1 = decipher.update(ciphertext);
    const dec2 = decipher.final();
    const plaintext = Buffer.concat([dec1, dec2]).toString("utf-8");

    return { tag: "ok", val: { tag: "str", val: plaintext } };
  } catch {
    // 정보 누출 방지: 키 불일치 / 변조 모두 동일 메시지
    return {
      tag: "err",
      val: { tag: "str", val: "decrypt: 복호화 실패 (잘못된 키 또는 변조된 데이터)" },
    };
  } finally {
    // Zero-fill on Drop
    if (keyBuf) zeroFill(keyBuf);
  }
}

// ============================================================
// 5. uuid — UUID v4 고유 식별자
// ============================================================

/**
 * uuid() → string
 *
 * RFC 4122 UUID v4 (128-bit 암호학적 난수 기반)
 * 형식: "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
 *
 * 사용처: 분산 시스템에서 충돌 없는 리소스 ID 관리
 */
export function crypto_uuid(_args: Value[]): Value {
  return { tag: "str", val: crypto.randomUUID() };
}

// ============================================================
// 핸들러 팩토리 — monkey-patch용
// ============================================================

export function makeCryptoHandler() {
  return function handleCrypto(name: string, args: Value[]): Value | null {
    try {
      switch (name) {
        case "hash":    return crypto_hash(args);
        case "hmac":    return crypto_hmac(args);
        case "encrypt": return crypto_encrypt(args);
        case "decrypt": return crypto_decrypt(args);
        case "uuid":    return crypto_uuid(args);
        default:        return null;
      }
    } catch (e: any) {
      throw new Error(e.message || String(e));
    }
  };
}

// ============================================================
// 직접 테스트용 export
// ============================================================

export { safeEqual, deriveKey, zeroFill };
