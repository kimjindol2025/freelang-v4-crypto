/**
 * FreeLang v4 Crypto Functions — 종합 테스트
 *
 * 케이스 구성 (총 48개):
 *   1. hash    (10개): 정확성, 알고리즘, 에지케이스
 *   2. hmac    ( 9개): 정확성, 키 관리, 에지케이스
 *   3. encrypt ( 9개): 정확성, 포맷, 보안 특성
 *   4. decrypt (10개): 라운드트립, 변조 감지, 에러 처리
 *   5. uuid    ( 5개): 포맷, 유일성, 분포
 *   6. 통합    ( 5개): 실사용 시나리오
 */

import * as crypto from "crypto";
import {
  crypto_hash, crypto_hmac,
  crypto_encrypt, crypto_decrypt,
  crypto_uuid,
  safeEqual, deriveKey, zeroFill,
} from "../src/crypto-functions";
import { Value } from "../../freelang-v4/src/vm";

// ============================================================
// 테스트 헬퍼
// ============================================================

let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (e: any) {
    console.error(`  ❌ ${name}`);
    console.error(`     ${e.message}`);
    failures.push(`${name}: ${e.message}`);
    failed++;
  }
}

function expect<T>(actual: T, expected: T, msg?: string): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) throw new Error(msg ?? `expected ${e}, got ${a}`);
}

function expectTrue(val: boolean, msg?: string): void {
  if (!val) throw new Error(msg ?? "expected true");
}

function expectFalse(val: boolean, msg?: string): void {
  if (val) throw new Error(msg ?? "expected false");
}

function str(v: Value): string { return (v as any).val; }
function tag(v: Value): string { return v.tag; }

function strArg(s: string): Value  { return { tag: "str", val: s }; }

// ============================================================
// 1. hash
// ============================================================

console.log("\n🔐 1. hash — 데이터 지문");

test("hash — SHA-256 기본값 hex 64자", () => {
  const res = crypto_hash([strArg("hello")]);
  expect(tag(res), "str");
  expect(str(res).length, 64);
});

test("hash — SHA-256 FIPS 공식 벡터 (abc)", () => {
  const res = crypto_hash([strArg("abc")]);
  // FIPS 180-4 / Node.js crypto 실측값
  const expected = crypto.createHash("sha256").update("abc").digest("hex");
  expect(str(res), expected);
  expect(str(res).length, 64);
});

test("hash — SHA-512 출력 128자", () => {
  const res = crypto_hash([strArg("test"), strArg("sha512")]);
  expect(tag(res), "str");
  expect(str(res).length, 128);
});

test("hash — 빈 문자열 sha256 (결정론적)", () => {
  const a = crypto_hash([strArg("")]);
  const b = crypto_hash([strArg("")]);
  expect(str(a), str(b));
  expect(str(a).length, 64);
});

test("hash — 1비트 차이 → 완전히 다른 값 (눈사태 효과)", () => {
  const h1 = crypto_hash([strArg("hello")]);
  const h2 = crypto_hash([strArg("hello1")]);
  expectFalse(str(h1) === str(h2), "눈사태 효과 실패");
});

test("hash — md5 약한 알고리즘 → WEAK: 접두사", () => {
  const res = crypto_hash([strArg("test"), strArg("md5")]);
  expectTrue(str(res).startsWith("WEAK:md5:"), "WEAK 접두사 없음");
});

test("hash — sha1 약한 알고리즘 → WEAK: 접두사", () => {
  const res = crypto_hash([strArg("test"), strArg("sha1")]);
  expectTrue(str(res).startsWith("WEAK:sha1:"), "WEAK 접두사 없음");
});

test("hash — 지원하지 않는 알고리즘 → err", () => {
  const res = crypto_hash([strArg("test"), strArg("rainbow")]);
  expect(tag(res), "err");
});

test("hash — 유니코드 입력 처리", () => {
  const res = crypto_hash([strArg("한글テスト🔐")]);
  expect(tag(res), "str");
  expect(str(res).length, 64);
});

test("hash — 대용량 입력 (100KB)", () => {
  const big = "A".repeat(100_000);
  const res = crypto_hash([strArg(big)]);
  expect(tag(res), "str");
  expect(str(res).length, 64);
});

// ============================================================
// 2. hmac
// ============================================================

console.log("\n🔐 2. hmac — 메시지 인증 코드");

test("hmac — SHA-256 기본 출력 hex 64자", () => {
  const res = crypto_hmac([strArg("message"), strArg("secret")]);
  expect(tag(res), "str");
  expect(str(res).length, 64);
});

test("hmac — 동일 키/데이터 → 동일 MAC (결정론적)", () => {
  const a = crypto_hmac([strArg("data"), strArg("mykey")]);
  const b = crypto_hmac([strArg("data"), strArg("mykey")]);
  expect(str(a), str(b));
});

test("hmac — 다른 키 → 다른 MAC (키 격리)", () => {
  const a = crypto_hmac([strArg("data"), strArg("key1")]);
  const b = crypto_hmac([strArg("data"), strArg("key2")]);
  expectFalse(str(a) === str(b), "키 격리 실패");
});

test("hmac — 데이터 변조 감지", () => {
  const a = crypto_hmac([strArg("original"), strArg("key")]);
  const b = crypto_hmac([strArg("tampered"), strArg("key")]);
  expectFalse(str(a) === str(b), "변조 감지 실패");
});

test("hmac — SHA-512 → 128자", () => {
  const res = crypto_hmac([strArg("msg"), strArg("key"), strArg("sha512")]);
  expect(tag(res), "str");
  expect(str(res).length, 128);
});

test("hmac — 빈 키 → err", () => {
  const res = crypto_hmac([strArg("data"), strArg("")]);
  expect(tag(res), "err");
});

test("hmac — 지원하지 않는 알고리즘 → err", () => {
  const res = crypto_hmac([strArg("data"), strArg("key"), strArg("md5")]);
  expect(tag(res), "err");
});

test("hmac — 유니코드 키", () => {
  const res = crypto_hmac([strArg("test"), strArg("비밀키🔑")]);
  expect(tag(res), "str");
  expect(str(res).length, 64);
});

test("hmac — Node.js crypto 결과와 일치", () => {
  const expected = crypto.createHmac("sha256", "key").update("data").digest("hex");
  const res = crypto_hmac([strArg("data"), strArg("key")]);
  expect(str(res), expected);
});

// ============================================================
// 3. encrypt
// ============================================================

console.log("\n🔐 3. encrypt — AES-256-GCM 암호화");

test("encrypt — ok(ciphertext) 반환", () => {
  const res = crypto_encrypt([strArg("hello"), strArg("mypassword")]);
  expect(tag(res), "ok");
});

test("encrypt — 출력 형식 iv:authTag:ciphertext (3 파트)", () => {
  const res = crypto_encrypt([strArg("hello"), strArg("key")]);
  const parts = str((res as any).val).split(":");
  expect(parts.length, 3);
});

test("encrypt — IV는 24자 hex (12 bytes)", () => {
  const res = crypto_encrypt([strArg("test"), strArg("key")]);
  const iv = str((res as any).val).split(":")[0];
  expect(iv.length, 24); // 12 bytes * 2 hex chars
});

test("encrypt — authTag는 32자 hex (16 bytes)", () => {
  const res = crypto_encrypt([strArg("test"), strArg("key")]);
  const authTag = str((res as any).val).split(":")[1];
  expect(authTag.length, 32); // 16 bytes * 2 hex chars
});

test("encrypt — 동일 입력 → 매번 다른 IV (랜덤 IV)", () => {
  const a = crypto_encrypt([strArg("same"), strArg("key")]);
  const b = crypto_encrypt([strArg("same"), strArg("key")]);
  const ivA = str((a as any).val).split(":")[0];
  const ivB = str((b as any).val).split(":")[0];
  expectFalse(ivA === ivB, "IV가 고정됨 — 재전송 공격 취약!");
});

test("encrypt — 빈 문자열 암호화 가능", () => {
  const res = crypto_encrypt([strArg(""), strArg("key")]);
  expect(tag(res), "ok");
});

test("encrypt — 유니코드 평문 암호화", () => {
  const res = crypto_encrypt([strArg("안녕하세요 🔐"), strArg("key")]);
  expect(tag(res), "ok");
});

test("encrypt — 32자 이하 키 자동 stretch", () => {
  const res = crypto_encrypt([strArg("hello"), strArg("short")]);
  expect(tag(res), "ok");
});

test("encrypt — 32자 초과 키 자동 shrink", () => {
  const longKey = "A".repeat(100);
  const res = crypto_encrypt([strArg("hello"), strArg(longKey)]);
  expect(tag(res), "ok");
});

// ============================================================
// 4. decrypt
// ============================================================

console.log("\n🔐 4. decrypt — AES-256-GCM 복호화");

test("decrypt — 라운드트립: encrypt → decrypt", () => {
  const plaintext = "제국의 기밀 데이터 🏰";
  const enc = crypto_encrypt([strArg(plaintext), strArg("mykey")]);
  const dec = crypto_decrypt([(enc as any).val, strArg("mykey")]);
  expect(tag(dec), "ok");
  expect(str((dec as any).val), plaintext);
});

test("decrypt — 빈 문자열 라운드트립", () => {
  const enc = crypto_encrypt([strArg(""), strArg("key")]);
  const dec = crypto_decrypt([(enc as any).val, strArg("key")]);
  expect(tag(dec), "ok");
  expect(str((dec as any).val), "");
});

test("decrypt — 유니코드 라운드트립", () => {
  const text = "한글테스트 日本語 🌍";
  const enc = crypto_encrypt([strArg(text), strArg("secret")]);
  const dec = crypto_decrypt([(enc as any).val, strArg("secret")]);
  expect(str((dec as any).val), text);
});

test("decrypt — 잘못된 키 → err (정보 누출 없음)", () => {
  const enc = crypto_encrypt([strArg("secret"), strArg("rightkey")]);
  const dec = crypto_decrypt([(enc as any).val, strArg("wrongkey")]);
  expect(tag(dec), "err");
  // 에러 메시지에 키 정보 노출 없음
  const errMsg = str((dec as any).val);
  expectFalse(errMsg.includes("rightkey"), "키 정보 노출!");
  expectFalse(errMsg.includes("wrongkey"), "키 정보 노출!");
});

test("decrypt — 변조된 ciphertext → err (GCM authTag 실패)", () => {
  const enc = crypto_encrypt([strArg("data"), strArg("key")]);
  const encrypted = str((enc as any).val);
  const parts = encrypted.split(":");
  // ciphertext 부분 변조
  parts[2] = "deadbeef" + parts[2].slice(8);
  const tampered: Value = { tag: "str", val: parts.join(":") };
  const dec = crypto_decrypt([tampered, strArg("key")]);
  expect(tag(dec), "err");
});

test("decrypt — 형식 오류 (파트 2개) → err", () => {
  const bad: Value = { tag: "str", val: "onlytwoparts:here" };
  const dec = crypto_decrypt([bad, strArg("key")]);
  expect(tag(dec), "err");
});

test("decrypt — 형식 오류 (빈 문자열) → err", () => {
  const bad: Value = { tag: "str", val: "" };
  const dec = crypto_decrypt([bad, strArg("key")]);
  expect(tag(dec), "err");
});

test("decrypt — 잘못된 hex IV → err", () => {
  const bad: Value = { tag: "str", val: "ZZZZZZZZZZZZZZZZZZZZZZZZ:aabbccdd11223344aabbccdd11223344:aabbcc" };
  const dec = crypto_decrypt([bad, strArg("key")]);
  expect(tag(dec), "err");
});

test("decrypt — 100KB 대용량 라운드트립", () => {
  const big = "X".repeat(100_000);
  const enc = crypto_encrypt([strArg(big), strArg("bigkey")]);
  const dec = crypto_decrypt([(enc as any).val, strArg("bigkey")]);
  expect(tag(dec), "ok");
  expect(str((dec as any).val).length, 100_000);
});

test("decrypt — 서로 다른 키로 암호화된 데이터는 교차 복호화 불가", () => {
  const enc1 = crypto_encrypt([strArg("data"), strArg("key1")]);
  const enc2 = crypto_encrypt([strArg("data"), strArg("key2")]);
  const dec  = crypto_decrypt([(enc1 as any).val, strArg("key2")]);
  expect(tag(dec), "err");
});

// ============================================================
// 5. uuid
// ============================================================

console.log("\n🔐 5. uuid — UUID v4 고유 식별자");

test("uuid — 형식: 8-4-4-4-12 (36자)", () => {
  const res = crypto_uuid([]);
  expect(tag(res), "str");
  expect(str(res).length, 36);
});

test("uuid — RFC 4122 패턴 검증", () => {
  const res = crypto_uuid([]);
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  expectTrue(uuidPattern.test(str(res)), `UUID 형식 불일치: ${str(res)}`);
});

test("uuid — 버전 비트 = 4", () => {
  const res = crypto_uuid([]);
  const version = str(res)[14]; // 15번째 문자
  expect(version, "4");
});

test("uuid — variant 비트 (8, 9, a, b 중 하나)", () => {
  const res = crypto_uuid([]);
  const variant = str(res)[19]; // 20번째 문자
  expectTrue(["8","9","a","b"].includes(variant), `variant 오류: ${variant}`);
});

test("uuid — 1000번 생성 중 중복 없음 (고유성)", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 1000; i++) {
    const id = str(crypto_uuid([]));
    if (seen.has(id)) throw new Error(`UUID 중복 발생: ${id}`);
    seen.add(id);
  }
  expect(seen.size, 1000);
});

// ============================================================
// 6. 통합 시나리오
// ============================================================

console.log("\n🏰 6. 통합 시나리오 — 제국의 방패");

test("시나리오: Audit 스냅샷 무결성 검증", () => {
  const snapshot   = JSON.stringify({ table: "users", rows: 1000, ts: 1700000000 });
  const hashA      = crypto_hash([strArg(snapshot)]);
  const hashB      = crypto_hash([strArg(snapshot)]);
  expect(str(hashA), str(hashB)); // 동일 스냅샷 → 동일 지문

  // 변조 감지
  const tampered   = snapshot.replace("1000", "999");
  const hashTamp   = crypto_hash([strArg(tampered)]);
  expectFalse(str(hashA) === str(hashTamp), "변조 감지 실패");
});

test("시나리오: 분산 노드 보안 토큰 검증 (hmac)", () => {
  const nodeKey    = "node-secret-2025";
  const payload    = JSON.stringify({ from: "node-1", action: "sync", ts: Date.now() });
  const token      = crypto_hmac([strArg(payload), strArg(nodeKey)]);

  // 수신 측 검증 (safeEqual로 constant-time 비교)
  const expected   = str(crypto_hmac([strArg(payload), strArg(nodeKey)]));
  expectTrue(safeEqual(str(token), expected), "토큰 검증 실패");

  // 위조 토큰 거부
  expectFalse(safeEqual(str(token), "fakefakefakefake".repeat(4)), "위조 토큰 통과!");
});

test("시나리오: 민감한 설정값 암호화 저장 후 접근", () => {
  const config     = JSON.stringify({ db_password: "s3cr3t!", api_key: "sk-live-abc123" });
  const masterKey  = "empire-master-key-2025";

  const encrypted  = crypto_encrypt([strArg(config), strArg(masterKey)]);
  expect(tag(encrypted), "ok");

  // 암호문에 원문이 보이지 않아야 함
  const cipherStr  = str((encrypted as any).val);
  expectFalse(cipherStr.includes("s3cr3t!"), "평문 노출!");

  // 올바른 키로 복호화
  const decrypted  = crypto_decrypt([(encrypted as any).val, strArg(masterKey)]);
  expect(tag(decrypted), "ok");
  const recovered  = JSON.parse(str((decrypted as any).val));
  expect(recovered.db_password, "s3cr3t!");
});

test("시나리오: UUID로 트랜잭션 추적", () => {
  const txId       = crypto_uuid([]);
  const auditKey   = `audit:${str(txId)}`;
  const hashInput  = `${auditKey}:${Date.now()}`;
  const fingerprint = crypto_hash([strArg(hashInput)]);

  expect(tag(txId), "str");
  expect(str(txId).length, 36);
  expect(tag(fingerprint), "str");
  expect(str(fingerprint).length, 64);
});

test("시나리오: Zero-fill on Drop — 키 버퍼 소거 확인", () => {
  const buf = Buffer.from("secret-key-12345678901234567890", "utf-8");
  const original = buf.toString("utf-8");

  zeroFill(buf);

  // 제로 채우기 후 원본 내용 없음
  expectFalse(buf.toString("utf-8").includes("secret"), "Zero-fill 실패: 키 흔적 남음!");
  expectTrue(buf.every((b) => b === 0), "Zero-fill 불완전");
});

// ============================================================
// 결과 요약
// ============================================================

const total = passed + failed;
console.log(`\n${"=".repeat(55)}`);
console.log(`테스트 결과: ${passed}/${total} 통과`);

if (failed > 0) {
  console.error(`\n실패 (${failed}개):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
} else {
  console.log("🏰 제국의 방패 — 모든 방어선 통과!");
  process.exit(0);
}
