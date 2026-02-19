#!/usr/bin/env node
/**
 * FreeLang v4 Crypto Functions — CLI 진입점
 * 제국의 방패: Hardened Security Runtime
 */

import * as fs from "fs";
import { Lexer } from "../../freelang-v4/src/lexer";
import { Parser } from "../../freelang-v4/src/parser";
import { TypeChecker } from "../../freelang-v4/src/checker";
import { Compiler } from "../../freelang-v4/src/compiler";
import { VM, Value } from "../../freelang-v4/src/vm";
import { makeCryptoHandler } from "./crypto-functions";

// ============================================================
// CryptoRunner — FreeLang 코드 실행 + Crypto 내장 함수 주입
// ============================================================

export class CryptoRunner {
  run(
    source: string,
    options: { noCheck?: boolean; dumpBc?: boolean } = {}
  ): { output: string[]; error?: string } {
    const { tokens, errors: lexErrors } = new Lexer(source).tokenize();
    if (lexErrors.length > 0) {
      return { output: [], error: lexErrors.map((e) => `lex:${e.line}: ${e.message}`).join("\n") };
    }

    const { program, errors: parseErrors } = new Parser(tokens).parse();
    if (parseErrors.length > 0) {
      return { output: [], error: parseErrors.map((e) => `parse:${e.line}: ${e.message}`).join("\n") };
    }

    if (!options.noCheck) {
      const errors = new TypeChecker().check(program);
      if (errors.length > 0) {
        return { output: [], error: errors.map((e) => `type:${e.line}: ${e.message}`).join("\n") };
      }
    }

    const chunk = new Compiler().compile(program);

    if (options.dumpBc) {
      return {
        output: [`--- bytecode (${chunk.code.length} bytes, ${chunk.functions.length} functions) ---`],
      };
    }

    // Crypto 내장 함수 monkey-patch
    const vm = new VM() as any;
    const cryptoHandler = makeCryptoHandler();
    const originalCallBuiltin = vm.callBuiltin.bind(vm);

    vm.callBuiltin = (name: string, args: Value[]): Value => {
      const result = cryptoHandler(name, args);
      if (result !== null) return result;
      return originalCallBuiltin(name, args);
    };

    return vm.run(chunk);
  }
}

// ============================================================
// CLI
// ============================================================

function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help") {
    console.log("FreeLang v4 Crypto Functions — 제국의 방패");
    console.log("Usage: ts-node src/main.ts <file.fl> [options]");
    console.log("");
    console.log("내장 함수 (5개):");
    console.log("  hash(data, algo?)          → string       [sha256|sha512|sha1|md5]");
    console.log("  hmac(data, key, algo?)     → string       [sha256|sha512]");
    console.log("  encrypt(plaintext, key)    → Result<str>  [AES-256-GCM]");
    console.log("  decrypt(ciphertext, key)   → Result<str>  [AES-256-GCM]");
    console.log("  uuid()                     → string       [UUID v4]");
    process.exit(0);
  }

  const file     = args[0];
  const noCheck  = args.includes("--no-check");
  const dumpBc   = args.includes("--dump-bc");

  let source: string;
  try {
    source = fs.readFileSync(file, "utf-8");
  } catch {
    console.error(`error: cannot read file '${file}'`);
    process.exit(1);
  }

  const runner = new CryptoRunner();
  const { output, error } = runner.run(source, { noCheck, dumpBc });
  for (const line of output) console.log(line);
  if (error) { console.error(error); process.exit(1); }
}

main();
