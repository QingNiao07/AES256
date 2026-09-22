// interop_test.mjs — 移动端 ⇄ 桌面端 双向互通测试（Node 运行）。
// 用法： node mobile/tests/interop_test.mjs <io_dir>
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";
import { encryptBytesV4, decryptBytesV4, readMetaV4, isV4 } from "../www/js/v4crypto.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const here = dirname(fileURLToPath(import.meta.url));
const io = process.argv[2] ? process.argv[2] : join(here, "_io");
const PW = readFileSync(join(io, "password.txt"), "utf8");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  " + extra : ""}`);
  cond ? pass++ : fail++;
};

// 1) 桌面端生成的容器 → JS 解密
for (const tag of ["normal", "empty"]) {
  const blobPath = join(io, `py_${tag}.aes256`);
  const plainPath = join(io, `py_${tag}.plain`);
  if (!existsSync(blobPath)) { ok(`decrypt py_${tag}`, false, "缺少输入"); continue; }
  const blob = new Uint8Array(readFileSync(blobPath));
  const expect = new Uint8Array(readFileSync(plainPath));
  ok(`isV4(py_${tag})`, isV4(blob));
  const meta = readMetaV4(blob);
  ok(`meta(py_${tag}) chain`, meta.chain.join(",") === "aes-256-gcm", JSON.stringify(meta));
  try {
    const out = await decryptBytesV4(blob, PW);
    ok(`decrypt py_${tag}`, out.length === expect.length && out.every((b, i) => b === expect[i]),
      `${out.length} B`);
  } catch (e) { ok(`decrypt py_${tag}`, false, e.message); }
}

// 2) 错误密码必须失败
try {
  const blob = new Uint8Array(readFileSync(join(io, "py_normal.aes256")));
  await decryptBytesV4(blob, "wrong-password");
  ok("wrong password rejected", false);
} catch (e) { ok("wrong password rejected", true, e.message.slice(0, 40)); }

// 3) JS 加密 → 写出容器，供 Python 解密
const payload = new TextEncoder().encode("移动端 → 桌面端 互通测试 " + "X".repeat(9000));
const blob = await encryptBytesV4(payload, PW, { iterations: 200000, name: "from_mobile.txt" });
writeFileSync(join(io, "js_out.aes256"), blob);
writeFileSync(join(io, "js_out.plain"), payload);
ok("js encrypt produced v4", isV4(blob), `${blob.length} B`);

// 4) JS 自往返
const rt = await decryptBytesV4(blob, PW);
ok("js self round-trip", rt.length === payload.length && rt.every((b, i) => b === payload[i]));

// 5) 篡改检测
const tampered = blob.slice();
tampered[tampered.length - 40] ^= 0xff;
try { await decryptBytesV4(tampered, PW); ok("tamper detected", false); }
catch (e) { ok("tamper detected", true, e.message.slice(0, 40)); }

console.log(`\n结果：pass=${pass} fail=${fail}`);
process.exit(fail === 0 ? 0 : 1);
