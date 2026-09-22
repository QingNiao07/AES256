// ============================================================================
// v4crypto.js — AES-256 加密工具箱 · 移动网页版（PWA）加密核心
// ----------------------------------------------------------------------------
// 与桌面端 app/core/multicipher.py（容器格式 v4）**逐字节互通**：
//   - 支持的互通子集：算法链 = [aes-256-gcm]，KDF = PBKDF2-HMAC-SHA256
//   - 头部布局、每块 (ct_len | ciphertext | tag) 、层 nonce 派生、
//     尾部 HMAC-SHA256 完整性、明文 SHA-256 校验，全部与 Python 端一致
//
// 为什么是子集：浏览器 WebCrypto 只提供 AES-GCM / ChaCha20-Poly1305 / AES-CBC，
// 不提供 Argon2id，也不提供 Camellia / CAST5 / Blowfish / 3DES。
// 因此移动端与桌面端互通时，桌面端需用 `python cli.py enc --kdf pbkdf2` 生成。
//
// 单一总密钥：密码经 PBKDF2 一次派生主密钥；层子密钥由主密钥 HKDF 域分离得到。
// 本模块同时可在浏览器（<script type="module">）与 Node（import）中运行。
// ============================================================================

const TE = new TextEncoder();
const TD = new TextDecoder();

export const CONTAINER_MAGIC = "AES256v4";
export const CONTAINER_VERSION = 4;
export const KDF_ARGON2 = 1;
export const KDF_PBKDF2 = 2;
export const DEFAULT_ITERATIONS = 600000;
export const DEFAULT_CHUNK = 4 * 1024 * 1024;
export const TAG_LEN = 16;
const MAX_NAME = 4096;

export const SUPPORTED_CHAIN = ["aes-256-gcm"];

const NONCE_INFO = TE.encode("aes256-tool::nonce::v1");
const KEY_INFO = TE.encode("aes256-tool::stack-key::v1");
const INTEGRITY_INFO = TE.encode("aes256-tool::integrity::v4");

// ---------------------------------------------------------------- 字节工具
function enc(s) { return TE.encode(s); }

function concat(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function u16(n) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, false); return b; }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, false); return b; }
function u64(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; }

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function allZero(a) { for (const x of a) if (x !== 0) return false; return true; }

export function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------- 密码学原语
export async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function hmacSha256(keyBytes, data) {
  const k = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

// HKDF-SHA256（RFC 5869）——与 app/core/kdf.py 的 hkdf() 等价
export async function hkdf(master, salt, info, length = 32) {
  const base = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info }, base, length * 8);
  return new Uint8Array(bits);
}

// 主密钥：PBKDF2-HMAC-SHA256（与 kdf.derive_master_custom(kdf_name="pbkdf2") 等价）
export async function deriveMasterPBKDF2(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    "raw", enc(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

// 层子密钥：HKDF(master, file_salt, KEY_INFO + algo + "::" + index)
// 注意：WebCrypto 的 AES-GCM 需要 CryptoKey 而非裸字节，故这里导入为密钥对象。
async function deriveLayerKey(master, fileSalt, algoId, index) {
  const info = concat(KEY_INFO, enc(algoId), enc("::"), enc(String(index)));
  const raw = await hkdf(master, fileSalt, info, 32);
  return crypto.subtle.importKey(
    "raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// 层 nonce：HMAC(file_salt, NONCE_INFO + uint64(index) + [layer] + [counter]) 迭代拼接
async function layerNonce(fileSalt, index, layer, size) {
  const msg = concat(NONCE_INFO, u64(index), new Uint8Array([layer]));
  let out = new Uint8Array(0);
  let ctr = 0;
  while (out.length < size) {
    const block = await hmacSha256(fileSalt, concat(msg, new Uint8Array([ctr])));
    out = concat(out, block);
    ctr += 1;
  }
  return out.slice(0, size);
}

// ---------------------------------------------------------------- 头部
export function buildHeader(chain, kdfSalt, fileSalt, kdfId, kdfTime, kdfMem,
                            kdfPar, kdfIters, chunkSize, origSize, origSha256, name) {
  if (kdfSalt.length !== 16 || fileSalt.length !== 16) throw new Error("盐必须 16 字节");
  const ids = chain.map((c) => enc(c));
  if (ids.length < 1 || ids.length > 255) throw new Error("算法链层数非法");
  const nameB = enc(name || "").slice(0, MAX_NAME);
  const parts = [
    enc(CONTAINER_MAGIC),
    new Uint8Array([CONTAINER_VERSION, kdfId, 0x01, 0]),
    kdfSalt, fileSalt,
    new Uint8Array([ids.length]),
  ];
  for (const id of ids) { parts.push(new Uint8Array([id.length]), id); }
  parts.push(
    u32(kdfTime), u32(kdfMem), u16(kdfPar), u32(kdfIters),
    u32(chunkSize), u64(origSize), origSha256,
    u16(nameB.length), nameB,
  );
  return concat(...parts);
}

export function parseHeader(bytes) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let off = 0;
  const magic = TD.decode(bytes.slice(0, 8));
  off = 8;
  if (magic !== CONTAINER_MAGIC) throw new Error("不是 v4 叠加加密容器（magic 不匹配）");
  const version = v.getUint8(off++);
  const kdfId = v.getUint8(off++);
  const flags = v.getUint8(off++);
  const rsv = v.getUint8(off++);
  if (version !== CONTAINER_VERSION) throw new Error("不支持的容器版本：" + version);
  const kdfSalt = bytes.slice(off, off + 16); off += 16;
  const fileSalt = bytes.slice(off, off + 16); off += 16;
  const nChain = v.getUint8(off++);
  const chain = [];
  for (let i = 0; i < nChain; i++) {
    const ln = v.getUint8(off++);
    chain.push(TD.decode(bytes.slice(off, off + ln)));
    off += ln;
  }
  const kdfTime = v.getUint32(off); off += 4;
  const kdfMem = v.getUint32(off); off += 4;
  const kdfPar = v.getUint16(off); off += 2;
  const kdfIters = v.getUint32(off); off += 4;
  const chunkSize = v.getUint32(off); off += 4;
  const origSize = Number(v.getBigUint64(off)); off += 8;
  const origSha256 = bytes.slice(off, off + 32); off += 32;
  const nameLen = v.getUint16(off); off += 2;
  const name = nameLen ? TD.decode(bytes.slice(off, off + nameLen)) : "";
  off += nameLen;
  return {
    version, kdfId, flags, kdfSalt, fileSalt, chain,
    kdfTime, kdfMem, kdfPar, kdfIters, chunkSize, origSize,
    origSha256, name, headerLen: off,
  };
}

// ---------------------------------------------------------------- 加密
export async function encryptBytesV4(data, password, opts = {}) {
  const iterations = opts.iterations || DEFAULT_ITERATIONS;
  const chunkSize = opts.chunkSize || DEFAULT_CHUNK;
  const name = opts.name || "";
  const chain = opts.chain || SUPPORTED_CHAIN;
  if (chain.length !== 1 || chain[0] !== SUPPORTED_CHAIN[0]) {
    throw new Error("移动网页版仅支持算法链 [aes-256-gcm]（WebCrypto 限制）；"
      + "请在桌面端使用 cli.py 叠加其它算法。");
  }
  const kdfSalt = crypto.getRandomValues(new Uint8Array(16));
  const fileSalt = crypto.getRandomValues(new Uint8Array(16));
  const master = await deriveMasterPBKDF2(password, kdfSalt, iterations);
  const origSha = await sha256(data);
  const header = buildHeader(chain, kdfSalt, fileSalt, KDF_PBKDF2,
    0, 0, 0, iterations, chunkSize, data.length, origSha, name);
  const layerKey = await deriveLayerKey(master, fileSalt, chain[0], 0);
  const hkey = await hkdf(master, fileSalt, INTEGRITY_INFO, 32);

  const parts = [header];
  const tailParts = [header];
  const nBlocks = Math.max(1, Math.ceil(data.length / chunkSize));
  for (let i = 0; i < nBlocks; i++) {
    const block = data.slice(i * chunkSize, (i + 1) * chunkSize);
    const nonce = await layerNonce(fileSalt, i, 0, 12);
    const aad = concat(header, u32(i), new Uint8Array([0]));
    const enc = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, layerKey, block));
    const ct = enc.slice(0, enc.length - TAG_LEN);
    const tag = enc.slice(enc.length - TAG_LEN);
    parts.push(u32(ct.length), ct, tag);
    tailParts.push(ct, tag);
  }
  parts.push(await hmacSha256(hkey, concat(...tailParts)));
  return concat(...parts);
}

// ---------------------------------------------------------------- 解密
export async function decryptBytesV4(blob, password) {
  const info = parseHeader(blob);
  if (info.kdfId !== KDF_PBKDF2) {
    throw new Error("移动网页版仅支持 PBKDF2 容器（kdf_id=" + info.kdfId
      + "，Argon2id 请用桌面端解密）");
  }
  if (info.chain.length !== 1 || info.chain[0] !== SUPPORTED_CHAIN[0]) {
    throw new Error("移动网页版仅支持算法链 [aes-256-gcm]，当前："
      + info.chain.join(" → "));
  }
  const master = await deriveMasterPBKDF2(password, info.kdfSalt,
    info.kdfIters || DEFAULT_ITERATIONS);
  const layerKey = await deriveLayerKey(master, info.fileSalt, info.chain[0], 0);
  const hkey = await hkdf(master, info.fileSalt, INTEGRITY_INFO, 32);

  const header = blob.slice(0, info.headerLen);
  const tailParts = [header];
  let off = info.headerLen;
  const chunkSize = info.chunkSize || DEFAULT_CHUNK;
  const nBlocks = Math.max(1, Math.ceil(info.origSize / chunkSize));
  let out = new Uint8Array(0);

  try {
    for (let i = 0; i < nBlocks; i++) {
      const ctLen = new DataView(blob.buffer, blob.byteOffset + off, 4).getUint32(0, false);
      off += 4;
      const ct = blob.slice(off, off + ctLen); off += ctLen;
      const tag = blob.slice(off, off + TAG_LEN); off += TAG_LEN;
      const nonce = await layerNonce(info.fileSalt, i, 0, 12);
      const aad = concat(header, u32(i), new Uint8Array([0]));
      const plain = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
        layerKey, concat(ct, tag)));
      out = concat(out, plain);
      tailParts.push(ct, tag);
    }
  } catch (e) {
    throw new Error("完整性校验失败：密码错误或文件已被篡改");
  }

  const storedTail = blob.slice(off, off + 32);
  const calcTail = await hmacSha256(hkey, concat(...tailParts));
  if (storedTail.length !== 32 || !equalBytes(storedTail, calcTail)) {
    throw new Error("整体完整性校验失败：文件已被修改或截断");
  }
  if (!allZero(info.origSha256) && !equalBytes(info.origSha256, await sha256(out))) {
    throw new Error("明文 SHA-256 与头部记录不一致：文件已损坏");
  }
  return out;
}

// ---------------------------------------------------------------- 只读元数据
export function readMetaV4(blob) {
  const info = parseHeader(blob);
  return {
    version: info.version,
    chain: info.chain,
    kdf: info.kdfId === KDF_PBKDF2 ? "pbkdf2" : "argon2id",
    iterations: info.kdfIters,
    chunk_size: info.chunkSize,
    orig_size: info.origSize,
    name: info.name,
  };
}

export function isV4(blob) {
  return blob.length >= 8 && TD.decode(blob.slice(0, 8)) === CONTAINER_MAGIC;
}
