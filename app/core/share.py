# -*- coding: utf-8 -*-
"""
app/core/share.py
=================
自解密分享页：生成一个自带解密逻辑的独立 HTML，
接收方无需安装任何软件，用浏览器输入密码即可解密。

安全设计（这是最容易做错的功能）
--------------------------------
1. 密码**绝不**写进链接、URL 片段或 HTML 属性；
2. 密文以 Base64 内嵌进 HTML（用户自行决定如何传递该 HTML）；
3. 解密完全在浏览器本地完成（WebCrypto AES-GCM），密文与密码都不出浏览器；
4. 页面不引入任何外部脚本 / CDN / 统计，可完全离线打开；
5. 默认文件名不提示内容，避免 metadata 泄露。

加密参数与 Python 端一致：
- 主密钥：本条分享页使用 PBKDF2-SHA256（浏览器原生），迭代 600000，
  因为 WebCrypto 无 Argon2；密钥长度 32 字节。
- 内容：AES-256-GCM，随机 12 字节 IV，AAD 为空。
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

PBKDF2_ITER = 600_000
SALT_LEN = 16
IV_LEN = 12


def _derive_master_pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER, dklen=32)


def build_share_page(plaintext: bytes, password: str, title: str = "AES-256 加密分享") -> str:
    """生成自解密 HTML 字符串。"""
    from Crypto.Cipher import AES

    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = _derive_master_pbkdf2(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    ct, tag = cipher.encrypt_and_digest(plaintext)

    b64 = lambda b: base64.b64encode(b).decode("ascii")
    payload = {"salt": b64(salt), "iv": b64(iv), "ct": b64(ct), "tag": b64(tag),
               "iter": PBKDF2_ITER}

    return _HTML_TEMPLATE.replace("__TITLE__", _esc(title)).replace(
        "__PAYLOAD__", _json_dump(payload))


def write_share_page(plaintext: bytes, password: str, dst: str | Path,
                     title: str = "AES-256 加密分享") -> Path:
    dst = Path(dst)
    dst.write_text(build_share_page(plaintext, password, title), encoding="utf-8")
    return dst


def _json_dump(obj) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False)


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>__TITLE__</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: "Microsoft YaHei", system-ui, sans-serif; max-width: 720px;
         margin: 40px auto; padding: 0 16px; line-height: 1.7; }
  h1 { color: #1976d2; font-size: 20px; }
  textarea, input { width: 100%; box-sizing: border-box; font-family: inherit;
                    padding: 8px; border: 1px solid #bbb; border-radius: 6px; }
  button { background: #1976d2; color: #fff; border: 0; border-radius: 6px;
           padding: 8px 16px; cursor: pointer; }
  button:disabled { background: #aaa; }
  .out { white-space: pre-wrap; word-break: break-all; border: 1px solid #ccc;
         border-radius: 6px; padding: 10px; margin-top: 12px; min-height: 60px; }
  .hint { color: #777; font-size: 13px; }
  .err { color: #c62828; }
</style>
</head>
<body>
<h1>__TITLE__</h1>
<p class="hint">本页面完全在浏览器本地解密，密文与密码都不会发送到任何服务器。
请用离线方式打开本 HTML。</p>

<label>密码</label>
<input id="pw" type="password" autocomplete="off" placeholder="输入解密密码">
<p><button id="go">解密</button></p>
<p id="msg" class="hint"></p>
<div class="out" id="out"></div>

<script id="payload" type="application/json">__PAYLOAD__</script>
<script>
(function () {
  "use strict";
  var meta = JSON.parse(document.getElementById("payload").textContent);
  function b64ToBytes(s) {
    var bin = atob(s), arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  async function decrypt(pw) {
    var enc = new TextEncoder();
    var salt = b64ToBytes(meta.salt), iv = b64ToBytes(meta.iv);
    var ct = b64ToBytes(meta.ct), tag = b64ToBytes(meta.tag);
    var keyMaterial = await crypto.subtle.importKey(
      "raw", enc.encode(pw), { name: "PBKDF2" }, false, ["deriveKey"]);
    var key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: meta.iter, hash: "SHA-256" },
      keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    // WebCrypto 要求 tag 拼在密文末尾
    var joined = new Uint8Array(ct.length + tag.length);
    joined.set(ct, 0); joined.set(tag, ct.length);
    var plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, joined);
    return new Uint8Array(plain);
  }
  document.getElementById("go").addEventListener("click", async function () {
    var msg = document.getElementById("msg"), out = document.getElementById("out");
    var pw = document.getElementById("pw").value;
    msg.textContent = "解密中…"; msg.className = "hint";
    out.textContent = "";
    try {
      var bytes = await decrypt(pw);
      // 尝试按 UTF-8 文本展示，失败则提示为二进制并提供下载
      try {
        out.textContent = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch (e) {
        var blob = new Blob([bytes]);
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "decrypted.bin";
        a.textContent = "内容为二进制，点击下载（" + bytes.length + " 字节）";
        out.appendChild(a);
      }
      msg.textContent = "解密成功。";
    } catch (e) {
      msg.textContent = "解密失败：密码错误或文件被篡改。";
      msg.className = "err";
    }
  });
})();
</script>
</body>
</html>
"""
