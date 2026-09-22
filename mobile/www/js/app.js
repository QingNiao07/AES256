// app.js — 移动网页版界面逻辑（响应式 · 触摸友好 · 全离线）。
import {
  encryptBytesV4, decryptBytesV4, readMetaV4, isV4, toHex,
  DEFAULT_ITERATIONS, SUPPORTED_CHAIN,
} from "./v4crypto.js";
import * as L from "./legal.js";

const $ = (id) => document.getElementById(id);
const state = { lang: localStorage.getItem("aes256tool.lang") || "zh_CN" };

// ------------------------------------------------------------------ i18n
const I18N = {
  zh_CN: {
    subtitle: "本地离线加密 · 与桌面端 v4 容器互通",
    tab_enc: "加密", tab_dec: "解密", tab_about: "关于",
    pick: "选择文件", picked: "已选择", drop: "或把文件拖到这里",
    password: "密码", confirm: "确认密码",
    iterations: "PBKDF2 迭代次数",
    do_enc: "加密并下载 .aes256", do_dec: "解密并下载",
    err_pwd: "两次输入的密码不一致", err_empty: "请先选择文件",
    err_nopwd: "请输入密码",
    working: "处理中…（派生密钥需要一点时间）",
    done: "完成", size: "原始大小", outsize: "输出大小",
    meta: "容器信息", chain: "算法链", kdf: "密钥派生", name: "原始文件名",
    fail: "失败", about_body:
      "AES-256 加密工具箱 · 移动网页版\n\n" +
      "• 完全本地运行：不联网、不上传任何数据。\n" +
      "• 与桌面端 v4 容器逐字节互通（PBKDF2 + AES-256-GCM）。\n" +
      "• 桌面端生成时请使用：python cli.py enc 文件 --kdf pbkdf2\n" +
      "• 单一总密钥：无论桌面端叠加多少算法，密钥始终只有一个。\n\n" +
      "作者：青鸟 / Qingniao · qingniao2007@126.com\n" +
      "许可：MIT · 版本 1.3.0 (mobile)",
    install: "安装到主屏幕 / 添加到桌面",
  },
  en_US: {
    subtitle: "Local offline encryption · interoperable with desktop v4",
    tab_enc: "Encrypt", tab_dec: "Decrypt", tab_about: "About",
    pick: "Choose file", picked: "Selected", drop: "or drop a file here",
    password: "Password", confirm: "Confirm password",
    iterations: "PBKDF2 iterations",
    do_enc: "Encrypt & download .aes256", do_dec: "Decrypt & download",
    err_pwd: "Passwords do not match", err_empty: "Choose a file first",
    err_nopwd: "Enter a password",
    working: "Working… (key derivation takes a moment)",
    done: "Done", size: "Original size", outsize: "Output size",
    meta: "Container info", chain: "Cipher chain", kdf: "Key derivation", name: "Original name",
    fail: "Failed", about_body:
      "AES-256 Encryption Toolbox · Mobile Web\n\n" +
      "• Runs fully locally: no network, no upload.\n" +
      "• Byte-for-byte compatible with desktop v4 (PBKDF2 + AES-256-GCM).\n" +
      "• On desktop generate with: python cli.py enc FILE --kdf pbkdf2\n" +
      "• Single master key: however many ciphers are stacked, only one key.\n\n" +
      "Author: Qingniao · qingniao2007@126.com · MIT · v1.3.0 (mobile)",
    install: "Install to home screen",
  },
};
const t = (k) => (I18N[state.lang] && I18N[state.lang][k]) || I18N.zh_CN[k] || k;

function applyLang() {
  document.documentElement.lang = state.lang === "zh_CN" ? "zh-CN" : "en";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.getAttribute("data-i18n");
    const v = t(k);
    if (v) el.textContent = v;
  });
  $("lang").textContent = state.lang === "zh_CN" ? "EN" : "中文";
  if (state.lang === "zh_CN") { $("legal-body").textContent = L.LEGAL.zh_CN.body; $("legal-header").textContent = L.LEGAL.zh_CN.header; $("legal-accept-line").textContent = L.LEGAL.zh_CN.accept_line; $("legal-gate").textContent = L.LEGAL.zh_CN.gate; $("btn-legal-accept").textContent = L.LEGAL.zh_CN.accept; $("btn-legal-decline").textContent = L.LEGAL.zh_CN.decline; }
  else { $("legal-body").textContent = L.LEGAL.en_US.body; $("legal-header").textContent = L.LEGAL.en_US.header; $("legal-accept-line").textContent = L.LEGAL.en_US.accept_line; $("legal-gate").textContent = L.LEGAL.en_US.gate; $("btn-legal-accept").textContent = L.LEGAL.en_US.accept; $("btn-legal-decline").textContent = L.LEGAL.en_US.decline; }
}

// ------------------------------------------------------------------ 工具
function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
  return (n / 1048576).toFixed(2) + " MiB";
}
function download(name, bytes) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click();
  a.remove(); setTimeout(() => URL.revokeObjectURL(url), 4000);
}
function setMsg(el, text, kind) {
  el.textContent = text || "";
  el.className = "msg" + (kind ? " " + kind : "");
}

// ------------------------------------------------------------------ 标签切换
function showTab(name) {
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("hidden", p.id !== "panel-" + name));
  document.querySelectorAll(".tabbar button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
}

// ------------------------------------------------------------------ 加密
let encFile = null, decFile = null;

async function doEncrypt() {
  const msg = $("enc-msg");
  if (!encFile) return setMsg(msg, t("err_empty"), "err");
  const pwd = $("enc-pwd").value;
  if (!pwd) return setMsg(msg, t("err_nopwd"), "err");
  if (pwd !== $("enc-pwd2").value) return setMsg(msg, t("err_pwd"), "err");
  const iters = parseInt($("enc-iters").value, 10) || DEFAULT_ITERATIONS;
  setMsg(msg, t("working"));
  try {
    const data = new Uint8Array(await encFile.arrayBuffer());
    const t0 = performance.now();
    const blob = await encryptBytesV4(data, pwd, { iterations: iters, name: encFile.name });
    const ms = Math.round(performance.now() - t0);
    download(encFile.name + ".aes256", blob);
    setMsg(msg, `${t("done")} ✓  ${fmtSize(blob.length)}  (${ms} ms)`, "ok");
  } catch (e) {
    setMsg(msg, t("fail") + ": " + e.message, "err");
  }
}

// ------------------------------------------------------------------ 解密
async function doDecrypt() {
  const msg = $("dec-msg");
  if (!decFile) return setMsg(msg, t("err_empty"), "err");
  const pwd = $("dec-pwd").value;
  if (!pwd) return setMsg(msg, t("err_nopwd"), "err");
  setMsg(msg, t("working"));
  try {
    const data = new Uint8Array(await decFile.arrayBuffer());
    const meta = isV4(data) ? readMetaV4(data) : null;
    const t0 = performance.now();
    const out = await decryptBytesV4(data, pwd);
    const ms = Math.round(performance.now() - t0);
    const name = (meta && meta.name) ? meta.name.replace(/\.aes256$/, "") : "decrypted.bin";
    download(name, out);
    setMsg(msg, `${t("done")} ✓  ${fmtSize(out.length)}  (${ms} ms)`, "ok");
    const rows = [
      [t("meta")], [t("chain"), meta ? meta.chain.join(" → ") : "-"],
      [t("kdf"), meta ? `${meta.kdf} / ${meta.iterations}` : "-"],
      [t("name"), meta ? meta.name : "-"], [t("size"), fmtSize(data.length)],
    ];
    $("dec-meta").innerHTML = rows.map((r) =>
      r.length === 1 ? `<div class="meta-h">${r[0]}</div>`
        : `<div class="meta-r"><span>${r[0]}</span><b>${r[1]}</b></div>`).join("");
  } catch (e) {
    setMsg(msg, t("fail") + ": " + e.message, "err");
    $("dec-meta").innerHTML = "";
  }
}

// ------------------------------------------------------------------ 初始化
function wiredrop(zone, input, onFile) {
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("over"); }));
  zone.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) onFile(f); });
  input.addEventListener("change", () => { if (input.files[0]) onFile(input.files[0]); });
}

function boot() {
  applyLang();
  $("lang").addEventListener("click", () => {
    state.lang = state.lang === "zh_CN" ? "en_US" : "zh_CN";
    localStorage.setItem("aes256tool.lang", state.lang);
    applyLang();
  });
  document.querySelectorAll(".tabbar button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

  wiredrop($("enc-drop"), $("enc-file"), (f) => { encFile = f; $("enc-name").textContent = `${t("picked")}: ${f.name} (${fmtSize(f.size)})`; });
  wiredrop($("dec-drop"), $("dec-file"), (f) => { decFile = f; $("dec-name").textContent = `${t("picked")}: ${f.name} (${fmtSize(f.size)})`; });
  $("btn-enc").addEventListener("click", doEncrypt);
  $("btn-dec").addEventListener("click", doDecrypt);

  // PWA 安装
  let deferred = null;
  window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); deferred = e; $("btn-install").classList.remove("hidden"); });
  $("btn-install").addEventListener("click", async () => {
    if (!deferred) return;
    deferred.prompt(); await deferred.userChoice; deferred = null; $("btn-install").classList.add("hidden");
  });
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("./sw.js").catch(() => {});

  // 法务闸门
  $("btn-legal-accept").addEventListener("click", () => {
    if (!$("legal-check").checked) return;
    L.accept(); $("legal-gate-overlay").classList.add("hidden");
  });
  $("btn-legal-decline").addEventListener("click", () => {
    document.body.innerHTML = `<div class="closed">${L.LEGAL[state.lang].gate}</div>`;
  });
  if (!L.isAccepted()) $("legal-gate-overlay").classList.remove("hidden");
  $("legal-check").addEventListener("change", (e) => { $("btn-legal-accept").disabled = !e.target.checked; });

  showTab("enc");
}

window.addEventListener("DOMContentLoaded", boot);
