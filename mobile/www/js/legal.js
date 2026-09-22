// legal.js — 移动版法务文本与「我接受」闸门状态。
// 文本与桌面端 app/legal.py 保持一致（精炼版），版本号同步。
export const LEGAL_VERSION = "1.0";

export const LEGAL = {
  zh_CN: {
    header: "《AES-256 加密工具箱》法律声明与免责协议",
    body: `一、软件合法性说明
1. 本软件是一款通用的数据加密工具，对本地文件进行加密、解密与完整性校验。
2. 本软件使用的密码学算法（AES-256-GCM、SHA-256、PBKDF2 等）均为国际公开、经广泛验证的标准算法，不含任何后门或破译他人加密的功能。
3. 本软件在浏览器本地运行：默认不联网、不上传任何数据；移动网页版不包含任何远程请求。
4. 使用者应遵守《中华人民共和国网络安全法》《数据安全法》《个人信息保护法》及当地法律。
5. 工具的合法性不代表使用行为的合法性；任何具体用途的合法性由使用者自行判断并负责。

二、作者免责声明
1. 本软件由作者（青鸟 / Qingniao，qingniao2007@126.com）按「现状」（AS IS）提供，仅供学习、研究及合法的个人数据保护之用。
2. 作者不参与、不控制、不知悉使用者的具体用途与数据内容；使用者行为及后果与作者无关。
3. 作者不作任何明示或默示担保，也不对因使用或无法使用本软件导致的损失承担责任。

三、免责协议条款（责任划分）
1. 使用者责任：保证用途合法并符合社会主义核心价值观；妥善保管密码（遗忘不可恢复）；自行备份数据并承担操作风险。
2. 作者责任：仅按能力提供软件功能，不介入使用者行为，不对数据与后果负责。
3. 责任切割：软件是「工具」，使用者是「操作者」，二者相互独立。

⚠ 只有本人勾选「我接受」后才能继续使用。若不同意，请退出本页面。`,
    accept_line: "我承诺将本软件用于合法用途，用途符合社会主义核心价值观，并已阅读、同意《法律声明与免责协议》。",
    accept: "我接受并继续",
    decline: "不同意并退出",
    gate: "首次使用前请阅读上述声明：只有本人勾选「我接受」后才能继续。",
  },
  en_US: {
    header: "AES-256 Encryption Toolbox · Legal Notice & Disclaimer",
    body: `1. Legality of the Software
1. A general-purpose data encryption tool that encrypts, decrypts and verifies local files.
2. Uses public, widely-verified standards (AES-256-GCM, SHA-256, PBKDF2). No backdoors; cannot break others' encryption.
3. Runs locally in the browser: no network access, no data upload. The mobile web build issues no remote requests.
4. Users must comply with all applicable laws and regulations in their jurisdiction.
5. The legality of the tool does not imply the legality of any particular use; that is determined by the user.

2. Author's Disclaimer
1. Provided "AS IS" by the author (Qingniao, qingniao2007@126.com) for study, research and lawful personal data protection.
2. The author does not participate in, control, or know the user's purposes or data.
3. No warranties of any kind; the author is not liable for losses from use or inability to use the Software.

3. Liability Terms
1. User's responsibility: lawful, values-compliant use; safeguard the password (unrecoverable if lost); back up data and bear operational risks.
2. Author's responsibility: provide functions to the best of ability; not liable for user data or consequences.
3. Separation: the software is a "tool", the user is the "operator"; they are independent.

⚠ Use proceeds ONLY after you check "I ACCEPT". If you disagree, exit this page.`,
    accept_line: "I undertake to use this software only for lawful purposes, in line with the core socialist values, and I accept the Legal Notice & Disclaimer.",
    accept: "I ACCEPT and continue",
    decline: "I do NOT accept, exit",
    gate: "Read the notice above before first use: proceeding requires you to personally check \"I ACCEPT\".",
  },
};

const KEY = "aes256tool.legal";

export function isAccepted() {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) || "null");
    return !!(v && v.accepted && v.version === LEGAL_VERSION);
  } catch (e) { return false; }
}

export function accept() {
  localStorage.setItem(KEY, JSON.stringify({
    accepted: true, version: LEGAL_VERSION, accepted_at: new Date().toISOString(),
  }));
}

export function revoke() { localStorage.removeItem(KEY); }
