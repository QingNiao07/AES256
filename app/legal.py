# -*- coding: utf-8 -*-
"""app/legal.py
==============
法律条款、合法性说明、作者免责声明与免责协议（中英双语），
以及「安装前声明」的接受状态持久化。

设计原则
--------
- 所有法务文本集中在本模块，避免散落在 UI 里；
- 中英各一份，随语言切换；
- 安装/首次运行必须由用户本人显式勾选「我接受」才能继续；
- 接受记录写入 config（legal.accepted / legal.accepted_at / legal.version），
  并同时写审计日志，保证可追溯。

免责要点（概括）
----------------
1. 本软件是通用加密工具，本身合法，但「使用行为」由使用者自行负责；
2. 作者不参与、不控制、不知悉使用者的具体用途与数据；
3. 使用者须确保用途合法、符合社会主义核心价值观与当地法律；
4. 不得用于任何违法、侵权、危害国家安全或公共利益的活动；
5. 数据丢失风险由使用者自担（务必保管好密码与密钥文件）；
6. 作者按「现状」提供软件，不作任何明示或默示担保；
7. 因使用或无法使用本软件导致的损失，作者不承担责任；
8. 若使用者违反上述约定，责任由使用者自行承担，与作者无关。

说明：以下文本为通用模板，旨在厘清责任边界，不构成正式法律意见；
正式发布前建议由专业法律人士结合目标司法辖区审阅。
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import meta

LEGAL_VERSION = "1.0"
DOC_VERSION = LEGAL_VERSION

# 对外文件名（导出用）
LEGAL_FILENAME = "LEGAL.md"

HEADER = "《AES-256 加密工具箱》法律声明与免责协议"


# ============================================================
# 1. 合法性说明
# ============================================================
LEGALITY_ZH = """\
一、软件合法性说明
1. 本软件（AES-256 加密工具箱，以下简称「本软件」）是一款通用的数据加密工具，
   其功能是对使用者本地文件进行加密、解密与完整性校验。
2. 本软件使用的密码学算法（如 AES-256-GCM、ChaCha20-Poly1305、SHA-256、Argon2id 等）
   均为国际公开、经学术界与工业界广泛验证的标准算法，软件本身不包含任何
   后门、破译或绕过他人加密的功能。
3. 本软件完全在本地离线运行：默认不联网、不上传任何数据；AI 助手默认关闭联网，
   需使用者显式授权。
4. 本软件为开源/免费软件，在中华人民共和国境内依法开发与提供；使用者应遵守
   《中华人民共和国网络安全法》《中华人民共和国数据安全法》《中华人民共和国
   个人信息保护法》及其他适用法律法规。
5. 本软件提供的是「技术中立」的工具。工具的合法性不代表使用行为的合法性；
   任何具体用途的合法性，由使用者自行判断并承担相应责任。
"""

LEGALITY_EN = """\
1. Legality of the Software
1. This software (the AES-256 Encryption Toolbox, "the Software") is a general-purpose
   data encryption tool that encrypts, decrypts and verifies integrity of local files.
2. The cryptographic algorithms used (e.g. AES-256-GCM, ChaCha20-Poly1305, SHA-256,
   Argon2id) are public, widely-verified standards. The Software contains no backdoors
   and no capability to break or bypass other people's encryption.
3. The Software runs fully offline by default: no network access, no data upload. The AI
   assistant is offline by default and requires explicit user consent to go online.
4. The Software is free/open software and is provided lawfully within the jurisdiction
   where it is distributed. Users must comply with all applicable laws and regulations.
5. The Software is a technology-neutral tool. The legality of the tool does not imply the
   legality of any particular use; the legality of any specific use is determined and
   borne by the user.
"""

# ============================================================
# 2. 安装 / 首次使用声明（需勾选「我接受」）
# ============================================================
INSTALL_DECLARATION_ZH = """\
安装与使用声明（须本人确认）

请在使用本软件前，认真阅读并确认以下声明：

1. 【合法用途】我承诺仅将本软件用于合法用途，不将其用于任何违反中华人民共和国
   法律法规、危害国家安全、损害社会公共利益或侵害他人合法权益的活动。
2. 【价值观】我承诺使用本软件的目的与方式须符合社会主义核心价值观，不用于传播
   违法有害信息或从事任何违法违规活动。
3. 【风险自担】我知悉加密具有不可逆性：一旦遗忘密码或丢失密钥文件，数据将无法
   恢复。相关风险由我本人承担。
4. 【责任自负】我对使用本软件的全部行为及其后果负责，与软件作者无关。
5. 【接受条款】我已阅读并理解《法律声明与免责协议》的全部内容，自愿接受其约束。

⚠ 只有在下方勾选「我接受」后，才能继续安装或首次使用。
   若不同意，请取消并卸载/退出本软件。
"""

INSTALL_DECLARATION_EN = """\
Installation & Use Declaration (personal confirmation required)

Please read and confirm the following before using the Software:

1. [Lawful use] I undertake to use the Software only for lawful purposes and not for any
   activity that violates applicable laws, endangers national security, harms the public
   interest, or infringes the rights of others.
2. [Values] I undertake that the purpose and manner of my use shall comply with the core
   socialist values, and I will not use it to spread illegal or harmful information or
   engage in any unlawful activity.
3. [Assumption of risk] I understand encryption is irreversible: if I forget the password
   or lose the key file, data cannot be recovered. I bear this risk myself.
4. [Own responsibility] I am responsible for all my acts and consequences of using the
   Software; they are unrelated to the author.
5. [Acceptance] I have read and understood the full Legal Notice & Disclaimer and accept
   its terms voluntarily.

⚠ Installation / first use proceeds ONLY after checking "I ACCEPT" below.
   If you disagree, cancel and uninstall / exit the Software.
"""

# ============================================================
# 3. 作者免责声明
# ============================================================
DISCLAIMER_ZH = """\
二、作者免责声明
1. 本软件由作者（青鸟 / Qingniao，{email}）以个人身份按「现状」（AS IS）提供，
   仅供学习、研究及合法的个人数据保护之用。
2. 作者不参与、不控制、也不知悉使用者使用本软件的具体目的、对象与数据内容；
   使用者的一切使用行为及其后果，与作者无关。
3. 作者不对本软件作任何明示或默示的担保，包括但不限于对适销性、特定用途适用性
   及不侵权的担保。
4. 对于因使用或无法使用本软件而导致的任何直接、间接、附带、特殊或后果性损失
   （包括但不限于数据丢失、业务中断、利润损失），作者概不承担任何责任。
5. 作者有权在不事先通知的情况下修改、更新或停止提供本软件，且不因此承担责任。
6. 本声明不排除或限制依适用法律不得排除或限制的责任。
"""

DISCLAIMER_EN = """\
2. Author's Disclaimer
1. The Software is provided "AS IS" by the author (Qingniao, {email}) in a personal
   capacity, for study, research and lawful personal data protection.
2. The author does not participate in, control, or have knowledge of the user's specific
   purposes, targets or data. All of the user's acts and consequences are unrelated to
   the author.
3. The author makes no warranties, express or implied, including merchantability, fitness
   for a particular purpose, and non-infringement.
4. The author shall not be liable for any direct, indirect, incidental, special or
   consequential damages (including data loss, business interruption, lost profits)
   arising from the use or inability to use the Software.
5. The author may modify, update or discontinue the Software without notice and without
   liability.
6. Nothing here excludes or limits liability that cannot be excluded or limited by law.
"""

# ============================================================
# 4. 免责协议条款（责任划分）
# ============================================================
LIABILITY_ZH = """\
三、免责协议条款（使用者责任与作者责任的划分）
1. 【使用者责任】
   (1) 保证使用目的与方式合法，并符合社会主义核心价值观；
   (2) 妥善保管密码、密钥文件与恢复码；遗忘或丢失导致数据不可恢复的，责任自负；
   (3) 自行备份重要数据，自行承担加密、解密、删除原文件等操作的风险；
   (4) 自行对其加密数据的来源与内容负责，不得用于侵犯他人权利；
   (5) 因使用行为引发的任何纠纷、索赔或法律责任，由使用者独立承担。
2. 【作者责任】
   (1) 作者仅负责按其能力提供软件功能，不介入使用者的具体使用行为；
   (2) 作者不对使用者的数据内容、使用目的及使用后果承担任何责任；
   (3) 作者仅在法律强制要求且不可排除的范围内承担责任，且以使用者为本软件实际
       支付的对价为上限（本软件免费，故上限为零）。
3. 【责任切割】
   (1) 软件是「工具」，使用者是「操作者」；工具的功能与操作者的行为相互独立；
   (2) 使用者一旦使用本软件，即视为已理解并接受上述责任划分；
   (3) 若使用者不同意上述划分，应立即停止使用并删除本软件。
4. 【争议解决】因本软件产生的争议，双方应友好协商；协商不成的，依法有管辖权的
   人民法院解决。
5. 【其他】本协议若部分条款被认定无效，不影响其余条款的效力。
"""

LIABILITY_EN = """\
3. Liability Terms (allocation of responsibility)
1. [User's responsibility]
   (1) Ensure the purpose and manner of use are lawful and comply with the core socialist
       values;
   (2) Safeguard the password, key file and recovery code; if forgotten or lost and data
       becomes unrecoverable, the user bears it;
   (3) Back up important data and bear the risks of encryption, decryption and source
       deletion operations;
   (4) Be responsible for the source and content of data, and not infringe others' rights;
   (5) Bear independently any dispute, claim or liability arising from the use.
2. [Author's responsibility]
   (1) The author only provides the software functions to the best of their ability and
       does not intervene in the user's specific acts;
   (2) The author is not liable for the user's data, purposes or consequences;
   (3) The author's liability is limited to what the user actually paid for the Software
       (the Software is free, so the cap is zero), except where liability cannot be
       excluded by law.
3. [Separation of responsibility]
   (1) The software is a "tool" and the user is the "operator"; the tool's function and the
       operator's acts are independent;
   (2) By using the Software, the user is deemed to have understood and accepted this
       allocation;
   (3) If the user disagrees, they should stop using and delete the Software immediately.
4. [Dispute resolution] Disputes shall be resolved through friendly negotiation; failing
   that, by a competent court according to law.
5. [Severability] If any clause is held invalid, the remaining clauses remain in effect.
"""

# 社会主义核心价值观（声明中显式列示，便于用户确认）
SOCIALIST_CORE_VALUES = (
    "富强、民主、文明、和谐",
    "自由、平等、公正、法治",
    "爱国、敬业、诚信、友善",
)
SOCIALIST_CORE_VALUES_EN = (
    "Prosperity, Democracy, Civility, Harmony",
    "Freedom, Equality, Justice, Rule of Law",
    "Patriotism, Dedication, Integrity, Friendship",
)


def _t(zh: str, en: str, lang: str) -> str:
    return zh if lang == "zh_CN" else en


def legality(lang: str = "zh_CN") -> str:
    return _t(LEGALITY_ZH, LEGALITY_EN, lang)


def declaration(lang: str = "zh_CN") -> str:
    return _t(INSTALL_DECLARATION_ZH, INSTALL_DECLARATION_EN, lang)


def disclaimer(lang: str = "zh_CN") -> str:
    email = meta.AUTHOR_EMAIL
    if lang == "zh_CN":
        return DISCLAIMER_ZH.format(email=email)
    return DISCLAIMER_EN.format(email=email)


def liability(lang: str = "zh_CN") -> str:
    return _t(LIABILITY_ZH, LIABILITY_EN, lang)


def full_text(lang: str = "zh_CN") -> str:
    """完整法务文本（HEADER + 四部分）。"""
    parts = [
        f"# {HEADER}",
        f"版本：{DOC_VERSION}    作者：{meta.author_line(lang)}",
        "",
        legality(lang),
        disclaimer(lang),
        liability(lang),
        declaration(lang),
    ]
    return "\n\n".join(parts)


def short_accept_line(lang: str = "zh_CN") -> str:
    if lang == "zh_CN":
        return ("我已阅读并同意《法律声明与免责协议》，承诺仅用于合法用途，"
                "且用途符合社会主义核心价值观。")
    return ("I have read and agree to the Legal Notice & Disclaimer, and undertake to use "
            "the Software only for lawful purposes consistent with the core socialist "
            "values.")


def core_values_line(lang: str = "zh_CN") -> str:
    vals = SOCIALIST_CORE_VALUES if lang == "zh_CN" else SOCIALIST_CORE_VALUES_EN
    return "；".join(vals) if lang == "zh_CN" else "; ".join(vals)


# ============================================================
# 接受状态持久化
# ============================================================
def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def is_accepted(root=None) -> bool:
    """是否已接受当前版本的法务条款。"""
    try:
        from . import config as cfgmod

        accepted = cfgmod.get("legal.accepted", False, root)
        version = cfgmod.get("legal.version", "", root)
        return bool(accepted) and str(version) == DOC_VERSION
    except Exception:
        return False


def accepted_info(root=None) -> dict:
    try:
        from . import config as cfgmod

        cfg = cfgmod.load(root)
        return dict(cfg.get("legal", {}))
    except Exception:
        return {}


def accept(root=None, who: str = "") -> dict:
    """记录接受状态（写 config + 审计），返回接受信息。"""
    from . import config as cfgmod

    ts = _now()
    info = {"accepted": True, "version": DOC_VERSION, "accepted_at": ts}
    if who:
        info["accepted_by"] = who
    cfgmod.set_value("legal", info, root)
    try:
        from .core import audit

        audit.append("legal", "accept",
                     f"接受法务条款 v{DOC_VERSION}" + (f" by {who}" if who else ""))
    except Exception:
        pass
    return info


def revoke(root=None) -> None:
    from . import config as cfgmod

    cfgmod.set_value("legal", {"accepted": False, "version": ""}, root)


def needs_acceptance(root=None) -> bool:
    """安装/首次运行是否需要用户确认。"""
    return not is_accepted(root)


def to_markdown(lang: str = "zh_CN") -> str:
    return full_text(lang)
