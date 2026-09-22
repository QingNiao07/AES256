# -*- coding: utf-8 -*-
"""mobile/kivy_app.py
====================
Kivy 原生移动 UI（可打包为 Android APK / iOS）。

特点
----
- 复用桌面端同一套核心：app.core.multicipher / kdf / security，容器 v4 完全互通。
- 触摸友好的简单布局；手机/平板/桌面均可运行（桌面需 pip install kivy）。
- 同样带「我接受」首次运行法务闸门与中英双语切换，与桌面端、PWA 保持一致。

运行
----
    pip install kivy
    python mobile/kivy_app.py
打包 Android（需 Android SDK + buildozer，见 mobile/buildozer.spec）：
    buildozer -v android debug
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from kivy.app import App
    from kivy.clock import Clock
    from kivy.core.clipboard import Clipboard
    from kivy.metrics import dp
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.button import Button
    from kivy.uix.checkbox import CheckBox
    from kivy.uix.label import Label
    from kivy.uix.popup import Popup
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.spinner import Spinner
    from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
    from kivy.uix.textinput import TextInput
    KIVY_OK = True
except Exception as _exc:  # pragma: no cover - 无 Kivy 环境
    KIVY_OK = False
    _KIVY_ERR = _exc

from app.core import algorithms, multicipher, kdf  # noqa: E402
from app import i18n, meta  # noqa: E402


# ------------------------------------------------------------------ 文案
TXT = {
    "zh_CN": {
        "title": "AES-256 加密工具箱 · 移动版",
        "tab_enc": "加密", "tab_dec": "解密",
        "pw": "密码", "pw2": "确认密码", "pick": "选择文件路径",
        "enc": "加密", "dec": "解密", "chain": "算法链",
        "log": "日志", "legal_ok": "我接受", "legal_no": "拒绝退出",
        "legal_gate": "请阅读并勾选「我接受」后继续（首次运行）。",
        "lang": "中文/English",
    },
    "en_US": {
        "title": "AES-256 Toolbox · Mobile",
        "tab_enc": "Encrypt", "tab_dec": "Decrypt",
        "pw": "Password", "pw2": "Confirm", "pick": "File path",
        "enc": "Encrypt", "dec": "Decrypt", "chain": "Cipher chain",
        "log": "Log", "legal_ok": "I ACCEPT", "legal_no": "Exit",
        "legal_gate": "Read and check \"I ACCEPT\" to continue (first run).",
        "lang": "中文/English",
    },
}


def t(key: str, lang: str) -> str:
    return TXT.get(lang, TXT["zh_CN"]).get(key, key)


if KIVY_OK:

    class MobileRoot(BoxLayout):
        def __init__(self, **kw):
            super().__init__(orientation="vertical", padding=dp(10), spacing=dp(8), **kw)
            self.lang = i18n.current_language() if i18n.current_language() in TXT else "zh_CN"
            self.pending_dec_path: str | None = None
            self._build()

        # ---------------------------------------------------------- 布局
        def _header(self):
            bar = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
            self.lbl_title = Label(text=t("title", self.lang), bold=True)
            bar.add_widget(self.lbl_title)
            b = Button(text="中/EN", size_hint_x=None, width=dp(70))
            b.bind(on_release=lambda *_: self._toggle_lang())
            bar.add_widget(b)
            return bar

        def _chain_row(self):
            row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
            row.add_widget(Label(text=t("chain", self.lang), size_hint_x=None, width=dp(80)))
            avail = [a["id"] for a in algorithms.list_algorithms() if a["available"]]
            self.spin = Spinner(text=avail[0] if avail else "aes-256-gcm",
                                values=avail or ["aes-256-gcm"])
            row.add_widget(self.spin)
            return row

        def _pw_row(self, hint_key: str, attr: str):
            row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
            row.add_widget(Label(text=t(hint_key, self.lang), size_hint_x=None, width=dp(80)))
            ti = TextInput(password=True, multiline=False)
            setattr(self, attr, ti)
            row.add_widget(ti)
            return row

        def _build(self):
            self.clear_widgets()
            self.add_widget(self._header())

            tabs = TabbedPanel(do_default_tab=False)
            for key, build in (("tab_enc", self._build_enc), ("tab_dec", self._build_dec)):
                item = TabbedPanelItem(text=t(key, self.lang))
                item.add_widget(build())
                tabs.add_widget(item)
            self.add_widget(tabs)

            self.log = Label(text="", size_hint_y=None, height=dp(120),
                             halign="left", valign="top",
                             text_size=(self.width - dp(20), None))
            sv = ScrollView()
            sv.add_widget(self.log)
            self.add_widget(sv)

        def _build_enc(self):
            box = BoxLayout(orientation="vertical", padding=dp(6), spacing=dp(6))
            box.add_widget(self._chain_row())
            box.add_widget(self._pw_row("pw", "pw_enc"))
            box.add_widget(self._pw_row("pw2", "pw_enc2"))
            row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
            row.add_widget(Label(text=t("pick", self.lang), size_hint_x=None, width=dp(80)))
            self.enc_path = TextInput(multiline=False)
            row.add_widget(self.enc_path)
            box.add_widget(row)
            b = Button(text=t("enc", self.lang), size_hint_y=None, height=dp(48))
            b.bind(on_release=lambda *_: self._do_encrypt())
            box.add_widget(b)
            return box

        def _build_dec(self):
            box = BoxLayout(orientation="vertical", padding=dp(6), spacing=dp(6))
            box.add_widget(self._pw_row("pw", "pw_dec"))
            row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
            row.add_widget(Label(text=t("pick", self.lang), size_hint_x=None, width=dp(80)))
            self.dec_path = TextInput(multiline=False)
            row.add_widget(self.dec_path)
            box.add_widget(row)
            b = Button(text=t("dec", self.lang), size_hint_y=None, height=dp(48))
            b.bind(on_release=lambda *_: self._do_decrypt())
            box.add_widget(b)
            return box

        # ---------------------------------------------------------- 逻辑
        def _toggle_lang(self):
            self.lang = "en_US" if self.lang == "zh_CN" else "zh_CN"
            i18n.set_language(self.lang)
            self._build()

        def _log(self, msg: str):
            self.log.text = (msg + "\n" + self.log.text)[:4000]

        def _do_encrypt(self):
            src = self.enc_path.text.strip()
            pwd = self.pw_enc.text
            if not src or not Path(src).exists():
                return self._log("✗ 文件不存在 / file not found")
            if not pwd:
                return self._log("✗ 请输入密码 / enter password")
            if pwd != self.pw_enc2.text:
                return self._log("✗ 两次密码不一致 / passwords differ")
            chain = [self.spin.text]
            try:
                salt = kdf.new_salt(16)
                recipe = {"salt": salt, "kdf_name": "pbkdf2", "time_cost": 0,
                          "memory_cost": 0, "parallelism": 0,
                          "iterations": kdf.PBKDF2_ITERATIONS}
                master = kdf.derive_master_custom(
                    pwd, salt, kdf_name="pbkdf2", iterations=kdf.PBKDF2_ITERATIONS)
                out = src + ".aes256"
                multicipher.encrypt_stream(src, out, master, chain,
                                           kdf_salt=salt, kdf_recipe=recipe)
                self._log(f"✓ 已加密 / encrypted → {out}")
            except Exception as exc:  # noqa: BLE001
                self._log(f"✗ {type(exc).__name__}: {exc}")

        def _do_decrypt(self):
            src = self.dec_path.text.strip()
            pwd = self.pw_dec.text
            if not src or not Path(src).exists():
                return self._log("✗ 文件不存在 / file not found")
            if not pwd:
                return self._log("✗ 请输入密码 / enter password")
            out = src[:-7] if src.endswith(".aes256") else src + ".dec"
            try:
                ok, res = multicipher.decrypt_file_password(src, out, pwd)
                if ok:
                    self._log(f"✓ 已解密 / decrypted → {out}")
                else:
                    self._log(f"✗ {res}")
            except Exception as exc:  # noqa: BLE001
                self._log(f"✗ {type(exc).__name__}: {exc}")

    class Aes256MobileApp(App):
        title = "AES-256 Toolbox · Mobile"

        def build(self):
            root = MobileRoot()
            Clock.schedule_once(lambda *_: self._legal_gate(root), 0.2)
            return root

        def _legal_gate(self, root):
            from app import legal
            if legal.is_accepted():
                return
            lang = root.lang
            box = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(8))
            sv = ScrollView()
            body = Label(text=legal.full_text(lang), size_hint_y=None, halign="left",
                         valign="top", text_size=(dp(320), None))
            body.bind(texture_size=lambda i, v: setattr(i, "height", v[1]))
            sv.add_widget(body)
            box.add_widget(sv)
            gate = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(6))
            cb = CheckBox(size_hint_x=None, width=dp(40))
            gate.add_widget(cb)
            gate.add_widget(Label(text=legal.short_accept_line(lang)))
            box.add_widget(gate)
            bar = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(6))
            okb = Button(text=t("legal_ok", lang), disabled=True)
            nob = Button(text=t("legal_no", lang))
            bar.add_widget(nob)
            bar.add_widget(okb)
            box.add_widget(bar)
            popup = Popup(title=legal.HEADER, content=box, auto_dismiss=False)

            def _sync(_, val):
                okb.disabled = not val
            cb.bind(active=_sync)
            okb.bind(on_release=lambda *_: (legal.accept(), popup.dismiss()))
            nob.bind(on_release=lambda *_: popup.dismiss())
            popup.open()


def main() -> int:
    if not KIVY_OK:
        print("[错误] 未安装 Kivy。请先 `pip install kivy`，或直接使用移动网页版"
              "（python mobile/serve.py）。", file=sys.stderr)
        print(f"[详情] {_KIVY_ERR}", file=sys.stderr)
        return 2
    i18n.set_language(i18n.current_language())
    print(f"AES-256 工具箱 · 移动版（Kivy）  作者：{meta.AUTHOR_ZH} <{meta.AUTHOR_EMAIL}>")
    Aes256MobileApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
