# -*- coding: utf-8 -*-
"""
app/ui/qt/security_dialog.py
============================
可配置安全参数对话框（图片来源第 5 项：用户按机器性能调优）。

提供三档预设单选、Argon2id/PBKDF2 明细、一键「按本机性能校准」，
并把结果写入 config.json 的 security 段。
"""
from __future__ import annotations

from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QGroupBox, QHBoxLayout, QLabel, QMessageBox,
                               QPushButton, QSpinBox, QVBoxLayout)

from ...core import security
from ...core.settings import load_params, save_params


class SecurityDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("安全参数")
        self.setMinimumWidth(440)
        p = load_params()

        root = QVBoxLayout(self)
        info = QLabel("调整密钥派生强度：越高越抗暴力破解，但解锁越慢。\n"
                      "建议先点「按本机性能校准」，自动挑出约 0.3~1.0 秒的组合。")
        info.setWordWrap(True)
        root.addWidget(info)

        g = QGroupBox("参数")
        form = QFormLayout(g)

        self.preset_box = QComboBox()
        self.preset_box.addItems(list(security.PRESET_NAMES))
        self.preset_box.setCurrentText("balanced")
        form.addRow("预设", self.preset_box)

        self.kdf_box = QComboBox()
        self.kdf_box.addItems(["argon2id", "pbkdf2"])
        self.kdf_box.setCurrentText(p.kdf)
        form.addRow("KDF", self.kdf_box)

        self.t = QSpinBox(); self.t.setRange(1, 20)
        self.t.setValue(p.argon2_time_cost)
        form.addRow("Argon2 time_cost", self.t)

        self.m = QSpinBox(); self.m.setRange(8, 1024); self.m.setSuffix(" MiB")
        self.m.setValue(max(8, p.argon2_memory_cost // 1024))
        form.addRow("Argon2 memory", self.m)

        self.par = QSpinBox(); self.par.setRange(1, 64)
        self.par.setValue(p.argon2_parallelism)
        form.addRow("Argon2 parallelism", self.par)

        self.iters = QSpinBox(); self.iters.setRange(100000, 5000000)
        self.iters.setSingleStep(100000); self.iters.setValue(p.pbkdf2_iterations)
        form.addRow("PBKDF2 迭代", self.iters)

        self.chunk = QSpinBox(); self.chunk.setRange(64, 65536); self.chunk.setSuffix(" KiB")
        self.chunk.setValue(max(64, p.chunk_size // 1024))
        form.addRow("分块大小", self.chunk)

        root.addWidget(g)

        row = QHBoxLayout()
        btn_cal = QPushButton("按本机性能校准")
        btn_cal.clicked.connect(self._calibrate)
        btn_pre = QPushButton("应用预设")
        btn_pre.clicked.connect(self._apply_preset)
        row.addWidget(btn_cal); row.addWidget(btn_pre)
        root.addLayout(row)

        self.est = QLabel("")
        root.addWidget(self.est)

        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        root.addWidget(bb)

        self.preset_box.currentTextChanged.connect(lambda _: self._apply_preset())
        for w in (self.kdf_box, self.t, self.m, self.par, self.iters, self.chunk):
            try:
                w.valueChanged.connect(self._refresh_est)
            except Exception:
                pass
        self.kdf_box.currentTextChanged.connect(self._refresh_est)
        self._refresh_est()

    # ---------- 内部 ----------
    def _collect(self) -> security.SecurityParams:
        return security.SecurityParams(
            kdf=self.kdf_box.currentText(),
            argon2_time_cost=self.t.value(),
            argon2_memory_cost=self.m.value() * 1024,
            argon2_parallelism=self.par.value(),
            pbkdf2_iterations=self.iters.value(),
            chunk_size=self.chunk.value() * 1024,
        )

    def _apply_preset(self):
        p = security.preset(self.preset_box.currentText())
        self.kdf_box.setCurrentText(p.kdf)
        self.t.setValue(p.argon2_time_cost)
        self.m.setValue(p.argon2_memory_cost // 1024)
        self.par.setValue(p.argon2_parallelism)
        self.iters.setValue(p.pbkdf2_iterations)
        self.chunk.setValue(p.chunk_size // 1024)
        self._refresh_est()

    def _calibrate(self):
        try:
            p, dt = security.calibrate()
        except Exception as e:                       # pragma: no cover
            QMessageBox.warning(self, "校准失败", str(e))
            return
        self.kdf_box.setCurrentText(p.kdf)
        self.t.setValue(p.argon2_time_cost)
        self.m.setValue(p.argon2_memory_cost // 1024)
        self.par.setValue(p.argon2_parallelism)
        self.iters.setValue(p.pbkdf2_iterations)
        self.est.setText(f"校准实测解锁耗时约 {dt * 1000:.0f} ms")
        self._refresh_est()

    def _refresh_est(self, *a):
        self.est.setText(f"当前：{self._collect().describe()}")

    def _save(self):
        p = self._collect()
        errs = p.validate()
        if errs:
            QMessageBox.warning(self, "参数不合法", "\n".join(errs))
            return
        try:
            save_params(p)
        except Exception as e:                       # pragma: no cover
            QMessageBox.critical(self, "保存失败", str(e))
            return
        QMessageBox.information(self, "已保存", "安全参数已写入 config.json，下次加密生效。")
        self.accept()
