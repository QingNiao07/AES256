# -*- coding: utf-8 -*-
"""mobile/serve.py
=================
移动网页版（PWA）本地启动器。

浏览器出于安全限制，要求通过 http(s) 或 localhost 才能注册 Service Worker
（离线缓存）。本脚本用标准库起一个只监听 127.0.0.1 的静态服务器，
**不访问任何外网**，仅用于把 mobile/www 提供给手机/平板浏览器。

用法：
    python mobile/serve.py            # 默认 127.0.0.1:8765
    python mobile/serve.py --port 9000 --host 0.0.0.0   # 局域网内手机访问

提示：
- 电脑与手机连同一 Wi-Fi 时，用 --host 0.0.0.0，手机浏览器打开
  http://<电脑IP>:<端口>/ 即可。
- 首次加载后页面会离线缓存，之后即使断网也可使用。
"""
from __future__ import annotations

import argparse
import functools
import http.server
import socket
import socketserver
import sys
from pathlib import Path

WWW = Path(__file__).resolve().parent / "www"


class _Handler(http.server.SimpleHTTPRequestHandler):
    # 关闭服务器版本头，减少指纹
    server_version = "AES256Mobile/1.3"
    sys_version = ""

    def end_headers(self):
        # PWA 相关：允许同源缓存，不联网
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt, *args):  # 精简日志
        sys.stderr.write("[serve] " + (fmt % args) + "\n")


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # 仅用于取本机 IP，不发送数据
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AES-256 加密工具箱 · 移动网页版本地服务器")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)

    if not WWW.exists():
        print(f"[错误] 未找到网页目录：{WWW}", file=sys.stderr)
        return 2

    handler = functools.partial(_Handler, directory=str(WWW))
    with socketserver.ThreadingTCPServer((args.host, args.port), handler) as httpd:
        httpd.allow_reuse_address = True
        tip = "127.0.0.1" if args.host in ("127.0.0.1", "localhost") else _local_ip()
        print("=" * 56)
        print("  AES-256 加密工具箱 · 移动网页版")
        print(f"  本机访问： http://127.0.0.1:{args.port}/")
        if args.host not in ("127.0.0.1", "localhost"):
            print(f"  手机访问： http://{tip}:{args.port}/   （同一 Wi-Fi）")
        print("  完全离线运行 · 按 Ctrl+C 停止")
        print("=" * 56)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[serve] 已停止")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
