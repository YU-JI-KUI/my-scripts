"""端口蜜罐：监听 8080，记录是谁连进来、发了什么字节。

用途：排查 uvicorn 周期性输出 "WARNING: Invalid HTTP request received." 的来源。
只用 Python 标准库，无需安装任何包，Windows 直接运行：

    python port_honeypot.py

原理：accept 连接后先「按住不放」，趁连接还活着用 netstat -ano
查出对端临时端口归属的 PID，再用 tasklist 反查进程名。

运行前先停掉占用 8080 的服务（ark-agentic）。
"""

import socket
import subprocess
from datetime import datetime

PORT = 8080  # 和 ark-agentic 用的端口一致


def find_pid_by_local_port(port: int) -> str:
    """在 netstat 输出里找占用指定本地端口的 PID。"""
    output = subprocess.run(
        ["netstat", "-ano"], capture_output=True, text=True
    ).stdout
    for line in output.splitlines():
        # 形如: TCP  127.0.0.1:6145  127.0.0.1:8080  ESTABLISHED  1234
        parts = line.split()
        if len(parts) >= 5 and parts[1].endswith(f":{port}"):
            return parts[-1]
    return ""


def process_name(pid: str) -> str:
    """用 tasklist 反查 PID 对应的进程名。"""
    if not pid:
        return "(未找到)"
    output = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True
    ).stdout
    lines = [ln for ln in output.splitlines() if ln.strip()]
    return lines[-1] if lines else "(未找到)"


def classify(data: bytes) -> str:
    """根据首字节判断对方在说什么协议。"""
    if data[:2] == b"\x16\x03":
        return "TLS 握手 —— 有进程在用 https:// 连这个 HTTP 端口"
    if data.startswith(b"PRI * HTTP/2.0"):
        return "HTTP/2 前导帧 —— gRPC/HTTP2 客户端连错端口"
    if data.startswith(b"PROXY"):
        return "Proxy Protocol 头"
    if not data:
        return "没发任何数据就断开（纯端口连通性探测）"
    return "未知字节，疑似安全软件探测包"


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", PORT))
    server.listen(5)
    print(f"蜜罐已就位，监听 127.0.0.1:{PORT}，按 Ctrl+C 退出\n")

    while True:
        conn, (peer_ip, peer_port) = server.accept()
        now = datetime.now().strftime("%H:%M:%S")
        print(f"[{now}] 连接来自 {peer_ip}:{peer_port}")

        # 连接还活着，立刻查 netstat 锁定对方 PID
        pid = find_pid_by_local_port(peer_port)
        print(f"  进程: PID={pid}  {process_name(pid)}")

        # 再看看对方发了什么
        conn.settimeout(2.0)
        try:
            data = conn.recv(128)
        except socket.timeout:
            data = b""
        print(f"  首段字节(hex): {data[:32].hex(' ') or '(空)'}")
        print(f"  判定: {classify(data)}\n")
        conn.close()


if __name__ == "__main__":
    main()
