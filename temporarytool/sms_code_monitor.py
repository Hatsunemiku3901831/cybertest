#!/usr/bin/env python3
"""
iPhone 短信验证码 → Mac → Agent 可读文件
监听 macOS Messages 数据库，新短信到达时自动提取验证码并写入文件。

依赖: macOS Messages.app 已在系统偏好设置中启用 iPhone 短信转发。
     需要已授予终端/Codex 对 ~/Library/Messages 的完全磁盘访问权限。
     系统偏好设置 → 隐私与安全性 → 完全磁盘访问权限 → 添加你的终端.app 和 Codex。

使用方式:
  # 前台运行（每次新验证码写入 /tmp/sms_code.txt）
  python3 sms_code_monitor.py

  # 开机自启/后台持久化（推荐用 launchd）
  python3 sms_code_monitor.py --daemon
"""

import sqlite3
import re
import time
import os
import sys
import argparse
from datetime import datetime, timedelta

# Messages 数据库路径
DB_PATH = os.path.expanduser("~/Library/Messages/chat.db")
# 验证码输出文件（Agent 读取的目标）
OUTPUT_FILE = "/tmp/sms_code.txt"
# 状态文件（记录最后处理的消息 ROWID，避免重复）
STATE_FILE = os.path.expanduser("~/.cache/sms_monitor_state.txt")
# 轮询间隔（秒）
POLL_INTERVAL = 2

# 验证码正则：匹配常见中文验证码短信
CODE_PATTERNS = [
    re.compile(r'验证码[：:]\s*(\d{4,8})'),  # 验证码：123456
    re.compile(r'验证码[是为]\s*(\d{4,8})'),  # 验证码为 123456
    re.compile(r'校验码[：:]\s*(\d{4,8})'),
    re.compile(r'动态码[：:]\s*(\d{4,8})'),
    re.compile(r'code[：:]\s*(\d{4,8})', re.IGNORECASE),
    re.compile(r'(\d{4,8})\s*[（(]验证码[）)]'),  # 123456（验证码）
    re.compile(r'短信验证码[为是：:]\s*(\d{4,8})'),
    # 英文通用
    re.compile(r'verification\s*code[：:]\s*(\d{4,8})', re.IGNORECASE),
    re.compile(r'one-?time\s*(pass)?code[：:]\s*(\d{4,8})', re.IGNORECASE),
    # 纯数字候选（6位数字，前后有空格或标点）
    re.compile(r'(?:^|\s)(\d{6})(?:\s|$|\.|,)'),
]

# 屏蔽词：排除非验证码类的6位数字（如订单号、金额等）
BLOCK_KEYWORDS = ['订单', '金额', '支付', '退款', '快递', '运单', '物流']


def get_last_processed_id():
    """读取最后处理过的消息 ROWID"""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                return int(f.read().strip())
    except (ValueError, OSError):
        pass
    return 0


def save_last_processed_id(rowid):
    """保存最后处理过的消息 ROWID"""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, 'w') as f:
            f.write(str(rowid))
    except OSError:
        pass


def extract_code(text):
    """从短信文本中提取验证码"""
    if not text:
        return None

    # 检查是否包含屏蔽关键词
    for kw in BLOCK_KEYWORDS:
        if kw in text:
            return None

    # 按优先级匹配
    for pattern in CODE_PATTERNS:
        match = pattern.search(text)
        if match:
            # pattern 中只有一个 group 就是验证码本身
            groups = match.groups()
            code = groups[-1]  # 取最后一个捕获组
            # 过滤明显的无效码（如全相同数字可能是假的）
            if len(set(code)) == 1 and len(code) >= 5:
                continue
            return code

    return None


def query_new_messages(db_path, since_rowid):
    """查询新短信"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Messages.app 核心表结构 (macOS Ventura+):
        # - message: ROWID, text, handle_id, date, date_delivered, is_from_me
        # - handle: ROWID, id (手机号/+86xxx), service
        # - chat_message_join: chat_id, message_id
        # 新消息: is_from_me=0 且 ROWID > since_rowid

        cursor.execute("""
            SELECT
                m.ROWID,
                m.text,
                m.date,
                h.id as sender,
                datetime(m.date/1000000000 + 978307200, 'unixepoch', 'localtime') as readable_time
            FROM message m
            JOIN handle h ON m.handle_id = h.ROWID
            WHERE m.ROWID > ?
              AND m.is_from_me = 0
              AND m.text IS NOT NULL
              AND m.text != ''
            ORDER BY m.ROWID ASC
        """, (since_rowid,))

        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        print(f"[ERROR] 数据库读取失败: {e}", file=sys.stderr)
        print(f"[HINT] 请确保终端已授权完全磁盘访问权限: 系统偏好设置 → 隐私与安全性 → 完全磁盘访问权限", file=sys.stderr)
        return []


def write_code(code, sender, text, readable_time):
    """将验证码写入输出文件"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = f"""[{timestamp}] 新验证码
发送方: {sender}
时间: {readable_time}
验证码: {code}
完整短信: {text[:200]}
---
"""
    try:
        with open(OUTPUT_FILE, 'a') as f:
            f.write(content)
        print(f"[{timestamp}] ✅ 验证码: {code} (来自 {sender}) → 已写入 {OUTPUT_FILE}")
        return True
    except OSError as e:
        print(f"[ERROR] 写入文件失败: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description='iPhone SMS → Agent 验证码桥接')
    parser.add_argument('--daemon', action='store_true', help='持续后台运行')
    parser.add_argument('--once', action='store_true', help='只检查一次后退出')
    parser.add_argument('--output', default=OUTPUT_FILE, help=f'输出文件路径 (默认: {OUTPUT_FILE})')
    args = parser.parse_args()

    global OUTPUT_FILE
    OUTPUT_FILE = args.output

    # 检查数据库是否存在
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Messages 数据库不存在: {DB_PATH}", file=sys.stderr)
        print("[HINT] 请确认已开启 iPhone 短信转发到 Mac", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] 短信监控已启动")
    print(f"[INFO] 数据库: {DB_PATH}")
    print(f"[INFO] 输出文件: {OUTPUT_FILE}")
    print(f"[INFO] 轮询间隔: {POLL_INTERVAL}s")
    print(f"[INFO] 按 Ctrl+C 停止")
    print()

    last_id = get_last_processed_id()
    print(f"[INFO] 从 ROWID={last_id} 之后开始监控新短信")

    if last_id == 0:
        # 首次运行：从最近的短信开始（跳过历史）
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(ROWID) FROM message")
            max_id = cursor.fetchone()[0]
            if max_id:
                last_id = max_id
                save_last_processed_id(last_id)
                print(f"[INFO] 首次运行，跳过历史短信，从 ROWID={last_id} 之后开始")
            conn.close()
        except sqlite3.Error:
            pass

    try:
        while True:
            messages = query_new_messages(DB_PATH, last_id)
            for msg in messages:
                code = extract_code(msg['text'])
                if code:
                    write_code(code, msg['sender'], msg['text'], msg['readable_time'])
                # 更新进度（无论是否提取到验证码）
                if msg['ROWID'] > last_id:
                    last_id = msg['ROWID']
                    save_last_processed_id(last_id)

            if args.once:
                print("[INFO] --once 模式，退出")
                break

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n[INFO] 监控已停止")
        sys.exit(0)


if __name__ == '__main__':
    main()
