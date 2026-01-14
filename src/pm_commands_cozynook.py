from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import re
import queue
import socket
import sys
import textwrap
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import aiohttp  # type: ignore

    _AIOHTTP_AVAILABLE = True
except Exception:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]
    _AIOHTTP_AVAILABLE = False

try:
    import aiofiles  # type: ignore

    _AIOFILES_AVAILABLE = True
except Exception:  # pragma: no cover
    aiofiles = None  # type: ignore[assignment]
    _AIOFILES_AVAILABLE = False

import astrbot.api.message_components as Comp
from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent
from astrbot.api.message_components import Plain
from astrbot.api.star import StarTools
from astrbot.core.utils.session_waiter import SessionController, session_waiter

from .models import EMPTY_PERSONA_NAME
from .text_utils import normalize_command_text, normalize_one_line, parse_command_choice, split_long_text


_ULA_RE = re.compile(r"^ula-[A-Za-z0-9]{16}$", re.IGNORECASE)
_XB_RE = re.compile(r"^xb-[A-Za-z0-9]{16}$", re.IGNORECASE)

_TEXT_EXTS = {
    ".txt",
    ".md",
    ".markdown",
    ".json",
    ".yaml",
    ".yml",
    ".csv",
    ".log",
}

_MAX_IMPORT_TEXT_FILE_BYTES = 512 * 1024

# 导出/下载缓存清理策略：参考 parser 的“下载后发出即可清理”的思路。
_EXPORT_DELETE_DELAY_SEC = 15 * 60
_CACHE_PRUNE_MAX_AGE_SEC = 24 * 60 * 60
_CACHE_PRUNE_MAX_FILES = 300

# CozyNook 站点/接口：按你的要求硬编码，不在 conf 显示。
COZYNOOK_SITE_URL = "https://c0zynook.com"
COZYNOOK_API_BASE = f"{COZYNOOK_SITE_URL}/api"

# 角色小屋：指定频道分享码（不在 conf 显示）。
DEFAULT_CHANNEL_INVITE_CODE = "XB-1F0C5B453D6E109B"


_PIL_MISSING_WARNED = False
_FONT_MISSING_WARNED = False


def _get_user_agent() -> str:
    return "astrbot-plugin-persona-manager/1.0"


def _is_xb(s: str) -> bool:
    return bool(_XB_RE.match(str(s or "").strip()))


async def _http_get_json_with_status_async(
    url: str,
    *,
    cookie_header: str = "",
    timeout_sec: int = 20,
    session: Any = None,
) -> tuple[int, dict[str, Any]]:
    """异步获取 JSON（依赖 aiohttp）。"""

    if not _AIOHTTP_AVAILABLE or aiohttp is None:
        logger.error("角色小屋：缺少 aiohttp，无法请求接口")
        return 0, {}

    headers = {"User-Agent": _get_user_agent()}
    if cookie_header:
        headers["Cookie"] = cookie_header

    timeout = aiohttp.ClientTimeout(total=max(int(timeout_sec), 1))
    close_session = False
    try:
        if session is None:
            session = aiohttp.ClientSession(timeout=timeout)
            close_session = True

        async with session.get(_normalize_url(url), headers=headers, timeout=timeout) as resp:
            status = int(resp.status)
            try:
                data = await resp.json(content_type=None)
            except Exception:
                raw = await resp.read()
                try:
                    data = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    data = {}
            return status, data if isinstance(data, dict) else {}
    except Exception:
        return 0, {}
    finally:
        if close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass


async def _http_post_json_with_status_async(
    url: str,
    body: dict[str, Any],
    *,
    cookie_header: str = "",
    timeout_sec: int = 20,
    session: Any = None,
) -> tuple[int, dict[str, Any]]:
    """异步 POST JSON（依赖 aiohttp）。"""

    if not _AIOHTTP_AVAILABLE or aiohttp is None:
        logger.error("角色小屋：缺少 aiohttp，无法请求接口")
        return 0, {}

    headers = {"User-Agent": _get_user_agent()}
    if cookie_header:
        headers["Cookie"] = cookie_header

    timeout = aiohttp.ClientTimeout(total=max(int(timeout_sec), 1))
    close_session = False
    try:
        if session is None:
            session = aiohttp.ClientSession(timeout=timeout)
            close_session = True

        async with session.post(_normalize_url(url), json=body, headers=headers, timeout=timeout) as resp:
            status = int(resp.status)
            try:
                data = await resp.json(content_type=None)
            except Exception:
                raw = await resp.read()
                try:
                    data = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    data = {}
            return status, data if isinstance(data, dict) else {}
    except Exception:
        return 0, {}
    finally:
        if close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass


async def _cozyverse_join_channel_by_invite_async(
    *,
    code: str,
    cookie: str,
    session: Any,
) -> tuple[int, dict[str, Any]]:
    code_s = str(code or "").strip().lower()
    url = f"{COZYNOOK_API_BASE}/invites/join"
    return await _http_post_json_with_status_async(url, {"code": code_s}, cookie_header=cookie, session=session)


async def _cozyverse_fetch_bootstrap_async(
    *,
    cookie: str,
    session: Any,
) -> tuple[int, dict[str, Any]]:
    url = f"{COZYNOOK_API_BASE}/bootstrap"
    return await _http_get_json_with_status_async(url, cookie_header=cookie, session=session)


async def _download_to_file_async(
    url: str,
    *,
    dest: Path,
    cookie_header: str = "",
    timeout_sec: int = 30,
    base_url: str | None = None,
    session: Any = None,
) -> Path:
    """异步下载文件（依赖 aiohttp），流式写盘避免 OOM。"""

    if not _AIOHTTP_AVAILABLE or aiohttp is None:
        raise RuntimeError("缺少 aiohttp，无法下载文件")

    dest.parent.mkdir(parents=True, exist_ok=True)
    final_url = _resolve_url(url, base=base_url or COZYNOOK_SITE_URL)

    # SSRF 防护：拒绝非 http(s)、以及指向 localhost/私网/回环的 host。
    try:
        parts0 = urllib.parse.urlsplit(final_url)
        if parts0.scheme not in {"http", "https"}:
            raise ValueError("unsupported scheme")
        host0 = parts0.hostname or ""
        if not await _is_safe_download_host(host0):
            raise ValueError(f"blocked host: {host0}")
    except Exception as ex:
        raise RuntimeError(f"疑似 SSRF 风险，已拒绝下载该 URL: {final_url}") from ex

    headers = {"User-Agent": _get_user_agent()}
    if cookie_header:
        headers["Cookie"] = cookie_header

    timeout = aiohttp.ClientTimeout(total=max(int(timeout_sec), 1))
    tmp = dest.with_name(dest.name + ".part")
    close_session = False
    try:
        if session is None:
            session = aiohttp.ClientSession(timeout=timeout)
            close_session = True

        current_url = final_url
        for _ in range(6):
            parts = urllib.parse.urlsplit(current_url)
            host = parts.hostname or ""
            if not await _is_safe_download_host(host):
                raise RuntimeError(f"疑似 SSRF 风险，已拒绝下载该 URL: {current_url}")

            async with session.get(
                _normalize_url(current_url),
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            ) as resp:
                # 手动处理重定向，避免自动跳转到内网地址。
                if 300 <= int(resp.status) < 400:
                    loc = resp.headers.get("Location") or resp.headers.get("location")
                    if loc:
                        current_url = urllib.parse.urljoin(current_url, str(loc))
                        continue

                resp.raise_for_status()

                if _AIOFILES_AVAILABLE and aiofiles is not None:
                    async with aiofiles.open(tmp, "wb") as f:  # type: ignore[attr-defined]
                        async for chunk in resp.content.iter_chunked(64 * 1024):
                            if chunk:
                                await f.write(chunk)
                else:
                    q: "queue.Queue[bytes | None]" = queue.Queue(maxsize=64)

                    def _writer() -> None:
                        with tmp.open("wb") as f:
                            while True:
                                item = q.get()
                                if item is None:
                                    break
                                f.write(item)

                    t = asyncio.to_thread(_writer)

                    async def _feed() -> None:
                        try:
                            async for chunk in resp.content.iter_chunked(64 * 1024):
                                if not chunk:
                                    continue
                                try:
                                    q.put_nowait(chunk)
                                except queue.Full:
                                    # 让出事件循环，等待 writer 消费
                                    await asyncio.to_thread(q.put, chunk)
                        finally:
                            try:
                                q.put_nowait(None)
                            except queue.Full:
                                await asyncio.to_thread(q.put, None)

                    await asyncio.gather(t, _feed())
                break
        else:
            raise RuntimeError(f"下载重定向过多，已放弃：{final_url}")
        tmp.replace(dest)
        return dest
    finally:
        if close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def _is_safe_download_host_sync(host: str) -> bool:
    """同步版本的下载 host 安全检查（用于无 aiohttp 时的回退下载）。

    在 asyncio.to_thread 中调用，允许阻塞解析。
    """

    if not host:
        return False

    host_s = host.strip().strip("[]")
    if _is_probably_localhost(host_s):
        return False

    # IP 字面量：快速判定
    try:
        if _is_private_or_local_ip(host_s):
            return False
        # 如果是合法 public IP，会走到这里
        return True
    except Exception:
        pass

    # 域名：DNS 解析所有 A/AAAA，任一落到私网/回环则拒绝
    try:
        infos = socket.getaddrinfo(host_s, None)
    except Exception:
        return False

    ips: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        try:
            ip = sockaddr[0]
            if isinstance(ip, str) and ip:
                ips.append(ip)
        except Exception:
            continue

    if not ips:
        return False

    for ip in ips:
        try:
            if _is_private_or_local_ip(ip):
                return False
        except Exception:
            return False

    return True


def _download_to_file_fallback_sync(
    url: str,
    *,
    dest: Path,
    cookie_header: str = "",
    timeout_sec: int = 30,
    base_url: str | None = None,
) -> Path:
    """无 aiohttp 时的同步下载回退（在 to_thread 中执行）。

    - 保留 SSRF 防护（host/IP 检查）
    - 手动处理重定向，避免跳到内网
    - 以 .part 临时文件写入，完成后 replace 原子落盘
    """

    dest.parent.mkdir(parents=True, exist_ok=True)
    final_url = _resolve_url(url, base=base_url or COZYNOOK_SITE_URL)

    try:
        parts0 = urllib.parse.urlsplit(final_url)
        if parts0.scheme not in {"http", "https"}:
            raise ValueError("unsupported scheme")
        host0 = parts0.hostname or ""
        if not _is_safe_download_host_sync(host0):
            raise ValueError(f"blocked host: {host0}")
    except Exception as ex:
        raise RuntimeError(f"疑似 SSRF 风险，已拒绝下载该 URL: {final_url}") from ex

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
            return None

    opener = urllib.request.build_opener(_NoRedirect)

    headers = {"User-Agent": _get_user_agent()}
    if cookie_header:
        headers["Cookie"] = cookie_header

    tmp = dest.with_name(dest.name + ".part")
    current_url = final_url
    try:
        for _ in range(6):
            parts = urllib.parse.urlsplit(current_url)
            host = parts.hostname or ""
            if not _is_safe_download_host_sync(host):
                raise RuntimeError(f"疑似 SSRF 风险，已拒绝下载该 URL: {current_url}")

            req = urllib.request.Request(_normalize_url(current_url), method="GET")
            for k, v in headers.items():
                req.add_header(k, v)

            try:
                with opener.open(req, timeout=max(int(timeout_sec), 1)) as resp:
                    with tmp.open("wb") as f:
                        while True:
                            chunk = resp.read(64 * 1024)
                            if not chunk:
                                break
                            f.write(chunk)
                tmp.replace(dest)
                return dest
            except urllib.error.HTTPError as he:
                code = int(getattr(he, "code", 0) or 0)
                if code in {301, 302, 303, 307, 308}:
                    loc = he.headers.get("Location") or he.headers.get("location")
                    if loc:
                        current_url = urllib.parse.urljoin(current_url, str(loc))
                        continue
                raise

        raise RuntimeError(f"下载重定向过多，已放弃：{final_url}")
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


@dataclass
class CozyPostFile:
    index: int
    name: str
    url: str
    kind: str  # image|file


def _safe_filename(name: str) -> str:
    s = (name or "").strip() or "file"
    for ch in "\\/:*?\"<>|":
        s = s.replace(ch, "_")
    return s[:120]


def _parse_post_files(files: Any) -> list[CozyPostFile]:
    out: list[CozyPostFile] = []
    if not isinstance(files, list):
        return out

    idx = 1
    for entry in files:
        url = ""
        name = ""
        kind = "file"

        if isinstance(entry, str):
            url = entry.strip()
            if url.startswith("data:image/"):
                kind = "image"
                name = f"image_{idx}.png"
            else:
                try:
                    name = urllib.parse.unquote(url.split("?")[0].split("#")[0].split("/")[-1])
                except Exception:
                    name = url.split("/")[-1]
        elif isinstance(entry, dict):
            url = str(entry.get("url") or entry.get("href") or "").strip()
            name = str(entry.get("name") or "").strip()
            kind_raw = str(entry.get("kind") or entry.get("type") or "").strip().lower()
            if kind_raw == "image" or url.startswith("data:image/"):
                kind = "image"

        if not url:
            continue
        if not name:
            name = f"image_{idx}.png" if kind == "image" else f"file_{idx}"

        out.append(CozyPostFile(index=idx, name=_safe_filename(name), url=url, kind=kind))
        idx += 1

    return out


def _is_ula(s: str) -> bool:
    return bool(_ULA_RE.match((s or "").strip()))


def _normalize_url(url: str) -> str:
    s = (url or "").strip()
    if not s:
        return ""
    if s.startswith("data:"):
        return s
    try:
        parts = urllib.parse.urlsplit(s)
        if not parts.scheme or not parts.netloc:
            return s
        path = urllib.parse.quote(parts.path, safe="/%")
        query = urllib.parse.quote(parts.query, safe="=&%")
        fragment = urllib.parse.quote(parts.fragment, safe="%")
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, fragment))
    except Exception:
        return s


def _resolve_url(url: str, *, base: str) -> str:
    s = (url or "").strip()
    if not s:
        return ""
    if s.startswith("data:"):
        return s
    if s.startswith("http://") or s.startswith("https://"):
        return s
    try:
        return urllib.parse.urljoin(base.rstrip("/") + "/", s.lstrip("/"))
    except Exception:
        return s


def _is_probably_localhost(host: str) -> bool:
    h = (host or "").strip().strip("[]").casefold()
    return h in {"localhost", "localhost.localdomain"} or h.endswith(".localhost")


def _is_private_or_local_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


async def _is_safe_download_host(host: str) -> bool:
    """尽量避免 SSRF：拒绝 localhost/私网/回环等地址。"""

    if not host:
        return False

    host_s = host.strip().strip("[]")
    if _is_probably_localhost(host_s):
        return False

    # IP 字面量：快速判定
    try:
        ipaddress.ip_address(host_s)
        return not _is_private_or_local_ip(host_s)
    except Exception:
        pass

    # 域名：允许官方域名；其余域名做一次解析并拒绝解析到私网/回环
    h = host_s.casefold()
    if h == "c0zynook.com" or h.endswith(".c0zynook.com"):
        return True

    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host_s, None, type=socket.SOCK_STREAM)
    except Exception:
        return False

    addrs: set[str] = set()
    for _family, _type, _proto, _canonname, sockaddr in infos:
        try:
            ip = sockaddr[0]
            if ip:
                addrs.add(str(ip))
        except Exception:
            continue

    if not addrs:
        return False

    return all(not _is_private_or_local_ip(ip) for ip in addrs)


async def _delete_file_later(path: Path, delay_sec: int) -> None:
    try:
        await asyncio.sleep(max(int(delay_sec), 0))
        await asyncio.to_thread(path.unlink, missing_ok=True)
    except Exception:
        return


def _schedule_delete(path: Path, delay_sec: int = _EXPORT_DELETE_DELAY_SEC) -> None:
    try:
        asyncio.create_task(_delete_file_later(path, delay_sec))
    except Exception:
        # 某些运行环境不允许 create_task；则放弃自动删除。
        return


def _prune_cache_dir(dir_path: Path, *, max_age_sec: int = _CACHE_PRUNE_MAX_AGE_SEC, max_files: int = _CACHE_PRUNE_MAX_FILES) -> None:
    try:
        if not dir_path.exists():
            return
        now = time.time()
        files = [p for p in dir_path.iterdir() if p.is_file()]
        # 先按过期删除
        for p in files:
            try:
                st = p.stat()
                if now - st.st_mtime > max_age_sec:
                    p.unlink(missing_ok=True)
            except Exception:
                continue

        # 再按数量裁剪（保留最新）
        files = [p for p in dir_path.iterdir() if p.is_file()]
        if len(files) <= max_files:
            return
        files.sort(key=lambda x: x.stat().st_mtime if x.exists() else 0.0, reverse=True)
        for p in files[max_files:]:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                continue
    except Exception:
        return


def _decode_probably_text(raw: bytes) -> str | None:
    if not raw:
        return ""
    if b"\x00" in raw:
        return None

    for enc in ("utf-8", "utf-8-sig", "gb18030", "gbk", "cp936"):
        try:
            return raw.decode(enc)
        except Exception:
            continue

    text = raw.decode("utf-8", errors="replace")
    if not text:
        return ""
    # 如果替换字符过多，通常说明不是可读文本
    if text.count("\ufffd") / max(len(text), 1) > 0.05:
        return None
    return text


def _is_importable_text_file(f: CozyPostFile) -> bool:
    if f.kind == "image":
        return False
    # 扩展名不在白名单也允许导入，但会受大小/解码启发式限制
    return True


def _make_file_component(file_path: Path):
    def _try_ctor(cls, *args, **kwargs):
        try:
            return cls(*args, **kwargs)
        except Exception:
            return None

    def _try_from_fs(cls):
        # 常见命名：fromFileSystem / from_file_system
        for attr in ("fromFileSystem", "from_file_system", "from_path", "fromPath"):
            fn = getattr(cls, attr, None)
            if callable(fn):
                try:
                    return fn(str(file_path))
                except Exception:
                    pass
        return None

    # 1) 优先尝试 API 组件（很多插件用的是 astrbot.api.message_components.File）
    try:
        from astrbot.api.message_components import File as ApiFile

        got = _try_from_fs(ApiFile)
        if got is not None:
            return got

        for kwargs in (
            {"name": file_path.name, "file": str(file_path)},
            {"name": file_path.name, "path": str(file_path)},
            {"file": str(file_path)},
            {"path": str(file_path)},
        ):
            got = _try_ctor(ApiFile, **kwargs)
            if got is not None:
                return got

        got = _try_ctor(ApiFile, str(file_path))
        if got is not None:
            return got
    except Exception:
        pass

    # 2) 再尝试核心组件（不同版本参数名/构造方式可能不同）
    try:
        from astrbot.core.message.components import File as CoreFile

        got = _try_from_fs(CoreFile)
        if got is not None:
            return got

        for kwargs in (
            {"name": file_path.name, "file": str(file_path)},
            {"name": file_path.name, "path": str(file_path)},
            {"file": str(file_path)},
            {"path": str(file_path)},
        ):
            got = _try_ctor(CoreFile, **kwargs)
            if got is not None:
                return got

        got = _try_ctor(CoreFile, str(file_path))
        if got is not None:
            return got
    except Exception:
        pass

    # 3) 最后尝试 Comp.File（动态获取）
    try:
        file_cls = getattr(Comp, "File", None)
        if file_cls is not None:
            got = _try_from_fs(file_cls)
            if got is not None:
                return got
            for kwargs in (
                {"name": file_path.name, "file": str(file_path)},
                {"name": file_path.name, "path": str(file_path)},
                {"file": str(file_path)},
                {"path": str(file_path)},
            ):
                got = _try_ctor(file_cls, **kwargs)
                if got is not None:
                    return got
            got = _try_ctor(file_cls, str(file_path))
            if got is not None:
                return got
    except Exception:
        pass

    return None


def _pick_font_path(preferred: str | None = None) -> str | None:
    # 优先使用用户显式配置的字体路径。
    preferred = (preferred or "").strip()
    if preferred:
        try:
            p = Path(preferred)
            if p.exists() and p.is_file():
                return str(p)
        except Exception:
            pass

    # 其次在系统字体目录中按“常见字体文件名”查找。
    roots: list[Path]
    if sys.platform.startswith("win"):
        roots = [Path("C:/Windows/Fonts")]
    elif sys.platform == "darwin":
        roots = [Path("/System/Library/Fonts"), Path("/Library/Fonts")]
    else:
        roots = [
            Path("/usr/share/fonts"),
            Path("/usr/local/share/fonts"),
            Path.home() / ".fonts",
        ]

    preferred_names = [
        # Windows
        "msyh.ttc",
        "msyh.ttf",
        "simsun.ttc",
        "simhei.ttf",
        # macOS
        "PingFang.ttc",
        "STHeiti Light.ttc",
        # Linux
        "NotoSansCJK-Regular.ttc",
        "NotoSansCJKsc-Regular.otf",
        "wqy-microhei.ttc",
        "wqy-zenhei.ttc",
        "DejaVuSans.ttf",
    ]

    for root in roots:
        try:
            if not root.exists():
                continue
            for fname in preferred_names:
                p = root / fname
                if p.exists() and p.is_file():
                    return str(p)
        except Exception:
            continue

    # 最后做一次“按文件名”有限递归搜索（在 to_thread 的渲染线程中执行，不阻塞事件循环）。
    for root in roots:
        try:
            if not root.exists():
                continue
            for fname in preferred_names:
                for p in root.rglob(fname):
                    if p.exists() and p.is_file():
                        return str(p)
        except Exception:
            continue

    return None


def _wrap_lines(text: str, *, width: int, max_lines: int) -> list[str]:
    text = (text or "").replace("\r", "").strip()
    if not text:
        return []
    out: list[str] = []
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            out.append("")
            continue
        out.extend(textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False))
        if len(out) >= max_lines:
            return out[:max_lines]
    return out[:max_lines]


def _format_post_date_str(v: Any) -> str:
    """尽量把不同来源的时间字段格式化成可读字符串。"""
    if v is None:
        return ""
    if isinstance(v, (int, float)):
        ts = float(v)
        # 兼容毫秒时间戳
        if ts > 1_000_000_000_000:
            ts = ts / 1000.0
        try:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
        except Exception:
            return ""
    try:
        s = str(v).strip()
    except Exception:
        return ""
    return s[:48]


def _render_post_preview_image(
    *,
    title: str,
    author: str,
    date_str: str,
    intro: str,
    content: str,
    files: list[CozyPostFile],
    pwd: str,
    font_path_preferred: str | None = None,
) -> Path | None:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        global _PIL_MISSING_WARNED
        if not _PIL_MISSING_WARNED:
            _PIL_MISSING_WARNED = True
            logger.info("CozyNook 预览图功能不可用：缺少可选依赖 Pillow（pip install pillow）。")
        return None

    w = 960
    h = 1280
    bg = (15, 16, 20)
    accent = (211, 161, 126)
    fg = (235, 235, 240)
    subtle = (160, 165, 175)

    img = Image.new("RGB", (w, h), bg)
    draw = ImageDraw.Draw(img)

    font_path = _pick_font_path(font_path_preferred)
    if not font_path:
        global _FONT_MISSING_WARNED
        if not _FONT_MISSING_WARNED:
            _FONT_MISSING_WARNED = True
            logger.info(
                "CozyNook 预览图渲染失败：未找到可用字体。\n"
                "请在配置中设置 `cozynook_preview_font_path` 指向一个字体文件（如 Windows: C:/Windows/Fonts/msyh.ttc）。"
            )
        return None

    try:
        font_title = ImageFont.truetype(font_path, 40)
        font_meta = ImageFont.truetype(font_path, 22)
        font_body = ImageFont.truetype(font_path, 24)
        font_small = ImageFont.truetype(font_path, 20)
    except Exception:
        # 字体不可用时直接降级为文本预览，避免“截图乱码/方块字”
        logger.debug("CozyNook 预览图字体加载失败，已跳过渲染（可在配置中指定字体路径）。")
        return None

    pad = 42
    y = 34

    draw.rounded_rectangle((pad - 16, y - 10, w - pad + 16, y + 66), radius=18, fill=(26, 28, 36))
    draw.text((pad, y), "CozyNook · 角色小屋", fill=accent, font=font_meta)
    y += 56

    title_lines = _wrap_lines((title or "(无标题)"), width=22, max_lines=2)
    for line in title_lines:
        draw.text((pad, y), line, fill=fg, font=font_title)
        y += 48
    y += 8

    meta = f"{(author or 'Unknown').strip()} · {date_str}"
    draw.text((pad, y), meta[:120], fill=subtle, font=font_meta)
    y += 44

    intro2 = (intro or "").strip()
    if intro2:
        draw.text((pad, y), "简介", fill=accent, font=font_meta)
        y += 28
        intro_lines = _wrap_lines(intro2, width=34, max_lines=6)
        for line in intro_lines:
            draw.text((pad, y), line, fill=fg, font=font_body)
            y += 30
        y += 14

    draw.text((pad, y), "正文", fill=accent, font=font_meta)
    y += 28
    body = (content or "").strip().replace("\r", "")
    body_lines = _wrap_lines(body, width=34, max_lines=14)
    for line in body_lines:
        draw.text((pad, y), line, fill=fg, font=font_body)
        y += 30
        if y > h - 240:
            break
    y += 14

    draw.text((pad, y), "附件", fill=accent, font=font_meta)
    y += 28

    if not files:
        draw.text((pad, y), "(无附件)", fill=subtle, font=font_small)
    else:
        for f in files[:18]:
            tag = "IMG" if f.kind == "image" else "FILE"
            line = f"{f.index}. [{tag}] {f.name}"
            draw.text((pad, y), line[:110], fill=subtle, font=font_small)
            y += 26

    out_dir = StarTools.get_data_dir("astrbot_plugin_persona_manager") / "cozynook_cache"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    out = out_dir / f"cozynook_post_{pwd.lower()}_{ts}.png"
    img.save(out)
    return out


def _format_post_text(
    *,
    pwd: str,
    title: str,
    author: str,
    intro: str,
    content: str,
    files: list[CozyPostFile],
    comments: list[str],
) -> str:
    title_line = (title or "(无标题)").strip()
    # 展示时不输出密码（ULA）。

    lines: list[str] = [f"标题：{title_line}", f"作者：{(author or '').strip()}"]

    intro2 = (intro or "").strip()
    if intro2:
        lines.append("简介：")
        lines.append(intro2)

    lines.append("正文：")
    lines.append((content or "").strip())

    lines.append("附件名：")
    if not files:
        lines.append("(无附件)")
    else:
        for f in files:
            tag = "[图片]" if f.kind == "image" else "[文件]"
            lines.append(f"{f.index}. {tag} {f.name}")

    lines.append("评论（最新10条）：")
    if not comments:
        lines.append("(无评论或接口未返回评论)")
    else:
        for i, c in enumerate(comments[:10], start=1):
            lines.append(f"{i}. {normalize_one_line(c)}")

    return "\n".join([line for line in lines if line is not None])


def _extract_recent_comments(payload: dict[str, Any]) -> list[str]:
    """尽量兼容不同字段名：返回最新 10 条评论文本（越新越靠前）。"""

    def _as_list(v: Any) -> list[Any]:
        return v if isinstance(v, list) else []

    post = payload.get("post") if isinstance(payload.get("post"), dict) else {}
    candidates: list[Any] = []

    for key in ("comments", "commentList", "replies", "messages", "items"):
        candidates = _as_list(post.get(key)) or _as_list(payload.get(key))
        if candidates:
            break

    if not candidates:
        return []

    # 尝试按时间排序（如果有时间字段），否则按原顺序取末尾。
    def _ts(item: Any) -> float:
        if not isinstance(item, dict):
            return 0.0
        for k in ("time", "createdAt", "created_at", "timestamp", "ts"):
            v = item.get(k)
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, str) and v.isdigit():
                try:
                    return float(v)
                except Exception:
                    pass
        return 0.0

    has_ts = any(isinstance(x, dict) and _ts(x) > 0 for x in candidates)
    items = list(candidates)
    if has_ts:
        items.sort(key=_ts, reverse=True)
        items = items[:10]
    else:
        items = items[-10:][::-1]

    out: list[str] = []
    for it in items:
        if isinstance(it, str):
            txt = it.strip()
            if txt:
                out.append(txt)
            continue
        if not isinstance(it, dict):
            continue

        user_obj = it.get("user")
        if isinstance(user_obj, dict):
            who = str(user_obj.get("name") or user_obj.get("nickname") or "").strip()
        else:
            who = str(it.get("author") or it.get("authorName") or it.get("user") or it.get("nickname") or "").strip()
        msg = str(it.get("content") or it.get("text") or it.get("message") or "").strip()
        t = str(it.get("time") or it.get("createdAt") or it.get("created_at") or "").strip()

        if not msg:
            continue
        if who and t:
            out.append(f"{who}（{t}）：{msg}")
        elif who:
            out.append(f"{who}：{msg}")
        else:
            out.append(msg)

    return out


async def _cozyverse_fetch_post_by_password_async(
    *,
    pwd: str,
    cookie: str,
    session: Any = None,
) -> tuple[int, dict[str, Any]]:
    """异步版本：通过后端接口用 ULA 打开帖子，返回 (status, post)。"""

    if not cookie:
        return 0, {}

    pwd_s = (pwd or "").strip()

    url = f"{COZYNOOK_API_BASE}/v1/posts/by-password?pwd={urllib.parse.quote(pwd_s)}"
    status, data = await _http_get_json_with_status_async(url, cookie_header=cookie, session=session)
    if isinstance(data, dict) and data.get("ok") and isinstance(data.get("post"), dict):
        return status, data.get("post") or {}

    url2 = f"{COZYNOOK_API_BASE}/posts/by-password?pwd={urllib.parse.quote(pwd_s)}"
    status2, data2 = await _http_get_json_with_status_async(url2, cookie_header=cookie, session=session)
    if not isinstance(data2, dict) or not data2.get("ok"):
        return status2 or status, {}
    post = data2.get("post")
    if not isinstance(post, dict):
        return status2 or status, {}
    return status2 or status, post


async def _cozyverse_fetch_latest_comments_v1_async(
    *,
    post_id: int,
    cookie: str,
    take: int = 10,
    session: Any = None,
) -> tuple[int, list[str]]:
    """异步版本：拉取最新评论。"""

    if not cookie:
        return 0, []

    ps = max(1, min(int(take or 10), 50))

    url = f"{COZYNOOK_API_BASE}/v1/posts/{int(post_id)}/comments/cursor?page_size={ps}"
    status, data = await _http_get_json_with_status_async(url, cookie_header=cookie, session=session)
    if isinstance(data, dict) and data.get("ok"):
        items = data.get("items")
        if not isinstance(items, list):
            items = []
        comments = _extract_recent_comments({"items": items})
        return status, comments[: int(take)]

    url2 = f"{COZYNOOK_API_BASE}/v1/posts/{int(post_id)}/comments?page=1&page_size={ps}"
    status2, data2 = await _http_get_json_with_status_async(url2, cookie_header=cookie, session=session)
    if isinstance(data2, dict) and data2.get("ok"):
        items2 = data2.get("items")
        if not isinstance(items2, list):
            cobj = data2.get("comments")
            if isinstance(cobj, dict) and isinstance(cobj.get("items"), list):
                items2 = cobj.get("items")
            else:
                items2 = []
        comments = _extract_recent_comments({"items": items2})
        return status2, comments[: int(take)]

    return status2 or status, []


async def cozynook_draw_channel_cards(self, event: AstrMessageEvent, section_name: Any = ""):
    """/角色小屋：从指定分享码频道随机抽卡片，并输出标题 + 密码。

    - /角色小屋：输出分区列表 + 从全频道随机抽取
    - /角色小屋 分区名：仅从该分区随机抽取
    """

    def _yield_merged_text(lines: list[str]):
        merged = "\n".join([str(x) for x in lines if str(x).strip()])
        parts = split_long_text(merged, max_chars=3000)
        nodes: list[Comp.Node] = []
        uin = str(event.get_self_id())
        for p in parts:
            nodes.append(Comp.Node(uin=uin, name="角色小屋", content=[Plain(p)]))
        return event.chain_result([Comp.Nodes(nodes)])

    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    # 必须有登录态 Cookie：/invites/join 与 /bootstrap 都需要鉴权才能拿到 posts。
    cookie = ""
    try:
        cookie = self._cfg.cozynook_cookie_header()
    except Exception:
        cookie = ""

    if not cookie:
        yield _yield_merged_text(
            [
                "未配置 Cozyverse 登录态 Cookie。",
                "请在插件配置里填写 cozynook_sid_cookie（可填 cv_auth=... 或 cv_sid=...）。",
            ]
        )
        return

    section_query = normalize_one_line(str(section_name or "")).strip()

    try:
        pick_n = int(getattr(self._cfg, "cozynook_channel_cards_pick", 15) or 15)
    except Exception:
        pick_n = 15
    if pick_n < 1:
        pick_n = 1
    if pick_n > 30:
        pick_n = 30

    code = str(DEFAULT_CHANNEL_INVITE_CODE or "").strip().lower()
    if not _is_xb(code):
        yield _yield_merged_text(["角色小屋分享码配置无效（应为 xb-16位）。"])
        return

    if not _AIOHTTP_AVAILABLE or aiohttp is None:
        yield _yield_merged_text(["缺少依赖 aiohttp，无法访问角色小屋接口。", "请安装：pip install aiohttp"])
        return

    session = None
    close_session = False
    try:
        timeout = aiohttp.ClientTimeout(total=max(int(getattr(self._cfg, "cozynook_timeout_sec", 20) or 20), 1))
        headers = {"User-Agent": _get_user_agent()}
        if cookie:
            headers["Cookie"] = cookie

        session = aiohttp.ClientSession(timeout=timeout, headers=headers)
        close_session = True

        j_status, j_data = await _cozyverse_join_channel_by_invite_async(code=code, cookie=cookie, session=session)
        if not (isinstance(j_data, dict) and j_data.get("ok")):
            if int(j_status or 0) == 401:
                yield _yield_merged_text(["登录态已失效：已退出。", "请更新 cozynook_sid_cookie 后重试。"])
                return
            yield _yield_merged_text(["加入频道失败：已退出。"])
            return

        try:
            channel_id = int(j_data.get("channelId") or 0)
        except Exception:
            channel_id = 0
        if channel_id <= 0:
            yield _yield_merged_text(["加入频道失败：已退出。"])
            return

        b_status, b_data = await _cozyverse_fetch_bootstrap_async(cookie=cookie, session=session)
        if not (isinstance(b_data, dict) and b_data.get("ok")):
            if int(b_status or 0) == 401:
                yield _yield_merged_text(["登录态已失效：已退出。", "请更新 cozynook_sid_cookie 后重试。"])
                return
            yield _yield_merged_text(["拉取频道内容失败：已退出。"])
            return

        channels = b_data.get("channels")
        if not isinstance(channels, list):
            channels = []

        channel_obj: dict[str, Any] | None = None
        for ch in channels:
            if not isinstance(ch, dict):
                continue
            try:
                if int(ch.get("id") or 0) == int(channel_id):
                    channel_obj = ch
                    break
            except Exception:
                continue

        sections = []
        if isinstance(channel_obj, dict):
            s = channel_obj.get("sections")
            if isinstance(s, list):
                sections = [x for x in s if isinstance(x, dict)]

        section_name_list = []
        section_id_by_name: dict[str, int] = {}
        for s in sections:
            name = normalize_one_line(str(s.get("name") or "")).strip()
            try:
                sid = int(s.get("id") or 0)
            except Exception:
                sid = 0
            if not name or sid <= 0:
                continue
            section_name_list.append(name)
            section_id_by_name[name.casefold()] = sid

        section_id_filter: int | None = None
        if section_query:
            section_id_filter = section_id_by_name.get(section_query.casefold())
            if not section_id_filter:
                hint = " / ".join(section_name_list) if section_name_list else "(暂无分区)"
                yield _yield_merged_text(
                    [
                        "未找到该分区，已退出。",
                        f"可用分区：{hint}",
                        "用法：/角色小屋 分区名",
                    ]
                )
                return

        posts = b_data.get("posts")
        if not isinstance(posts, list):
            posts = []

        in_channel = []
        for p in posts:
            if not isinstance(p, dict):
                continue
            try:
                if int(p.get("channelId") or 0) != int(channel_id):
                    continue
            except Exception:
                continue
            if section_id_filter is not None:
                try:
                    if int(p.get("sectionId") or 0) != int(section_id_filter):
                        continue
                except Exception:
                    continue
            in_channel.append(p)

        with_pwd = []
        for p in in_channel:
            pwd = str(p.get("postPwd") or "").strip()
            if not pwd:
                continue
            with_pwd.append(p)

        if not with_pwd:
            lines = []
            if section_query:
                lines.append(f"【分区】{section_query}")
            lines.extend(["频道暂无可用卡片（可能卡片未公开密码，或你没有查看权限）。", "已退出。"])
            yield _yield_merged_text(lines)
            return

        want = min(int(pick_n), len(with_pwd))
        chosen = random.sample(with_pwd, want) if len(with_pwd) > want else list(with_pwd)

        lines: list[str] = []
        if not section_query:
            if section_name_list:
                lines.append("【分区】" + " / ".join(section_name_list))
                lines.append("用法：/角色小屋 分区名  （仅从该分区随机）")
            else:
                lines.append("【分区】(暂无分区)")
        else:
            lines.append(f"【分区】{section_query}")

        lines.append(f"【角色小屋】抽到 {want} 张卡片")
        for i, p in enumerate(chosen, 1):
            title = str(p.get("title") or "").strip() or "(无标题)"
            pwd = str(p.get("postPwd") or "").strip()
            lines.append(f"{i}. {title} — {pwd}")

        if want < int(pick_n):
            lines.append(f"（本次仅抽到 {want} 张：频道内可见密码的卡片不足 {pick_n} 张）")

        lines.append("\n可用指令：/获取卡片 ula-xxxx（查看帖子） /导入角色 ula-xxxx（导入）")

        yield _yield_merged_text(lines)
    finally:
        if close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass


async def cozynook_get(self, event: AstrMessageEvent, arg, *, allow_import: bool, mode: str | None = None):
    """/获取卡片 与 /导入角色 /导出角色 的统一入口。

    mode:
      - None: 交互式询问导入/导出
      - "import": 直接进入导入流程
      - "export": 直接进入导出流程
    """

    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    raw = str(arg or "").strip()
    if not raw:
        yield event.plain_result("用法：/获取卡片 ula-XXXXXXXXXXXXXXXX（16位）")
        return

    pwd = raw
    if not _is_ula(pwd):
        yield event.plain_result("用法：/获取卡片 ula-XXXXXXXXXXXXXXXX（16位）")
        return

    cookie = ""
    try:
        cookie = self._cfg.cozynook_cookie_header()
    except Exception:
        cookie = ""

    if not cookie:
        yield event.plain_result(
            "未配置 Cozyverse 登录态 Cookie。\n"
            "请在插件配置里填写 `cozynook_sid_cookie`：可填 `cv_auth=...` 或 `cv_sid=...`（从浏览器 Cookie 复制）。"
        )
        return

    # 评论展示条数可配置（0-50）；默认 10。
    try:
        take = int(getattr(self._cfg, "cozynook_comments_take", 10) or 0)
    except Exception:
        take = 10
    if take < 0:
        take = 0
    if take > 50:
        take = 50

    post_id = 0
    comments: list[str] = []

    session = None
    close_session = False
    try:
        # 复用同一个 aiohttp session：获取帖子 + 拉评论 + 后续导入/导出下载共享连接池
        if not _AIOHTTP_AVAILABLE or aiohttp is None:
            yield event.plain_result("缺少依赖 aiohttp，无法访问角色小屋接口。请安装：pip install aiohttp")
            return

        timeout = aiohttp.ClientTimeout(total=max(int(getattr(self._cfg, "cozynook_timeout_sec", 20) or 20), 1))
        headers = {"User-Agent": _get_user_agent()}
        if cookie:
            headers["Cookie"] = cookie

        session = aiohttp.ClientSession(timeout=timeout, headers=headers)
        close_session = True

        status, post = await _cozyverse_fetch_post_by_password_async(pwd=pwd, cookie=cookie, session=session)

        if isinstance(post, dict):
            try:
                post_id = int(post.get("id") or 0)
            except Exception:
                post_id = 0
            if post_id > 0 and take > 0:
                try:
                    _c_status, comments = await _cozyverse_fetch_latest_comments_v1_async(
                        post_id=post_id,
                        cookie=cookie,
                        take=take,
                        session=session,
                    )
                except Exception:
                    comments = []
    except Exception as ex:
        logger.error(f"Cozyverse 拉取失败: {ex!s}")
        yield event.plain_result("Cozyverse 拉取失败，请稍后重试。")
        if close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass
        return

    if not post:
        st = int(status or 0)
        if st == 404:
            yield event.plain_result("未获取到帖子内容（密码可能错误或帖子不存在）。")
        elif st == 401:
            yield event.plain_result(
                "未获取到帖子内容（登录态失效或未登录，接口返回 401）。\n"
                "请更新插件配置 `cozynook_sid_cookie`：推荐填 `cv_auth=...`（从浏览器 Cookie 复制）。"
            )
        elif st == 403:
            yield event.plain_result("未获取到帖子内容（无权限访问，接口返回 403）。")
        elif st == 0:
            yield event.plain_result("未获取到帖子内容（网络异常或接口无响应）。")
        else:
            yield event.plain_result("未获取到帖子内容（接口返回异常）。")
        if close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass
        return

    title = str(post.get("title") or "").strip()
    author = str(post.get("authorName") or "").strip()
    intro = str(post.get("intro") or "").strip()
    content = str(post.get("content") or "").strip()
    files = _parse_post_files(post.get("files"))

    date_str = _format_post_date_str(
        post.get("time")
        or post.get("createdAt")
        or post.get("created_at")
        or post.get("date")
        or post.get("created")
    )
    if not date_str:
        date_str = time.strftime("%Y-%m-%d", time.localtime())

    # 获取帖子时：优先发送“合并转发聊天记录”文本（含附件名与最新评论）。
    use_preview = bool(getattr(self._cfg, "cozynook_use_preview_image", False))
    if use_preview:
        try:
            preferred_font = str(getattr(self._cfg, "cozynook_preview_font_path", "") or "").strip()
        except Exception:
            preferred_font = ""

        preview = await asyncio.to_thread(
            _render_post_preview_image,
            title=title,
            author=author,
            date_str=date_str,
            intro=intro,
            content=content,
            files=files,
            pwd=pwd,
            font_path_preferred=preferred_font,
        )
        if preview is not None:
            yield event.chain_result([Comp.Image(str(preview))])
            _schedule_delete(Path(preview))
        else:
            merged = _format_post_text(
                pwd=pwd,
                title=title,
                author=author,
                intro=intro,
                content=content,
                files=files,
                comments=comments,
            )
            parts = split_long_text(merged, max_chars=3000)
            nodes: list[Comp.Node] = []
            uin = str(event.get_self_id())
            for p in parts:
                nodes.append(Comp.Node(uin=uin, name="角色小屋", content=[Plain(p)]))
            yield event.chain_result([Comp.Nodes(nodes)])
    else:
        merged = _format_post_text(
            pwd=pwd,
            title=title,
            author=author,
            intro=intro,
            content=content,
            files=files,
            comments=comments,
        )
        parts = split_long_text(merged, max_chars=3000)
        nodes: list[Comp.Node] = []
        uin = str(event.get_self_id())
        for p in parts:
            nodes.append(Comp.Node(uin=uin, name="角色小屋", content=[Plain(p)]))
        yield event.chain_result([Comp.Nodes(nodes)])

    mode_norm = (mode or "").strip().lower()
    if mode_norm in {"import", "导入"}:
        async for r in _handle_import_flow(
            self,
            event,
            pwd=pwd,
            title=title,
            author=author,
            intro=intro,
            content=content,
            files=files,
            cookie=cookie,
            base_url=COZYNOOK_SITE_URL,
            session=session,
        ):
            yield r
        if close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass
        return

    yield event.plain_result(
        "请选择操作：\n"
        "- /导入：导入为你的人设（不使用前后置提示词）\n"
        "- /导出：导出帖子内容/附件\n"
        "也可直接用命令：/导入角色 ula-xxxx 或 /导出角色 ula-xxxx"
    )

    timeout = int(getattr(self._cfg, "session_timeout_sec", 300) or 300)
    initial_sender_id = str(event.get_sender_id())
    initial_event = event

    @session_waiter(timeout=timeout, record_history_chains=False)
    async def waiter(controller: SessionController, e: AstrMessageEvent):
        if self._is_self_message_event(e) or self._is_empty_echo_event(e):
            controller.keep(timeout=timeout, reset_timeout=True)
            return
        if str(e.get_sender_id()) != initial_sender_id:
            controller.keep(timeout=timeout, reset_timeout=True)
            return
        if e is initial_event:
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        e.stop_event()

        text = (e.message_str or "").strip().lstrip("/／").strip()
        if text in {"导出", "export"}:
            controller.stop()
            async for rr in _handle_export_flow(
                self,
                e,
                pwd=pwd,
                title=title,
                author=author,
                intro=intro,
                content=content,
                files=files,
                cookie=cookie,
                base_url=COZYNOOK_SITE_URL,
                session=session,
            ):
                await e.send(rr)
            return
        if text in {"导入", "import"}:
            controller.stop()
            async for rr in _handle_import_flow(
                self,
                e,
                pwd=pwd,
                title=title,
                author=author,
                intro=intro,
                content=content,
                files=files,
                cookie=cookie,
                base_url=COZYNOOK_SITE_URL,
                session=session,
            ):
                await e.send(rr)
            return

        # 未明确选择 /导入 或 /导出：立刻结束会话并终止传播。
        await e.send(
            e.plain_result(
                "未选择操作，已退出。需要导入/导出请重新发送：/获取卡片 ula-xxxx\n"
                "或直接用：/导入角色 ula-xxxx /导出角色 ula-xxxx"
            )
        )
        controller.stop()
        return

    try:
        await waiter(event)
    except TimeoutError:
        yield event.plain_result("会话超时，已退出操作选择。")

    if close_session and session is not None:
        try:
            await session.close()
        except Exception:
            pass


async def _handle_export_flow(
    self,
    event: AstrMessageEvent,
    *,
    pwd: str,
    title: str,
    author: str,
    intro: str,
    content: str,
    files: list[CozyPostFile],
    cookie: str,
    base_url: str,
    session: Any = None,
):
    # 导出流程不再重复发送一遍聊天记录（获取帖子时已发送）。
    if not files:
        return

    listing = "附件列表：\n" + "\n".join([f"{f.index}. {'[图片]' if f.kind=='image' else '[文件]'} {f.name}" for f in files])
    yield event.plain_result(listing + "\n\n请输入要导出的序号（支持多选，如：1 3 4）")

    timeout = int(getattr(self._cfg, "session_timeout_sec", 300) or 300)
    initial_sender_id = str(event.get_sender_id())
    initial_event = event

    @session_waiter(timeout=timeout, record_history_chains=False)
    async def waiter(controller: SessionController, e: AstrMessageEvent):
        e.stop_event()
        if self._is_self_message_event(e) or self._is_empty_echo_event(e):
            controller.keep(timeout=timeout, reset_timeout=True)
            return
        if str(e.get_sender_id()) != initial_sender_id:
            controller.keep(timeout=timeout, reset_timeout=True)
            return
        if e is initial_event:
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        raw_text = (e.message_str or "").strip()
        picks = _parse_number_picks(normalize_command_text(raw_text))
        if not picks:
            await e.send(e.plain_result("请输入序号（如：1 2 3）"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        chosen = [f for f in files if f.index in picks]
        if not chosen:
            await e.send(e.plain_result("未匹配到附件序号，请重新输入。"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        chosen.sort(key=lambda x: picks.index(x.index))
        await _send_files(self, e, chosen, cookie=cookie, base_url=base_url, session=session)
        controller.stop()

    try:
        await waiter(event)
    except TimeoutError:
        yield event.plain_result("会话超时，已退出导出。")


async def _handle_import_flow(
    self,
    event: AstrMessageEvent,
    *,
    pwd: str,
    title: str,
    author: str,
    intro: str,
    content: str,
    files: list[CozyPostFile],
    cookie: str,
    base_url: str,
    session: Any = None,
):
    timeout = int(getattr(self._cfg, "session_timeout_sec", 300) or 300)
    initial_sender_id = str(event.get_sender_id())

    yield event.plain_result("请输入角色名称")
    state: dict[str, Any] = {
        "name": "",
        "intro": "",
        "tags": [],
        "picks": [],
        "stage": "name",
        "options": [],
        # wrapper
        "use_wrapper": False,
        "wrapper_use_config": True,
        "wrapper_prefix": "",
        "wrapper_suffix": "",
        # clean
        "clean_use_config": False,
        "clean_regex": "",
    }

    @session_waiter(timeout=timeout, record_history_chains=False)
    async def waiter(controller: SessionController, e: AstrMessageEvent):
        e.stop_event()
        if self._is_self_message_event(e) or self._is_empty_echo_event(e):
            controller.keep(timeout=timeout, reset_timeout=True)
            return
        if str(e.get_sender_id()) != initial_sender_id:
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        text = (e.message_str or "").strip()
        if state["stage"] == "name":
            state["name"] = text.strip()
            state["stage"] = "intro"
            await e.send(e.plain_result("请输入角色简介"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        if state["stage"] == "intro":
            state["intro"] = text.strip()
            state["stage"] = "tags"
            await e.send(e.plain_result("请输入角色标签（空格分隔，可留空输入 /跳过）"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        if state["stage"] == "tags":
            choice = parse_command_choice(text)
            state["tags"] = [] if choice == "skip" else [x for x in text.split() if x.strip()]
            state["stage"] = "wrapper_choice"
            await e.send(
                e.plain_result(
                    "是否使用已配置好的前后置提示词？\n"
                    "- /是：使用已配置\n"
                    "- /否：自定义填写\n"
                    "- /跳过：不使用\n"
                    "请输入：/是 /否 /跳过"
                )
            )
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        if state["stage"] == "wrapper_choice":
            choice = parse_command_choice(text)
            if choice == "yes":
                state["use_wrapper"] = True
                state["wrapper_use_config"] = True
                state["stage"] = "clean_choice"
                await e.send(
                    e.plain_result(
                        "是否使用已配置好的正则文本清洗表达式？\n"
                        "- /是：使用已配置\n"
                        "- /否：自定义填写\n"
                        "- /跳过：不使用\n"
                        "请输入：/是 /否 /跳过"
                    )
                )
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            if choice in {"no", "custom"}:
                state["use_wrapper"] = True
                state["wrapper_use_config"] = False
                state["stage"] = "wrapper_prefix"
                await e.send(e.plain_result("请输入前置提示词（输入 /跳过 表示留空）"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            if choice == "skip":
                state["use_wrapper"] = False
                state["stage"] = "clean_choice"
                await e.send(
                    e.plain_result(
                        "是否使用已配置好的正则文本清洗表达式？\n"
                        "- /是：使用已配置\n"
                        "- /否：自定义填写\n"
                        "- /跳过：不使用\n"
                        "请输入：/是 /否 /跳过"
                    )
                )
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            await e.send(e.plain_result("请输入：/是 /否 /跳过"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        if state["stage"] == "wrapper_prefix":
            raw = (e.message_str or "").strip()
            state["wrapper_prefix"] = "" if parse_command_choice(raw) == "skip" else raw
            state["stage"] = "wrapper_suffix"
            await e.send(e.plain_result("请输入后置提示词（输入 /跳过 表示留空）"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        if state["stage"] == "wrapper_suffix":
            raw = (e.message_str or "").strip()
            state["wrapper_suffix"] = "" if parse_command_choice(raw) == "skip" else raw
            state["stage"] = "clean_choice"
            await e.send(
                e.plain_result(
                    "是否使用已配置好的正则文本清洗表达式？\n"
                    "- /是：使用已配置\n"
                    "- /否：自定义填写\n"
                    "- /跳过：不使用\n"
                    "请输入：/是 /否 /跳过"
                )
            )
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        if state["stage"] == "clean_choice":
            choice = parse_command_choice(text)
            if choice == "yes":
                state["clean_use_config"] = True
                state["clean_regex"] = ""
                state["stage"] = "pick_prep"
            elif choice in {"no", "custom"}:
                state["clean_use_config"] = False
                state["stage"] = "clean_regex"
                await e.send(
                    e.plain_result(
                        "请输入正则表达式（用于清洗注入的角色内容：re.sub(pattern, '', text)）。\n"
                        "输入 /跳过 表示不设置。"
                    )
                )
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            elif choice == "skip":
                state["clean_use_config"] = False
                state["clean_regex"] = ""
                state["stage"] = "pick_prep"
            else:
                await e.send(e.plain_result("请输入：/是 /否 /跳过"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            # 进入选择导入内容阶段
            if state["stage"] == "pick_prep":
                importable = [f for f in files if _is_importable_text_file(f)]
                options: list[dict[str, Any]] = [{"type": "body", "label": "正文"}]
                for f in importable:
                    options.append({"type": "file", "file": f, "label": f"附件文本：{f.name}"})
                state["options"] = options

                if len(options) == 1:
                    state["picks"] = [1]
                    controller.stop()
                    return

                state["stage"] = "pick"
                listing = "请选择要导入的内容序号（支持多选，如：1 3 2；按输入顺序拼接，输入 /跳过 默认仅导入正文）：\n" + "\n".join(
                    [f"{i}. {opt['label']}" for i, opt in enumerate(options, start=1)]
                )
                await e.send(e.plain_result(listing))
                controller.keep(timeout=timeout, reset_timeout=True)
                return

        if state["stage"] == "clean_regex":
            if parse_command_choice(text) == "skip":
                state["clean_regex"] = ""
                state["stage"] = "pick_prep"
                # 复用 clean_choice 的 pick_prep 逻辑：直接走一遍
                importable = [f for f in files if _is_importable_text_file(f)]
                options: list[dict[str, Any]] = [{"type": "body", "label": "正文"}]
                for f in importable:
                    options.append({"type": "file", "file": f, "label": f"附件文本：{f.name}"})
                state["options"] = options

                if len(options) == 1:
                    state["picks"] = [1]
                    controller.stop()
                    return

                state["stage"] = "pick"
                listing = "请选择要导入的内容序号（支持多选，如：1 3 2；按输入顺序拼接，输入 /跳过 默认仅导入正文）：\n" + "\n".join(
                    [f"{i}. {opt['label']}" for i, opt in enumerate(options, start=1)]
                )
                await e.send(e.plain_result(listing))
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            pattern = (e.message_str or "").strip()
            if not pattern:
                await e.send(e.plain_result("请输入正则表达式，或 /跳过。"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            try:
                re.compile(pattern)
            except Exception:
                await e.send(e.plain_result("正则表达式无效，请重新输入，或 /跳过。"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            state["clean_regex"] = pattern
            state["stage"] = "pick_prep"

            importable = [f for f in files if _is_importable_text_file(f)]
            options: list[dict[str, Any]] = [{"type": "body", "label": "正文"}]
            for f in importable:
                options.append({"type": "file", "file": f, "label": f"附件文本：{f.name}"})
            state["options"] = options

            if len(options) == 1:
                state["picks"] = [1]
                controller.stop()
                return

            state["stage"] = "pick"
            listing = "请选择要导入的内容序号（支持多选，如：1 3 2；按输入顺序拼接，输入 /跳过 默认仅导入正文）：\n" + "\n".join(
                [f"{i}. {opt['label']}" for i, opt in enumerate(options, start=1)]
            )
            await e.send(e.plain_result(listing))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        if state["stage"] == "pick":
            if parse_command_choice(text) == "skip":
                state["picks"] = [1]
                controller.stop()
                return

            picks = _parse_number_picks(normalize_command_text(text))
            options = state.get("options") or []
            if not picks:
                await e.send(e.plain_result("请输入序号（如：1 2 3），或 /跳过。"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            if any(p <= 0 or p > len(options) for p in picks):
                await e.send(e.plain_result("序号超出范围，请重新输入。"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            state["picks"] = picks
            controller.stop()
            return

        controller.keep(timeout=timeout, reset_timeout=True)

    try:
        await waiter(event)
    except TimeoutError:
        yield event.plain_result("会话超时，已退出导入。")
        return

    name = (state.get("name") or "").strip()
    if not name:
        yield event.plain_result("缺少角色名称，已取消导入。")
        return

    user_intro = (state.get("intro") or "").strip()
    tags = state.get("tags") or []
    picks: list[int] = state.get("picks") or []
    options: list[dict[str, Any]] = state.get("options") or []
    use_wrapper = bool(state.get("use_wrapper") or False)
    wrapper_use_config = bool(state.get("wrapper_use_config") if state.get("wrapper_use_config") is not None else True)
    wrapper_prefix = str(state.get("wrapper_prefix") or "")
    wrapper_suffix = str(state.get("wrapper_suffix") or "")
    clean_use_config = bool(state.get("clean_use_config") or False)
    clean_regex = str(state.get("clean_regex") or "")

    if not picks:
        picks = [1]

    imported_parts: list[str] = []
    for pick in picks:
        opt = options[pick - 1] if 0 <= pick - 1 < len(options) else None
        if not isinstance(opt, dict):
            continue

        if opt.get("type") == "body":
            base_text = (content or "").strip()
            if base_text:
                imported_parts.append(base_text)
            continue

        if opt.get("type") == "file":
            f = opt.get("file")
            if isinstance(f, CozyPostFile):
                file_text = await _build_import_content_from_files(
                    self,
                    [f],
                    cookie=cookie,
                    base_url=base_url,
                    session=session,
                )
                if (file_text or "").strip():
                    imported_parts.append(file_text.strip())

    imported_text = "\n\n".join([t for t in imported_parts if (t or "").strip()]).strip()

    final_intro = normalize_one_line(user_intro)
    source_line = normalize_one_line(f"来源：{title} / {author}")
    final_intro = (final_intro + "\n" + source_line).strip() if final_intro else source_line

    try:
        await self._svc.upsert_user_persona(
            user_id=str(event.get_sender_id()),
            user_name=str(event.get_sender_name()),
            name=name,
            intro=final_intro,
            content=imported_text,
            use_wrapper=use_wrapper,
            wrapper_use_config=wrapper_use_config,
            wrapper_prefix=wrapper_prefix,
            wrapper_suffix=wrapper_suffix,
            clean_use_config=clean_use_config,
            clean_regex=clean_regex,
            tags=tags,
        )

        group_id = self._resolve_group_key(event)
        await self._svc.switch_persona_for_context(
            user_id=str(event.get_sender_id()),
            group_id=group_id,
            name=EMPTY_PERSONA_NAME,
        )
    except ValueError as ve:
        yield event.plain_result(str(ve))
        return
    except Exception as ex:
        logger.error(f"导入失败: {ex!s}")
        yield event.plain_result("导入失败，请稍后重试。")
        return

    yield event.plain_result(f"已导入角色：{name}（已切回休息模式）")


def _parse_number_picks(text: str) -> list[int]:
    raw = (text or "").replace(",", " ").replace("，", " ").strip()
    if not raw:
        return []
    out: list[int] = []
    for part in raw.split():
        try:
            n = int(part)
        except Exception:
            continue
        if n <= 0:
            continue
        if n not in out:
            out.append(n)
    return out


    


async def _build_import_content_from_files(
    self,
    files: list[CozyPostFile],
    *,
    cookie: str,
    base_url: str,
    session: Any = None,
) -> str:
    parts: list[str] = []
    base_dir = StarTools.get_data_dir("astrbot_plugin_persona_manager") / "cozynook_cache" / "downloads"
    base_dir.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(_prune_cache_dir, base_dir)

    timeout_sec = max(int(getattr(self._cfg, "cozynook_timeout_sec", 30) or 30), 1)
    use_aiohttp = bool(_AIOHTTP_AVAILABLE and aiohttp is not None)

    # 外部传入 session 可能已被关闭（例如上层复用了全局 session 但生命周期已结束）。
    if use_aiohttp and session is not None and bool(getattr(session, "closed", False)):
        session = None

    close_session = False
    if use_aiohttp and session is None:
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        headers = {"User-Agent": _get_user_agent()}
        if cookie:
            headers["Cookie"] = cookie
        session = aiohttp.ClientSession(timeout=timeout, headers=headers)
        close_session = True

    try:
        for f in files:
            # 按你的要求：导入严格只导入文字，不写入图片/链接占位
            if f.kind == "image":
                continue

            ext = (Path(f.name).suffix or "").lower()
            allow_by_ext = ext in _TEXT_EXTS

            try:
                dest = base_dir / f"{int(time.time())}_{f.index}_{f.name}"
                if use_aiohttp:
                    local = await _download_to_file_async(
                        f.url,
                        dest=dest,
                        cookie_header=cookie,
                        timeout_sec=timeout_sec,
                        base_url=base_url,
                        session=session,
                    )
                else:
                    local = await asyncio.to_thread(
                        _download_to_file_fallback_sync,
                        f.url,
                        dest=dest,
                        cookie_header=cookie,
                        timeout_sec=timeout_sec,
                        base_url=base_url,
                    )
            except Exception:
                continue

            try:
                raw = local.read_bytes()
                if (not allow_by_ext) and len(raw) > _MAX_IMPORT_TEXT_FILE_BYTES:
                    continue
                text = _decode_probably_text(raw)
                if text is None:
                    continue
                text = text.strip()
                if not text:
                    continue
                parts.append(f"[{f.name}]\n{text}")
            except Exception:
                continue
            finally:
                # 导入仅用于提取文本：读完立即清理，避免残留
                try:
                    Path(local).unlink(missing_ok=True)
                except Exception:
                    pass
    finally:
        if use_aiohttp and close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass

    return "\n\n".join([p for p in parts if p.strip()])


async def _send_files(
    self,
    event: AstrMessageEvent,
    files: list[CozyPostFile],
    *,
    cookie: str,
    base_url: str,
    session: Any = None,
):
    base_dir = StarTools.get_data_dir("astrbot_plugin_persona_manager") / "cozynook_cache" / "exports"
    base_dir.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(_prune_cache_dir, base_dir)

    timeout_sec = max(int(getattr(self._cfg, "cozynook_timeout_sec", 30) or 30), 1)

    # 外部传入 session 可能已被关闭；此时直接丢弃并重建，避免下载失败回退 URL。
    if session is not None and bool(getattr(session, "closed", False)):
        session = None

    close_session = False
    if session is None and _AIOHTTP_AVAILABLE and aiohttp is not None:
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        headers = {"User-Agent": _get_user_agent()}
        if cookie:
            headers["Cookie"] = cookie
        session = aiohttp.ClientSession(timeout=timeout, headers=headers)
        close_session = True

    try:
        for f in files:
            if f.kind == "image":
                try:
                    ext = ".png" if f.url.startswith("data:image/") else ("." + f.name.split(".")[-1] if "." in f.name else ".png")
                    local = base_dir / f"{int(time.time())}_{f.index}_{_safe_filename(f.name)}{ext}"
                    if f.url.startswith("data:image/"):
                        try:
                            import base64

                            b64 = f.url.split(",", 1)[1]

                            def _decode_and_write_image() -> None:
                                local.write_bytes(base64.b64decode(b64))

                            await asyncio.to_thread(_decode_and_write_image)
                        except Exception:
                            await event.send(event.plain_result(f"图片导出失败：{f.name}"))
                            continue
                    else:
                        if session is not None:
                            try:
                                await _download_to_file_async(
                                    f.url,
                                    dest=local,
                                    cookie_header=cookie,
                                    timeout_sec=timeout_sec,
                                    base_url=base_url,
                                    session=session,
                                )
                            except RuntimeError as ex:
                                # aiohttp session 可能在执行过程中被关闭；此时回退到同步下载。
                                if "Session is closed" in str(ex):
                                    await asyncio.to_thread(
                                        _download_to_file_fallback_sync,
                                        f.url,
                                        dest=local,
                                        cookie_header=cookie,
                                        timeout_sec=timeout_sec,
                                        base_url=base_url,
                                    )
                                else:
                                    raise
                        else:
                            await asyncio.to_thread(
                                _download_to_file_fallback_sync,
                                f.url,
                                dest=local,
                                cookie_header=cookie,
                                timeout_sec=timeout_sec,
                                base_url=base_url,
                            )

                    try:
                        await event.send(event.chain_result([Comp.Image(str(local))]))
                    finally:
                        # 无论发送成功与否，只要落盘了就延时清理，避免缓存堆积。
                        try:
                            if Path(local).exists():
                                _schedule_delete(Path(local))
                        except Exception:
                            pass
                except Exception:
                    await event.send(event.plain_result(f"图片：{f.name}\n{f.url}"))
                continue

            try:
                local = base_dir / f"{int(time.time())}_{f.index}_{_safe_filename(f.name)}"
                if f.url.startswith("data:"):
                    import base64

                    b64 = f.url.split(",", 1)[1]

                    def _decode_and_write_file() -> None:
                        local.write_bytes(base64.b64decode(b64))

                    await asyncio.to_thread(_decode_and_write_file)
                else:
                    if session is not None:
                        try:
                            await _download_to_file_async(
                                f.url,
                                dest=local,
                                cookie_header=cookie,
                                timeout_sec=timeout_sec,
                                base_url=base_url,
                                session=session,
                            )
                        except RuntimeError as ex:
                            if "Session is closed" in str(ex):
                                await asyncio.to_thread(
                                    _download_to_file_fallback_sync,
                                    f.url,
                                    dest=local,
                                    cookie_header=cookie,
                                    timeout_sec=timeout_sec,
                                    base_url=base_url,
                                )
                            else:
                                raise
                    else:
                        await asyncio.to_thread(
                            _download_to_file_fallback_sync,
                            f.url,
                            dest=local,
                            cookie_header=cookie,
                            timeout_sec=timeout_sec,
                            base_url=base_url,
                        )

                file_comp = _make_file_component(local)
                if file_comp is None:
                    raise RuntimeError("当前适配器不支持文件组件")

                try:
                    await event.send(event.chain_result([file_comp]))
                finally:
                    # 无论发送成功与否，只要落盘了就延时清理
                    try:
                        if Path(local).exists():
                            _schedule_delete(Path(local))
                    except Exception:
                        pass
            except Exception:
                await event.send(event.plain_result(f"文件：{f.name}\n{_normalize_url(f.url)}"))
    finally:
        if close_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass
