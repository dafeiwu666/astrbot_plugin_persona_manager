from __future__ import annotations

import asyncio
import json
import re
import textwrap
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import astrbot.api.message_components as Comp
from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent
from astrbot.api.message_components import Plain
from astrbot.api.star import StarTools
from astrbot.core.utils.session_waiter import SessionController, session_waiter

from .models import EMPTY_PERSONA_NAME
from .text_utils import normalize_one_line, split_long_text


_ULA_RE = re.compile(r"^ula-[A-Za-z0-9]{16}$", re.IGNORECASE)

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

# 角色小屋市场页：默认指向固定帖子密码
DEFAULT_MARKET_POST_PWD = "ULA-882BC987FF367255"


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
                    name = urllib.request.url2pathname(url.split("?")[0].split("#")[0].split("/")[-1])
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


async def _delete_file_later(path: Path, delay_sec: int) -> None:
    try:
        await asyncio.sleep(max(int(delay_sec), 0))
        path.unlink(missing_ok=True)
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
    # 优先对齐 parser：astrbot.core.message.components.File
    try:
        from astrbot.core.message.components import File as CoreFile

        return CoreFile(name=file_path.name, file=str(file_path))
    except Exception:
        pass

    # 其次尝试 astrbot.api.message_components 的 File（若存在）
    try:
        file_cls = getattr(Comp, "File", None)
        if file_cls is not None:
            return file_cls(name=file_path.name, file=str(file_path))
    except Exception:
        pass

    return None


def _http_get_json(url: str, *, cookie_header: str = "", timeout_sec: int = 20) -> dict[str, Any]:
    _status, payload = _http_get_json_with_status(url, cookie_header=cookie_header, timeout_sec=timeout_sec)
    return payload


def _http_get_json_with_status(url: str, *, cookie_header: str = "", timeout_sec: int = 20) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(_normalize_url(url), method="GET")
    req.add_header("User-Agent", "astrbot-plugin-persona-manager/1.0")
    if cookie_header:
        req.add_header("Cookie", cookie_header)

    raw = b""
    status = 0
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            raw = resp.read()
    except urllib.error.HTTPError as he:
        status = int(getattr(he, "code", 0) or 0)
        try:
            raw = he.read()  # type: ignore[attr-defined]
        except Exception:
            raw = b""

    if not raw:
        return status, {}

    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        return status, data if isinstance(data, dict) else {}
    except Exception:
        return status, {}


def _download_to_file(
    url: str,
    *,
    dest: Path,
    cookie_header: str = "",
    timeout_sec: int = 30,
    base_url: str | None = None,
) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    final_url = _resolve_url(url, base=base_url or COZYNOOK_SITE_URL)
    req = urllib.request.Request(_normalize_url(final_url), method="GET")
    req.add_header("User-Agent", "astrbot-plugin-persona-manager/1.0")
    if cookie_header:
        req.add_header("Cookie", cookie_header)
    tmp = dest.with_name(dest.name + ".part")
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            with tmp.open("wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
        tmp.replace(dest)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
    return dest


def _pick_font_path() -> str | None:
    # 优先选择可显示中文的字体；不同系统路径不同。
    candidates = [
        # Linux 常见
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        # Windows 常见
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/msyh.ttf",
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/simsun.ttc",
        # 兜底
        "arial.ttf",
    ]

    for p in candidates:
        try:
            if Path(p).exists():
                return p
        except Exception:
            continue
    # 对于像 "arial.ttf" 这种仅靠 fontconfig 的名字，不能用 exists 判断
    return "arial.ttf"


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


def _render_post_preview_image(
    *,
    title: str,
    author: str,
    date_str: str,
    intro: str,
    content: str,
    files: list[CozyPostFile],
    pwd: str,
) -> Path | None:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return None

    w = 960
    h = 1280
    bg = (15, 16, 20)
    accent = (211, 161, 126)
    fg = (235, 235, 240)
    subtle = (160, 165, 175)

    img = Image.new("RGB", (w, h), bg)
    draw = ImageDraw.Draw(img)

    font_path = _pick_font_path()
    if not font_path:
        return None

    try:
        font_title = ImageFont.truetype(font_path, 40)
        font_meta = ImageFont.truetype(font_path, 22)
        font_body = ImageFont.truetype(font_path, 24)
        font_small = ImageFont.truetype(font_path, 20)
    except Exception:
        # 字体不可用时直接降级为文本预览，避免“截图乱码/方块字”
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

    meta = f"{(author or 'Unknown').strip()} · {date_str} · {pwd.upper()}"
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
    # 不额外新增“密码”分区：将 ULA 拼入标题行，满足“标题/作者/简介/正文/附件名/评论”结构。
    title_line = f"{title_line}（{pwd.upper()}）"

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


def _cozyverse_fetch_post_by_password(*, pwd: str, cookie: str) -> tuple[int, dict[str, Any]]:
    """通过后端接口用 ULA 打开帖子，返回 (status, post)。

    说明：优先使用 v1：`GET /api/v1/posts/by-password`（需要登录态 Cookie）。
    若后端未部署该 v1 端点，则回退到旧端点：`GET /api/posts/by-password`。
    """

    if not cookie:
        return 0, {}

    pwd_s = (pwd or "").strip()

    # 1) v1 preferred
    url = f"{COZYNOOK_API_BASE}/v1/posts/by-password?pwd={urllib.parse.quote(pwd_s)}"
    status, data = _http_get_json_with_status(url, cookie_header=cookie)
    if isinstance(data, dict) and data.get("ok") and isinstance(data.get("post"), dict):
        return status, data.get("post") or {}

    # 2) fallback to legacy
    url2 = f"{COZYNOOK_API_BASE}/posts/by-password?pwd={urllib.parse.quote(pwd_s)}"
    status2, data2 = _http_get_json_with_status(url2, cookie_header=cookie)
    if not isinstance(data2, dict) or not data2.get("ok"):
        return status2 or status, {}
    post = data2.get("post")
    if not isinstance(post, dict):
        return status2 or status, {}
    return status2 or status, post


def _cozyverse_fetch_latest_comments_v1(*, post_id: int, cookie: str, take: int = 10) -> tuple[int, list[str]]:
    """通过 v1 插件接口拉取最新评论（需要登录态 + 频道权限）。

    优先使用游标分页接口（更稳定，且明确 newest-first）：
    - GET /api/v1/posts/{id}/comments/cursor?page_size=...

    若后端未实现 cursor，则回退到页码分页（README 约定 page=1 为最新一页）。
    """

    if not cookie:
        return 0, []

    ps = max(1, min(int(take or 10), 50))

    # 1) cursor: newest-first
    url = f"{COZYNOOK_API_BASE}/v1/posts/{int(post_id)}/comments/cursor?page_size={ps}"
    status, data = _http_get_json_with_status(url, cookie_header=cookie)
    if isinstance(data, dict) and data.get("ok"):
        items = data.get("items")
        if not isinstance(items, list):
            items = []
        comments = _extract_recent_comments({"items": items})
        return status, comments[: int(take)]

    # 2) fallback: page=1
    url2 = f"{COZYNOOK_API_BASE}/v1/posts/{int(post_id)}/comments?page=1&page_size={ps}"
    status2, data2 = _http_get_json_with_status(url2, cookie_header=cookie)
    if isinstance(data2, dict) and data2.get("ok"):
        items2 = data2.get("items")
        if not isinstance(items2, list):
            # 兼容潜在结构变更：{comments:{items:...}}
            cobj = data2.get("comments")
            if isinstance(cobj, dict) and isinstance(cobj.get("items"), list):
                items2 = cobj.get("items")
            else:
                items2 = []
        comments = _extract_recent_comments({"items": items2})
        return status2, comments[: int(take)]

    return status2 or status, []


async def cozynook_get(self, event: AstrMessageEvent, arg, *, allow_import: bool, mode: str | None = None):
    """/角色小屋 与 /获取角色 的统一入口。

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
    pwd = DEFAULT_MARKET_POST_PWD if not raw else raw
    if not _is_ula(pwd):
        yield event.plain_result("用法：/获取角色 ula-XXXXXXXXXXXXXXXX（16位）")
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

    try:
        status, post = await asyncio.to_thread(_cozyverse_fetch_post_by_password, pwd=pwd, cookie=cookie)
    except Exception as ex:
        logger.error(f"Cozyverse 拉取失败: {ex!s}")
        yield event.plain_result("Cozyverse 拉取失败，请稍后重试。")
        return

    if not post:
        if int(status) == 404:
            yield event.plain_result("未获取到帖子内容（密码可能错误或帖子不存在）。")
        else:
            yield event.plain_result("未获取到帖子内容（接口返回异常）。")
        return

    post_id = 0
    try:
        post_id = int(post.get("id") or 0)
    except Exception:
        post_id = 0
    title = str(post.get("title") or "").strip()
    author = str(post.get("authorName") or "").strip()
    intro = str(post.get("intro") or "").strip()
    content = str(post.get("content") or "").strip()
    files = _parse_post_files(post.get("files"))

    # 获取帖子时不再渲染图片：只发送“合并转发聊天记录”文本（含附件名与最新评论）。
    # 评论展示条数可配置（0-50）；默认 10。
    try:
        take = int(getattr(self._cfg, "cozynook_comments_take", 10) or 0)
    except Exception:
        take = 10
    if take < 0:
        take = 0
    if take > 50:
        take = 50

    comments: list[str] = []
    if post_id > 0 and take > 0:
        try:
            _c_status, comments = await asyncio.to_thread(
                _cozyverse_fetch_latest_comments_v1,
                post_id=post_id,
                cookie=cookie,
                take=take,
            )
        except Exception:
            comments = []
    merged = _format_post_text(pwd=pwd, title=title, author=author, intro=intro, content=content, files=files, comments=comments)
    parts = split_long_text(merged, max_chars=3000)
    nodes: list[Comp.Node] = []
    uin = str(event.get_self_id())
    for p in parts:
        nodes.append(Comp.Node(uin=uin, name="角色小屋", content=[Plain(p)]))
    yield event.chain_result([Comp.Nodes(nodes)])

    if not allow_import:
        async for r in _handle_export_flow(
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
        ):
            yield r
        return

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
        ):
            yield r
        return
    if mode_norm in {"export", "导出"}:
        async for r in _handle_export_flow(
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
        ):
            yield r
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
            ):
                await e.send(rr)
            return

        await e.send(e.plain_result("请输入：/导入 或 /导出"))
        controller.keep(timeout=timeout, reset_timeout=True)

    try:
        await waiter(event)
    except TimeoutError:
        yield event.plain_result("会话超时，已退出。")


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
):
    # 导出流程不再重复发送一遍聊天记录（获取帖子时已发送）。
    if not files:
        return

    listing = "附件列表：\n" + "\n".join([f"{f.index}. {'[图片]' if f.kind=='image' else '[文件]'} {f.name}" for f in files])
    yield event.plain_result(listing + "\n\n请输入要导出的序号（支持多选，如：1 3 4），或输入 /跳过")

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

        text = (e.message_str or "").strip().lstrip("/／").strip()
        if text in {"跳过", "skip"}:
            controller.stop()
            return

        picks = _parse_number_picks(text)
        if not picks:
            await e.send(e.plain_result("请输入序号（如：1 2 3），或 /跳过"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        chosen = [f for f in files if f.index in picks]
        if not chosen:
            await e.send(e.plain_result("未匹配到附件序号，请重新输入。"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        chosen.sort(key=lambda x: picks.index(x.index))
        await _send_files(self, e, chosen, cookie=cookie, base_url=base_url)
        controller.stop()

    try:
        await waiter(event)
    except TimeoutError:
        yield event.plain_result("会话超时，已结束导出。")


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
            t = text.lstrip("/／").strip()
            state["tags"] = [] if t == "跳过" else [x for x in text.split() if x.strip()]
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
            t = text.lstrip("/／").strip().lower()
            if t in {"是", "y", "yes", "1", "开启", "开", "使用"}:
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

            if t in {"否", "n", "no", "0", "自定义", "custom"}:
                state["use_wrapper"] = True
                state["wrapper_use_config"] = False
                state["stage"] = "wrapper_prefix"
                await e.send(e.plain_result("请输入前置提示词（输入 /跳过 表示留空）"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            if t in {"跳过", "skip"}:
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
            t = text.lstrip("/／").strip()
            state["wrapper_prefix"] = "" if t == "跳过" else (e.message_str or "").strip()
            state["stage"] = "wrapper_suffix"
            await e.send(e.plain_result("请输入后置提示词（输入 /跳过 表示留空）"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        if state["stage"] == "wrapper_suffix":
            t = text.lstrip("/／").strip()
            state["wrapper_suffix"] = "" if t == "跳过" else (e.message_str or "").strip()
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
            t = text.lstrip("/／").strip().lower()
            if t in {"是", "y", "yes", "1", "开启", "开", "使用"}:
                state["clean_use_config"] = True
                state["clean_regex"] = ""
                state["stage"] = "pick_prep"
            elif t in {"否", "n", "no", "0", "自定义", "custom"}:
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
            elif t in {"跳过", "skip"}:
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
            t = text.lstrip("/／").strip()
            if t in {"跳过", "skip"}:
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
            t = text.lstrip("/／").strip()
            if t in {"跳过", "skip"}:
                state["picks"] = [1]
                controller.stop()
                return

            picks = _parse_number_picks(text)
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
                file_text = await _build_import_content_from_files(self, [f], cookie=cookie, base_url=base_url)
                if (file_text or "").strip():
                    imported_parts.append(file_text.strip())

    imported_text = "\n\n".join([t for t in imported_parts if (t or "").strip()]).strip()

    final_intro = normalize_one_line(user_intro)
    source_line = normalize_one_line(f"来源：{title} / {author} / {pwd.upper()}")
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


    


async def _build_import_content_from_files(self, files: list[CozyPostFile], *, cookie: str, base_url: str) -> str:
    parts: list[str] = []
    base_dir = StarTools.get_data_dir("astrbot_plugin_persona_manager") / "cozynook_cache" / "downloads"
    base_dir.mkdir(parents=True, exist_ok=True)
    _prune_cache_dir(base_dir)

    for f in files:
        # 按你的要求：导入严格只导入文字，不写入图片/链接占位
        if f.kind == "image":
            continue

        ext = (Path(f.name).suffix or "").lower()
        allow_by_ext = ext in _TEXT_EXTS

        try:
            local = await asyncio.to_thread(
                _download_to_file,
                f.url,
                dest=base_dir / f"{int(time.time())}_{f.index}_{f.name}",
                cookie_header=cookie,
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

            # 导入仅用于提取文本：读取成功后尽快删除文件
            _schedule_delete(Path(local), delay_sec=60)
        except Exception:
            continue

    return "\n\n".join([p for p in parts if p.strip()])


async def _send_files(self, event: AstrMessageEvent, files: list[CozyPostFile], *, cookie: str, base_url: str):
    base_dir = StarTools.get_data_dir("astrbot_plugin_persona_manager") / "cozynook_cache" / "exports"
    base_dir.mkdir(parents=True, exist_ok=True)
    _prune_cache_dir(base_dir)

    for f in files:
        if f.kind == "image":
            try:
                ext = ".png" if f.url.startswith("data:image/") else ("." + f.name.split(".")[-1] if "." in f.name else ".png")
                local = base_dir / f"{int(time.time())}_{f.index}_{_safe_filename(f.name)}{ext}"
                if f.url.startswith("data:image/"):
                    try:
                        import base64

                        b64 = f.url.split(",", 1)[1]
                        local.write_bytes(base64.b64decode(b64))
                    except Exception:
                        await event.send(event.plain_result(f"图片导出失败：{f.name}"))
                        continue
                else:
                    await asyncio.to_thread(
                        _download_to_file,
                        f.url,
                        dest=local,
                        cookie_header=cookie,
                        base_url=base_url,
                    )

                await event.send(event.chain_result([Comp.Image(str(local))]))

                # 发送成功后延时删除，避免适配器尚未读完文件
                _schedule_delete(Path(local))
            except Exception:
                await event.send(event.plain_result(f"图片：{f.name}\n{f.url}"))
            continue

        try:
            local = base_dir / f"{int(time.time())}_{f.index}_{_safe_filename(f.name)}"
            if f.url.startswith("data:"):
                import base64

                b64 = f.url.split(",", 1)[1]
                local.write_bytes(base64.b64decode(b64))
            else:
                await asyncio.to_thread(
                    _download_to_file,
                    f.url,
                    dest=local,
                    cookie_header=cookie,
                    base_url=base_url,
                )

            file_comp = _make_file_component(local)
            if file_comp is None:
                raise RuntimeError("当前适配器不支持文件组件")
            await event.send(event.chain_result([file_comp]))

            # 发送成功后延时删除
            _schedule_delete(Path(local))
        except Exception:
            await event.send(event.plain_result(f"文件：{f.name}\n{_normalize_url(f.url)}"))
