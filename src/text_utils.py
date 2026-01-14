from __future__ import annotations


_YES_TOKENS = {"是", "y", "yes", "1", "开启", "开", "使用"}
_NO_TOKENS = {"否", "n", "no", "0", "关闭", "关", "不使用"}
_CUSTOM_TOKENS = {"自定义", "custom"}
_SKIP_TOKENS = {"跳过", "skip"}
_KEEP_TOKENS = {"保持", "keep"}

_YES_TOKENS_FOLDED = {x.casefold() for x in _YES_TOKENS}
_NO_TOKENS_FOLDED = {x.casefold() for x in _NO_TOKENS}
_CUSTOM_TOKENS_FOLDED = {x.casefold() for x in _CUSTOM_TOKENS}
_SKIP_TOKENS_FOLDED = {x.casefold() for x in _SKIP_TOKENS}
_KEEP_TOKENS_FOLDED = {x.casefold() for x in _KEEP_TOKENS}


def normalize_command_text(text: str) -> str:
    """规范化交互式短指令输入。

    - 去掉前导 / 或 ／
    - 去掉首尾空白
    - 不做 lower/casefold（由 parse_command_choice 统一处理）
    """

    return (text or "").strip().lstrip("/／").strip()


def parse_command_choice(text: str) -> str | None:
    """解析交互式输入为标准 choice。

    Returns:
        "yes" | "no" | "custom" | "skip" | "keep" | None
    """

    t = normalize_command_text(text)
    if not t:
        return None
    t2 = t.casefold()

    if t2 in _YES_TOKENS_FOLDED:
        return "yes"
    if t2 in _NO_TOKENS_FOLDED:
        return "no"
    if t2 in _CUSTOM_TOKENS_FOLDED:
        return "custom"
    if t2 in _SKIP_TOKENS_FOLDED:
        return "skip"
    if t2 in _KEEP_TOKENS_FOLDED:
        return "keep"

    return None


def normalize_one_line(s: str) -> str:
    s = (s or "").replace("\r\n", "\n").replace("\r", "\n")
    return " ".join([p for p in s.split("\n") if p.strip()])


def is_finish_edit_command(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    t = t.lstrip("/／").strip()
    t = t.split()[0] if t.split() else ""
    return t in {"结束角色编辑", "结束角色"}


def truncate_text(text: str, max_length: int = 30) -> str:
    """
    截断文本，如果超过最大长度则在末尾添加省略号
    
    Args:
        text: 要截断的文本
        max_length: 最大长度（默认30个字符）
    
    Returns:
        截断后的文本
    """
    text = (text or "").strip()
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def split_long_text(text: str, max_chars: int = 3000) -> list[str]:
    """
    将长文本分割成多个不超过指定长度的片段
    
    Args:
        text: 要分割的文本
        max_chars: 每个片段的最大字符数（默认3000）
    
    Returns:
        文本片段列表
    """
    if len(text) <= max_chars:
        return [text]
    
    parts = []
    remaining = text
    
    while remaining:
        chunk = remaining[:max_chars]
        remaining = remaining[max_chars:]
        parts.append(chunk)
    
    return parts
