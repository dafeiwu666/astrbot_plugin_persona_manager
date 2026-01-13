from __future__ import annotations


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
