from __future__ import annotations

# 兼容不同加载方式：对外提供与 src 同名模块。

try:
    from .src.pm_keyword_trigger import *  # type: ignore
except Exception:  # pragma: no cover
    raise
