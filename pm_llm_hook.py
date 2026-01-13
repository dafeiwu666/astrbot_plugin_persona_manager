from __future__ import annotations

# 兼容不同加载方式：对外提供与 src 同名模块。

try:
    from .src.pm_llm_hook import *  # type: ignore
except Exception:  # pragma: no cover
    # 若该目录结构不存在，则保持 ImportError 语义
    raise
