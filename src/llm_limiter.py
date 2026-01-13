from __future__ import annotations

import asyncio
import time
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field


class LLMUsageStats(BaseModel):
    """单个用户/群组的LLM使用统计"""
    model_config = ConfigDict(extra="allow")
    
    count: int = 0
    last_reset_date: str = ""  # YYYY-MM-DD格式


class LLMUsageStore(BaseModel):
    """LLM使用次数存储"""
    model_config = ConfigDict(extra="allow")
    
    group_usage: dict[str, LLMUsageStats] = Field(default_factory=dict)
    private_usage: dict[str, LLMUsageStats] = Field(default_factory=dict)


class LLMLimiter:
    """LLM调用次数限制管理器"""

    # 兼容某些加载器可能频繁重建插件实例：
    # 使用进程内全局存储，避免每次都从 0 开始导致“看起来无限”。
    _GLOBAL_LOCK: asyncio.Lock | None = None
    _GLOBAL_STORE: LLMUsageStore | None = None
    
    def __init__(
        self,
        *,
        lock: asyncio.Lock | None = None,
        now_date: Callable[[], str],  # 返回当前日期 YYYY-MM-DD
    ):
        if lock is not None:
            self._lock = lock
        else:
            if LLMLimiter._GLOBAL_LOCK is None:
                LLMLimiter._GLOBAL_LOCK = asyncio.Lock()
            self._lock = LLMLimiter._GLOBAL_LOCK
        self._now_date = now_date

        # 内存存储（进程内共享）
        if LLMLimiter._GLOBAL_STORE is None:
            LLMLimiter._GLOBAL_STORE = LLMUsageStore()
        self._store = LLMLimiter._GLOBAL_STORE
    
    def _get_current_date(self) -> str:
        """获取当前日期字符串"""
        return self._now_date()
    
    def _ensure_reset(self, stats: LLMUsageStats) -> None:
        """确保统计数据在新的一天被重置"""
        current_date = self._get_current_date()
        if stats.last_reset_date != current_date:
            stats.count = 0
            stats.last_reset_date = current_date
    
    async def check_group_limit(
        self,
        *,
        group_id: str,
        limit: int,
    ) -> tuple[bool, int, int]:
        """检查群聊是否达到限制
        
        Args:
            group_id: 群组ID
            limit: 限制次数（-1表示不限制）
        
        Returns:
            (是否允许, 当前已使用次数, 剩余次数)
        """
        if limit < 0:
            return True, 0, -1
        
        async with self._lock:
            if group_id not in self._store.group_usage:
                self._store.group_usage[group_id] = LLMUsageStats()
            
            stats = self._store.group_usage[group_id]
            self._ensure_reset(stats)
            
            used = stats.count
            remaining = max(0, limit - used)
            allowed = used < limit
            
            return allowed, used, remaining
    
    async def check_private_limit(
        self,
        *,
        user_id: str,
        limit: int,
    ) -> tuple[bool, int, int]:
        """检查私聊是否达到限制
        
        Args:
            user_id: 用户ID
            limit: 限制次数（-1表示不限制）
        
        Returns:
            (是否允许, 当前已使用次数, 剩余次数)
        """
        if limit < 0:
            return True, 0, -1
        
        async with self._lock:
            if user_id not in self._store.private_usage:
                self._store.private_usage[user_id] = LLMUsageStats()
            
            stats = self._store.private_usage[user_id]
            self._ensure_reset(stats)
            
            used = stats.count
            remaining = max(0, limit - used)
            allowed = used < limit
            
            return allowed, used, remaining
    
    async def increment_group_usage(self, *, group_id: str) -> None:
        """增加群聊使用次数"""
        async with self._lock:
            if group_id not in self._store.group_usage:
                self._store.group_usage[group_id] = LLMUsageStats()
            
            stats = self._store.group_usage[group_id]
            self._ensure_reset(stats)
            stats.count += 1
    
    async def increment_private_usage(self, *, user_id: str) -> None:
        """增加私聊使用次数"""
        async with self._lock:
            if user_id not in self._store.private_usage:
                self._store.private_usage[user_id] = LLMUsageStats()
            
            stats = self._store.private_usage[user_id]
            self._ensure_reset(stats)
            stats.count += 1
    
    async def get_group_stats(self, *, group_id: str) -> tuple[int, str]:
        """获取群聊统计信息
        
        Returns:
            (使用次数, 统计日期)
        """
        async with self._lock:
            if group_id not in self._store.group_usage:
                return 0, self._get_current_date()
            
            stats = self._store.group_usage[group_id]
            self._ensure_reset(stats)
            return stats.count, stats.last_reset_date
    
    async def get_private_stats(self, *, user_id: str) -> tuple[int, str]:
        """获取私聊统计信息
        
        Returns:
            (使用次数, 统计日期)
        """
        async with self._lock:
            if user_id not in self._store.private_usage:
                return 0, self._get_current_date()
            
            stats = self._store.private_usage[user_id]
            self._ensure_reset(stats)
            return stats.count, stats.last_reset_date


def get_current_date_str() -> str:
    """获取当前日期字符串 YYYY-MM-DD"""
    return time.strftime("%Y-%m-%d", time.localtime())
