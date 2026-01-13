from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PersonaPluginConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    whitelist_user_ids: list[str] = Field(default_factory=list)
    whitelist_group_ids: list[str] = Field(default_factory=list)

    group_llm_limit: int = -1
    private_llm_limit: int = -1

    default_prefix: str = ""
    default_suffix: str = ""

    # 注入文本清洗：默认正则（用于 re.sub(pattern, "", text)）
    default_clean_regex: str = ""

    session_timeout_sec: int = 300

    external_persona_id: str = ""

    # CozyNook：用于访问需要登录态/鉴权的接口。
    # 这里配置的是 sid 的 cookie 值（或完整 cookie 片段）。
    # 示例：
    # - 仅值：abcdefg...
    # - 完整片段：sid=abcdefg...
    cozynook_sid_cookie: str = ""

    # Cozyverse v1：拉取评论条数（用于 /角色小屋 展示“最新评论”）。
    # 后端强制 page_size <= 50；这里也强制不超过 50。
    cozynook_comments_take: int = 10
    
    # 昵称同步配置
    sync_nickname_on_switch: bool = False
    nickname_sync_mode: str = "group_card"  # profile, group_card, hybrid
    nickname_template: str = "{persona_name}"
    
    # 聊天记录重置配置
    auto_reset_on_switch: bool = False

    # 关键词触发：一行一个规则，格式：关键词:提示词
    # - 关键词前加 ~ 表示“包含匹配”（大小写不敏感）
    # - 不加 ~ 表示“去除所有空白字符后完全匹配”（大小写敏感）
    keyword_persona_triggers: str = ""

    @field_validator("keyword_persona_triggers", mode="before")
    @classmethod
    def _coerce_keyword_persona_triggers(cls, v: Any) -> str:
        # 某些加载器/面板会把配置值包一层 {"value": ...}
        if isinstance(v, dict) and "value" in v:
            v = v.get("value")
        if v is None:
            return ""
        try:
            return str(v)
        except Exception:
            return ""

    @field_validator("whitelist_user_ids", mode="before")
    @classmethod
    def _coerce_whitelist(cls, v: Any) -> list[str]:
        # 某些加载器/面板会把配置值包一层 {"value": ...}
        if isinstance(v, dict) and "value" in v:
            v = v.get("value")
        if v is None:
            return []
        if isinstance(v, str):
            # 兼容：用逗号/换行/空格分隔的字符串
            parts = [p.strip() for p in v.replace("\r", "\n").replace(",", "\n").split("\n")]
            return [p for p in parts if p]
        if not isinstance(v, list):
            return []
        return [str(x) for x in v]

    @field_validator("whitelist_group_ids", mode="before")
    @classmethod
    def _coerce_whitelist_groups(cls, v: Any) -> list[str]:
        if isinstance(v, dict) and "value" in v:
            v = v.get("value")
        if v is None:
            return []
        if isinstance(v, str):
            parts = [p.strip() for p in v.replace("\r", "\n").replace(",", "\n").split("\n")]
            return [p for p in parts if p]
        if not isinstance(v, list):
            return []
        return [str(x) for x in v]

    @field_validator("group_llm_limit", "private_llm_limit", mode="before")
    @classmethod
    def _coerce_limit(cls, v: Any) -> int:
        if isinstance(v, dict) and "value" in v:
            v = v.get("value")
        try:
            return int(v)
        except Exception:
            return -1

    @field_validator("session_timeout_sec", mode="before")
    @classmethod
    def _coerce_timeout(cls, v: Any) -> int:
        if isinstance(v, dict) and "value" in v:
            v = v.get("value")
        try:
            return int(v)
        except Exception:
            return 300

    @field_validator("cozynook_comments_take", mode="before")
    @classmethod
    def _coerce_cozynook_comments_take(cls, v: Any) -> int:
        if isinstance(v, dict) and "value" in v:
            v = v.get("value")
        try:
            n = int(v)
        except Exception:
            n = 10
        if n < 0:
            n = 0
        if n > 50:
            n = 50
        return n

    @classmethod
    def from_raw(cls, raw: Any) -> PersonaPluginConfig:
        if not isinstance(raw, dict):
            raw = {}
        return cls.model_validate(raw)

    def is_whitelisted(self, sender_id: str) -> bool:
        """兼容旧方法名：用于“是否允许使用插件”（私聊维度）。

        语义：用户白名单为空 -> 不做限制（允许所有人）。
        用户白名单非空 -> 仅列表内用户允许。
        """
        return self.is_user_allowed(str(sender_id))

    def is_user_allowed(self, user_id: str) -> bool:
        """是否允许用户使用插件（白名单为空则不限制）。"""
        if not self.whitelist_user_ids:
            return True
        return str(user_id) in set(self.whitelist_user_ids)
    
    def is_user_unlimited(self, user_id: str) -> bool:
        """检查用户是否在白名单中（私聊无次数限制）。

        语义：用户白名单为空 -> 视为“全部白名单”（所有用户私聊无次数限制）。
        用户白名单非空 -> 仅列表内用户无次数限制。
        """
        if not self.whitelist_user_ids:
            return True
        return str(user_id) in set(self.whitelist_user_ids)

    def is_group_allowed(self, group_id: str) -> bool:
        """是否允许在群聊中使用插件。

        语义：群白名单为空 -> 视为“全部白名单”（允许任意群使用）。
        群白名单非空 -> 仅列表内群允许。
        """
        if not self.whitelist_group_ids:
            return True
        return str(group_id) in set(self.whitelist_group_ids)

    def is_group_unlimited(self, group_id: str) -> bool:
        """检查群聊是否在白名单中（群聊无次数限制）。

        语义：群白名单为空 -> 视为“全部白名单”（任意群聊无次数限制）。
        群白名单非空 -> 仅列表内群聊无次数限制。
        """
        if not self.whitelist_group_ids:
            return True
        return str(group_id) in set(self.whitelist_group_ids)

    # 兼容旧方法名：历史上用于群白名单判断
    def is_group_whitelisted(self, group_id: str) -> bool:
        return self.is_group_unlimited(group_id)

    def cozynook_cookie_header(self) -> str:
        """返回可直接用于 HTTP Header 的 Cookie 字符串。

        Cozyverse 后端鉴权可能使用：
        - `cv_auth=<token>`（新：无状态签名 token）
        - `cv_sid=<sid>`（旧：sessions 表）

        这里允许你直接粘贴任意 Cookie 片段：
        - 用户填写 "cv_auth=..." / "cv_sid=..." / "sid=..." / "cv_auth=...; cv_sid=..." -> 原样返回
        - 用户填写 "xxx" -> 自动拼为 "cv_sid=xxx"（兼容旧配置习惯）
        """
        raw = (self.cozynook_sid_cookie or "").strip()
        if not raw:
            return ""
        if "=" in raw:
            return raw
        return f"cv_sid={raw}"
