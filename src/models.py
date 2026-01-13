from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# 空人设常量：表示用户未选择任何人设
EMPTY_PERSONA_NAME = "__empty__"


class Visibility(str, Enum):
    PRIVATE = "private"


class Scope(str, Enum):
    USER = "user"


class CurrentSelection(BaseModel):
    model_config = ConfigDict(extra="allow")

    scope: Scope
    name: str
    # 当 scope=USER 且该选择用于群聊上下文时，记录“该人设属于哪个用户”，
    # 以便群聊按 group_id 存储选择、但仍能解析到创建者的用户角色内容。
    owner_user_id: str = ""
    ts: int = 0

    @field_validator("scope", mode="before")
    @classmethod
    def _coerce_scope(cls, v: Any) -> Scope:
        # 如果已经是 Scope 枚举对象，直接返回
        if isinstance(v, Scope):
            return v
        # 如果是字符串，尝试转换
        try:
            return Scope(str(v))
        except Exception:
            return Scope.USER


class UserPersona(BaseModel):
    model_config = ConfigDict(extra="allow")

    intro: str = ""
    content: str = ""
    visibility: Visibility = Visibility.PRIVATE
    use_wrapper: bool = True

    owner_name: str = ""
    updated_at: int = 0

    pending_request_id: str | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("visibility", mode="before")
    @classmethod
    def _coerce_visibility(cls, v: Any) -> Visibility:
        # 如果已经是 Visibility 枚举对象，直接返回
        if isinstance(v, Visibility):
            return v
        # 如果是字符串，尝试转换
        try:
            return Visibility(str(v))
        except Exception:
            return Visibility.PRIVATE


class UserBucket(BaseModel):
    model_config = ConfigDict(extra="allow")

    personas: dict[str, UserPersona] = Field(default_factory=dict)
    current: CurrentSelection | None = None


class Store(BaseModel):
    """插件持久化数据。

    注意：使用 extra=allow 以便兼容旧字段/未来扩展字段。
    """

    model_config = ConfigDict(extra="allow")

    version: int = 1
    users: dict[str, UserBucket] = Field(default_factory=dict)
    # 群聊维度的“当前人设选择”：key=group_id
    group_current: dict[str, CurrentSelection] = Field(default_factory=dict)

    @classmethod
    def empty(cls) -> Store:
        return cls()

    def ensure_user(self, user_id: str) -> UserBucket:
        bucket = self.users.get(user_id)
        if bucket is None:
            bucket = UserBucket()
            self.users[user_id] = bucket
        return bucket


class ResolvedPersona(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    intro: str = ""
    content: str
    visibility: Visibility
    use_wrapper: bool
    owner_user_id: str
    owner_name: str


class PersonaResolutionResult(BaseModel):
    """人设解析结果，包含人设信息和删除状态。"""
    model_config = ConfigDict(extra="allow")

    persona: ResolvedPersona | None
    was_deleted: bool = False  # 是否因为人设被删除而返回None
    deleted_persona_name: str | None = None  # 被删除的人设名称
    deleted_persona_scope: Scope | None = None  # 被删除的人设作用域


def json_safe_dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")
