from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# 空人设常量：表示用户未选择任何人设
EMPTY_PERSONA_NAME = "__empty__"


class Visibility(str, Enum):
    PRIVATE = "private"
    PENDING = "pending"
    PUBLIC = "public"


class Scope(str, Enum):
    USER = "user"
    PUBLIC = "public"


class CurrentSelection(BaseModel):
    model_config = ConfigDict(extra="allow")

    scope: Scope
    name: str
    # 当 scope=USER 且该选择用于群聊上下文时，记录“该人设属于哪个用户”，
    # 以便群聊按 group_id 存储选择、但仍能解析到创建者的私密人设内容。
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


class PublicPersona(BaseModel):
    model_config = ConfigDict(extra="allow")

    intro: str = ""
    content: str = ""
    owner_user_id: str = ""
    owner_name: str = ""
    use_wrapper: bool = True
    approved_at: int = 0
    tags: list[str] = Field(default_factory=list)


class ReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_id: str
    user_name: str
    persona_name: str
    submitted_at: int

    target_type: str
    target_id: str
    platform_id: str
    
    # 原始会话上下文，用于将审核结果返回到申请人原始位置
    # 格式："group_{group_id}" 或 "private_{user_id}"
    original_context: str = ""

    status: ReviewStatus = ReviewStatus.PENDING
    reason: str = ""

    approved_at: int | None = None
    rejected_at: int | None = None

    @field_validator("status", mode="before")
    @classmethod
    def _coerce_status(cls, v: Any) -> ReviewStatus:
        try:
            return ReviewStatus(str(v))
        except Exception:
            return ReviewStatus.PENDING


class DeletionType(str, Enum):
    FORCE_DELETE = "force_delete"
    UNPUBLISH = "unpublish"


class PendingDeletion(BaseModel):
    """待确认的删除操作。"""
    model_config = ConfigDict(extra="allow")

    deletion_id: str  # 随机生成的ID
    deletion_type: DeletionType  # 强制删除或撤下
    persona_name: str
    initiator_user_id: str  # 发起操作的用户ID
    initiator_name: str  # 发起操作的用户名称
    reason: str = ""  # 操作理由
    created_at: int
    expires_at: int  # 过期时间

    target_type: str
    target_id: str
    platform_id: str

    # 发起时的平台/原始上下文：用于把审核结果回传给发起者
    # original_context 格式："group_{group_id}" 或 "private_{user_id}"
    initiator_platform_id: str = ""
    original_context: str = ""

    @field_validator("deletion_type", mode="before")
    @classmethod
    def _coerce_deletion_type(cls, v: Any) -> DeletionType:
        # 如果已经是 DeletionType 枚举对象，直接返回
        if isinstance(v, DeletionType):
            return v

        # 兼容旧数据/异常序列化值：
        # - "UNPUBLISH" / "FORCE_DELETE"（枚举名）
        # - "DeletionType.UNPUBLISH"（枚举对象被 str() 后的形式）
        # - 中文值（如"撤下"/"强制删除"）
        raw = "" if v is None else str(v)
        s = raw.strip()
        if not s:
            return DeletionType.FORCE_DELETE

        sl = s.lower()
        if "unpublish" in sl or "撤下" in s:
            return DeletionType.UNPUBLISH
        if "force_delete" in sl or "强制删除" in s:
            return DeletionType.FORCE_DELETE

        # 标准值："unpublish" / "force_delete"
        try:
            return DeletionType(sl)
        except Exception:
            return DeletionType.FORCE_DELETE


class Store(BaseModel):
    """插件持久化数据。

    注意：使用 extra=allow 以便兼容旧字段/未来扩展字段。
    """

    model_config = ConfigDict(extra="allow")

    version: int = 1
    users: dict[str, UserBucket] = Field(default_factory=dict)
    public: dict[str, PublicPersona] = Field(default_factory=dict)
    # 群聊维度的“当前人设选择”：key=group_id
    group_current: dict[str, CurrentSelection] = Field(default_factory=dict)
    review_requests: dict[str, ReviewRequest] = Field(default_factory=dict)
    review_inbox_last: dict[str, str] = Field(default_factory=dict)
    pending_deletions: dict[str, PendingDeletion] = Field(default_factory=dict)

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
