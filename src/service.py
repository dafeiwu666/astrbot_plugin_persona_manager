from __future__ import annotations

import asyncio
import secrets
import uuid
from collections.abc import Callable

from .models import (
    CurrentSelection,
    DeletionType,
    EMPTY_PERSONA_NAME,
    PendingDeletion,
    PersonaResolutionResult,
    PublicPersona,
    ResolvedPersona,
    ReviewRequest,
    ReviewStatus,
    Scope,
    Store,
    UserPersona,
    Visibility,
)
from .repository import StoreRepository


class PersonaService:
    _REVIEW_REQUESTS_KEEP: int = 10

    def __init__(
        self,
        repo: StoreRepository,
        *,
        lock: asyncio.Lock | None = None,
        now_ts: Callable[[], int],
    ):
        self._repo = repo
        self._lock = lock or asyncio.Lock()
        self._now_ts = now_ts

    def _trim_review_requests(self, *, store: Store) -> None:
        """裁剪审核记录，仅保留最近若干条，避免 store.json 无限增长。

        规则：
        - 永远保留所有 PENDING（避免待审流程被裁剪破坏）。
        - 在此基础上，按 submitted_at 倒序，仅保留最新 _REVIEW_REQUESTS_KEEP 条已完成（APPROVED/REJECTED）。
        - 同步清理 review_inbox_last 中指向不存在/非 PENDING 的指针。
        """
        keep = int(self._REVIEW_REQUESTS_KEEP)
        if keep <= 0:
            return

        reqs = store.review_requests or {}

        pending_ids: list[str] = []
        finished_ranked: list[tuple[int, str]] = []  # (submitted_at, req_id)
        for rid, r in reqs.items():
            if r.status == ReviewStatus.PENDING:
                pending_ids.append(rid)
                continue
            ts = 0
            try:
                ts = int(getattr(r, "submitted_at", 0) or 0)
            except Exception:
                ts = 0
            finished_ranked.append((ts, rid))

        # 仅裁剪“已完成”的部分；PENDING 全保留
        finished_ranked.sort(key=lambda x: (x[0], x[1]), reverse=True)
        keep_finished_ids = {rid for _ts, rid in finished_ranked[:keep]}
        keep_ids = set(pending_ids) | keep_finished_ids

        if len(keep_ids) < len(reqs):
            store.review_requests = {rid: reqs[rid] for rid in keep_ids if rid in reqs}

        # 清理 inbox_last：只保留指向仍存在且为 PENDING 的请求
        if store.review_inbox_last:
            for k, rid in list(store.review_inbox_last.items()):
                r = store.review_requests.get(rid)
                if (not r) or (r.status != ReviewStatus.PENDING):
                    store.review_inbox_last.pop(k, None)

    async def load_store(self) -> Store:
        return await self._repo.load()

    async def upsert_user_persona(
        self,
        *,
        user_id: str,
        user_name: str,
        name: str,
        intro: str,
        content: str,
        use_wrapper: bool,
        tags: list[str] | None = None,
    ) -> None:
        async with self._lock:
            store = await self._repo.load()

            bucket = store.ensure_user(user_id)
            bucket.personas[name] = UserPersona(
                intro=intro,
                content=content,
                visibility=Visibility.PRIVATE,
                use_wrapper=use_wrapper,
                owner_name=user_name,
                updated_at=self._now_ts(),
                tags=tags or [],
            )
            bucket.current = CurrentSelection(
                scope=Scope.USER,
                name=name,
                ts=self._now_ts(),
            )
            await self._repo.save(store)

    async def get_current(self, user_id: str) -> tuple[Scope, str] | None:
        store = await self._repo.load()
        bucket = store.ensure_user(user_id)
        cur = bucket.current
        if not cur or not cur.name:
            return None
        
        # 如果选择的是空人设，返回空人设
        if cur.name == EMPTY_PERSONA_NAME:
            return cur.scope, cur.name
        
        # 检查人设是否仍然存在
        if cur.scope == Scope.USER:
            if cur.name not in bucket.personas:
                # 人设已被删除，切换到空人设
                async with self._lock:
                    store2 = await self._repo.load()
                    bucket2 = store2.ensure_user(user_id)
                    bucket2.current = CurrentSelection(
                        scope=Scope.USER,
                        name=EMPTY_PERSONA_NAME,
                        ts=self._now_ts(),
                    )
                    await self._repo.save(store2)
                return Scope.USER, EMPTY_PERSONA_NAME
        elif cur.scope == Scope.PUBLIC:
            # 公开市场已移除：历史 PUBLIC 统一切回空人设
            async with self._lock:
                store2 = await self._repo.load()
                bucket2 = store2.ensure_user(user_id)
                bucket2.current = CurrentSelection(
                    scope=Scope.USER,
                    name=EMPTY_PERSONA_NAME,
                    ts=self._now_ts(),
                )
                await self._repo.save(store2)
            return Scope.USER, EMPTY_PERSONA_NAME
        
        return cur.scope, cur.name

    def _normalize_group_id(self, group_id: str | None) -> str | None:
        if group_id is None:
            return None
        s = str(group_id).strip()
        if not s or s == "0":
            return None
        return s

    def _get_context_current(
        self, *, store: Store, user_id: str, group_id: str | None
    ) -> CurrentSelection | None:
        gid = self._normalize_group_id(group_id)
        if gid:
            return store.group_current.get(gid)
        bucket = store.ensure_user(user_id)
        return bucket.current

    async def get_current_for_context(
        self, *, user_id: str, group_id: str | None
    ) -> tuple[Scope, str] | None:
        """获取当前人设（群聊按 group_id、私聊按 user_id）。"""
        store = await self._repo.load()
        cur = self._get_context_current(store=store, user_id=user_id, group_id=group_id)
        if not cur or not cur.name:
            return None

        if cur.name == EMPTY_PERSONA_NAME:
            return cur.scope, cur.name

        gid = self._normalize_group_id(group_id)

        # 校验当前选择仍然存在；不存在则切回空人设（写回对应上下文）
        if cur.scope == Scope.USER:
            owner_id = (cur.owner_user_id or user_id).strip() or user_id
            owner_bucket = store.ensure_user(owner_id)
            if cur.name not in owner_bucket.personas:
                async with self._lock:
                    store2 = await self._repo.load()
                    if gid:
                        store2.group_current[gid] = CurrentSelection(
                            scope=Scope.USER,
                            name=EMPTY_PERSONA_NAME,
                            owner_user_id="",
                            ts=self._now_ts(),
                        )
                    else:
                        b2 = store2.ensure_user(user_id)
                        b2.current = CurrentSelection(
                            scope=Scope.USER,
                            name=EMPTY_PERSONA_NAME,
                            owner_user_id="",
                            ts=self._now_ts(),
                        )
                    await self._repo.save(store2)
                return Scope.USER, EMPTY_PERSONA_NAME
        elif cur.scope == Scope.PUBLIC:
            # 公开市场已移除：历史 PUBLIC 统一切回空人设
            async with self._lock:
                store2 = await self._repo.load()
                if gid:
                    store2.group_current[gid] = CurrentSelection(
                        scope=Scope.USER,
                        name=EMPTY_PERSONA_NAME,
                        owner_user_id="",
                        ts=self._now_ts(),
                    )
                else:
                    b2 = store2.ensure_user(user_id)
                    b2.current = CurrentSelection(
                        scope=Scope.USER,
                        name=EMPTY_PERSONA_NAME,
                        owner_user_id="",
                        ts=self._now_ts(),
                    )
                await self._repo.save(store2)
            return Scope.USER, EMPTY_PERSONA_NAME

        return cur.scope, cur.name

    async def switch_persona_for_context(
        self, *, user_id: str, group_id: str | None, name: str
    ) -> Scope | None:
        """切换当前人设（群聊按 group_id、私聊按 user_id）。

        群聊上下文允许：
        - 切换到调用者自己的角色（会记录 owner_user_id=user_id）
        - 切换到空人设
        """
        gid = self._normalize_group_id(group_id)
        async with self._lock:
            store = await self._repo.load()
            user_bucket = store.ensure_user(user_id)

            def _set_current(sel: CurrentSelection) -> None:
                if gid:
                    store.group_current[gid] = sel
                else:
                    user_bucket.current = sel

            # 空人设
            if name == EMPTY_PERSONA_NAME:
                _set_current(
                    CurrentSelection(
                        scope=Scope.USER,
                        name=EMPTY_PERSONA_NAME,
                        owner_user_id="",
                        ts=self._now_ts(),
                    )
                )
                await self._repo.save(store)
                return Scope.USER

            # 仅允许切换到调用者自己的角色
            if name in user_bucket.personas:
                _set_current(
                    CurrentSelection(
                        scope=Scope.USER,
                        name=name,
                        owner_user_id=user_id if gid else "",
                        ts=self._now_ts(),
                    )
                )
                await self._repo.save(store)
                return Scope.USER

        return None

    async def resolve_persona_for_inject_for_context(
        self, *, user_id: str, group_id: str | None
    ) -> PersonaResolutionResult:
        """按上下文解析用于注入的人设：群聊按 group_id，私聊按 user_id。"""
        store = await self._repo.load()
        cur = self._get_context_current(store=store, user_id=user_id, group_id=group_id)

        if not cur or cur.name == EMPTY_PERSONA_NAME:
            return PersonaResolutionResult(persona=None)

        name = cur.name
        scope = cur.scope

        if scope == Scope.USER:
            owner_id = (cur.owner_user_id or user_id).strip() or user_id
            owner_bucket = store.ensure_user(owner_id)
            p = owner_bucket.personas.get(name)
            if not p or not p.content.strip():
                if not p:
                    # 人设被删：切回空人设并提示
                    async with self._lock:
                        store2 = await self._repo.load()
                        gid = self._normalize_group_id(group_id)
                        if gid:
                            store2.group_current[gid] = CurrentSelection(
                                scope=Scope.USER,
                                name=EMPTY_PERSONA_NAME,
                                owner_user_id="",
                                ts=self._now_ts(),
                            )
                        else:
                            b2 = store2.ensure_user(user_id)
                            b2.current = CurrentSelection(
                                scope=Scope.USER,
                                name=EMPTY_PERSONA_NAME,
                                owner_user_id="",
                                ts=self._now_ts(),
                            )
                        await self._repo.save(store2)
                    return PersonaResolutionResult(
                        persona=None,
                        was_deleted=True,
                        deleted_persona_name=name,
                        deleted_persona_scope=scope,
                    )
                return PersonaResolutionResult(persona=None)

            return PersonaResolutionResult(
                persona=ResolvedPersona(
                    name=name,
                    intro=p.intro,
                    content=p.content,
                    visibility=p.visibility,
                    use_wrapper=p.use_wrapper,
                    owner_user_id=owner_id,
                    owner_name=p.owner_name,
                )
            )

        # Scope.PUBLIC（历史遗留）：统一降级为空人设
        async with self._lock:
            store2 = await self._repo.load()
            gid = self._normalize_group_id(group_id)
            if gid:
                store2.group_current[gid] = CurrentSelection(
                    scope=Scope.USER,
                    name=EMPTY_PERSONA_NAME,
                    owner_user_id="",
                    ts=self._now_ts(),
                )
            else:
                b2 = store2.ensure_user(user_id)
                b2.current = CurrentSelection(
                    scope=Scope.USER,
                    name=EMPTY_PERSONA_NAME,
                    owner_user_id="",
                    ts=self._now_ts(),
                )
            await self._repo.save(store2)
        return PersonaResolutionResult(
            persona=None,
            was_deleted=True,
            deleted_persona_name=name,
            deleted_persona_scope=scope,
        )

    async def set_current(self, *, user_id: str, scope: Scope, name: str) -> None:
        async with self._lock:
            store = await self._repo.load()
            bucket = store.ensure_user(user_id)
            bucket.current = CurrentSelection(scope=scope, name=name, ts=self._now_ts())
            await self._repo.save(store)

    async def resolve_persona_for_inject(
        self, *, user_id: str
    ) -> PersonaResolutionResult:
        store = await self._repo.load()
        bucket = store.ensure_user(user_id)
        cur = bucket.current
        
        # 如果没有选择或选择的是空人设，返回空结果
        if not cur or cur.name == EMPTY_PERSONA_NAME:
            return PersonaResolutionResult(persona=None)

        name = cur.name
        scope = cur.scope
        
        if scope == Scope.USER:
            p = bucket.personas.get(name)
            # 如果人设不存在或内容为空，自动切换到空人设
            if not p or not p.content.strip():
                # 人设已被删除，需要切换回空人设并提醒
                if not p:
                    async with self._lock:
                        bucket.current = CurrentSelection(
                            scope=Scope.USER,
                            name=EMPTY_PERSONA_NAME,
                            ts=self._now_ts()
                        )
                        await self._repo.save(store)
                    return PersonaResolutionResult(
                        persona=None,
                        was_deleted=True,
                        deleted_persona_name=name,
                        deleted_persona_scope=scope,
                    )
                # 内容为空，不提醒
                return PersonaResolutionResult(persona=None)
            
            return PersonaResolutionResult(
                persona=ResolvedPersona(
                    name=name,
                    intro=p.intro,
                    content=p.content,
                    visibility=p.visibility,
                    use_wrapper=p.use_wrapper,
                    owner_user_id=user_id,
                    owner_name=p.owner_name,
                )
            )

        # Scope.PUBLIC（历史遗留）：统一降级为空人设
        async with self._lock:
            bucket.current = CurrentSelection(
                scope=Scope.USER,
                name=EMPTY_PERSONA_NAME,
                ts=self._now_ts(),
            )
            await self._repo.save(store)
        return PersonaResolutionResult(
            persona=None,
            was_deleted=True,
            deleted_persona_name=name,
            deleted_persona_scope=scope,
        )

    async def list_lines(self, *, user_id: str):
        store = await self._repo.load()
        bucket = store.ensure_user(user_id)

        personas: list[tuple[str, UserPersona]] = [(name, p) for name, p in bucket.personas.items()]
        return {"personas": personas}

    async def search_by_tags(self, *, user_id: str, search_tags: list[str]):
        """根据tags搜索人设。
        
        Args:
            user_id: 用户ID
            search_tags: 要搜索的tag列表，支持 "私密"、"公开"、"自己公开" 等特殊标签
        
        Returns:
            包含匹配人设的字典，格式与list_lines相同
        """
        store = await self._repo.load()
        bucket = store.ensure_user(user_id)
        
        # 过滤掉历史作用域标签，剩下的是普通标签
        normal_tags = [t for t in search_tags if t not in ["私密", "公开", "自己公开"]]
        normal_tags_lower = [t.lower() for t in normal_tags]

        personas: list[tuple[str, UserPersona]] = []
        for name, p in bucket.personas.items():
            if self._matches_all_tags(p.tags, normal_tags_lower):
                personas.append((name, p))

        return {"personas": personas}
    
    def _matches_all_tags(self, persona_tags: list[str], search_tags_lower: list[str]) -> bool:
        """检查人设的tags是否匹配所有搜索标签。"""
        if not search_tags_lower:
            return True
        
        persona_tags_lower = [t.lower() for t in persona_tags]
        for search_tag in search_tags_lower:
            if search_tag not in persona_tags_lower:
                return False
        return True

    async def switch_persona(self, *, user_id: str, name: str) -> Scope | None:
        async with self._lock:
            store = await self._repo.load()
            bucket = store.ensure_user(user_id)

            # 允许切换到空人设
            if name == EMPTY_PERSONA_NAME:
                bucket.current = CurrentSelection(
                    scope=Scope.USER, name=EMPTY_PERSONA_NAME, ts=self._now_ts()
                )
                await self._repo.save(store)
                return Scope.USER

            if name in bucket.personas:
                bucket.current = CurrentSelection(scope=Scope.USER, name=name, ts=self._now_ts())
                await self._repo.save(store)
                return Scope.USER

        return None

    async def delete_user_persona(self, *, user_id: str, name: str) -> tuple[bool, str]:
        """删除用户角色。
        
        Returns:
            (success, message)
            - success: 是否成功删除
            - message: 失败原因或空字符串
        """
        async with self._lock:
            store = await self._repo.load()
            bucket = store.ensure_user(user_id)

            # 检查人设是否存在于私密库
            if name not in bucket.personas:
                # 检查是否是已公开的人设
                if name in store.public:
                    pub = store.public[name]
                    if pub.owner_user_id == user_id:
                        return False, "该角色已公开，无法直接删除。如需下架，请使用 /下架投稿 命令。"
                    else:
                        return False, "只能删除自己创建的角色。"
                else:
                    return False, "角色不存在。"

            del bucket.personas[name]

            if bucket.current and bucket.current.name == name:
                bucket.current = CurrentSelection(
                    scope=Scope.USER,
                    name=EMPTY_PERSONA_NAME,
                    ts=self._now_ts()
                )

            await self._repo.save(store)
            return True, ""

    async def get_user_persona(
        self, *, user_id: str, name: str
    ) -> UserPersona | None:
        """获取用户的角色。"""
        store = await self._repo.load()
        bucket = store.ensure_user(user_id)
        return bucket.personas.get(name)

    async def can_edit_persona(
        self, *, user_id: str, name: str
    ) -> tuple[bool, str]:
        """检查是否可以修改角色设定。
        
        Returns:
            (can_edit, reason)
            - can_edit: True if editable
            - reason: 不可编辑的原因（当 can_edit=False 时）
        """
        store = await self._repo.load()
        bucket = store.ensure_user(user_id)
        
        persona = bucket.personas.get(name)
        if not persona:
            return False, "角色不存在或不属于你"
        
        # 只能编辑私密且未公开的人设
        if persona.visibility != Visibility.PRIVATE:
            if persona.visibility == Visibility.PUBLIC:
                return False, "已公开的角色无法修改设定"
            elif persona.visibility == Visibility.PENDING:
                return False, "审核中的角色无法修改设定"
        
        return True, ""

    async def update_user_persona_content(
        self,
        *,
        user_id: str,
        name: str,
        intro: str,
        content: str,
        use_wrapper: bool,
        tags: list[str] | None = None,
    ) -> bool:
        """更新用户角色的内容（不改名字）。
        
        Returns:
            True if updated successfully, False if persona not found or not editable
        """
        async with self._lock:
            store = await self._repo.load()
            bucket = store.ensure_user(user_id)
            
            persona = bucket.personas.get(name)
            if not persona:
                return False
            
            # 只能编辑私密且未公开的人设
            if persona.visibility != Visibility.PRIVATE:
                return False
            
            # 更新内容
            persona.intro = intro
            persona.content = content
            persona.use_wrapper = use_wrapper
            persona.updated_at = self._now_ts()
            if tags is not None:
                persona.tags = tags
            
            await self._repo.save(store)
            return True

    async def submit_public_request(
        self,
        *,
        user_id: str,
        user_name: str,
        persona_name: str,
        target_type: str,
        target_id: str,
        platform_id: str,
        review_key: str,
        original_context: str,
    ) -> tuple[str, str, UserPersona | None]:
        """提交公开审核。

        Returns:
            (status, req_id, persona)
            - status: ok | not_found | already_public
        """
        async with self._lock:
            store = await self._repo.load()
            bucket = store.ensure_user(user_id)
            p = bucket.personas.get(persona_name)
            if not p:
                return "not_found", "", None
            if p.visibility == Visibility.PUBLIC:
                return "already_public", "", None

            req_id = uuid.uuid4().hex
            store.review_requests[req_id] = ReviewRequest(
                user_id=user_id,
                user_name=user_name,
                persona_name=persona_name,
                submitted_at=self._now_ts(),
                target_type=target_type,
                target_id=target_id,
                platform_id=platform_id,
                original_context=original_context,
                status=ReviewStatus.PENDING,
                reason="",
            )
            store.review_inbox_last[review_key] = req_id

            p.visibility = Visibility.PENDING
            p.pending_request_id = req_id

            self._trim_review_requests(store=store)

            await self._repo.save(store)
            return "ok", req_id, p

    def _pick_pending_request_from_inbox(
        self, *, store: Store, review_key: str
    ) -> tuple[str, ReviewRequest] | None:
        req_id = store.review_inbox_last.get(review_key)
        if not req_id:
            return None
        req = store.review_requests.get(req_id)
        if not req or req.status != ReviewStatus.PENDING:
            return None
        return req_id, req

    def _reject_request_for_conflict(self, *, req: ReviewRequest) -> None:
        req.status = ReviewStatus.REJECTED
        req.reason = "公开库已存在同名角色（不同创建者），无法公开"
        req.rejected_at = self._now_ts()

    def _approve_request_to_public(
        self, *, store: Store, req: ReviewRequest
    ) -> tuple[str, str, str, str, str] | None:
        """执行同意公开，返回 (user_id, persona_name, user_name, original_platform, original_context)。

        注意：调用方需要在锁内，并在成功/失败后自行 save(store)。
        """
        user_id = req.user_id
        persona_name = req.persona_name
        user_name = req.user_name
        original_platform = req.platform_id
        original_context = req.original_context

        existing = store.public.get(persona_name)
        if existing and existing.owner_user_id != user_id:
            self._reject_request_for_conflict(req=req)
            return None

        bucket = store.ensure_user(user_id)
        p = bucket.personas.get(persona_name)
        if not p:
            req.status = ReviewStatus.REJECTED
            req.reason = "角色不存在"
            req.rejected_at = self._now_ts()
            return None

        store.public[persona_name] = PublicPersona(
            intro=p.intro,
            content=p.content,
            owner_user_id=user_id,
            owner_name=p.owner_name or user_name,
            use_wrapper=p.use_wrapper,
            approved_at=self._now_ts(),
            tags=p.tags,
        )

        # 从私密库中删除（完全转移到公开库）
        del bucket.personas[persona_name]

        # 如果用户当前使用的是这个人设（私密scope），切换到公开scope
        if (
            bucket.current
            and bucket.current.scope == Scope.USER
            and bucket.current.name == persona_name
        ):
            bucket.current = CurrentSelection(
                scope=Scope.PUBLIC,
                name=persona_name,
                ts=self._now_ts(),
            )

        req.status = ReviewStatus.APPROVED
        req.approved_at = self._now_ts()
        return user_id, persona_name, user_name, original_platform, original_context

    def _reject_request_to_private(
        self, *, store: Store, req: ReviewRequest, reason: str
    ) -> tuple[str, str, str, str, str]:
        """执行拒绝公开，返回 (user_id, persona_name, user_name, original_platform, original_context)。

        注意：调用方需要在锁内，并在调用后自行 save(store)。
        """
        user_id = req.user_id
        persona_name = req.persona_name
        user_name = req.user_name
        original_platform = req.platform_id
        original_context = req.original_context

        bucket = store.ensure_user(user_id)
        p = bucket.personas.get(persona_name)
        if p:
            p.visibility = Visibility.PRIVATE
            p.pending_request_id = None

        req.status = ReviewStatus.REJECTED
        req.reason = reason
        req.rejected_at = self._now_ts()
        return user_id, persona_name, user_name, original_platform, original_context

    async def get_pending_request_from_inbox(
        self, *, review_key: str
    ) -> tuple[str, ReviewRequest] | None:
        store = await self._repo.load()
        return self._pick_pending_request_from_inbox(store=store, review_key=review_key)

    async def list_pending_requests_for_target(
        self, *, target_type: str, target_id: str, platform_id: str
    ) -> list[tuple[str, ReviewRequest]]:
        """列出指定审核目标下的所有待审请求（PENDING）。"""
        store = await self._repo.load()
        out: list[tuple[int, str, ReviewRequest]] = []  # (submitted_at, req_id, req)
        for req_id, req in (store.review_requests or {}).items():
            if req.status != ReviewStatus.PENDING:
                continue
            if req.target_type != target_type:
                continue
            if str(req.target_id) != str(target_id):
                continue
            # 平台可能与配置不一致（例如审核群ID相同但平台名不同），此时仍应展示。
            ts = 0
            try:
                ts = int(getattr(req, "submitted_at", 0) or 0)
            except Exception:
                ts = 0
            out.append((ts, req_id, req))

        # 最新的放前面
        out.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [(req_id, req) for _ts, req_id, req in out]

    async def list_all_pending_public_requests(self) -> list[tuple[str, ReviewRequest]]:
        """列出所有待审公开申请（不按 target 过滤）。"""
        store = await self._repo.load()
        out: list[tuple[int, str, ReviewRequest]] = []
        for req_id, req in (store.review_requests or {}).items():
            if req.status != ReviewStatus.PENDING:
                continue
            ts = 0
            try:
                ts = int(getattr(req, "submitted_at", 0) or 0)
            except Exception:
                ts = 0
            out.append((ts, req_id, req))
        out.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [(req_id, req) for _ts, req_id, req in out]

    async def list_pending_deletions_for_target(
        self, *, target_type: str, target_id: str, platform_id: str
    ) -> list[tuple[str, PendingDeletion]]:
        """列出指定审核目标下的所有待确认删除请求。

        deletion_type:
        - FORCE_DELETE: 强制删除公开角色
        - UNPUBLISH: 下架投稿（撤下公开角色）
        """
        store = await self._repo.load()
        now = self._now_ts()

        out: list[tuple[int, str, PendingDeletion]] = []  # (created_at, deletion_id, pending)
        for del_id, pending in (store.pending_deletions or {}).items():
            if pending.expires_at and pending.expires_at <= now:
                continue
            if pending.target_type != target_type:
                continue
            if str(pending.target_id) != str(target_id):
                continue
            # 平台可能与配置不一致（例如审核群ID相同但平台名不同），此时仍应展示。
            ts = 0
            try:
                ts = int(getattr(pending, "created_at", 0) or 0)
            except Exception:
                ts = 0
            out.append((ts, del_id, pending))

        out.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [(del_id, pending) for _ts, del_id, pending in out]

    async def list_all_pending_deletions(self) -> list[tuple[str, PendingDeletion]]:
        """列出所有待确认删除/撤下请求（不按 target 过滤，自动跳过过期）。"""
        store = await self._repo.load()
        now = self._now_ts()
        out: list[tuple[int, str, PendingDeletion]] = []
        for del_id, pending in (store.pending_deletions or {}).items():
            if pending.expires_at and pending.expires_at <= now:
                continue
            ts = 0
            try:
                ts = int(getattr(pending, "created_at", 0) or 0)
            except Exception:
                ts = 0
            out.append((ts, del_id, pending))
        out.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [(del_id, pending) for _ts, del_id, pending in out]

    async def approve_from_inbox(
        self, *, review_key: str
    ) -> tuple[str, str, str, str] | None:
        """返回 (user_id, persona_name, original_platform, original_context) 或 None"""
        async with self._lock:
            store = await self._repo.load()
            picked = self._pick_pending_request_from_inbox(store=store, review_key=review_key)
            if not picked:
                return None
            _req_id, req = picked

            approved = self._approve_request_to_public(store=store, req=req)
            self._trim_review_requests(store=store)
            await self._repo.save(store)

            if not approved:
                return None

            user_id, persona_name, _user_name, original_platform, original_context = approved
            return user_id, persona_name, original_platform, original_context

    async def reject_from_inbox(
        self, *, review_key: str, reason: str
    ) -> tuple[str, str, str, str] | None:
        """返回 (user_id, persona_name, original_platform, original_context) 或 None"""
        async with self._lock:
            store = await self._repo.load()
            picked = self._pick_pending_request_from_inbox(store=store, review_key=review_key)
            if not picked:
                return None
            _req_id, req = picked

            user_id, persona_name, _user_name, original_platform, original_context = (
                self._reject_request_to_private(store=store, req=req, reason=reason)
            )
            self._trim_review_requests(store=store)
            await self._repo.save(store)
            return user_id, persona_name, original_platform, original_context

    async def approve_by_request_id(
        self, *, req_id: str
    ) -> tuple[str, str, str, str, str] | None:
        """通过请求ID同意公开。
        
        Returns:
            (user_id, persona_name, user_name, original_platform, original_context) 或 None
        """
        async with self._lock:
            store = await self._repo.load()
            req = store.review_requests.get(req_id)
            if not req:
                return None
            if req.status != ReviewStatus.PENDING:
                return None

            approved = self._approve_request_to_public(store=store, req=req)
            self._trim_review_requests(store=store)
            await self._repo.save(store)
            return approved

    async def reject_by_request_id(
        self, *, req_id: str, reason: str
    ) -> tuple[str, str, str, str, str] | None:
        """通过请求ID拒绝公开。
        
        Returns:
            (user_id, persona_name, user_name, original_platform, original_context) 或 None
        """
        async with self._lock:
            store = await self._repo.load()
            req = store.review_requests.get(req_id)
            if not req:
                return None
            if req.status != ReviewStatus.PENDING:
                return None

            result = self._reject_request_to_private(store=store, req=req, reason=reason)
            self._trim_review_requests(store=store)
            await self._repo.save(store)
            return result

    async def create_deletion_request(
        self,
        *,
        persona_name: str,
        deletion_type: DeletionType,
        initiator_user_id: str,
        initiator_name: str,
        reason: str,
        target_type: str,
        target_id: str,
        platform_id: str,
        initiator_platform_id: str = "",
        original_context: str = "",
        expiry_seconds: int = 86400,
    ) -> tuple[bool, str, str | None]:
        """创建删除请求。
        
        Args:
            persona_name: 角色名称
            deletion_type: 删除类型（强制删除或撤下）
            initiator_user_id: 发起者用户ID
            initiator_name: 发起者名称
            reason: 操作理由
            target_type: 目标类型（group或user）
            target_id: 目标ID
            platform_id: 平台ID
            expiry_seconds: 过期时间（秒）
            
        Returns:
            (success, message, deletion_id)
        """
        async with self._lock:
            store = await self._repo.load()
            
            # 检查角色是否存在
            pub = store.public.get(persona_name)
            if not pub:
                return False, "该公开角色不存在。", None
            
            # 清理过期的删除请求
            now = self._now_ts()
            expired_ids = [
                del_id
                for del_id, pending in store.pending_deletions.items()
                if pending.expires_at <= now
            ]
            for del_id in expired_ids:
                store.pending_deletions.pop(del_id, None)
            
            # 生成唯一ID
            deletion_id = uuid.uuid4().hex[:8]  # 使用8位短ID
            while deletion_id in store.pending_deletions:
                deletion_id = uuid.uuid4().hex[:8]
            
            # 创建删除请求
            pending = PendingDeletion(
                deletion_id=deletion_id,
                deletion_type=deletion_type,
                persona_name=persona_name,
                initiator_user_id=initiator_user_id,
                initiator_name=initiator_name,
                reason=reason,
                created_at=now,
                expires_at=now + expiry_seconds,
                target_type=target_type,
                target_id=target_id,
                platform_id=platform_id,
                initiator_platform_id=initiator_platform_id,
                original_context=original_context,
            )
            
            store.pending_deletions[deletion_id] = pending
            await self._repo.save(store)
            
            return True, "删除请求已创建。", deletion_id

    async def reject_deletion_request(
        self,
        *,
        deletion_id: str,
        expected_type: DeletionType | None = None,
    ) -> tuple[bool, str, PendingDeletion | None, str | None, str | None]:
        """拒绝/取消一个待确认的删除请求（不执行删除）。

        用于审核员拒绝“下架投稿（撤下公开角色）”等场景：
        - 将 pending_deletions 中对应记录移除
        - 不修改公开库/用户当前角色

        Returns:
            (success, message, pending, owner_user_id, owner_name)
        """
        async with self._lock:
            store = await self._repo.load()

            pending = store.pending_deletions.get(deletion_id)
            if not pending:
                return False, "删除请求不存在或已过期。", None, None, None

            if pending.expires_at <= self._now_ts():
                store.pending_deletions.pop(deletion_id, None)
                await self._repo.save(store)
                return False, "删除请求已过期。", None, None, None

            if expected_type is not None and pending.deletion_type != expected_type:
                return False, "删除请求类型不匹配。", None, None, None

            persona_name = pending.persona_name
            pub = store.public.get(persona_name)
            owner_user_id = pub.owner_user_id if pub else None
            owner_name = pub.owner_name if pub else None

            store.pending_deletions.pop(deletion_id, None)
            await self._repo.save(store)

            return True, "删除请求已拒绝。", pending, owner_user_id, owner_name

    async def confirm_deletion(
        self, *, deletion_id: str
    ) -> tuple[bool, str, str | None, DeletionType | None, list[str], str | None, str]:
        """确认删除请求。
        
        Args:
            deletion_id: 删除请求ID
            
        Returns:
            (success, message, persona_name, deletion_type, affected_users, owner_user_id, reason)
        """
        async with self._lock:
            store = await self._repo.load()
            
            # 查找删除请求
            pending = store.pending_deletions.get(deletion_id)
            if not pending:
                return False, "删除请求不存在或已过期。", None, None, [], None, ""
            
            # 检查是否过期
            if pending.expires_at <= self._now_ts():
                store.pending_deletions.pop(deletion_id, None)
                await self._repo.save(store)
                return False, "删除请求已过期。", None, None, [], None, ""
            
            persona_name = pending.persona_name
            final_persona_name = persona_name
            deletion_type = pending.deletion_type
            reason = pending.reason
            
            # 执行删除操作
            if deletion_type == DeletionType.FORCE_DELETE:
                # 强制删除逻辑
                pub = store.public.get(persona_name)
                if not pub:
                    store.pending_deletions.pop(deletion_id, None)
                    await self._repo.save(store)
                    return False, "该公开角色不存在。", persona_name, deletion_type, [], None, reason
                
                owner_user_id = pub.owner_user_id
                # 不在确认删除时批量“静默切回空人设”。
                # 用户侧会在 get_current/resolve_persona_for_inject 时发现角色不存在并自愈切回休息模式。
                affected_users: list[str] = []
                
                # 删除公开角色
                store.public.pop(persona_name, None)
                
                # 从拥有者的角色列表中删除（如果还存在旧数据）
                owner_bucket = store.users.get(owner_user_id)
                if owner_bucket and persona_name in owner_bucket.personas:
                    del owner_bucket.personas[persona_name]
                
            else:  # UNPUBLISH
                # 撤下逻辑
                pub = store.public.get(persona_name)
                if not pub:
                    store.pending_deletions.pop(deletion_id, None)
                    await self._repo.save(store)
                    return False, "该公开角色不存在。", persona_name, deletion_type, [], None, reason
                
                owner_user_id = pub.owner_user_id
                # 同上：不在此处批量切回空人设，交由运行时自愈逻辑处理。
                affected_users: list[str] = []
                
                # 从公开库中移除
                store.public.pop(persona_name, None)
                
                # 将角色恢复到拥有者的私密库
                owner_bucket = store.ensure_user(owner_user_id)

                # 若私密库已存在同名角色，则为“下架后恢复”的角色加 4 位随机 ID 后缀避免覆盖。
                if persona_name in owner_bucket.personas:
                    digits = "0123456789"
                    for _ in range(100):
                        suffix = "".join(secrets.choice(digits) for _ in range(4))
                        candidate = f"{persona_name}{suffix}"
                        if candidate not in owner_bucket.personas:
                            final_persona_name = candidate
                            break
                    else:
                        # 极端情况下仍冲突：退化为 uuid 末尾 4 位
                        final_persona_name = f"{persona_name}{uuid.uuid4().hex[-4:]}"

                owner_bucket.personas[final_persona_name] = UserPersona(
                    intro=pub.intro,
                    content=pub.content,
                    visibility=Visibility.PRIVATE,
                    use_wrapper=pub.use_wrapper,
                    owner_name=pub.owner_name,
                    updated_at=self._now_ts(),
                    tags=pub.tags,
                    pending_request_id=None,
                )
                # 不再自动修改拥有者 current；由用户自行切换/或在后续读取时按现有自愈逻辑处理。
            
            # 移除删除请求
            store.pending_deletions.pop(deletion_id, None)
            await self._repo.save(store)
            
            return True, "删除操作已完成。", final_persona_name, deletion_type, affected_users, owner_user_id, reason
