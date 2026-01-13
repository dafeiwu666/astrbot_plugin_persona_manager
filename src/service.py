from __future__ import annotations

import asyncio
from collections.abc import Callable

from .models import (
    CurrentSelection,
    EMPTY_PERSONA_NAME,
    PersonaResolutionResult,
    ResolvedPersona,
    Scope,
    Store,
    UserPersona,
    Visibility,
)
from .repository import StoreRepository


class PersonaService:
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

        p = bucket.personas.get(name)
        # 如果人设不存在或内容为空，自动切换到空人设
        if not p or not p.content.strip():
            # 人设已被删除，需要切换回空人设并提醒
            if not p:
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

    async def list_lines(self, *, user_id: str):
        store = await self._repo.load()
        bucket = store.ensure_user(user_id)

        personas: list[tuple[str, UserPersona]] = [(name, p) for name, p in bucket.personas.items()]
        return {"personas": personas}

    async def search_by_tags(self, *, user_id: str, search_tags: list[str]):
        """根据tags搜索人设。
        
        Args:
            user_id: 用户ID
            search_tags: 要搜索的tag列表
        
        Returns:
            包含匹配人设的字典，格式与list_lines相同
        """
        store = await self._repo.load()
        bucket = store.ensure_user(user_id)
        
        normal_tags_lower = [t.lower() for t in search_tags]

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

            if name not in bucket.personas:
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
            
            # 更新内容
            persona.intro = intro
            persona.content = content
            persona.use_wrapper = use_wrapper
            persona.updated_at = self._now_ts()
            if tags is not None:
                persona.tags = tags
            
            await self._repo.save(store)
            return True
