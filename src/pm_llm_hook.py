from __future__ import annotations

import asyncio
import re

from astrbot.api.event import AstrMessageEvent
from astrbot.core.provider.entities import ProviderRequest

from .models import EMPTY_PERSONA_NAME


def _safe_delattr(obj: object, name: str) -> None:
    try:
        delattr(obj, name)
    except AttributeError:
        return


async def inject_persona(self, event: AstrMessageEvent, req: ProviderRequest):
    # 逻辑从 main.Main.inject_persona 原样抽取；Main 仍保留装饰器入口。
    if not self._enabled():
        return

    user_id = str(event.get_sender_id())

    group_id_str = self._resolve_group_key(event)

    # 外部角色一致性保护：
    # - 当内部不是休息模式时，默认意味着“我希望使用统一外部角色”
    # - 如果外部角色已被切走（不再是配置的统一外部ID），则自动切回休息模式，避免错配注入
    unified_external_id = self._cfg.external_persona_id.strip()
    if unified_external_id:
        current_external_id = await self._get_current_external_persona_id(event)
        if current_external_id and current_external_id != unified_external_id:
            # 关键：当前人设选择需按上下文判断
            # - 私聊：按 user_id
            # - 群聊：按 group_id
            cur = await self._svc.get_current_for_context(
                user_id=user_id, group_id=group_id_str
            )
            if cur and cur[1] != EMPTY_PERSONA_NAME:
                await self._svc.switch_persona_for_context(
                    user_id=user_id,
                    group_id=group_id_str,
                    name=EMPTY_PERSONA_NAME,
                )
                await self._force_reset_conversation(event)

                req.cancelled = True
                event.stop_event()
                await event.send(
                    event.plain_result(
                        "检测到外部角色已被切换（不再是小屋内人设），已自动切换为休息模式并重置聊天记录。"
                    )
                )
                return

            # 内部已是休息模式：不做矫正（避免打扰），但仍要继续执行额度限制。
            pass

    # 检查次数限制
    quota_already_counted = bool(getattr(event, "_pm_quota_counted", False))
    if quota_already_counted:
        _safe_delattr(event, "_pm_quota_counted")

    allowed, deny_msg = await self._check_and_maybe_increment_llm_usage(
        event,
        count=not quota_already_counted,
    )
    if not allowed:
        req.cancelled = True
        event.stop_event()  # 停止事件传播
        await event.send(event.plain_result(deny_msg or "今日额度已用完，明天再来吧~"))
        return

    # 关键词触发：仅注入“关键词人设提示词”，不注入前后缀与当前人设。
    kw_content = getattr(event, "_pm_keyword_persona_content", None)
    if isinstance(kw_content, str) and kw_content.strip():
        injected = kw_content
        if req.system_prompt and not req.system_prompt.endswith("\n"):
            req.system_prompt += "\n"
        req.system_prompt = (req.system_prompt or "") + injected

        # 清理一次性标记，避免影响后续请求
        _safe_delattr(event, "_pm_keyword_persona_content")
        _safe_delattr(event, "_pm_keyword_matched")
        return

    result = await self._svc.resolve_persona_for_inject_for_context(
        user_id=user_id, group_id=group_id_str
    )

    # 如果角色被删除，拦截LLM并提醒用户
    if result.was_deleted:
        req.cancelled = True
        event.stop_event()  # 停止事件传播

        # 如果配置启用，自动重置聊天记录（因为已自动切换到休息模式）
        await self._reset_conversation_if_enabled(event)

        await event.send(
            event.plain_result(
                f"检测到你当前使用的角色「{result.deleted_persona_name}」已被删除，已自动切换为休息模式。"
            )
        )
        return

    persona = result.persona
    if not persona or not persona.content.strip():
        return

    # 1) 先对“角色内容”做可选正则清洗（不清洗前后置提示词）
    base_text = persona.content
    clean_pattern = ""
    if bool(getattr(persona, "clean_use_config", False)):
        clean_pattern = (getattr(self._cfg, "default_clean_regex", "") or "").strip()
    else:
        clean_pattern = (getattr(persona, "clean_regex", "") or "").strip()

    if clean_pattern:
        try:
            base_text = await asyncio.to_thread(re.sub, clean_pattern, "", base_text)
        except Exception:
            # 正则错误不阻断注入，直接按原文注入
            base_text = persona.content

    # 2) 再根据“前后置提示词”配置进行包装
    injected = base_text
    if persona.use_wrapper:
        use_cfg_wrapper = bool(getattr(persona, "wrapper_use_config", True))
        if use_cfg_wrapper:
            prefix = self._cfg.default_prefix
            suffix = self._cfg.default_suffix
        else:
            prefix = getattr(persona, "wrapper_prefix", "") or ""
            suffix = getattr(persona, "wrapper_suffix", "") or ""
        injected = f"{prefix}{base_text}{suffix}"

    if not injected.strip():
        return

    # 追加到现有 system_prompt，避免覆盖其他插件/系统预设
    if req.system_prompt and not req.system_prompt.endswith("\n"):
        req.system_prompt += "\n"
    req.system_prompt = (req.system_prompt or "") + injected
