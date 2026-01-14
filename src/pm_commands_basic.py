from __future__ import annotations

import re

from astrbot.api import logger
import astrbot.api.message_components as Comp
from astrbot.api.event import AstrMessageEvent
from astrbot.api.message_components import Plain
from astrbot.core.star.filter.command import GreedyStr
from astrbot.core.utils.session_waiter import SessionController, session_waiter

from .models import EMPTY_PERSONA_NAME
from .session_state import PersonaEditStage, PersonaEditState
from .text_utils import is_finish_edit_command, normalize_one_line, split_long_text, truncate_text


def _get_command_token(message_str: str) -> str:
    raw = (message_str or "").strip()
    if not raw:
        return ""
    if not (raw.startswith("/") or raw.startswith("／")):
        return ""
    s = raw.lstrip("/／").strip()
    if not s:
        return ""
    return s.split(maxsplit=1)[0].casefold()


def _is_allowed_session_command_token(token: str) -> bool:
    # 会话内允许的“短指令”，避免被识别为“其他命令”而中断会话。
    # 这里是保守集合：仅覆盖本插件交互式编辑里出现的指令。
    return token in {
        "跳过",
        "是",
        "否",
        "保持",
        "清空",
        "取消",
        "退出",
        "中断",
        # 英文/别名
        "y",
        "yes",
        "n",
        "no",
        "skip",
        "custom",
    }


def _build_grouped_persona_nodes(*, user_id: str, user_name: str, grouped: dict) -> list[Comp.Node]:
    nodes: list[Comp.Node] = []

    # 仅保留“人设” - 每个人设一个独立节点
    for name, p in grouped.get("personas", []) or grouped.get("private", []):
        intro = normalize_one_line(p.intro).strip()
        intro_display = truncate_text(intro, 30)
        tags_str = " ".join([f"[{tag}]" for tag in p.tags]) if p.tags else ""
        content = f"{tags_str}{name}" if tags_str else f"{name}"
        if intro_display:
            content += f"\n{intro_display}"
        nodes.append(
            Comp.Node(
                uin=user_id,
                name=user_name,
                content=[Plain(content)],
            ),
        )

    return nodes


async def add_persona(self, event: AstrMessageEvent, name: GreedyStr):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    # 强制要求命令必须带名称：/创建角色 名称
    # 不使用 GreedyStr 兜底，避免缺参时出现 "GreedyStr"/"None" 被当作有效名称。
    name = self._extract_command_tail(getattr(event, "message_str", "") or "", "创建角色").strip()
    if not name:
        yield event.plain_result("缺少角色名称，请使用：/创建角色 名称")
        return

    yield event.plain_result("请输入简介")

    timeout = int(self._cfg.session_timeout_sec)
    state: PersonaEditState = PersonaEditState(name=name, use_wrapper=True)
    initial_event = event
    initial_sender_id = str(event.get_sender_id())

    @session_waiter(timeout=timeout, record_history_chains=False)
    async def waiter(controller: SessionController, e: AstrMessageEvent):
        # 忽略机器人自身消息/空回流事件，避免自我触发导致循环提示。
        if self._is_self_message_event(e) or self._is_empty_echo_event(e):
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        nonlocal state

        # 只接受“发起会话的用户”的消息，避免群聊里他人/机器人消息推进状态机。
        if str(e.get_sender_id()) != initial_sender_id:
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        # 避免把触发命令的那条消息当作会话输入（不同版本里 event 可能不是同一对象）。
        if e is initial_event or self._looks_like_command_message(getattr(e, "message_str", "") or "", "创建角色"):
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        raw_text = (getattr(e, "message_str", "") or "").strip()
        token = _get_command_token(raw_text)

        # 允许用户通过发送其他命令“打断”当前会话：结束会话并放行事件给其他处理器。
        if token and (not _is_allowed_session_command_token(token)) and (not is_finish_edit_command(raw_text)):
            controller.stop()
            return

        # 显式退出：/取消 /退出
        if token in {"取消", "退出", "中断"}:
            e.stop_event()
            await e.send(e.plain_result("已退出角色创建流程。"))
            controller.stop()
            return

        # 阻止事件传播，避免触发其他处理器（如LLM回复）
        e.stop_event()

        text = (getattr(e, "message_str", "") or "").strip()

        if is_finish_edit_command(text):
            try:
                content = state.build_content()
                await self._svc.upsert_user_persona(
                    user_id=str(e.get_sender_id()),
                    user_name=str(e.get_sender_name()),
                    name=state.name,
                    intro=state.intro,
                    content=content,
                    use_wrapper=bool(state.use_wrapper),
                    wrapper_use_config=bool(state.wrapper_use_config),
                    wrapper_prefix=state.wrapper_prefix,
                    wrapper_suffix=state.wrapper_suffix,
                    clean_use_config=bool(state.clean_use_config),
                    clean_regex=state.clean_regex,
                    tags=state.tags,
                )
                await e.send(e.plain_result(f"已保存角色：{state.name}"))
            except ValueError as ve:
                # 捕获名称重复的错误
                await e.send(e.plain_result(str(ve)))
            except Exception as ex:
                logger.error(f"保存角色失败: {ex!s}")
                await e.send(e.plain_result("保存失败，已退出角色编辑。"))
            finally:
                controller.stop()
            return

        async def _ask_clean() -> None:
            await e.send(
                e.plain_result(
                    "是否使用已配置好的正则文本清洗表达式？\n"
                    "- /是：使用已配置\n"
                    "- /否：自定义填写\n"
                    "- /跳过：不使用\n"
                    "请输入：/是 /否 /跳过"
                )
            )

        async def _handle_intro() -> None:
            state.intro = text
            state.stage = PersonaEditStage.TAGS
            await e.send(e.plain_result("请输入标签（多个标签用空格分隔，如：大世界 纯爱），如果不需要标签请输入 /跳过"))
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_tags() -> None:
            t = text.lstrip("/／").strip()
            if t == "跳过":
                state.tags = []
            else:
                state.tags = [x.strip() for x in text.split() if x.strip()]
            state.stage = PersonaEditStage.WRAPPER
            await e.send(
                e.plain_result(
                    "是否使用已配置好的前后置提示词？\n"
                    "- /是：使用已配置\n"
                    "- /否：自定义填写\n"
                    "- /跳过：不使用\n"
                    "请输入：/是 /否 /跳过"
                )
            )
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_wrapper() -> None:
            t = text.lstrip("/／").strip().lower()
            if t in {"是", "y", "yes", "1", "开启", "开", "使用"}:
                state.use_wrapper = True
                state.wrapper_use_config = True
                state.stage = PersonaEditStage.CLEAN
                await _ask_clean()
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            if t in {"否", "n", "no", "0", "自定义", "custom"}:
                state.use_wrapper = True
                state.wrapper_use_config = False
                state.stage = PersonaEditStage.WRAPPER_PREFIX
                await e.send(e.plain_result("请输入前置提示词（输入 /跳过 表示留空）"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            if t in {"跳过", "skip"}:
                state.use_wrapper = False
                state.stage = PersonaEditStage.CLEAN
                await _ask_clean()
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            await e.send(e.plain_result("请输入：/是 /否 /跳过"))
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_wrapper_prefix() -> None:
            t = text.lstrip("/／").strip()
            state.wrapper_prefix = "" if t == "跳过" else (getattr(e, "message_str", "") or "").strip()
            state.stage = PersonaEditStage.WRAPPER_SUFFIX
            await e.send(e.plain_result("请输入后置提示词（输入 /跳过 表示留空）"))
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_wrapper_suffix() -> None:
            t = text.lstrip("/／").strip()
            state.wrapper_suffix = "" if t == "跳过" else (getattr(e, "message_str", "") or "").strip()
            state.stage = PersonaEditStage.CLEAN
            await _ask_clean()
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_clean() -> None:
            t = text.lstrip("/／").strip().lower()
            if t in {"是", "y", "yes", "1", "开启", "开", "使用"}:
                state.clean_use_config = True
                state.clean_regex = ""
                state.stage = PersonaEditStage.CONTENT
                await e.send(e.plain_result("请输入角色设定"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            if t in {"否", "n", "no", "0", "自定义", "custom"}:
                state.clean_use_config = False
                state.stage = PersonaEditStage.CLEAN_REGEX
                await e.send(
                    e.plain_result(
                        "请输入正则表达式（用于清洗注入的角色内容：re.sub(pattern, '', text)）。\n"
                        "输入 /跳过 表示不设置。"
                    )
                )
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            if t in {"跳过", "skip"}:
                state.clean_use_config = False
                state.clean_regex = ""
                state.stage = PersonaEditStage.CONTENT
                await e.send(e.plain_result("请输入角色设定"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            await e.send(e.plain_result("请输入：/是 /否 /跳过"))
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_clean_regex() -> None:
            t = text.lstrip("/／").strip()
            if t in {"跳过", "skip"}:
                state.clean_regex = ""
                state.stage = PersonaEditStage.CONTENT
                await e.send(e.plain_result("请输入角色设定"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return

            pattern = (getattr(e, "message_str", "") or "").strip()
            if not pattern:
                await e.send(e.plain_result("请输入正则表达式，或 /跳过。"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            try:
                re.compile(pattern)
            except Exception:
                await e.send(e.plain_result("正则表达式无效，请重新输入，或 /跳过。"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            state.clean_regex = pattern
            state.stage = PersonaEditStage.CONTENT
            await e.send(e.plain_result("请输入角色设定"))
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_content() -> None:
            if not text:
                await e.send(e.plain_result("请输入角色设定"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            state.add_part(text)
            state.stage = PersonaEditStage.CONTINUE
            await e.send(e.plain_result("是否继续，继续则输入内容，结束输入/结束角色编辑"))
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_continue() -> None:
            state.add_part(text)
            await e.send(e.plain_result("是否继续，继续则输入内容，结束输入/结束角色编辑"))
            controller.keep(timeout=timeout, reset_timeout=True)

        stage_handlers = {
            PersonaEditStage.INTRO: _handle_intro,
            PersonaEditStage.TAGS: _handle_tags,
            PersonaEditStage.WRAPPER: _handle_wrapper,
            PersonaEditStage.WRAPPER_PREFIX: _handle_wrapper_prefix,
            PersonaEditStage.WRAPPER_SUFFIX: _handle_wrapper_suffix,
            PersonaEditStage.CLEAN: _handle_clean,
            PersonaEditStage.CLEAN_REGEX: _handle_clean_regex,
            PersonaEditStage.CONTENT: _handle_content,
            PersonaEditStage.CONTINUE: _handle_continue,
        }

        handler = stage_handlers.get(state.stage, _handle_continue)
        await handler()

    try:
        await waiter(event)
    except TimeoutError:
        yield event.plain_result("会话超时，已退出角色创建。")
    finally:
        event.stop_event()


async def list_personas(self, event: AstrMessageEvent):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    user_id = str(event.get_sender_id())
    user_name = str(event.get_sender_name())

    grouped = await self._svc.list_lines(user_id=user_id)

    nodes = _build_grouped_persona_nodes(user_id=user_id, user_name=user_name, grouped=grouped)

    if not nodes:
        yield event.plain_result("暂无角色。")
        return

    yield event.chain_result([Comp.Nodes(nodes)])


async def search_personas(self, event: AstrMessageEvent):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    yield event.plain_result(
        "请输入要搜索的标签（多个标签用空格分隔）\n"
        "示例：\n"
        "  大世界 纯爱 - 搜索所有带这两个标签的角色\n"
        "  纯爱 - 搜索带\"纯爱\"标签的角色"
    )

    timeout = int(self._cfg.session_timeout_sec)

    @session_waiter(timeout=timeout, record_history_chains=False)
    async def waiter(controller: SessionController, e: AstrMessageEvent):
        # 阻止事件传播，避免触发其他处理器（如LLM回复）
        e.stop_event()

        # 忽略机器人自身消息/空回流事件，避免会话自我触发。
        if self._is_self_message_event(e) or self._is_empty_echo_event(e):
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        text = (getattr(e, "message_str", "") or "").strip()

        if not text:
            await e.send(e.plain_result("标签不能为空，请重新输入"))
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        # 解析标签（用空格分隔）
        search_tags = [t.strip() for t in text.split() if t.strip()]

        user_id = str(e.get_sender_id())
        user_name = str(e.get_sender_name())

        grouped = await self._svc.search_by_tags(user_id=user_id, search_tags=search_tags)

        nodes = _build_grouped_persona_nodes(user_id=user_id, user_name=user_name, grouped=grouped)

        if not nodes:
            tags_display = "、".join(search_tags)
            await e.send(e.plain_result(f"未找到匹配标签「{tags_display}」的角色。"))
        else:
            await e.send(e.chain_result([Comp.Nodes(nodes)]))

        controller.stop()

    try:
        await waiter(event)
    except TimeoutError:
        yield event.plain_result("会话超时，已退出查找。")
    finally:
        event.stop_event()


async def switch_persona(self, event: AstrMessageEvent, name: GreedyStr):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    name = str(name).strip()
    if not name:
        yield event.plain_result("用法：/切换角色 名称\n或使用：/休息模式 来清除角色")
        return

    user_id = str(event.get_sender_id())
    group_id = self._resolve_group_key(event)

    scope = await self._svc.switch_persona_for_context(
        user_id=user_id,
        group_id=group_id,
        name=name,
    )
    if scope is not None:
        # 切换成功后，同步切换外部人设（统一切换到配置的外部人设）
        # 但在“空人设”时不强制切外部人设，避免覆盖其他插件/用户的外部人设选择。
        if name != EMPTY_PERSONA_NAME:
            await self._switch_external_persona(event)

        # 如果配置启用，自动重置聊天记录
        await self._reset_conversation_if_enabled(event)

        # 同步昵称/群名片
        external_persona_name = None
        if name == EMPTY_PERSONA_NAME:
            external_persona_name = await self._get_current_external_persona_display_name(event)

        await self._nickname_sync.maybe_sync_nickname(
            event,
            persona_name=name,
            external_persona_name=external_persona_name,
            force=True,
        )

        if name == EMPTY_PERSONA_NAME:
            yield event.plain_result("已进入休息模式（不使用任何角色）")
        else:
            yield event.plain_result(f"已切换角色：{name}")
        return

    yield event.plain_result("未找到该角色（仅支持自己的角色）。")


async def switch_to_empty_persona(self, event: AstrMessageEvent):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    user_id = str(event.get_sender_id())
    group_id = self._resolve_group_key(event)

    await self._svc.switch_persona_for_context(
        user_id=user_id,
        group_id=group_id,
        name=EMPTY_PERSONA_NAME,
    )

    # 如果配置启用，自动重置聊天记录
    await self._reset_conversation_if_enabled(event)

    # 同步昵称/群名片
    external_persona_name = await self._get_current_external_persona_display_name(event)

    await self._nickname_sync.maybe_sync_nickname(
        event,
        persona_name=EMPTY_PERSONA_NAME,
        external_persona_name=external_persona_name,
        force=True,
    )

    yield event.plain_result("已进入休息模式（不使用任何角色）")


async def current_persona(self, event: AstrMessageEvent):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    user_id = str(event.get_sender_id())
    group_id = self._resolve_group_key(event)

    cur = await self._svc.get_current_for_context(
        user_id=user_id,
        group_id=group_id,
    )
    if not cur:
        yield event.plain_result("当前未切换任何角色（休息模式）。")
        return

    _scope, name = cur

    # 如果是空人设，显示特殊提示
    if name == EMPTY_PERSONA_NAME:
        yield event.plain_result("当前角色：休息模式（未使用任何角色）")
        return

    yield event.plain_result(f"当前角色：{name}")


async def view_persona(self, event: AstrMessageEvent, name: GreedyStr):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    name = str(name).strip()
    if not name:
        yield event.plain_result("用法：/查看角色 名称")
        return

    user_id = str(event.get_sender_id())

    persona = await self._svc.get_user_persona(user_id=user_id, name=name)

    if not persona:
        yield event.plain_result("未找到该角色（仅支持查看自己的角色）。")
        return

    # 构建人设信息：人设类型、名称、标签、完整简介
    tags_str = "、".join(persona.tags) if persona.tags else "无"
    user_name = str(event.get_sender_name())

    base_info = (f"【角色】{name}\n" f"标签: {tags_str}")

    # 简介分段处理
    intro_parts = split_long_text(persona.intro, max_chars=3000)

    # 使用转发消息（合并聊天记录）发送
    nodes = []

    # 第一个节点：基础信息
    nodes.append(
        Comp.Node(
            uin=user_id,
            name=user_name,
            content=[Plain(base_info)],
        )
    )

    # 添加简介节点
    for i, part in enumerate(intro_parts, 1):
        if len(intro_parts) > 1:
            intro_text = f"简介 (第{i}/{len(intro_parts)}部分):\n{part}"
        else:
            intro_text = f"简介:\n{part}"

        nodes.append(
            Comp.Node(
                uin=user_id,
                name=user_name,
                content=[Plain(intro_text)],
            )
        )

    yield event.chain_result([Comp.Nodes(nodes)])


async def delete_persona(self, event: AstrMessageEvent, name: GreedyStr):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    name = str(name).strip()
    if not name:
        yield event.plain_result("用法：/删除角色 名称")
        return

    user_id = str(event.get_sender_id())

    ok, message = await self._svc.delete_user_persona(user_id=user_id, name=name)
    if not ok:
        yield event.plain_result(message)
        return

    # 删除成功后，检查是否切换到了空人设（即删除的是当前人设）
    # 如果是，且配置启用，自动重置聊天记录
    cur = await self._svc.get_current(user_id)
    if cur and cur[1] == EMPTY_PERSONA_NAME:
        await self._reset_conversation_if_enabled(event)

    yield event.plain_result(f"已删除角色：{name}")


async def edit_persona(self, event: AstrMessageEvent, name: GreedyStr):
    err = self._require_access(event)
    if err:
        yield event.plain_result(err)
        return

    name = str(name).strip()
    if not name:
        yield event.plain_result("用法：/修改设定 角色名")
        return

    user_id = str(event.get_sender_id())

    # 检查人设是否存在且可编辑
    can_edit, reason = await self._svc.can_edit_persona(user_id=user_id, name=name)
    if not can_edit:
        yield event.plain_result(f"无法修改该设定：{reason}")
        return

    # 获取现有人设信息
    persona = await self._svc.get_user_persona(user_id=user_id, name=name)
    if not persona:
        yield event.plain_result("角色不存在。")
        return

    intro_display = truncate_text(persona.intro, 30)
    yield event.plain_result(
        f"开始修改设定：{name}\n"
        f"当前简介：{intro_display}\n"
        "请输入新的简介（直接输入覆盖，输入 /保持 则不修改）"
    )

    timeout = int(self._cfg.session_timeout_sec)
    state = PersonaEditState(
        name=name,
        intro=persona.intro,
        use_wrapper=persona.use_wrapper,
        tags=persona.tags.copy() if persona.tags else [],
    )
    initial_event = event
    initial_sender_id = str(event.get_sender_id())
    # 将现有内容设为初始部分
    if persona.content:
        state.parts = [persona.content]

    @session_waiter(timeout=timeout, record_history_chains=False)
    async def waiter(controller: SessionController, e: AstrMessageEvent):
        # 忽略机器人自身消息/空回流事件，避免自我触发导致循环提示。
        if self._is_self_message_event(e) or self._is_empty_echo_event(e):
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        # 只接受发起者消息，避免群聊里他人/机器人消息推进编辑流程。
        if str(e.get_sender_id()) != initial_sender_id:
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        # 同上：避免把触发命令的那条消息当作会话输入。
        if e is initial_event or self._looks_like_command_message(getattr(e, "message_str", "") or "", "修改设定"):
            controller.keep(timeout=timeout, reset_timeout=True)
            return

        raw_text = (getattr(e, "message_str", "") or "").strip()
        token = _get_command_token(raw_text)

        # 允许用户通过发送其他命令“打断”当前会话：结束会话并放行事件给其他处理器。
        if token and (not _is_allowed_session_command_token(token)) and (not is_finish_edit_command(raw_text)):
            controller.stop()
            return

        # 显式退出：/取消 /退出
        if token in {"取消", "退出", "中断"}:
            e.stop_event()
            await e.send(e.plain_result("已退出设定修改流程。"))
            controller.stop()
            return

        # 阻止事件传播，避免触发其他处理器（如LLM回复）
        e.stop_event()

        text = (getattr(e, "message_str", "") or "").strip()
        text_cmd = text.lstrip("/／").strip()

        if is_finish_edit_command(text):
            try:
                content = state.build_content()
                success = await self._svc.update_user_persona_content(
                    user_id=str(e.get_sender_id()),
                    name=state.name,
                    intro=state.intro,
                    content=content,
                    use_wrapper=bool(state.use_wrapper),
                    tags=state.tags,
                )
                if success:
                    await e.send(e.plain_result(f"已更新设定：{state.name}"))
                else:
                    await e.send(e.plain_result("更新失败，角色可能已被删除。"))
            except Exception as ex:
                logger.error(f"更新角色失败: {ex!s}")
                await e.send(e.plain_result("更新失败，已退出设定修改。"))
            finally:
                controller.stop()
            return

        async def _handle_intro() -> None:
            if text_cmd == "保持":
                pass
            else:
                state.intro = text
            state.stage = PersonaEditStage.TAGS
            current_tags = " ".join(state.tags) if state.tags else "无"
            await e.send(
                e.plain_result(
                    f"当前标签：{current_tags}\n"
                    "请输入新的标签（多个标签用空格分隔），输入 /保持 则不修改，输入 /清空 则清空所有标签"
                )
            )
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_tags() -> None:
            if text_cmd == "保持":
                pass
            elif text_cmd == "清空":
                state.tags = []
            else:
                state.tags = [t.strip() for t in text.split() if t.strip()]
            state.stage = PersonaEditStage.WRAPPER
            current = "是" if bool(state.use_wrapper) else "否"
            await e.send(
                e.plain_result(
                    f"当前是否使用前后置破限提示词：{current}\n"
                    "是否使用已编辑好的前后置破限提示词？\n"
                    "- /是：使用\n"
                    "- /否：不使用\n"
                    "请输入：/是 或 /否（输入 /保持 则不修改）"
                )
            )
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_wrapper() -> None:
            t = text_cmd.lower()
            if t == "保持":
                pass
            elif t in {"是", "y", "yes", "1", "开启", "开", "使用"}:
                state.use_wrapper = True
            elif t in {"否", "n", "no", "0", "关闭", "关", "不使用"}:
                state.use_wrapper = False
            else:
                await e.send(e.plain_result("请输入：/是 或 /否（输入 /保持 则不修改）"))
                controller.keep(timeout=timeout, reset_timeout=True)
                return
            state.stage = PersonaEditStage.CONTENT
            current_content = "\n".join(state.parts) if state.parts else ""
            preview = current_content[:200] + ("..." if len(current_content) > 200 else "")
            await e.send(
                e.plain_result(
                    f"当前角色设定预览：\n{preview}\n\n"
                    "请输入新的角色设定（直接输入覆盖，输入 /保持 则不修改）"
                )
            )
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_content() -> None:
            if text_cmd == "保持":
                state.stage = PersonaEditStage.CONTINUE
                await e.send(
                    e.plain_result(
                        "内容保持不变。\n"
                        "是否继续编辑，继续则输入内容，结束输入 /结束角色编辑"
                    )
                )
            else:
                state.parts = []
                if text:
                    state.add_part(text)
                state.stage = PersonaEditStage.CONTINUE
                await e.send(e.plain_result("是否继续，继续则输入内容，结束输入 /结束角色编辑"))
            controller.keep(timeout=timeout, reset_timeout=True)

        async def _handle_continue() -> None:
            state.add_part(text)
            await e.send(e.plain_result("是否继续，继续则输入内容，结束输入 /结束角色编辑"))
            controller.keep(timeout=timeout, reset_timeout=True)

        stage_handlers = {
            PersonaEditStage.INTRO: _handle_intro,
            PersonaEditStage.TAGS: _handle_tags,
            PersonaEditStage.WRAPPER: _handle_wrapper,
            PersonaEditStage.CONTENT: _handle_content,
            PersonaEditStage.CONTINUE: _handle_continue,
        }

        handler = stage_handlers.get(state.stage, _handle_continue)
        await handler()

    try:
        await waiter(event)
    except TimeoutError:
        yield event.plain_result("会话超时，已退出设定修改。")
    finally:
        event.stop_event()
