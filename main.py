from __future__ import annotations

import time
from sys import maxsize
from pathlib import Path

import astrbot.api.message_components as Comp
from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain, filter
from astrbot.api.message_components import Plain
from astrbot.api.star import Context, Star, StarTools
from astrbot.core.provider.entities import ProviderRequest
from astrbot.core.star.filter.command import GreedyStr
from astrbot.core.utils.session_waiter import SessionController, session_waiter

# 插件代码统一放在 src 子包内；这里使用明确的相对导入，避免加载器差异导致的 ImportError。
from .src.config import PersonaPluginConfig
from .src.llm_limiter import LLMLimiter, get_current_date_str
from .src.models import EMPTY_PERSONA_NAME
from .src.nickname_sync import NicknameSync
from .src.repository import StoreRepository
from .src.service import PersonaService
from .src.session_state import PersonaEditStage, PersonaEditState
from .src.text_utils import (
    is_finish_edit_command,
    normalize_one_line,
    truncate_text,
    split_long_text,
)
from .src import pm_commands_basic as _pm_commands_basic
from .src import pm_keyword_trigger as _pm_keyword_trigger
from .src import pm_llm_hook as _pm_llm_hook
from .src import pm_commands_cozynook as _pm_commands_cozynook


class Main(Star):
    """角色管理（会话添加/列表转发/注入前后缀 + CozyNook 角色小屋）"""

    def __init__(self, context: Context, config: dict | None = None):
        super().__init__(context)
        self._cfg = PersonaPluginConfig.from_raw(config)
        data_dir: Path = StarTools.get_data_dir("astrbot_plugin_persona_manager")
        self._repo = StoreRepository(data_dir / "store.json", logger=logger)
        self._svc = PersonaService(self._repo, now_ts=self._now_ts)
        self._limiter = LLMLimiter(now_date=get_current_date_str)
        self._nickname_sync = NicknameSync()
        self._nickname_sync.load_config(config)

        # 关键词触发规则缓存（按 raw 文本变化重建）
        self._kw_trigger_raw: str | None = None
        self._kw_triggers: list[tuple[str, str, str]] = []  # (mode, keyword, prompt)
        
        logger.info(
            f"Persona Manager 昵称同步配置：{self._nickname_sync.describe_settings()}"
        )

    def _now_ts(self) -> int:
        return int(time.time())

    @staticmethod
    def _remove_all_whitespace(s: str) -> str:
        # 去除所有空白字符（空格/制表/换行等）
        return "".join((s or "").split())

    def _get_keyword_persona_triggers(self) -> list[tuple[str, str, str]]:
        raw = self._cfg.keyword_persona_triggers or ""
        if raw == (self._kw_trigger_raw or ""):
            return self._kw_triggers

        triggers: list[tuple[str, str, str]] = []
        text = raw.replace("\r", "\n")
        for line in text.split("\n"):
            line = (line or "").strip()
            if not line:
                continue
            if ":" not in line:
                continue
            k, prompt = line.split(":", 1)
            k = (k or "").strip()
            prompt = (prompt or "").strip()
            if not k or not prompt:
                continue
            if k.startswith("~"):
                keyword = k[1:].strip()
                if not keyword:
                    continue
                triggers.append(("contains", keyword, prompt))
            else:
                triggers.append(("exact", k, prompt))

        self._kw_trigger_raw = raw
        self._kw_triggers = triggers
        return triggers

    def _match_keyword_persona(self, message_text: str) -> tuple[str, str] | None:
        """返回 (matched_keyword, prompt) 或 None。"""
        msg = message_text or ""
        if not msg:
            return None

        triggers = self._get_keyword_persona_triggers()
        if not triggers:
            return None

        msg_no_ws = self._remove_all_whitespace(msg)
        msg_ci = msg.casefold()

        for mode, keyword, prompt in triggers:
            if mode == "contains":
                if keyword.casefold() in msg_ci:
                    return keyword, prompt
            else:
                # 完全匹配：去除所有空白字符后匹配（大小写敏感）
                if msg_no_ws == self._remove_all_whitespace(keyword):
                    return keyword, prompt
        return None

    async def _check_and_maybe_increment_llm_usage(
        self,
        event: AstrMessageEvent,
        *,
        count: bool,
    ) -> tuple[bool, str | None]:
        """检查并（可选）增加 LLM 使用次数。

        统一封装群聊/私聊的额度逻辑，便于关键词触发与 on_llm_request 共用。

        Returns:
            (allowed, deny_message)
        """
        user_id = str(event.get_sender_id())
        group_id_str = self._resolve_group_key(event)

        if group_id_str is not None:
            # 群聊场景
            unlimited = self._is_group_whitelisted(event)
            limit = self._cfg.group_llm_limit
            if not unlimited:
                allowed, used, _remaining = await self._limiter.check_group_limit(
                    group_id=group_id_str,
                    limit=limit,
                )
                if not allowed:
                    return False, f"今日群聊AI回复次数已用完（{used}/{limit}），明天再来吧~"
                if count and limit >= 0:
                    await self._limiter.increment_group_usage(group_id=group_id_str)
            return True, None

        # 私聊场景
        if not self._cfg.is_user_unlimited(user_id):
            limit = self._cfg.private_llm_limit
            allowed, used, _remaining = await self._limiter.check_private_limit(
                user_id=user_id,
                limit=limit,
            )
            if not allowed:
                return False, f"今日私聊AI回复次数已用完（{used}/{limit}），明天再来吧~"
            if count and limit >= 0:
                await self._limiter.increment_private_usage(user_id=user_id)
        return True, None

    # -------------------------
    # keyword trigger
    # -------------------------

    @filter.event_message_type(filter.EventMessageType.ALL, priority=maxsize - 50)
    async def keyword_trigger_llm(self, event: AstrMessageEvent):
        """平台消息下发时：关键词触发临时人设并发起一次 LLM 请求。"""
        async for r in _pm_keyword_trigger.keyword_trigger_llm(self, event):
            yield r

    def _is_self_message_event(self, event: AstrMessageEvent) -> bool:
        """判断该消息是否由机器人自身发送。

        某些平台/适配器会把机器人发出的消息也回流为 AstrMessageEvent。
        如果不做过滤，基于 session_waiter 的交互式流程可能把 bot 的输出当成输入，导致循环提示。
        """
        try:
            sender_id = self._safe_str(event.get_sender_id())
            self_id = self._safe_str(event.get_self_id())
            return bool(sender_id and self_id and sender_id == self_id)
        except Exception:
            return False

    def _is_empty_echo_event(self, event: AstrMessageEvent) -> bool:
        """判断是否是“空内容回流事件”。

        在部分平台（或分段/转发等链路）中，bot 发送消息后可能触发一条 message_str 为空且消息链为空的事件。
        这种事件不代表真实用户输入，应直接忽略以避免会话状态机自我推进。
        """
        try:
            text = (getattr(event, "message_str", "") or "").strip()
            if text:
                return False
            msgs = []
            try:
                msgs = event.get_messages() or []
            except Exception:
                msgs = []
            return len(msgs) == 0
        except Exception:
            return False

    @staticmethod
    def _safe_str(v: object) -> str:
        try:
            return str(v).strip()
        except Exception:
            return ""

    @staticmethod
    def _extract_command_tail(message_str: str, command: str) -> str:
        s = (message_str or "").strip()
        if not s:
            return ""
        s2 = s.lstrip("/／").strip()
        if not s2.startswith(command):
            return ""
        tail = s2[len(command) :].strip()
        return tail

    @staticmethod
    def _looks_like_command_message(message_str: str, command: str) -> bool:
        raw = (message_str or "").strip()
        if not raw:
            return False
        if not (raw.startswith("/") or raw.startswith("／")):
            return False

        s = raw.lstrip("/／").strip()
        if not s.startswith(command):
            return False
        if len(s) == len(command):
            return True
        # 允许：/命令<空白>参数
        return s[len(command)].isspace()

    def _get_event_message_type_value(self, event: AstrMessageEvent) -> str:
        """尽量拿到 AstrBot 的 message_type.value（如 GroupMessage/FriendMessage）。"""
        # event.session.message_type.value（官方实现）
        session = getattr(event, "session", None)
        if session is not None:
            mt = getattr(session, "message_type", None)
            if mt is not None:
                value = getattr(mt, "value", None)
                if value is not None:
                    return self._safe_str(value)
                return self._safe_str(mt)

        # event.get_message_type()（部分版本暴露）
        get_mt = getattr(event, "get_message_type", None)
        if callable(get_mt):
            mt = get_mt()
            if mt is not None:
                value = getattr(mt, "value", None)
                if value is not None:
                    return self._safe_str(value)
                return self._safe_str(mt)

        # 最后回退：从 unified_msg_origin 解析（官方格式 platform_id:message_type:session_id）
        origin = self._safe_str(getattr(event, "unified_msg_origin", ""))
        if origin and ":" in origin:
            parts = origin.split(":", 2)
            if len(parts) >= 2:
                return (parts[1] or "").strip()

        return ""

    def _get_event_session_id(self, event: AstrMessageEvent) -> str:
        session = getattr(event, "session", None)
        if session is not None:
            sid = getattr(session, "session_id", None)
            if sid is not None:
                return self._safe_str(sid)
        get_sid = getattr(event, "get_session_id", None)
        if callable(get_sid):
            return self._safe_str(get_sid())

        # 最后回退：从 unified_msg_origin 解析（官方格式 platform_id:message_type:session_id）
        origin = self._safe_str(getattr(event, "unified_msg_origin", ""))
        if origin and ":" in origin:
            parts = origin.split(":", 2)
            if len(parts) >= 3:
                return (parts[2] or "").strip()
        return ""

    @staticmethod
    def _extract_group_id_from_session_id(session_id: str) -> str | None:
        """从 session_id 中尽量提取稳定的“群维度 ID”。

        许多适配器会用形如 `room%<id>` / `group%<id>` / `user%<id>` 的 session_id。
        群消息时通常可取最后一段作为群ID（即使 get_group_id() 拿不到）。
        """
        s = (session_id or "").strip()
        if not s:
            return None
        if "%" in s:
            tail = s.split("%")[-1].strip()
            if tail and tail.lower() != "unknown":
                return tail
        return None

    def _is_group_message(self, event: AstrMessageEvent) -> bool:
        # 优先使用 group_id 判断（官方 get_group_id: 非群返回空串）
        raw_group_id = getattr(event, "get_group_id", lambda: None)()
        group_id = self._safe_str(raw_group_id)
        if group_id and group_id != "0":
            return True

        # 回退：从 message_type.value 判断
        mt = self._get_event_message_type_value(event)
        return mt.lower().startswith("group")

    def _group_whitelist_keys(self, event: AstrMessageEvent) -> list[str]:
        """生成可能用于群白名单匹配的一组候选 key。

        AstrBot 官方 whitelist stage 同时支持：
        - 直接写 group_id（有些适配器可靠）
        - 写 unified_msg_origin（/sid 输出，官方明确可用于白名单）
        因适配器差异，这里同时提供多种候选，提升命中率。
        """
        keys: list[str] = []

        raw_group_id = getattr(event, "get_group_id", lambda: None)()
        group_id = self._safe_str(raw_group_id)
        if group_id and group_id != "0":
            keys.append(group_id)

        session_id = self._get_event_session_id(event)
        group_from_session = self._extract_group_id_from_session_id(session_id)
        if group_from_session:
            keys.append(group_from_session)

        origin = self._safe_str(getattr(event, "unified_msg_origin", ""))
        if origin:
            keys.append(origin)

        # 兼容之前插件内调试版本的 fallback key 格式
        platform = self._safe_str(getattr(event, "get_platform_id", lambda: "")()).lower()
        if origin and platform:
            keys.append(f"{platform}:origin:{origin}")

        out: list[str] = []
        seen: set[str] = set()
        for k in keys:
            k = (k or "").strip()
            if not k or k in seen:
                continue
            seen.add(k)
            out.append(k)
        return out

    def _is_group_whitelisted(self, event: AstrMessageEvent) -> bool:
        # 未配置群白名单：视为“全部白名单”。
        if not self._cfg.whitelist_group_ids:
            return True
        wl = set(str(x) for x in self._cfg.whitelist_group_ids)
        return any(k in wl for k in self._group_whitelist_keys(event))

    def _resolve_group_key(self, event: AstrMessageEvent) -> str | None:
        """解析群聊上下文的稳定 Key。

        目的：
        - 适配某些适配器在群聊里返回 0/"" 等“假值” group_id，导致群聊被误判成私聊。
        - 用统一的 key 驱动：白名单判定（群维度）与群聊额度限额。

        规则：
        - 若判定为群消息：
          - 能得到有效 group_id（非空且非 "0"）则直接使用。
          - 否则尽量从 session_id 中提取群ID（如 room%123 -> 123）。
          - 再不行则使用 unified_msg_origin（官方明确是稳定会话标识）。
        - 若判定为非群消息：返回 None。
        """
        raw_group_id = getattr(event, "get_group_id", lambda: None)()
        group_id = self._safe_str(raw_group_id)
        origin = self._safe_str(getattr(event, "unified_msg_origin", ""))
        session_id = self._get_event_session_id(event)

        if not self._is_group_message(event):
            return None

        if group_id and group_id != "0":
            return group_id

        group_from_session = self._extract_group_id_from_session_id(session_id)
        if group_from_session:
            return group_from_session

        if origin:
            return origin

        # 极端兜底：保证群消息不落到“私聊分支”
        fallback = session_id or "unknown_group"
        return fallback

    def _enabled(self) -> bool:
        return bool(self._cfg.enabled)

    def _is_whitelisted(self, event: AstrMessageEvent) -> bool:
        return self._cfg.is_whitelisted(str(event.get_sender_id()))

    def _require_access(self, event: AstrMessageEvent) -> str | None:
        if not self._enabled():
            return "插件未启用。"
        
        # 群聊场景：若配置了群白名单，则仅允许白名单群聊使用（白名单用户不应越权到群聊）。
        # 未配置群白名单：视为全部白名单。
        group_key = self._resolve_group_key(event)
        if group_key is not None:
            allowed = self._is_group_whitelisted(event)
            if allowed:
                return None
            return "此群聊不在白名单内，无法使用此功能。"
        
        # 私聊场景：检查用户白名单
        if not self._cfg.is_user_allowed(str(event.get_sender_id())):
            return "你不在白名单内，无法使用此功能。"
        return None

    async def _switch_external_persona(self, event: AstrMessageEvent) -> None:
        """切换对话内的外部角色（通过 AstrBot 的 persona 管理器）。
        
        无论切换到哪个插件内角色，都统一切换到配置的外部角色。
        
        Args:
            event: 消息事件
        """
        external_id = self._cfg.external_persona_id.strip()
        if not external_id:
            return
        
        try:
            # 获取外部 persona 以验证其存在
            await self.context.persona_manager.get_persona(external_id)
            
            # 切换当前对话的外部角色
            unified_msg_origin = event.unified_msg_origin
            cid = await self.context.conversation_manager.get_curr_conversation_id(
                unified_msg_origin
            )
            
            if cid:
                # 更新对话的 persona_id（仅限对话内切换）
                await self.context.conversation_manager.update_conversation(
                    unified_msg_origin=unified_msg_origin,
                    conversation_id=cid,
                    persona_id=external_id,
                    history=None,  # 保留历史记录
                )
                logger.info(f"已同步切换外部角色至：{external_id}")
        except ValueError:
            # 外部 persona 不存在
            logger.warning(f"外部角色切换失败：{external_id}（外部角色不存在）")
        except Exception as ex:
            logger.error(f"切换外部角色失败：{ex}")

    @staticmethod
    def _extract_external_persona_display_name(external_persona: object) -> str | None:
        """尽量从 AstrBot 的 persona 对象中提取可读名称。

        兼容不同版本/实现：优先使用 name/display_name/persona_name，
        如果只有 persona_id 这种稳定标识，则返回 None（避免把 ID 当作昵称显示）。
        """
        for attr in ("name", "display_name", "persona_name", "title"):
            value = getattr(external_persona, attr, None)
            if isinstance(value, str) and value.strip():
                return value.strip()

        persona_id = getattr(external_persona, "persona_id", None)
        if isinstance(persona_id, str) and persona_id.strip():
            return None
        return None

    async def _get_current_external_persona_display_name(
        self, event: AstrMessageEvent
    ) -> str | None:
        """从当前对话读取外部 persona，并提取可读名称。

        目标：在“空人设”状态下不强制覆盖外部 persona，
        但如果其他插件/用户已经切换了外部 persona，这里能读到并用于昵称同步。

        兼容策略：尽量调用 conversation_manager 的常见 getter；
        任意一步失败都返回 None（不影响主流程）。
        """
        try:
            unified_msg_origin = event.unified_msg_origin
            cid = await self.context.conversation_manager.get_curr_conversation_id(
                unified_msg_origin
            )
            if not cid:
                return None

            cm = self.context.conversation_manager
            convo = None

            if hasattr(cm, "get_conversation"):
                getter = getattr(cm, "get_conversation")
                try:
                    convo = await getter(unified_msg_origin, cid)
                except TypeError:
                    try:
                        convo = await getter(
                            unified_msg_origin=unified_msg_origin, conversation_id=cid
                        )
                    except Exception:
                        convo = None
                except Exception:
                    convo = None

            if convo is None and hasattr(cm, "get_conversation_by_id"):
                getter = getattr(cm, "get_conversation_by_id")
                try:
                    convo = await getter(cid)
                except TypeError:
                    try:
                        convo = await getter(conversation_id=cid)
                    except Exception:
                        convo = None
                except Exception:
                    convo = None

            if convo is None:
                return None

            if isinstance(convo, dict):
                persona_id = convo.get("persona_id")
            else:
                persona_id = getattr(convo, "persona_id", None)
            if not isinstance(persona_id, str) or not persona_id.strip():
                return None

            external_persona = await self.context.persona_manager.get_persona(
                persona_id.strip()
            )
            return self._extract_external_persona_display_name(external_persona)
        except Exception:
            return None

    async def _get_current_external_persona_id(self, event: AstrMessageEvent) -> str | None:
        """读取当前对话使用的外部 persona_id。

        用于检测“外部人设已被其他插件/用户切走”的情况。
        任意一步失败都返回 None。
        """
        try:
            unified_msg_origin = event.unified_msg_origin
            cid = await self.context.conversation_manager.get_curr_conversation_id(
                unified_msg_origin
            )
            if not cid:
                return None

            cm = self.context.conversation_manager
            convo = None

            if hasattr(cm, "get_conversation"):
                getter = getattr(cm, "get_conversation")
                try:
                    convo = await getter(unified_msg_origin, cid)
                except TypeError:
                    try:
                        convo = await getter(
                            unified_msg_origin=unified_msg_origin, conversation_id=cid
                        )
                    except Exception:
                        convo = None
                except Exception:
                    convo = None

            if convo is None and hasattr(cm, "get_conversation_by_id"):
                getter = getattr(cm, "get_conversation_by_id")
                try:
                    convo = await getter(cid)
                except TypeError:
                    try:
                        convo = await getter(conversation_id=cid)
                    except Exception:
                        convo = None
                except Exception:
                    convo = None

            if convo is None:
                return None

            if isinstance(convo, dict):
                persona_id = convo.get("persona_id")
            else:
                persona_id = getattr(convo, "persona_id", None)

            if not isinstance(persona_id, str):
                return None
            persona_id = persona_id.strip()
            return persona_id or None
        except Exception:
            return None

    async def _reset_conversation_if_enabled(self, event: AstrMessageEvent) -> None:
        """如果配置启用，重置当前对话的聊天记录。
        
        根据 AstrBot 的 reset 命令实现：
        - 调用 conversation_manager.update_conversation，将 history 设为空列表
        - 设置 _clean_ltm_session 标记来清理长期记忆会话
        
        Args:
            event: 消息事件
        """
        if not self._cfg.auto_reset_on_switch:
            return
        
        try:
            unified_msg_origin = event.unified_msg_origin
            cid = await self.context.conversation_manager.get_curr_conversation_id(
                unified_msg_origin
            )
            
            if not cid:
                logger.debug("无当前对话，跳过重置聊天记录")
                return
            
            # 重置对话历史为空列表（参考 AstrBot 的 reset 命令）
            await self.context.conversation_manager.update_conversation(
                unified_msg_origin,
                cid,
                [],  # 清空历史记录
            )
            
            # 设置标记以清理长期记忆会话（如果有）
            event.set_extra("_clean_ltm_session", True)
            
            logger.info(f"已自动重置聊天记录（对话ID: {cid}）")
        except Exception as ex:
            logger.error(f"自动重置聊天记录失败：{ex}")

    async def _force_reset_conversation(self, event: AstrMessageEvent) -> None:
        """强制重置当前对话聊天记录（不受配置开关影响）。"""
        try:
            unified_msg_origin = event.unified_msg_origin
            cid = await self.context.conversation_manager.get_curr_conversation_id(
                unified_msg_origin
            )
            if not cid:
                return

            await self.context.conversation_manager.update_conversation(
                unified_msg_origin,
                cid,
                [],
            )
            event.set_extra("_clean_ltm_session", True)
        except Exception as ex:
            logger.error(f"强制重置聊天记录失败：{ex}")

    async def _safe_send_message_by_id(
        self,
        message_type: str,
        target_id: str,
        chain: MessageChain,
        *,
        platforms: list[str],
    ) -> bool:
        """按候选平台依次尝试发送消息。

        解决某些环境下 platform_id 可能为适配器名（如 sula）但 StarTools 不支持的问题。
        """
        tried: set[str] = set()
        for p in platforms:
            p = (p or "").strip()
            if not p or p in tried:
                continue
            tried.add(p)
            try:
                await StarTools.send_message_by_id(
                    message_type,
                    str(target_id),
                    chain,
                    platform=p,
                )
                return True
            except ValueError as e:
                # 常见：不支持的平台
                logger.warning(f"发送消息失败（不支持的平台 {p}）：{e!s}")
                continue
            except Exception as e:
                logger.error(f"发送消息失败（platform={p}）：{e!s}")
                continue
        return False

    def _platform_candidates(self, *platforms: str) -> list[str]:
        """去重并清理平台候选列表（保持顺序）。"""
        out: list[str] = []
        seen: set[str] = set()
        for p in platforms:
            p = (p or "").strip()
            if not p or p in seen:
                continue
            seen.add(p)
            out.append(p)
        return out

    async def _send_plain(
        self,
        message_type: str,
        target_id: str,
        text: str,
        *,
        platforms: list[str],
    ) -> bool:
        return await self._safe_send_message_by_id(
            message_type,
            target_id,
            MessageChain([Plain(text)]),
            platforms=platforms,
        )

    # -------------------------
    # llm hook
    # -------------------------

    @filter.on_llm_request()
    async def inject_persona(self, event: AstrMessageEvent, req: ProviderRequest):
        """LLM 请求时：注入当前角色设定到 system prompt。"""
        await _pm_llm_hook.inject_persona(self, event, req)

    # -------------------------
    # commands
    # -------------------------

    @filter.command("创建角色")
    async def add_persona(self, event: AstrMessageEvent, 名称: GreedyStr):
        """平台消息下发时：创建角色（会话式引导输入简介/标签/设定）。"""
        async for r in _pm_commands_basic.add_persona(self, event, 名称):
            yield r

    @filter.command("角色列表")
    async def list_personas(self, event: AstrMessageEvent):
        """平台消息下发时：列出你的角色列表（合并转发）。"""
        async for r in _pm_commands_basic.list_personas(self, event):
            yield r

    @filter.command("角色小屋")
    async def cozynook_market(self, event: AstrMessageEvent):
        """平台消息下发时：打开 CozyNook 角色小屋市场帖（仅导出）。"""
        # CozyNook 市场页：只允许导出
        async for r in _pm_commands_cozynook.cozynook_get(self, event, "", allow_import=False):
            yield r

    @filter.command("获取角色")
    async def cozynook_get_role(self, event: AstrMessageEvent, 密码或ULA: GreedyStr = GreedyStr("")):
        """平台消息下发时：从 CozyNook 获取帖子（可导入或导出）。"""
        # 指定 ula-xxxx：允许导入或导出
        async for r in _pm_commands_cozynook.cozynook_get(self, event, 密码或ULA, allow_import=True):
            yield r

    @filter.command("导入角色")
    async def cozynook_import_role(self, event: AstrMessageEvent, 密码或ULA: GreedyStr):
        """平台消息下发时：从 CozyNook 导入为本地角色。"""
        # 显式导入命令：跳过“/导入 /导出”选择
        async for r in _pm_commands_cozynook.cozynook_get(
            self,
            event,
            密码或ULA,
            allow_import=True,
            mode="import",
        ):
            yield r

    @filter.command("导出角色")
    async def cozynook_export_role(self, event: AstrMessageEvent, 密码或ULA: GreedyStr):
        """平台消息下发时：从 CozyNook 导出附件/内容。"""
        # 显式导出命令：跳过“/导入 /导出”选择
        async for r in _pm_commands_cozynook.cozynook_get(
            self,
            event,
            密码或ULA,
            allow_import=True,
            mode="export",
        ):
            yield r

    @filter.command("查找角色")
    async def search_personas(self, event: AstrMessageEvent):
        """平台消息下发时：按标签查找角色（会话式输入标签）。"""
        async for r in _pm_commands_basic.search_personas(self, event):
            yield r

    @filter.command("切换角色")
    async def switch_persona(self, event: AstrMessageEvent, 名称: GreedyStr):
        """平台消息下发时：切换当前会话使用的角色。"""
        async for r in _pm_commands_basic.switch_persona(self, event, 名称):
            yield r

    @filter.command("休息模式")
    async def switch_to_empty_persona(self, event: AstrMessageEvent):
        """平台消息下发时：进入休息模式（不注入任何角色）。"""
        async for r in _pm_commands_basic.switch_to_empty_persona(self, event):
            yield r

    @filter.command("当前角色")
    async def current_persona(self, event: AstrMessageEvent):
        """平台消息下发时：查看当前会话正在使用的角色。"""
        async for r in _pm_commands_basic.current_persona(self, event):
            yield r

    @filter.command("查看角色")
    async def view_persona(self, event: AstrMessageEvent, 名称: GreedyStr):
        """平台消息下发时：查看指定角色详情。"""
        async for r in _pm_commands_basic.view_persona(self, event, 名称):
            yield r

    @filter.command("删除角色")
    async def delete_persona(self, event: AstrMessageEvent, 名称: GreedyStr):
        """平台消息下发时：删除指定角色。"""
        async for r in _pm_commands_basic.delete_persona(self, event, 名称):
            yield r

    @filter.command("修改设定")
    async def edit_persona(self, event: AstrMessageEvent, 名称: GreedyStr):
        """平台消息下发时：修改角色设定（会话式交互）。"""
        async for r in _pm_commands_basic.edit_persona(self, event, 名称):
            yield r

    # 审核/市场相关命令已移除：仅保留“人设”与 CozyNook 角色小屋能力。
