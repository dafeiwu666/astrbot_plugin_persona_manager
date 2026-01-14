from __future__ import annotations

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent

try:  # 可选依赖：仅在安装 aiocqhttp 适配器时可用
    from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
        AiocqhttpMessageEvent,
    )
except Exception:  # pragma: no cover
    AiocqhttpMessageEvent = None  # type: ignore

from .models import EMPTY_PERSONA_NAME


class NicknameSync:
    """QQ昵称/群名片同步管理器，参考 persona_plus 插件实现"""

    def __init__(self):
        self.enabled: bool = False
        self.nickname_sync_mode: str = "group_card"  # profile, group_card, hybrid
        self.nickname_template: str = "{persona_name}"
        self._last_synced_persona: dict[str, str] = {}  # bot_key -> persona_name

    def load_config(self, config: dict | None) -> None:
        """从配置中加载昵称同步设置"""
        if not config:
            self.enabled = False
            self.nickname_sync_mode = "group_card"
            self.nickname_template = "{persona_name}"
            return

        self.enabled = config.get("sync_nickname_on_switch", False)
        self.nickname_sync_mode = config.get("nickname_sync_mode", "group_card")
        if self.nickname_sync_mode not in {"profile", "group_card", "hybrid"}:
            logger.warning(
                f"Persona Manager 昵称同步模式 {self.nickname_sync_mode} 无效，将使用默认值 group_card"
            )
            self.nickname_sync_mode = "group_card"
        self.nickname_template = config.get("nickname_template", "{persona_name}")

    def describe_settings(self) -> str:
        """返回当前设置的描述"""
        return f"enabled={self.enabled}, mode={self.nickname_sync_mode}"

    def format_nickname(self, persona_name: str) -> str:
        """根据模板格式化昵称"""
        try:
            nickname = self.nickname_template.format(persona_name=persona_name)
        except Exception as exc:
            logger.warning(f"Persona Manager 昵称模板解析失败：{exc}，使用人设名")
            nickname = persona_name
        return nickname[:60] if nickname else persona_name[:60]

    async def maybe_sync_nickname(
        self,
        event: AstrMessageEvent,
        persona_name: str,
        external_persona_name: str | None = None,
        *,
        force: bool = False,
    ) -> None:
        """根据配置可能同步昵称或群名片（仅在切换时同步）
        
        Args:
            event: 消息事件
            persona_name: 插件内人设名称（可能是空字符串或 EMPTY_PERSONA_NAME）
            external_persona_name: 外部人设名称（当插件内人设为空时使用）
            force: 是否强制同步（忽略缓存）
        """
        # 平台无关：仅在事件对象暴露 bot 且 bot 具备对应能力时尝试。
        bot = getattr(event, "bot", None)
        if bot is None:
            return

        if not (self.enabled or force):
            return

        # 确定要显示的昵称
        display_name = persona_name
        if not persona_name or persona_name == EMPTY_PERSONA_NAME:
            # 插件内人设为空，使用外部人设名
            if external_persona_name:
                display_name = external_persona_name
            else:
                # 外部人设名也为空，不同步
                logger.debug("Persona Manager 插件内外人设均为空，跳过昵称同步")
                return

        # 检查是否需要同步（避免重复操作）
        # 只在切换时同步一次，通过缓存判断是否已同步过相同人设
        # 使用插件特定的前缀，避免与其他插件（如 persona_plus）的缓存冲突
        # 同时包含 group_id，避免不同群聊之间的缓存冲突
        group_id = event.get_group_id()
        bot_key = f"persona_manager:{event.get_platform_id()}:{event.get_self_id()}"
        if group_id:
            bot_key += f":{group_id}"
            
        if not force and self._last_synced_persona.get(bot_key) == display_name:
            logger.debug(f"Persona Manager 人设 {display_name} 已同步过，跳过 (Key: {bot_key})")
            return

        nickname = self.format_nickname(display_name)
        is_group = bool(event.get_group_id())

        nickname_applied = False

        # 根据模式选择同步方式
        if self.nickname_sync_mode == "profile":
            # profile 模式：修改 QQ 昵称（群聊和私聊都修改）
            nickname_applied = await self._sync_qq_profile(event, nickname)
        elif self.nickname_sync_mode == "group_card":
            # group_card 模式：只在群聊中修改群名片，私聊不修改
            if is_group:
                nickname_applied = await self._sync_group_card(event, nickname)
        elif self.nickname_sync_mode == "hybrid":
            # hybrid 模式：群聊修改群名片，私聊修改 QQ 昵称
            if is_group:
                nickname_applied = await self._sync_group_card(event, nickname)
            else:
                nickname_applied = await self._sync_qq_profile(event, nickname)

        # 只有在成功应用昵称后才更新缓存，避免下次重复尝试
        if nickname_applied:
            self._last_synced_persona[bot_key] = display_name
            logger.info(f"Persona Manager 已同步昵称为 {display_name}")

    async def _sync_qq_profile(
        self, event: AstrMessageEvent, nickname: str
    ) -> bool:
        """修改 QQ 昵称"""
        bot = getattr(event, "bot", None)
        if bot is None:
            return False

        if hasattr(bot, "set_qq_profile"):
            try:
                await bot.set_qq_profile(nickname=nickname)
                logger.debug(f"Persona Manager 已同步 QQ 昵称为 {nickname}")
                return True
            except Exception as exc:
                logger.error(f"Persona Manager 同步 QQ 昵称失败：{exc}")
        else:
            logger.warning(
                "Persona Manager 当前适配器未实现 set_qq_profile 接口，跳过 QQ 昵称同步。"
            )
        return False

    async def _sync_group_card(self, event: AstrMessageEvent, card: str) -> bool:
        """修改群名片"""
        group_id = event.get_group_id()
        if not group_id:
            return False

        user_id = event.get_self_id()
        bot = getattr(event, "bot", None)
        if bot is None:
            return False

        if hasattr(bot, "call_action"):
            try:
                await bot.call_action(
                    "set_group_card",
                    group_id=int(group_id),
                    user_id=int(user_id),
                    card=card,
                )
                logger.debug(f"Persona Manager 已同步群名片为 {card} (群 {group_id})")
                return True
            except Exception as exc:
                logger.error(f"Persona Manager 同步群名片失败：{exc}")
        else:
            logger.warning(
                "Persona Manager 当前适配器未实现 call_action 接口，跳过群名片同步。"
            )
        return False

    def clear_cache(self) -> None:
        """清除缓存"""
        self._last_synced_persona.clear()

    def reset_persona_cache(self, persona_name: str) -> None:
        """重置特定人设的缓存"""
        to_remove = [
            key
            for key, value in self._last_synced_persona.items()
            if value == persona_name
        ]
        for key in to_remove:
            self._last_synced_persona.pop(key, None)
