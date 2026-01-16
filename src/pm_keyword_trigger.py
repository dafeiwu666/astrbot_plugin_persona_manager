from __future__ import annotations

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent


async def keyword_trigger_llm(self, event: AstrMessageEvent):
    # 逻辑从 main.Main.keyword_trigger_llm 原样抽取；Main 仍保留装饰器入口。
    if not self._enabled():
        return

    # 忽略机器人自身消息/空回流事件，避免循环触发。
    if self._is_self_message_event(event) or self._is_empty_echo_event(event):
        return

    text_raw = (getattr(event, "message_str", "") or "").strip()
    if not text_raw:
        return

    # 允许以 /关键词 形式触发：用于匹配与 prompt 时去掉前导斜杠
    text = (
        text_raw.lstrip("/／").strip()
        if text_raw.startswith(("/", "／"))
        else text_raw
    )
    if not text:
        return

    matched = self._match_keyword_persona(text)
    if not matched:
        return

    matched_keyword, prompt = matched

    # 外部 persona 一致性拦截（仅对“关键词触发”生效）：
    # - 不发起 LLM
    # - 不计入额度
    unified_external_id = self._cfg.external_persona_id.strip()
    if unified_external_id:
        current_external_id = await self._get_current_external_persona_id(event)
        if current_external_id and current_external_id != unified_external_id:
            event.stop_event()
            await event.send(event.plain_result("检测到外部 persona 已被切换（不为配置的统一外部 persona），已拦截本次关键词触发。"))
            return

    # 记录触发日志
    logger.info(
        "关键词触发LLM：keyword=%s sender=%s group=%s",
        matched_keyword,
        str(event.get_sender_id()),
        str(getattr(event, "get_group_id", lambda: "")() or ""),
    )

    # 在 event 上挂载本次触发的“关键词人设提示词”，供 on_llm_request hook 覆盖注入
    setattr(event, "_pm_keyword_persona_content", prompt)
    setattr(event, "_pm_keyword_matched", matched_keyword)

    # 关键词触发也要纳入额度统计：在发起 LLM 前先做额度校验/计数。
    # 为避免 on_llm_request 再次计数，这里设置一次性标记。
    allowed, deny_msg = await self._check_and_maybe_increment_llm_usage(event, count=True)
    if not allowed:
        event.stop_event()
        await event.send(event.plain_result(deny_msg or "今日额度已用完，明天再来吧~"))
        return
    setattr(event, "_pm_quota_counted", True)

    # 尽量绑定到当前会话的 Conversation，确保读取/写入同一份聊天历史。
    conversation = None
    try:
        umo = str(getattr(event, "unified_msg_origin", "") or "").strip()
        conv_mgr = getattr(self.context, "conversation_manager", None)
        if conv_mgr and umo:
            cid = await conv_mgr.get_curr_conversation_id(umo)
            if cid:
                conversation = await conv_mgr.get_conversation(umo, cid)
            else:
                # 当前会话还没有对话：创建一个新的对话（仅首次会发生）
                new_cid = await conv_mgr.new_conversation(umo)
                conversation = await conv_mgr.get_conversation(umo, new_cid)
    except Exception:
        conversation = None

    # 发起一次 LLM 请求（使用当前会话的模型；若 conversation 可用则读写同一历史）
    yield event.request_llm(prompt=text, conversation=conversation)

    # request 已发起，清理一次性标记（兜底，正常会在 on_llm_request 中再清理一次）
    try:
        delattr(event, "_pm_quota_counted")
    except Exception:
        pass
