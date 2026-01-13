## 📖 简介

本插件为 AstrBot 提供“角色注入 / 人设管理”能力：你可以创建多个角色设定，并在对话时一键切换；插件会在 LLM 请求前把当前角色内容注入到 system prompt，从而让主 AI 以指定人设进行回复。

同时支持：
- **会话式创建/修改角色**（引导式输入简介、标签、设定内容）
- **群聊/私聊分别维护当前角色**（同一用户在不同群可使用不同角色）
- **关键词触发临时人设**（匹配关键词后仅注入对应提示词，不注入当前角色与前后缀）
- **CozyNook 社区角色小屋**（浏览帖子、导入为本地角色、导出附件；也可在网页端上传/发布人设并分享给大家）
- **可选：统一外部 persona、自动重置聊天记录、昵称/群名片同步**

## ✨ 特性

- **🧩 角色管理**：创建、查看、列表、标签搜索、切换、删除、修改设定
- **🧷 注入包装器**：可为角色内容套用统一的前置/后置提示词（`default_prefix` / `default_suffix`）
- **🧠 LLM Hook 注入**：在 `on_llm_request` 阶段追加到 `system_prompt`，避免覆盖其它插件/系统预设
- **🧯 安全防循环**：忽略机器人自身消息与空回流事件，避免会话状态机自触发
- **🧾 每日次数限制**：支持群聊/私聊按日限额（可按白名单放行）
- **🏠 CozyNook 角色小屋**：支持 `ula-xxxxxxxxxxxxxxxx`（16位）密码获取/导入/导出

## 📦 安装

1. 确保你已经安装了 [AstrBot](https://github.com/Soulter/AstrBot)。
2. 将本插件文件夹放入 AstrBot 的 `data/plugins/` 目录下。
3. （可选）安装 Pillow：当使用 CozyNook“帖子预览图”渲染能力时需要。
   ```bash
   pip install pillow
   ```
4. 重启 AstrBot。

## 🔧 配置

配置项见插件自带 schema（`_conf_schema.json`）。常用项如下：

| 配置项 | 说明 | 备注 |
| :--- | :--- | :--- |
| `enabled` | 是否启用插件 | |
| `whitelist_user_ids` | 私聊白名单用户 | 为空表示不限制（所有用户允许/无限制） |
| `whitelist_group_ids` | 群聊白名单 | 为空表示不限制（所有群允许/无限制） |
| `private_llm_limit` | 私聊每日次数限制 | `-1` 不限制，`0` 禁用 |
| `group_llm_limit` | 群聊每日次数限制 | `-1` 不限制，`0` 禁用 |
| `default_prefix` / `default_suffix` | 角色注入前后缀 | 仅当角色启用包装器时生效 |
| `session_timeout_sec` | 会话式创建/编辑超时（秒） | |
| `external_persona_id` | 统一外部角色 ID | 配置后可实现“对话内外部 persona 统一” |
| `auto_reset_on_switch` | 切换角色时自动重置聊天记录 | |
| `sync_nickname_on_switch` | 切换角色时同步昵称/群名片 | 仅部分平台支持（如 aiocqhttp） |
| `nickname_sync_mode` / `nickname_template` | 昵称同步模式与模板 | 支持 `{persona_name}` 占位符 |
| `keyword_persona_triggers` | 关键词触发规则 | 每行一条：`关键词:提示词`；`~关键词` 为包含匹配 |
| `cozynook_sid_cookie` | Cozyverse 登录态 Cookie | 用于拉取需要鉴权的内容 |
| `cozynook_comments_take` | 拉取最新评论条数 | `0-50`，`0` 表示不拉取 |

## 💻 指令列表

### 🧑‍🎤 基础角色管理

| 指令 | 说明 |
| :--- | :--- |
| `/创建角色 名称` | 会话式创建角色（按提示输入简介/标签/设定内容） |
| `/角色列表` | 列出你的所有角色（合并转发） |
| `/查找角色` | 按标签搜索角色（会话式输入标签） |
| `/查看角色 名称` | 查看角色详情（含标签与简介） |
| `/切换角色 名称` | 切换当前会话（群/私聊维度）的角色 |
| `/休息模式` | 清空当前会话角色（不注入任何角色） |
| `/当前角色` | 查看当前会话正在使用的角色 |
| `/修改设定 角色名` | 会话式修改简介/标签/设定内容 |
| `/删除角色 名称` | 删除角色 |

### 🏠 CozyNook 角色小屋

CozyNook 是一个偏“社区分享”的角色小屋：你可以在网页端发布/上传人设，生成 `ula-xxxxxxxxxxxxxxxx`（16位）密码；群友通过本插件输入 ULA 即可一键拉取并导入。

| 指令 | 说明 |
| :--- | :--- |
| `/角色小屋` | 打开默认市场帖（只允许导出） |
| `/获取角色 ula-xxxxxxxxxxxxxxxx` | 获取指定帖子内容（可选择导入或导出） |
| `/导入角色 ula-xxxxxxxxxxxxxxxx` | 直接导入为本地角色（导入后会切回休息模式） |
| `/导出角色 ula-xxxxxxxxxxxxxxxx` | 直接进入导出流程（选择附件序号下载） |

## 📌 行为说明

插件在 LLM 注入、关键词触发、额度统计、外部 persona 一致性保护等方面有明确行为约定，详见 [BEHAVIOR.md](BEHAVIOR.md)。

## 🗂️ 数据存储

- 角色与状态持久化存放在 AstrBot 数据目录下：`astrbot_plugin_persona_manager/store.json`
- CozyNook 导出/下载会使用缓存目录（会定期清理）
