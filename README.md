# dsh-session-http

## 一句话简介

一个架在普通 DSH Session 之上的 JSON HTTP 网关：外部程序（脚本、聊天桥接、微信中转）通过 HTTP 就能列出工作区与会话、创建会话、投递一条用户消息并拿到回答——投递的消息会像在 Web UI 里亲手敲的一样，出现在会话对话里。

## 技术选型

| 项 | 选型 | 说明 |
|---|---|---|
| 语言 / 依赖 | 纯 JS，只 `import node:crypto` | 不依赖任何内部包，全部能力经 Cordis context 注入 |
| 插件形态 | Cordis 函数插件 | 导出 `name` / `inject` / `apply` |
| HTTP 载体 | 复用宿主 `webServer` | 用 `exact` / `prefix` 两种路由注册 |
| 会话管理 | `sessionController` | 创建 / 解析 Agent / 投递消息 |
| 工作区 | `workspaceRegistry` | 列表 / 按路径解析或创建 / 挂接会话 |
| 鉴权 | `X-Api-Key` 头 + 凭据引用 | 配置只存「环境变量名」，值每请求实时解析 |
| 密钥比对 | SHA256 + `timingSafeEqual` | 常数时间比较，防时序侧信道 |
| 消息投递 | `Agent.followup` | 投递一条人类 user 消息，等价 GUI 手敲 |

## 核心流程（动作清单）

### 阶段一：接入与鉴权（每个请求共用）

1. 拿到一个 HTTP 请求
2. 取出请求头里的 `X-Api-Key`
3. 用配置里的 `secretEnv`（凭据引用名，默认 `DSH_SESSION_HTTP_KEY`）从凭据服务实时解析出期望密钥——每请求解析一次，不缓存
4. 解析不到 → 回 `503`（凭据未配置 / 不可用），整个请求终止
5. 把「收到的 key」和「期望 key」各自算成 SHA256 摘要
6. 用 `timingSafeEqual` 常数时间比对两份摘要
7. 比对不等 → 回 `401`，请求终止
8. 比对通过 → 把请求交给对应路由，进入下面各阶段

### 阶段二：只读查询（列工作区 / 列会话 / 看详情）

GET `/workspaces`：

1. 从工作区注册表取出全部工作区
2. 逐个拼成 `{ workspaceId, path, title, sessionIds }` 列表
3. 回 `200`

GET `/sessions`：

1. 取出工作区索引：建一张「会话 id → 所属工作区」映射 + 一份「已归档会话」集合
2. 从会话控制器列出全部会话
3. 逐个拼上 title / displayTitle / cwd / running / blank / archived / workspaceId 等字段
4. 默认过滤掉「已归档」和「空白未提问」的会话；显式传 `?includeArchived=true` 或 `?includeBlank=true` 才保留
5. 回 `200`

GET `/sessions/{id}`：

1. 取出该会话的详情（走 inspect，不激活 Agent）
2. 标题若从列表投影里读不到，就退回 null（不因标题失败而整体失败）
3. 拼上 cwd / workspace / archived / attached / eventCount
4. 回 `200`；找不到 → 回 `404`

### 阶段三：创建 / 领养会话（POST /sessions）

1. 校验入参：`workspaceId` 与 `cwd` 只能给一个；`permissionPreset` 必须能解析；`approvalPolicy` 只能是 `ask`/`never`
2. 拼成创建请求（`sessionId` 可指定；`agentPreset` 用请求值，没给则用默认值）
3. 调用会话控制器创建会话
4. 若给了 `cwd`：按该路径加一把「按位置锁」，串行执行「按路径解析或创建工作区 → 挂接会话」，避免并发丢失记录
5. 应用权限姿态：写入 `permissionPreset`（若给）+ `approvalPolicy`（避免弹窗卡住无人值守的 API）
6. 没给 `text` → 回 `200`，会话保持空白态，流程结束
7. 给了 `text` → 无缝接续到「阶段四」的投递流程（一次调用完成「建会话 + 说第一句 + 拿回答」）

### 阶段四：投递消息并等回答（POST /sessions/{id}/messages 的 text 分支）

1. 解析出该会话的 Agent（解析不到 → 回 `404`）
2. 造一条人类 user 消息：生成新 id + role=user + source=user，深度冻结不可改
3. 先挂好「等回答」的监听，再投递消息（避免错过认领事件）
4. 用 `followup` 把消息投进会话（等价 GUI 手敲，会显示成真实用户回合）
5. 监听 `agent/inbox/claimed`：等这条消息被某个 turn 认领，记下 turn 号
6. 监听 `session/event`：`assistant/message` 逐段收集文本；`turn/end` 时收尾
7. 中途判定三种结局：
   - 超过 `turnTimeoutMs`（默认 10 分钟）→ 回 `504`，消息仍留在队列
   - 消息被丢弃 → 回 `409`
   - turn 结束 → 把结束原因转成 code/message，回 `200` 带上拼接好的回答文本
8. 若 turn 停在「审批 / 提问」上 → 进入「阶段五 / 阶段六」

### 阶段五：中继审批（approval/request）

1. 用 `prepend` 抢先监听 `approval/request`（抢在浏览器弹窗前）
2. 判断该会话是否被 HTTP 调用者持有（正在 driving 或已 parked）；不是 → `next()` 交回浏览器弹窗
3. 是 → 生成一个 `approvalId`，记进待处理交互表，设超时 `approvalTimeoutMs`（默认 2 分钟）
4. 唤醒正在等这个会话的调用者
5. turn 就地停车 → 回 `202`，body 里带 `reply`（同一 URL + 请求体模板），调用者照抄即可回答
6. 调用者回贴 `decision`（allow/deny）→ 结算该审批，继续推进 turn
7. 超时 / 取消 / 插件卸载 → 一律按 `rejected` 结算（fail-closed，绝不越权放行）

### 阶段六：中继提问（user-questions/request）

1. 用 `prepend` 抢先监听 `user-questions/request`
2. 生成一个 `questionId`，记进待处理交互表，设超时 `approvalTimeoutMs`
3. 回 `202`，body 里带 `questions` 与示例 `answers`
4. 调用者回贴 `answers` → 逐条校验（id 必须是被问到的、选项必须被提供过、单选不能多选、同一题不重复）
5. 校验通过 → 用结构化 `{ answers }` 结算，继续推进 turn
6. 超时 → 拒绝（不伪造一个「跳过」来冒充没发生的人类决定）

### 阶段七：回答交互并继续（answerInteraction）

1. 用 interactionId 查待处理交互表；查不到或会话不匹配 → 回 `404`
2. 先结算交互（审批给决定、提问给答案），工具调用立刻恢复
3. 若该会话有 parked 的 turn → 重新推进 turn（回到阶段四第 5 步继续等）
4. 没有 parked → 回 `200`（状态 `answered`）

## HTTP 端点 / 入参

| 方法 | 路径 | 用途 | 关键入参 |
|---|---|---|---|
| GET | `/workspaces` | 列出全部工作区 | 无 |
| GET | `/sessions` | 列出可见会话 | `?includeArchived=true`、`?includeBlank=true` |
| GET | `/sessions/{id}` | 单个会话详情 | 无（路径 id） |
| POST | `/sessions` | 创建 / 领养会话 | `workspaceId` 或 `cwd`、`sessionId`、`agentPreset`、`permissionPreset`、`approvalPolicy`、`text` |
| POST | `/sessions/{id}/messages` | 发消息 / 答审批 / 答提问 | `text`；或 `approvalId`+`decision`；或 `questionId`+`answers` |
| GET | `/interactions` | 全部待处理交互（审批 + 提问） | 无 |
| GET | `/approvals` | 仅待处理审批 | 无 |
| POST | `/approvals/{id}` | 单独判定一个审批 | `outcome` = `allow`/`deny` |

## 配置项

| 配置项 | 默认值 | 含义 |
|---|---|---|
| `secretEnv` | `DSH_SESSION_HTTP_KEY` | 凭据引用名（环境变量名），每请求解析 |
| `maxBodyBytes` | 1048576（1MB） | 请求体大小上限，超出回 `413` |
| `turnTimeoutMs` | 600000（10 分钟） | 等一次 turn 完成的超时 |
| `approvalTimeoutMs` | 120000（2 分钟） | 一个审批 / 提问等待决策的超时 |
| `approvalPolicy` | 见下 | 网关创建会话用的审批策略 |
| `relayApprovals` | `true` | 是否把审批 / 提问中继给 HTTP 调用者 |
| `permissionPreset` | 无 | 网关创建会话时套用的权限预设 |
| `defaultAgentPreset` | 无 | 默认 Agent 预设 |
| `turnErrorText` | `Agent turn did not complete.` | turn 非正常结束且无文本时的兜底文案 |

> `approvalPolicy` 的默认值：`relayApprovals` 开启且未显式配置时取 `ask`（好让中继能拦截到审批），否则取 `never`。`never` 不是「放行」，而是「从不询问、直接判 `rejected` 且不派发 answerer」——沙箱仍保留，一次性提权请求被确定性拒绝，Agent 会被告知并自行调整。

## 关键设计点

- **凭据引用而非明文**：配置只存环境变量名，值每请求实时解析——密钥轮换后下一次调用即生效，无需重启。
- **按 turn 而非按会话持有**：HTTP 调用者只在「正等这个 turn」时才算持有，不长期霸占会话，人在 GUI 里打字时仍能正常弹窗、不会被 API 悄悄超时。
- **一个端点三种动作**：发消息、答审批、答提问全走 `POST /sessions/{id}/messages`，`202` 响应里自带 `reply`（URL + body 模板），桥接端无需轮询、无需第二个通道。
- **审批 fail-closed**：超时、取消、插件卸载一律按 `rejected` 结算，绝不默认放行。
- **按位置锁**：对同一工作区 / 目录的并发「建会话 + 挂接」串行化，不同位置仍并行，避免 read-modify-write 丢记录。
- **会话落地优先于分组**：工作区挂接失败不影响会话已创建的事实，仍回 `200` 报出 sessionId，不让调用者「拿到一个再也叫不回名字的孤儿会话」。
- **纯 builtins + 无默认导出**：只 `import node:crypto`，以 `@local/*` 方式装进 DSH profile；不用 `export default`，以免覆盖 `name`/`inject` 兄弟导出导致 apply 拿不到服务。
