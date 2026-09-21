# Edge Authority DNS Zone Distribution Service

面向园区边缘解析节点的**纯后端权威 DNS 区分发服务**：

- 运维平台通过**版本化 HTTP JSON API**（`/v1/...`）发布区数据；
- 边缘节点通过**真实 DNS 协议**（UDP/TCP，53 端口语义）查询 SOA / A /
  AAAA / CNAME / TXT / MX / NS；
- 通过 **TCP + TSIG（RFC 2845 风格，HMAC-SHA256）** 发起 **AXFR / IXFR**；
- 两个可互换的服务实例共享一份持久化存储，另有独立的历史清理进程和一个
  一次性验收服务 `verify`。

整个项目只依赖 Python 3.11 **标准库**；克隆后只需 Docker 即可构建、启动与验收。

---

## 快速开始（仅需 Docker）

```bash
# 构建并启动两个 edge 实例 + 独立 cleaner
docker compose up --build -d

# 一次性验收（两个实例、真实 HTTP/UDP/TCP/TSIG 流量），退出码即结果
docker compose run --rm verify
#   或：构建后自动跑验收并在其结束时停止
docker compose up --build --abort-on-container-exit --exit-code-from verify

# 在容器内跑单元/集成测试
docker compose run --rm --entrypoint docker-entrypoint.sh edge-1 test
```

宿主机端口可用环境变量配置（compose 默认见文件）：

| 变量        | 含义                          | 默认 |
|-------------|-------------------------------|------|
| `API_PORT`  | edge-1 的 HTTP 管理 API 宿主端口 | 8080 |
| `DNS_PORT`  | edge-1 的 DNS TCP+UDP 宿主端口 | 5353 |
| `API_PORT_2`/`DNS_PORT_2` | edge-2 的宿主端口 | 8180 / 5454 |

健康检查：`GET /healthz`，同时检查 **HTTP 自身、持久化连接（SQLite）、UDP
DNS 监听、TCP DNS 监听**；任一项不就绪返回 503。

---

## HTTP 管理 API（v1）

所有请求/响应为 JSON；所有错误均返回**稳定机器码**：
`{"error":{"code":"...","message":"...","details":{...}}}`。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/v1/zones` | 创建区（含初始 SOA/NS、序列号、保留策略） |
| GET  | `/v1/zones` | 列出区元数据 |
| GET  | `/v1/zones/{zone}` | 读取当前区元数据（当前序列号/版本、计数、SOA、NS） |
| POST | `/v1/zones/{zone}/publish` | **原子发布变更集** |
| GET  | `/v1/zones/{zone}/requests/{requestId}` | 查询发布结果（持久化幂等账本） |
| PUT  | `/v1/zones/{zone}/retention` | 配置历史保留版本数 |
| POST | `/v1/zones/{zone}/keys` | 原子安装/轮换传送密钥（一次性返回 base64 密钥） |
| GET  | `/v1/zones/{zone}/keys` | 列出密钥（**绝不含密钥材料**） |
| POST | `/v1/zones/{zone}/keys/{keyId}/revoke` | 立即撤销密钥 |

### 发布请求

```json
{
  "requestId": "deploy-2026-09-18-001",
  "baseSerial": 12,
  "nextSerial": 13,
  "changes": [
    {"action": "replace", "name": "@", "type": "SOA", "ttl": 3600,
     "records": [{"mname":"ns1.example.","rname":"admin.example.",
                  "serial":13,"refresh":7200,"retry":3600,
                  "expire":1209600,"minimum":3600}]},
    {"action": "replace", "name": "www", "type": "A", "ttl": 300,
     "records": [{"address": "192.0.2.10"}]},
    {"action": "delete",  "name": "old", "type": "AAAA"}
  ]
}
```

- `@` 表示区顶点；相对名自动补全区；名称/RDATA 一律规范化为**确定性小写
  规范形式**（AAAA 压缩表示、名称绝对化等）。
- 一次发布**整体提交或整体失败**：
  - 顶点必须始终有**唯一 SOA**且 SOA.serial == `nextSerial`；
  - 顶点必须有**至少一个 NS**；
  - 记录不得越出本区（含标签边界校验，`evil-example.com.` 不会落入
    `example.com.`）；
  - **CNAME 不得与同名任何其他类型并存**；
  - 失败不占用序列号、不留下部分 RRset。
- **幂等**：`(zone, requestId)` 持久化。相同**规范化请求**重试返回首次结果
  （COMMITTED 重放或 FAILED 重放）；相同 requestId 携带不同内容稳定返回
  `IDEMPOTENCY_CONFLICT`。规范化在打开写事务前完成（大小写/表示差异视为同
  一请求，语义差异视为冲突）。

### 序列号：RFC 1982

按 32 位无符号空间、半区间顺序比较（`app/serial.py`），**绝不使用普通整数
大小比较**：

- `4294967295 → 0` 是合法前进；
- 相等、倒退 → `SERIAL_INVALID`；
- 距离恰好 `2^31`（不可判定）→ `SERIAL_UNDECIDABLE`；
- 两个实例基于同一 `baseSerial` 并发提交时，只有一个成功，失败方收到
  `VERSION_CONFLICT`，并在 `details.currentSerial` 中给出可重新 rebase 的当前
  序列号。

### 错误码（可区分）

`MALFORMED_JSON`、`VALIDATION_ERROR`、`LIMIT_EXCEEDED`、`ZONE_NOT_FOUND`、
`ZONE_ALREADY_EXISTS`、`NAME_OUT_OF_ZONE`、`VERSION_CONFLICT`、
`IDEMPOTENCY_CONFLICT`、`SERIAL_INVALID`、`SERIAL_UNDECIDABLE`、
`ZONE_INVALID`、`CHANGESET_INVALID`、`KEY_NOT_FOUND`、`KEY_STATE_INVALID`、
`NO_ACTIVE_KEY`、`REQUEST_NOT_FOUND`、`NOT_FOUND`、`METHOD_NOT_ALLOWED`、
`INTERNAL`。

### 限制（持久化前拒绝）

单区记录数、单次变更数、名称/标签长度、RDATA 长度、单条 RR 不得超过 DNS
TCP 消息容量；UDP 纯 DNS 负载 512 字节超限即置 TC。均可由环境变量调优
（`app/config.py`）。

---

## DNS 行为

- **UDP / TCP 均回答 SOA**（以及 NS/A/AAAA/CNAME/TXT/MX），回答为权威（AA）。
- **AXFR / IXFR 只允许 TCP**；UDP 上收到传送请求返回 **TC=1** 且不带数据。
- 非本区问题 → REFUSED；无法解析的类型 → NOTIMP；畸形消息 → FORMERR；
  服务从不因单个坏报文崩溃。
- **AXFR**：以**当前 SOA 开始并结束**（同一 SOA），中间记录按
  `(name, rtype, rdata)` 确定性排序输出。
- **IXFR**（请求 authority 段携带客户端当前 SOA）：
  - 从客户端序列号到当前固定目标序列号存在**完整连续历史** → 按发布边界输出
    全部 DEL 集 / ADD 集（每段以 SOA 删除/新增起始，顺序确定）；
  - 客户端已等于目标 → 仅返回当前 SOA；
  - 序列号未知、过旧（已被安全清理）、位于当前的“未来”、RFC 1982 不可判定，
    **一律回退为同一目标版本的完整 AXFR**——绝不返回截断增量或空成功。

### TSIG 传送认证（每区密钥）

- 算法 HMAC-SHA256（RFC 4635），密钥名/算法名/48 位时间/16 位 fudge 等遵循
  RFC 2845 线格式；时间只采用**服务端 UTC**（`now ± fudge`，fudge 上限校验）。
- 仅 **ACTIVE** 与**尚未到期的 RETIRING** 密钥可启动新传送；**REVOKED、已
  到期、未知密钥、签名错误、时间越界**在读取任何区数据前即被拒绝（TSIG
  BADKEY/BADSIG/BADTIME，响应中无任何记录）。
- 轮换是原子的：安装新 ACTIVE 时旧 ACTIVE 变为带明确 `expiresAt` 的
  RETIRING；可立即撤销。
- **首末消息签名**，中间消息不签名；多消息响应按 RFC 2845 running-MAC
  （请求 MAC → 首响 MAC → 末响 MAC）。
- 密钥材料**只在安装响应中返回一次**，永不出现在列表、健康检查、错误响应或
  日志中。

---

## 关键设计取舍（一致性 / 恢复）

### 1. 事务边界

所有写操作在 SQLite **`BEGIN IMMEDIATE`** 单写事务中完成（`app/storage.py`）。
发布在同一事务里：读取当前版本 → 校验序列号/幂等键/区不变量/限制 →
物化新版本**全量快照**与**逐发布差异** → 写 `versions`、推进区指针、写幂等
账本、入清理队列。提交前任何校验失败即回滚，因此**不会占用序列号，也不会
留下半套 RRset**。两个并发发布在单写锁上串行化，后到者观察到新版本并得到
确定性 `VERSION_CONFLICT`。

### 2. 版本不可变 + 快照固定方式

每个版本是**不可变的全量快照**（`records` 按 `(zone, version_id)` 复制），并
附带该版本相对上一版本的有序差异（`changes`，DEL 段在前、ADD 段在后，SOA
居段首）。因此：

- 传送不需要从多个版本“拼接”数据，天然避免新旧拼接；
- 新发布只追加新版本行，**绝不修改旧版本**；
- 传送线程在认证提交后开启一个**专用连接 + WAL 只读事务**
  （`Database.snapshot_conn()`）。SQLite WAL 保证该事务持有稳定读快照：传送
  期间即使发生发布或删除，该连接读到的始终是固定版本；活跃读事务还会阻止
  checkpoint 覆盖其所需页。

### 3. 在途引用管理（pin）

传送在**开始的同一个 IMMEDIATE 事务**里完成：密钥策略判定 → MAC 校验 →
决定 AXFR/IXFR 与目标版本 → 校验 IXFR 历史连续性 → 插入
`transfer_refs(version_id, min_version, key_gen, OPEN)`。

- AXFR 钉住目标版本；IXFR 额外用 `min_version` 钉住差异链起点版本；
- 线程把**认证时的密钥字节与代际保存在自身内存**中。之后发布、密钥轮换/
  撤销都不影响该连接：它仍用旧密钥合法签名并输出旧固定版本；**后续新连接**
  才观察到新密钥/新版本；
- 每发一条消息做一次心跳（`last_seen`），结束（含客户端断开、异常）在
  `finally` 中标记 DONE 并关闭快照连接——**不泄漏连接、事务或引用**；
- 崩溃实例遗留的 OPEN pin 在 `REF_STALE_SECONDS`（默认 300s）后由清理进程
  回收。

### 4. 清理协调（独立进程，可崩溃恢复）

清理由**独立进程**（`SERVICE_ROLE=cleaner`）驱动，任务表
`cleanup_tasks` 使用**租约协议**：

1. 领取任务本身是一个独立提交的 IMMEDIATE 事务：置 RUNNING、写 token 与
   `lease_expires`。在领取之后、删除部分候选之后、或提交之前任意时刻终止，
   都只留下一条到期可被重新领取的 RUNNING 行；
2. 删除判定是**幂等谓词**：只删除同时“老于保留窗口”且“老于所有存活在途
   pin 的 `MIN(version_id, min_version)`”的连续前缀版本（不可变版本/差异/
   快照三处按同一 version_id 删除）；崩溃后重跑只是对剩余行再次求谓词，
   结果可恢复、可重复；
3. 发布和保留策略变更都会入队 PENDING 任务，因此任务丢失也会被后续事件
   补偿；清理前顺手回收 DONE/僵死 pin 行。

被清理后，旧客户端的 IXFR 因起点版本缺失而**回退为完整 AXFR**（历史连续性
检查失败即回退），不会出现断裂/截断增量。

### 5. 不依赖单进程常驻或实例亲和性

- 区数据持久化在共享卷上的 SQLite（WAL），两个 edge 实例完全可互换：任何
  实例可处理任何 HTTP 重试、SOA 查询或 TSIG 传送；
- 幂等账本、序列号历史、密钥代际与在途引用都在数据库中，**任一实例重启后
  状态仍在**；
- 传送**流式输出**：RR 由游标逐行产出、按 DNS 容量贪心打包（首末预留 TSIG
  空间），只保持一条消息的前瞻以识别末包签名；不会把整区永久或整包常驻
  进程内存。接受连接使用较小 `SO_SNDBUF`，慢次级产生真实背压，使 pin 在
  整个传送期间真实存活。

---

## 存储 / 迁移

- 数据库：SQLite（WAL、`synchronous=FULL`、`busy_timeout=30s`），路径
  `DB_PATH`（容器内 `/data/dns.db`，compose 命名卷 `dnsdata`）。
- 迁移文件：`migrations/0001_init.sql`，进程启动时**自动、幂等**应用
  （`INSERT OR IGNORE` 防并发首启竞争），无需手工初始化。
- 主要表：`zones`、`versions`、`records`（不可变快照）、`changes`（差异）、
  `publish_requests`（幂等账本）、`keys`（含代际/状态/到期）、
  `transfer_refs`（在途 pin）、`cleanup_tasks`（租约队列）。

---

## 测试

- `tests/test_serial.py`：RFC 1982 边界（回绕、2³¹ 不可判定、等值/倒退）。
- `tests/test_canonical.py`：名称/RDATA 规范化与越界。
- `tests/test_storage.py`：原子发布、幂等、并发冲突、清理、pin 保护、密钥。
- `tests/test_integration.py`：在真实环回 socket 上启动 HTTP + UDP/TCP：
  SOA/记录查询、TSIG AXFR/IXFR 与签名链、清理后 AXFR 回退、5 路并发发布只
  1 胜、密钥轮换/撤销，以及关键场景：
  - **在途传送期间发布 + 轮换 + 撤销密钥 + 清理**：已开始连接仍完整输出固定
    旧版本且签名可验，新连接观察新状态；
  - 客户端中途断开不泄漏 pin/事务；
  - 重新打开数据库（模拟重启）后账本、历史、密钥状态完整。
- `app/verify.py`：compose 的 `verify` 服务对两个实例跑 68 项网络验收。

本地无 Docker 时可直接：`python3 -m unittest discover -s tests -v`。

## 目录

```
app/
  config.py       运行配置/限制
  errors.py       稳定机器码
  serial.py       RFC 1982 序列算术
  canonical.py    名称/RDATA 规范化与校验
  dnswire.py      DNS 线协议、TSIG 编解码与验签
  dnsclient.py    TSIG 客户端（verify/测试复用）
  storage.py      SQLite 事务、发布、密钥、pin、清理协调
  api.py          HTTP v1 管理 API
  dns_server.py   UDP/TCP 端点、AXFR/IXFR 流式传送
  cleaner.py      独立历史清理 worker
  verify.py       一次性网络验收服务
  server.py       进程入口（edge / cleaner）
migrations/       数据库迁移
tests/            自动化测试
Dockerfile  docker-compose.yml  docker-entrypoint.sh
```
