# 开发记录（dev log）

本目录记录**实现层**的决策、计划与执行日志。规范（什么 / 为什么 / 字节长什么样）在 [../spec/](../spec/)，母方案在 [../tech.md](../tech.md)。**三者的权威顺序：spec > 本目录 > 代码注释。**

## 文件

| 文件 | 内容 | 维护时机 |
|---|---|---|
| [plan.md](plan.md) | 里程碑 M0–M8、范围、验收标准 | 里程碑开始 / 结束时更新状态 |
| [decisions.md](decisions.md) | ADR（实现级决策），编号 ADR-001 起 | 每次做出实现选择时**先写**再写代码 |
| [log.md](log.md) | 时间线执行日志：做了什么、跑了什么命令、结果如何、下一步 | 每个里程碑结束、每次会话结束时追加 |
| [open-questions.md](open-questions.md) | 需要用户决策 / spec 未覆盖的问题 | 一旦发现即记录；有结论后移入 decisions.md |

## 记录约定

- **ADR**：一条决策一个编号，写清「背景 / 决策 / 代价 / 备选」。被推翻的决策**不删除**，标注 `已被 ADR-xxx 取代`。规范层的 D-01…D-18 不在本目录重复，引用即可。
- **日志条目**：时间（本地）→ 里程碑 → 变更摘要 → 验证证据（命令 + 结果）→ 遗留问题。
- **验证证据必须是真实执行过的命令输出摘要**，不是"应该能过"。记录形如：`go test ./internal/crypto -run TestKDF -count=1 → ok 0.31s`。
- **未验证的事必须显式标注**（`未验证`），不许写成已完成。

## 代码布局

~~~text
cmd/apex/                 CLI 入口
internal/apexerr/         错误码 / 退出码（10.5 的稳定契约）
internal/crypto/          口令派生、子密钥、AEAD、AAD 拼装（02 章）
internal/armor/           Armor Key：Crockford Base32 + CRC32C（02 章 D-16）
internal/codec/           zstd 压缩层（03 章 3.4）
internal/pathx/           路径归一化与安全校验（全局约定 / 05 章 5.6）
internal/wire/            线格式：msgpack、Slice Envelope、Pack、Journal（03/04 章）
internal/vault/           vault.meta、控制平面、锁（01/02 章）
internal/store/           Target 目录布局、pack 写入/读取、原子换入（03/05 章）
internal/journal/         链校验、重放状态机、checkpoint（04/05 章）
internal/index/           state.db（05 章 D-13）
internal/pipeline/        backup / restore / verify 管线（05/06 章）
internal/config/          config.toml（10 章）
internal/cli/             命令面（10 章）
testdata/golden/          Golden vectors（12.3）
~~~

## 与 spec 的映射

实现中任何"spec 没说"的空白，先写入 [open-questions.md](open-questions.md)；做出临时取舍则写入 ADR 并标注 `临时`。
