# 实现计划（里程碑）

> 目标：按 spec 交付 `eimmortal` v1 的**可运行、可测试**实现。规范层不再改动；若发现规范缺陷，记录到 open-questions.md，不在实现中静默偏离。

## 范围边界

**v1 必须实现**（12.8 验收相关）：init / backup / restore / log / show / ls / cat / verify / status / doctor / export-key / import-key / gc / rebuild-state / compact / note。

**v1 明确不做**（spec 已定）：rekey、watch、mount、去重、eviction、改密码、多源根、多写者。

## 里程碑

| 里程碑 | 内容 | 交付物 | 验收 |
|---|---|---|---|
| **M0** 脚手架 | go.mod、目录骨架、Makefile、错误码与退出码、开发记录体系 | `internal/apexerr`、`docs/dev/*` | `go build ./...`、`go test ./internal/apexerr` |
| **M1** 密码学基座 | Argon2id 派生、HKDF 子密钥、AEAD 封装、AAD 拼装、Armor Key | `internal/crypto`、`internal/armor` | GV-3/4/5；AAD 长度 54/26/49；nonce 唯一性测试 |
| **M2** 线格式 | canonical msgpack、Slice Envelope v1、PackHeader/Footer、Journal body v3 | `internal/wire` | GV-1/2；解析器防御清单（03 章 3.3）逐条单测；fuzz 目标 |
| **M3** 存储层 | 目录布局与白名单、pack writer（rollover、footer）、reader、`renameDurable`、三层锁、孤儿清理 | `internal/store`、`internal/vault` | 崩溃点 K1–K7 单测（12.2 的单元级切片） |
| **M4** vault 与 state.db | vault.meta v2、KDF 校准与冻结、init 强度检查、export/import-key、state.db schema + 锚点 | `internal/index`、`internal/vault` | I13（无明文路径）、I14（可重建）、I19/I20 |
| **M5** 备份管线 | 扫描与差异（fast/strict）、S0–S7 提交协议、读期一致性、dry-run | `internal/pipeline` | I8、I16、I17；C1–C7 |
| **M6** 恢复与查询 | 链校验、重放状态机（含 checkpoint）、restore 安全边界与覆盖策略、log/show/ls/cat | `internal/journal`、`internal/pipeline` | I4、I5/I6、I7、I10；C8；zip-slip 拒绝 |
| **M7** 运维命令 | verify（size/sample/deep）、doctor --self-check、status、gc、rebuild-state、compact、note | `internal/cli` | 12.8 第 7 条；10.6 `status --json` schema |
| **M8** 验收 | 崩溃注入 C1–C9、属性测试、fuzz 30min、golden CI、RECOVERY.txt、README | 全部 | 12.8 的 9 条 DoD |

## 里程碑内的固定节奏（PDCA）

1. **Plan**：读相关 spec 章节，列出要写的接口与测试点；未覆盖处写 open-question。
2. **Do**：先写测试或 golden，再写实现；单文件不超过一个明确职责。
3. **Check**：`go vet` + `go test -race`；崩溃/篡改用例必须真的看到失败再看到通过。
4. **Act**：更新 [log.md](log.md)、[decisions.md](decisions.md)，必要时回填 open-questions。

## 状态

| 里程碑 | 状态 | 备注 |
|---|---|---|
| M0 | ✅ 完成 | 见 log.md |
| M1 | ✅ 完成 | GV-3/4/5 已入库；AAD 长度 54/26/25/49 有单测 |
| M2 | ✅ 完成 | GV-1/2 入库；3 个 fuzz 目标 15s 无 panic |
| M3 | ✅ 完成 | pathx/store/lock 均有测试 |
| M4 | ✅ 完成 | vault.meta/state.db/Armor/校准/强度策略 |
| M5 | ✅ 完成 | S0–S7、diff 排序、读期一致性、dry-run、session 截断 |
| M6 | ✅ 完成 | 链校验/重放、restore 安全边界、快照穿梭、断点续解 |
| M7 | ✅ 完成（compact 除外） | 16 个命令可用；status/doctor/verify 有 JSON |
| M8 | ✅ 基本完成 | K1–K8 kill 注入、属性测试、3 个 fuzz 目标（2min×3）、15 项恶意输入审计；30min fuzz 与运行时 CI 待补 |
| **M9** 收尾 | `compact` ✅、跨平台**编译** ✅、性能基线 ✅（280/418 MiB/s）、xattr（Q10）✅、运行时 CI ⬜、checkpoint（Q7 已决定暂不做） | — | 12.7 |