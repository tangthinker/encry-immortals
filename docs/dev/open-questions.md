# 待决策 / 待确认事项

> 规则：发现即记录；有结论后移入 [decisions.md](decisions.md) 并在此标记 **已解决**（保留编号，不删除）。
> 优先级：**P0** = 阻塞当前里程碑；**P1** = 影响设计但可先按推荐值实现；**P2** = 细节打磨。

## Q1（P0）依赖策略与 SQLite 驱动

- **问题**：是否允许引入 `modernc.org/sqlite`（纯 Go、体积大、编译慢）、`klauspost/compress`、`pelletier/go-toml/v2` 等第三方纯 Go 依赖？
- **推荐**：允许（见 ADR-002 / ADR-003）。全手写 SQLite 不现实，CGO 版本会增加跨平台 CI 成本。
- **若拒绝的替代方案**：state.db 改为自研追加式 KV（`index.db` + 行格式），代价是丧失 SQL 与事务，且 I14 重建逻辑需要自己写校验。
- **状态**：默认按推荐执行，等待确认。

## Q2（P1）二进制名与命令前缀

- **问题**：二进制名 `apex` 是否接受？spec 全文使用 `apex`，但仓库名为 `encry-immortals`。
- **推荐**：`apex`（ADR-001）。
- **状态**：默认按推荐执行，等待确认。

## Q3（P1）里程碑范围与顺序

- **问题**：是否按 [plan.md](plan.md) 的 M0→M8 顺序推进（先打通 init→backup→restore 的可用闭环，再补 compact/checkpoint 等）？
- **推荐**：是。M5（backup）+ M6（restore）优先形成端到端可用路径，M7 的 compact/checkpoint 随后。
- **状态**：默认按推荐执行，等待确认。

## Q4（P2）E16（Armor 损坏）的退出码

- **问题**：10.5 未给 E16 指定退出码。
- **推荐**：复用 12（格式非法），错误号仍为 E16（ADR-006）。
- **状态**：默认按推荐执行，等待确认。

## Q5（P2）`status --json` 的 schema 版本策略

- **问题**：10.6 的 `"schema": 1` 何时递增？新增字段算不算破坏？
- **推荐**：只增字段不递增；删除/改语义才递增。写进 README。
- **状态**：待确认。

## Q6（P2）checkpoint 的默认参数

- **问题**：`checkpoint.every_commits=256`、`checkpoint.max_age_days=30` 是否保持 spec 默认？
- **推荐**：保持。
- **状态**：待确认。
