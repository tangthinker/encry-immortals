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
## Q7（P0，已有实测结论）checkpoint 与符号链接的规范缺口

- **问题**：04.4 的 checkpoint `tree` 节点无法表达符号链接目标（见 ADR-015）。若生成 checkpoint，重放起点之后的符号链接会丢失。
- **实测（2026-10-17，`APEX_SCALE_TEST=1 go test ./internal/journal -run TestChainLoadScaling -v`）**：

| 提交数 | 每提交 op 数 | 总 op 数 | 链校验+重放耗时 |
|---|---|---|---|
| 100 | 10 | 1,000 | 4 ms |
| 500 | 10 | 5,000 | 27 ms |
| 1000 | 10 | 10,000 | 57 ms |
| 1000 | 100 | 100,000 | 86 ms |
| 2000 | 10 | 20,000 | 65 ms |

  12.7 的验收目标是"1000 次提交（含 checkpoint）< 3 s"；**当前不含 checkpoint 只有 57 ms**，而且 100k op 的 1000 次提交也只有 86 ms。
- **为什么 checkpoint 收效有限**：I5 要求校验每个 journal 的 `prev_hash`，而 `prev_hash` 在**密文内部**（04.2），所以无论有没有 checkpoint，都必须解密全部 journal；checkpoint 只能省掉"把 op 应用到树上"这一步，而实测这一步不是瓶颈。
- **修订后的方案 A**：扩 payload 为 `[kind=1, vault_params, packs, dirs, tree, links]`（journal body 升 v4，解码端兼容 v3）。收益主要是**空间与语义完整**（checkpoint 能完整表达符号链接），不是速度。
- **方案 B**：只在"库中没有符号链接"时生成 checkpoint（行为随数据变化，难解释）。
- **方案 C（当前实现，修订后推荐）**：v1 不生成 checkpoint。等到真实库的链加载超过 3 s（或 journal 总体积达到数百 MB）再引入，届时按方案 A 一次性做对。
- **状态**：已按 C 实现；是否升级为 A 取决于你对"未来是否要支持超大历史库"的判断。

## Q8（P2）源根目录的 mode/mtime 未记录

- **问题**：09.6 要求"源目录为空且不存在任何文件 → 产生 journal（记录源根目录的 mode）"，但路径模型禁止空路径，`wire` 会拒绝 `Path == ""` 的 op。
- **方案 A**：允许 `OpMkdir` 的 `Path == ""` 作为"根目录"特例（需要放宽 wire 校验与 pathx）。
- **方案 B**：新增 `root` 字段进 journal payload（线格式变更）。
- **方案 C**：不记录（当前实现），restore 后根目录 mode 由 umask 决定。
- **当前实现**：C，已在 README 的"已知限制"中间接体现。

## Q9（P1）✅ 已解决：`compact` 已实现

- **结论**：`apex compact --out <新 TargetDir> [--at <seq>] [--new-identity --new-vault <dir>] [--dry-run] [--accept-data-loss]`，实现见 ADR-019。
- **验证**：`TestCompact*` 5 个用例 + CLI 实测（dry-run → compact → 切换配置 → rebuild-state → restore → `diff -r` OK → `verify --deep` 0 失败 → 旧库未被改动）。
- **遗留细节**：同身份 compact 后需手工改配置并 `rebuild-state`；若希望自动切换，请提出（会引入跨目录配置写入，风险是改错用户的配置）。

## Q10（P2）✅ 已解决：xattr 检测已实现，macOS ACL / 资源分叉仍是缺口

- **实现**：`internal/scan/xattr_{darwinlinux,other}.go` 用 `unix.Llistxattr`（不跟随符号链接）检测；命中即 `E21` 并列出前 3 个属性名，提示 `scan.ignore_xattr = true` 或 `scan.exclude`。
- **验证**：`TestScanRejectsXattrsByDefault`（设置 `com.apex.test` → 默认拒绝，`IgnoreXattr` 放行）；CLI 实测 E21 文案正确。
- **仍缺**：macOS 的 ACL（`acl_get_file`，非 xattr）与资源分叉（`com.apple.ResourceFork` 属于 xattr，已被检测）。若需要 ACL，须用平台专用 API，建议单独排期。

## Q11（P2）✅ 已解决：`status --chain`

- **实现**：新增 `--chain`；解锁后统计 `referenced/orphan/missing`，并校验锚点 MAC、给出"锚点落后于磁盘"告警。默认行为不变（不需要密码）。
- **验证**：`TestCLIStatusChainAndWaitForPacks` 断言 `local=1, referenced=1, missing=0, orphan=0`。

## Q12（P2）常见密码字典只有约 120 条

- **问题**：08.4 要求 init 时比对上"常见密码前 10 万条"；当前内置清单约 120 条。
- **推荐**：引入一个可选词表文件（`~/.config/apex/weak-passwords.txt`，bloom filter 预编译），缺失时退化为当前内置清单并给出提示。
- **状态**：待确认是否值得引入额外资产。