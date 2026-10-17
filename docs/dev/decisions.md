# 实现级决策记录（ADR）

> 规范层决策见 [../spec/README.md](../spec/README.md) 的 D-01…D-18。本文件只记「spec 没写、但写代码必须选一个」的实现决策。
> 每条包含：背景 / 决策 / 代价 / 备选。被推翻的决策保留原文并标注取代关系。

---

## ADR-001 模块路径与二进制名

- **背景**：仓库 `github.com/tangthinker/encry-immortals`，spec 全文以 `apex` 称呼工具。
- **决策**：Go module 路径 = `github.com/tangthinker/encry-immortals`；二进制名 = `apex`（构建产物 `bin/apex`），CLI 帮助与错误文案中的命令名统一为 `apex`。
- **代价**：仓库名与工具名不一致，需要在 README 里说明一次。
- **备选**：二进制沿用仓库名 `encry-immortals`（与 spec 文案冲突，错误提示里的 `apex ...` 建议命令会失效）。

## ADR-002 依赖策略

- **背景**：需要 zstd、Argon2id/XChaCha20、终端密码输入、SQLite、TOML。全部手写不现实，但每引入一个依赖都扩大信任面（08 章 8.7）。
- **决策**：只引入下列**纯 Go**依赖，且全部集中在薄封装层里，便于将来替换：

| 依赖 | 用途 | 封装点 |
|---|---|---|
| `golang.org/x/crypto/argon2`、`chacha20poly1305` | KDF / AEAD（08 章唯一无条件信任的第三方） | `internal/crypto` |
| `github.com/klauspost/compress/zstd` | 3.4 压缩层 + Armor | `internal/codec` / `internal/armor` |
| `golang.org/x/term` | 无回显读密码（10.4） | `internal/cli` |
| `modernc.org/sqlite` | state.db（纯 Go，无需 CGO） | `internal/index` |
| `github.com/pelletier/go-toml/v2` | config.toml | `internal/config` |
| `golang.org/x/text/unicode/norm` | NFC 归一化（全局约定 / 5.8） | `internal/pathx` |

- **不引入**：msgpack 库（见 ADR-004）、CLI 框架（见 ADR-005）、日志库（10.6 只要 stdout/stderr 两条通道）、断言库。
- **代价**：SQLite 依赖较大（modernc 约 10 MB 源码）；msgpack/CLI 手写多约 400 行代码。
- **备选**：`mattn/go-sqlite3`（CGO，交叉编译与 CI 复杂）；自研 KV 文件（放弃 SQL 查询与事务，I14 重建逻辑更易出错）。

## ADR-003 SQLite 驱动：modernc.org/sqlite

- **背景**：5.7 定义了 5 张表与事务语义。
- **决策**：`modernc.org/sqlite`（纯 Go），DSN 加 `_pragma=journal_mode(WAL)`、`_pragma=synchronous(FULL)`（5.1 S7）。
- **代价**：首次编译慢；WAL 会在控制平面目录多出 `-wal/-shm` 文件（doctor 需知道这两类文件属正常）。
- **备选**：`mattn/go-sqlite3`（CGO）；BoltDB（无 SQL，锚点查询可做，但 schema 迁移麻烦）。

## ADR-004 手写 canonical MessagePack

- **背景**：4.2 要求固定位置数组 schema、最短整数编码、禁止 float、跨实现字节稳定（golden vector 依赖）。
- **决策**：在 `internal/wire/mpack` 手写最小编解码器，只支持：nil、bool、正/负整数（最短表示）、bin8/16/32、str8/16/32、fixarray/array16/array32。解码器对非规范表示（如用 uint16 表示 3）**报错**而非接受，确保"写出的字节唯一"。禁止 map、float、ext。
- **代价**：约 300 行代码与测试；未来加字段需要改 schema 版本。
- **备选**：`vmihailenco/msgpack`（无法保证最短编码与字段顺序稳定，需额外校验）。

## ADR-005 CLI 路由：标准库 flag + 手写子命令表

- **背景**：10.1 命令表 + 10.2 全局 flag + 10.5 稳定退出码；每个命令都要在 help 里声明"是否修改 TargetDir"。
- **决策**：`internal/cli` 自己维护 `map[string]*Command`，每个命令一个 `flag.FlagSet`（`ContinueOnError`），全局 flag 先解析再分发。错误统一经 `apexerr` 转成退出码。**不使用** cobra/urfave。
- **代价**：help 排版与 shell 补全要自己写（v1 不做补全）。
- **备选**：cobra（引依赖 + 默认行为把错误印到 stdout，与 10.6 输出契约冲突）。

## ADR-006 退出码补充：E16（Armor 损坏）→ 12

- **背景**：10.5 给出了 E2/E10/E11/E12/E13/E14/E20/E21 的退出码，但没有给 02 章 2.10 的 `E16 Armor 字符串损坏（CRC 校验失败）` 指定退出码。
- **决策**：E16 复用退出码 **12（数据损坏 / 格式非法）**，错误号保持 `E16` 以便与 E12 区分文案与排查路径。
- **代价**：脚本若只看退出码无法区分"用户抄错 Armor"与"云端数据损坏"；可用 stderr 的 E 编号区分。
- **待用户确认**：见 open-questions Q4。

## ADR-007 Go 版本与构建约束

- **决策**：`go 1.24`（`crypto/hkdf` 自 1.24 起进标准库）；开发机 1.27。测试钩子（12.2 `APEX_TEST_CRASH_AT`）只在 `-tags testhooks` 下编译。
- **代价**：用户需 Go ≥ 1.24 构建；发布二进制不受影响。

## ADR-008 单元测试用低开销 KDF 参数

- **背景**：Argon2id 默认 256 MiB / t=3，单次秒级，单测不可用。
- **决策**：测试里直接构造 `KDFParams{time:1, memory:64 KiB, threads:1, keylen:32}`；**但** `init` 路径与 `vault.meta` 校验路径仍强制 spec 硬下限（131072 KiB）。测试用参数只通过内部构造函数注入，不经过 CLI，也不写入 vault.meta。
- **代价**：单测覆盖不到"硬下限拒绝"之外的性能特征（由基准测试单独覆盖）。

## ADR-009 错误与输出通道

- **决策**：`internal/apexerr.Error` 唯一错误类型；人类进度/警告 → stderr，结果数据 → stdout（10.6）；`--json` 时 stdout 只允许一个 JSON 文档。panic 只在 `--debug` 下打印栈。
- **代价**：所有命令的实现都要显式区分两条输出流，写起来略啰嗦。

## ADR-010 时间与路径的规范化入口

- **决策**：路径入库前统一经 `internal/pathx.Normalize`（NFC + `/` + 相对 + 拒绝 `..`/绝对/空段/非法 UTF-8/超 255 B 段）；时间一律 `UnixNano`/`Unix` 整数，禁止 `time.Time` 进入线格式。
- **代价**：Windows 上的长路径与保留名处理集中在一处，需专门单测。
