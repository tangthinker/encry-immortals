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
## ADR-011 切片长度：线格式硬上限 64 MiB + 策略默认 32 MiB

- **背景**：3.3 写 `plain_len <= MaxSlicePlain（默认 32 MiB）`，但 3.6 与 10.3 的 `slice_plain_bytes` 是**可配置**的（11.5 还建议调到 64 MiB）。若把 32 MiB 写死成解析器硬上限，改配置就会产生自己读不了的数据。
- **决策**：
  - `wire.MaxSlicePlainHard = 64 MiB`：**解析器**的绝对上限，超过即 `E12`（不依赖配置，保证任何实现都能拒绝危险声明）。
  - `wire.DefaultSlicePlain = 32 MiB`：**策略**默认值，由存储层按 `slice_plain_bytes` 校验（大于策略值报错）。
- **代价**：两处常量，需要在 `config` 校验时保证 `slice_plain_bytes <= MaxSlicePlainHard`。
- **备选**：把上限做成参数透传（接口污染）；或写死 32 MiB（配置一改就自伤）。

## ADR-012 解码器拒绝非规范 MessagePack

- **背景**：4.2 要求"最短编码、字节稳定"，但没有规定解码器遇到非最短编码怎么办。
- **决策**：**拒绝**（`ErrNonCanonical`），而不是接受后规范化。理由：接受非规范编码会让"同一语义多种字节"进入系统，破坏 golden vector 与哈希链的可预期性。
- **代价**：第三方（未来）实现必须严格遵循最短编码，否则互不兼容——这是有意的约束。
- **备选**：宽松接受（隐患：不同实现写出不同字节，链哈希不一致）。

## ADR-013 路径校验分两层

- **背景**：全局约定要求 NFC 归一化 + 相对路径 + 禁止 `..`；05.6 要求 restore 做 zip-slip 防护；09.6 要求拒绝非法 UTF-8 与超长路径。
- **决策**：
  - `internal/wire`：**格式级**校验（非空、UTF-8、无 NUL、无绝对路径、无 `..`/`.`/空段、单段 ≤255 B、总长 ≤4096 B、pack 名必须是 `data/...dat`）。这些规则与平台无关，解码即拒绝。
  - `internal/pathx`：**平台策略级**校验（NFC 归一化、大小写折叠冲突、Windows 保留名/长路径、安全 join）。
- **代价**：两条规则集需要在测试里各自覆盖；好处是"读别人的数据"与"写自己的数据"分别有明确边界。
- **备选**：全部放到 pathx（解码层会接受危险路径，依赖调用方记得校验，风险高）。
## ADR-014 备份差异以 journal 重放为准，state.db 只做缓存

- **背景**：05.4 的 fast 模式以 `state.db` 的 `(size, mtime)` 为判据。但 `state.db` 按 D-13 只存 `HMAC(PathKey, path)`，**不存明文路径**——而 `DELETE` op 必须携带明文路径。只靠 state.db 无法生成删除记录。
- **决策**：每次 `backup` 先重放 journal 链得到当前树（明文路径在内存中），再与扫描结果比对；`state.db` 只承担 (a) 锚点/水位，(b) status/演练时间戳，(c) 未来可作为 hash 缓存。
- **代价**：每次备份都要解密全部 journal。v1 不生成 checkpoint，所以 1000 次提交会明显变慢（符合 12.7 的"无 checkpoint 允许慢"分支）。
- **备选**：state.db 存明文路径（违反 D-13 / I13）；或把路径 HMAC→明文映射另存（等于变相存明文）。

## ADR-015 v1 不生成 checkpoint journal

- **背景**：04.4 的 checkpoint payload 是 `[kind=1, vault_params, packs, dirs, tree]`，其中 `tree` 节点只能表达普通文件（`[path, mode, size, mtime, sha, slices]`），**没有符号链接目标字段**。一旦写出 checkpoint，重放起点之后的符号链接就会永久丢失。
- **决策**：v1 **不生成** checkpoint，始终全量重放；解码端已能正确读取 checkpoint（含 pack→txn 反查），为将来扩展留好位置。
- **代价**：restore/backup 启动时间随提交次数线性增长。
- **待用户决策**：见 open-questions Q7（扩展 schema 加 `links[]` 并升 body 版本，或接受"checkpoint 库不支持符号链接"）。
- **补充（2026-10-17 实测）**：`TestChainLoadScaling` 测得 1000 次提交（1 万 op）链校验+重放 **57 ms**，1000 次提交 × 100 op（10 万 op）**86 ms**，2000 次提交 **65 ms**——远低于 12.7 的 3 s 目标。另有一个结构性原因：`prev_hash` 在密文内（04.2），checkpoint **不能**减少解密量，只能省掉 op 应用。因此 ADR-015 的"v1 不生成 checkpoint"由"临时取舍"升级为**有数据支撑的结论**，Q7 的方案 A 仅在未来历史库过大时才需要。

## ADR-016 session 上限的截断语义

- **背景**：10.3 的 `session_max_mib` 限制单次备份写入量，但规范没说"超了怎么办"。
- **决策**：按路径顺序处理 ADD/MODIFY，达到上限即停止写入**后续文件内容**；已处理的 op 与全部 DELETE/RMDIR/MKDIR/SYMLINK/META 照常提交。结果里 `truncated=true` 并提示剩余改动留给下次。
- **代价**：一次备份可能只覆盖部分变更；但每次提交仍然自洽，下次会重新检测到剩余变更。
- **备选**：整体失败（会把已写入的 pack 变成孤儿）；或自动拆成多次提交（复杂且用户不可见）。

## ADR-017 restore 断点续解的进度格式

- **背景**：05.6 要求 `.apex-restore-progress` 支持中断续解。
- **决策**：目标目录内的 JSONL 文件：首行 `{"seq":N}`，之后每完成一个文件追加 `{"seq":0,"path":"..."}`；续解时按 `seq` 匹配，不匹配即重来；全部完成后删除该文件。判定"已完成"仅用于跳过，仍会按覆盖策略校验内容。
- **代价**：进度文件本身让目标目录非空；`restore` 的空目录检查显式忽略该文件名。
- **备选**：state.db 记录（跨机恢复时不存在）。

## ADR-018 读期一致性与切片残留

- **背景**：05.4 要求读前读后 `stat` 比对；但切片是边读边加密写入 pack 的，重试会留下未被引用的切片。
- **决策**：比对 `(size, mtime_ns, ctime_ns, inode, dev)`；不一致时按 `on_change_during_read`（retry 3 次 / skip / fail）处理。重试产生的废弃切片留在 pack 内但不被 journal 引用——pack 的 footer 会记录它们，`verify` 不把它们当作文件内容。
- **代价**：极端情况下浪费几十 MiB 云端空间（下次 `compact` 才会消失）。
- **备选**：先在内存中完整读取再写（大文件内存翻倍，违反 5.5 的内存预算）。
## ADR-019 compact 的形态：新目录 + 只重打包被引用的内容 + 自检后交付

- **背景**：11.4 只有流程描述，没有接口细节；同时 `vault.meta` 不能进入 TargetDir（盲盒原则），所以"换身份"必然涉及两个目录。
- **决策**：
  - `apex compact --out <新 TargetDir> [--at <seq>] [--new-identity --new-vault <新控制平面>] [--dry-run] [--accept-data-loss]`。
  - **同身份**（默认）：复用当前 `vault.meta` 与密钥，只重建数据目录；完成后提示用户改 `target_dir` 并执行 `rebuild-state`（不自动改 state.db，避免用户还没确认就把缓存指错）。
  - **新身份**：要求 `--new-vault`，走一次 `vault.Init`（新 salt / vault_id / 口令，KDF 重新校准），并把新 `state.db` 的锚点直接写成 seq=1。
  - **只写被引用的内容**：逐个文件读旧切片（校验 AEAD + `plain_sha256`）→ 按当前配置重新压缩 → 写入新 pack；跳过的只是已删除历史。
  - **交付前自检**：重新加载新链，逐切片再解密校验，并比对每个文件的 `content_sha256`；自检失败即报错，绝不宣称成功。
  - **绝不删除**旧库；缺 pack 时默认 `E13` 中止，`--accept-data-loss` 才跳过并列出清单。
  - 写前检查 `statfs` 可用空间（unix），不足直接 `E14`。
- **代价**：`--new-identity` 需要新密码 + 新控制平面目录；同身份 compact 后必须手工切换配置并 `rebuild-state`。
- **备选**：原地重建（会破坏"旧库不动"的安全边界）；在 TargetDir 内放 `vault.meta`（违反盲盒原则）。
## ADR-020 restore 不做逐文件 fsync，改为"续解时重新校验"

- **背景**：05.6 只要求"先写 `.apex-tmp` 再 rename"以保证原子可见性，没有要求逐文件 fsync。但实测逐文件 `f.Sync()` 把 128 MiB 的还原吞吐从 418 MiB/s 压到 182 MiB/s（低于 12.7 的 300 MiB/s 目标）。
- **决策**：
  1. 去掉每文件 `f.Sync()`，只做 write → close → verify(SHA-256) → rename。
  2. 续解时，**进度文件标记为已完成**的文件仍会重新计算 SHA-256；不一致就重写（不受 `--overwrite=never` 限制，因为它属于"我们自己的残留"，不是用户数据）。
  3. `prepareDest` 允许目标目录非空——前提是存在 seq 匹配的进度文件（即这是同一快照的中断续解）。
- **代价**：掉电后可能出现"文件名已在、内容半截"的文件；重跑 `restore` 会自动修复（依赖第 2 条）。备份侧的 pack/journal 仍然强制 fsync（5.1 不可妥协）。
- **备选**：保留逐文件 fsync（吞吐不达标）；或加 `--fast-restore` 开关（多一个用户要理解的旋钮，且默认行为仍要选一个）。
## ADR-021 压缩参数可调 + 关闭 zstd 帧 CRC

- **背景**：10.3 的 `[codec] zstd_level` / `min_compress_bytes` 之前**没有接线**——`internal/codec` 把 level 5 与 4096 B 写死，改配置没有任何效果。同时 zstd 默认会在每个帧里放 4 字节 CRC。
- **决策**：
  1. `codec.Options{Level, MinBytes, ProbeBytes, ProbeRatio}` + 按 level 缓存 encoder（`sync.Map`），`CompressWith` 为唯一入口；`config.CodecOptions()` 把配置文件映射进来。
  2. pipeline（backup / note / compact）与 journal 封包全部使用配置里的级别；`wire.SealJournalFileWithOptions` 新增，旧的 `SealJournalFile` 仍用默认参数。
  3. **关闭 zstd 帧 CRC**（`zstd.WithEncoderCRC(false)`）：切片完整性已由 Poly1305 与 `plain_sha256` 覆盖，帧 CRC 只是重复校验；journal 同理。
  4. 默认级别仍是 5（spec 3.4），不擅自提高。
  5. 解码窗口下界修正：zstd 要求窗口 ≥1 KiB，之前当 `maxLen < 1024`（用户把 `min_compress_bytes` 调小后可能出现）会直接解码失败。
- **代价**：GV-2 的密文字节发生变化 → 重新生成并把"用固定 nonce 重新封包必须逐字节一致"写进测试，防止未来静默漂移。GV-1/3/4/5 不受影响。
- **实测**（同一份 359,472 B 的 spec 文本，单切片）：level 1 → 58,464 B，level 19 → 49,697 B（省 15%）。`go test -bench BenchmarkCompressLevels` 给出各档吞吐。
- **备选**：默认改 9（收益 5–15%，但 spec 写死 5，且会拖慢大库首备）；保留帧 CRC（每个切片多 4 B + 一次 CRC 计算，收益为零）。
