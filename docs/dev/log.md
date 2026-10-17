# 开发日志（时间线）

> 每条记录：时间 → 里程碑 → 做了什么 → 验证证据 → 遗留问题。
> 记录规则见 [README.md](README.md)：命令与结果是**实际执行**的，未验证项必须标注。

## 开发环境说明（首个里程碑实测）

本仓库所在环境的全局 Go 缓存（`~/go/pkg/mod`、`~/Library/Caches/go-build`、sumdb 缓存）**不可写**（file sandbox: 仅 workspace 可写）。
因此所有 Go 命令都在仓库内使用本地缓存运行：

~~~bash
export GOCACHE="$PWD/.cache/go-build"
export GOMODCACHE="$PWD/.cache/gomod"
export GOSUMDB=off          # sumdb 缓存不可写；go.sum 仍记录并校验哈希
export GOFLAGS=-mod=mod
~~~

`.cache/` 已在 `.gitignore` 中。用户本机全局缓存可写时**不需要**这些变量，直接用 `make` 目标即可。

---

## 2026-10-17 · M0 脚手架 ✅

**Plan**

- 通读母方案 `docs/tech.md` 与 spec 01–12，确认实现顺序与禁止项（不改密码、不去重、不 eviction、单写者、无守护进程）。
- 确定模块路径、二进制名、依赖策略、CLI 路由方式：ADR-001…ADR-010。

**Do**

- `go.mod`（module `github.com/tangthinker/encry-immortals`，go 1.24）、`.gitignore`、`Makefile`（build/test/vet/fmt/golden/fuzz/clean）。
- 开发记录体系：`docs/dev/{README,plan,decisions,log,open-questions}.md`。
- `internal/apexerr`：Code（E1/E2/E10–E21/E130）、10.5 退出码映射、`Error`（What/Scope/Next/Err）、`ExitCode`/`CodeOf`/`From`。

**Check（实际输出）**

- `go build ./...` → 无输出（通过）。
- `go vet ./...` → 无输出（通过）。
- `go test ./internal/apexerr` → `ok  	github.com/tangthinker/encry-immortals/internal/apexerr	0.301s`。

**Act**

- 记录环境限制与 ADR；未发现 spec 冲突。

---

## 2026-10-17 · M1 密码学基座 ✅

**Plan**

- 按 02 章实现：Argon2id → MasterKey、HKDF-SHA256 四把子密钥、XChaCha20-Poly1305 封装、四种 AAD（54/26/25/49 B）、auth_verifier 完整契约、Armor Key（Crockford Base32 + CRC32C）、zstd 压缩层（3.4）。
- goldens：GV-3（auth_verifier 密文）、GV-4（Base32 + CRC）、GV-5（四把子密钥）。

**Do**

- `internal/crypto`：`keys.go`（KDFParams 校验与硬下限、CanonBlock、DeriveMasterKey、DeriveSubkeys）、`secure.go` + `secure_unix.go`/`secure_other.go`（mlock 尽力 + 显式清零）、`aead.go`（唯一 AEAD 入口、CSPRNG nonce）、`aad.go`（四个 AAD 构造器 + PathHMAC + AnchorMAC）、`verifier.go`（19 B 常量、统一失败错误）。
- `internal/codec`：zstd level 5、`<4096 B` 跳过、64 KiB 采样不可压缩判定、解压上限防炸弹。
- `internal/armor`：Crockford Base32（无填充）、CRC32C（Castagnoli）、`APEX-KEY-V2-` 前缀、5 字符分组 + 72 列换行、`E16` 错误。
- `tools/goldengen`：生成 GV-3/4/5 到 `testdata/golden/`。

**Check（实际输出）**

- `go test ./internal/...` → `ok apexerr 0.301s / ok armor 0.104s / ok codec 0.409s / ok crypto 0.456s`。
- 交叉验证（非自证）：
  - HKDF 子密钥与测试内独立实现的 RFC 5869 逐字节一致；
  - Crockford 编码与 `encoding/base32`（自定义字母表、无填充）逐字节一致；
  - `DeriveMasterKey` 与 `argon2.IDKey` 输出一致（128 MiB 下限参数，~1 s，`-short` 下跳过）。
- 负向用例：AAD 篡改、跨库 vault_id、截断/翻位密文、弱 KDF 参数、Armor 单字符噪声、解压炸弹全部被拒绝。

**Act**

- 新增 ADR-008（测试用低开销 KDF 参数只走内部构造函数，CLI 与 vault.meta 仍强制硬下限）。
- 待用户确认：Q1 依赖策略、Q2 二进制名、Q3 里程碑顺序（已按推荐值执行）。
---

## 2026-10-17 · M2 线格式 ✅

**Plan**

- 按 03/04 章实现：canonical MessagePack（D-10）、Slice Envelope v1、PackHeader/Footer、Journal body v3 + Journal 密文容器。
- 目标：golden GV-1/GV-2、解析器防御清单逐条单测、fuzz 目标。

**Do**

- `internal/wire/mpack`：最短整数/str/bin/array 编码；解码器**拒绝**非规范表示（ADR-012）。
- `internal/wire/envelope.go`：50 B 信封、54 B AAD、解密前 OOM 上界检查；`SealSliceWithNonce` 仅供 golden/测试。
- `internal/wire/pack.go`：32 B PackHeader（随机 pack_id + 随机 padding）、footer 加解密、`LocateFooter` 三步定位（拒绝被截断的尾巴）。
- `internal/wire/journal.go`：7 元/8 元数组 schema、6 种 op、MKDIR/RMDIR/SYMLINK/META、checkpoint tree；解码期结构校验（index 连续、pack_idx 在界、size↔slices 一致、路径规则、mode 无类型位）；Journal 密文容器（28 B 头 + zstd + AEAD，seq/vault_id 入 AAD）。
- `tools/goldengen` 增加 GV-1/GV-2；`internal/wire/{envelope,pack,journal,golden}_test.go`；3 个 fuzz 目标。

**Check（实际输出）**

- `go test ./internal/wire/...` → `ok internal/wire 0.330s`、`ok internal/wire/mpack`。
- fuzz（每目标 15 s）：FuzzSliceEnvelope 6,780,527 execs、FuzzJournalDecode 7,972,639 execs、FuzzOpenJournalFile 541,905 execs → 全部 PASS，无 panic。
- 负向用例（实测通过）：切片 AAD 七要素任一被改（offset/index/packID/txnID/codec/ver_alg/长度）→ 解密失败；journal 重编号 seq+1 → 解密失败；trailing 字节 → 拒绝；`..`/绝对路径/空段/类型位 mode → 解码拒绝。

**Act**

- 新增 ADR-011（64 MiB 线格式硬上限 vs 32 MiB 策略默认）、ADR-012（拒绝非规范 msgpack）、ADR-013（路径校验分两层）。
- 遗留：`maxCompressedLen` 与 zstd worst-case 的实际对照留待 M8 的性能/边界复核。
---

## 2026-10-17 · M3 存储层 ✅

**Plan**：目录布局与白名单、原子换入 + 目录 fsync、pack writer（rollover/footer）、reader（I7 校验）、三层锁、暂存区清扫、路径策略。

**Do**

- `internal/pathx`：NFC 归一化、拒绝 `..`/绝对/空段/非法 UTF-8/超长段、Windows 保留名、`SafeJoin`/`Contains`/`Overlap`、大小写折叠冲突检测。
- `internal/store`：`Layout`（白名单校验、`data/YYYY-MM` 分片、pack/journal 命名与解析、暂存区同卷校验）、`RenameDurable`/`FsyncDir`/`CommitStaged`/`WriteFileDurable`、`SweepStaging`。
- `internal/store/packwriter.go`：写前 rollover 决策、footer、fsync→rename→fsync(dir)、输出 `packs[]` 指纹（size/sha256/slice_count）。
- `internal/store/packreader.go`：size 预校验（E13）、pack 头校验、seek 读信封、解密、解压、`plain_sha256` 复验（I7）、`VerifyPack`。
- `internal/lock`：控制平面 flock（unix）与 O_EXCL 回退（windows）、`.apex.lock` JSON 持有者记录、`BreakTargetLock`。

**Check（实际输出）**

- `go test ./internal/store/... ./internal/lock/... ./internal/pathx/...` → 三个包全 `ok`（0.4 s 级）。
- 负向用例：pack 大小不符 → `E13`；篡改密文 → `E12`；错误 txn_id → 解密失败；`SweepStaging` 只删 24h 前的残留；同进程二次加锁 → `E20`。

---

## 2026-10-17 · M4 vault 与 state.db ✅

**Plan**：vault.meta v2 契约、KDF 校准与冻结、密码强度策略、Armor Key 导出/导入、RECOVERY.txt、state.db schema 与锚点。

**Do**

- `internal/vault`：`Meta`（Base64URL 显式编解码）、`NewMeta`/`ParseMeta`/`LoadMeta`/`Save`（0600 + 目录 0700 + 原子写）、`Unlock`（统一 E10）、`Calibrate`（可注入 Probe）、`CheckPassword`（长度/重复/纯数字/常见字典）、`Init` + `RECOVERY.txt`、`Armor`/`ParseArmorString`。
- `internal/index`：modernc.org/sqlite（纯 Go，ADR-003），WAL + `synchronous=FULL`，5 张表 + vault_id/last_seq/演练/导出时间戳，`PutEntry`/`Entry`/`PutAnchor`/`LatestAnchor`/`LatestCheckpoint`/`ClearIndex`/`Reset`。

**Check（实际输出）**

- `go test ./internal/index/...` → `ok`（0.8 s）。
- `go test ./internal/vault/...` → `ok`（0.8 s，含 2 次 128 MiB Argon2id 派生）。
- I13 实测：写入明文路径的 HMAC 后，`state.db` 与 `state.db-wal` 中都不出现明文路径。
- 校准决策表实测：1.5 s → 保持 256 MiB；快 → 翻倍到 512 MiB；慢 → 回退 128 MiB；极快 → 封顶 1 GiB。
- 密码强度：`password`/`123456789012`/`aaaaaaaaaaaaaa` → weak；`correct horse battery staple` → 非 weak。

**Act / 遗留**

- 待用户决策：Q7 起新增（见 open-questions）。
---

## 2026-10-17 · M5 备份管线 ✅ / M6 恢复管线 ✅

**Plan**：把 05.1 S0–S7 变成可执行的提交协议；把 04.3–04.5 变成可验证的重放状态机；打通 `init → backup → restore` 的端到端闭环。

**Do（M5）**

- `internal/journal`：`Load` 解密+校验整条链（seq 连续性 I10、文件名 vs body.seq I6、prev_hash 链 I5、pack→txn 反查 I2），`replay` 按 04.5 规则建树（MODIFY→ADD 容错、DELETE/RMDIR 幂等、RMDIR 非空即 E12、META 保留、SYMLINK 记目标）。
- `internal/scan`：目录遍历 + NFC 归一化 + 排除规则；对硬链接、稀疏文件、设备/FIFO/socket、逃逸符号链接 fail-fast（E21）。
- `internal/pipeline`：`ComputeDiff`（DELETE→RMDIR 深→浅→MKDIR 浅→深→内容 op，RMDIR 前校验目录已空）；`Backup` 实现 S0–S7：预检/同卷/重叠/白名单 → 暂存清扫 → `.apex.lock` → 重放 + 扫描 → 写 pack（rollover/fsync/rename/目录 fsync）→ 写 journal（zstd+AEAD，seq 严格 +1，O_EXCL 等价语义）→ state.db 与锚点；支持 `--dry-run`、`session_max_mib` 截断、读期 stat 比对与 retry/skip/fail。

**Do（M6）**

- `Restore`：链校验 → 建目录（浅→深）→ 写文件（pack 读取器校验 size/AEAD/codec/plain_sha256，单切片重试 3 次）→ 建符号链接 → 统一 chmod → 深→浅设置 mtime；`--at` 快照穿梭；覆盖策略 never/if-changed/always；zip-slip 路径校验；损坏文件记入清单并继续，结束返回 E12；`.apex-restore-progress` JSONL 断点续解。
- `apex cat/ls`：直接从 pack 读切片，不落盘。

**Check（实际输出）**

- `go test ./internal/pipeline/...` → `ok`（0.7–0.9 s）：往返（含空文件/160 KiB 多切片/空目录/符号链接）、二次备份无 journal（I8）、删除+修改+新增的统计、META-only、dry-run 零落盘、非空目标拒绝、Target 污染拒绝、源/目标重叠拒绝、链增长连续。
- 崩溃点近似用例（12.2 的 K4/K5/K7 语义）：孤立 pack 不被引用且不影响后续备份；24h 前的 `.tmp/00000001.journal.tmp` 被清扫；删除 state.db 后二次备份仍判定无变更（证明差异不依赖缓存）。
- `go test ./internal/journal/... ./internal/scan/...` → `ok`：prev_hash 篡改 → E11；中间 journal 删除 → E11；密文翻位 → 拒绝；重命名 journal（seq 绑定 AAD）→ 拒绝；RMDIR 非空 → E12；硬链接/逃逸符号链接 → E21；NFC 归一化生效。

## 2026-10-17 · M7 CLI 与命令面 ✅（`compact` 除外）

**Do**

- `internal/cli`：全局 flag（`--config/--vault/--json/--debug/--password-fd/--password-file`，含 `APEX_PASSWORD_FD`）、stdout/stderr 双通道、统一退出码；密码只从 TTY/文件/fd 读取，配置文件禁止出现 password 字段。
- 命令：`init`（校准 + 强度检查 + Armor Key + RECOVERY.txt）、`backup`、`restore`、`log`、`show`、`ls`、`cat`、`status`（含 10.6 JSON）、`doctor`（白名单/同卷/暂存/序号，`--chain` 校验链与锚点）、`verify`（size/抽样/deep）、`export-key`、`import-key`、`gc`、`rebuild-state`、`note`、`version`。
- `cmd/apex/main.go`：SIGINT/SIGTERM → 退出码 130。

**Check（实际输出，CLI 冒烟）**

~~~text
$ apex init                     → 打印 vault_id / KDF / 内存峰值 / 单行+分组 Armor Key / 恢复须知路径
$ apex backup --source ... -m "first commit"
已提交 seq=1 · ADD 4 MODIFY 0 DELETE 0 META 0 DIR 1 LINK 1
1 个 pack · 579 B · journal 862 B · 用时 29ms
$ apex log                      → 00000001 2026-10-17 commit ops=6 dirs=1 packs=1 9c4bdd80 first commit
$ apex status                   → Data 579 B in 1 packs / Anchor 47BF-5503 / Health anchor OK · …
$ apex restore <dest>           → 已还原 seq=1 · 文件 4 目录 1 链接 1 · 200.0 KiB · 用时 21ms
$ diff -r source <dest>         → DIFF OK
$ apex verify --deep            → 本地 1 / 引用 1 / 缺失 0 / 大小不符 0 / 孤儿 0；深度校验 4 文件 失败 0
$ apex backup --source ...      → no changes
$ apex ls                       → 列出 0644/0640/0755、大小、link -> a.txt
~~~

- `go test ./internal/cli/...` → `ok 2.6s`：备份→日志→状态→还原→deep 校验全链路、退出码（未知命令 2 / 错误密码 10 / 非空目标 2）、`export-key --json` → 删除 vault.meta → `import-key --key-file` 后可继续解锁、`doctor --chain` 无 FAIL、`init` 生成 vault.meta 与 RECOVERY.txt。
- `go vet ./...` 与 `go test ./...`（15 个包）全部通过。

**遗留**

- `compact` 未实现（Q9）；checkpoint 未生成（Q7）；xattr/ACL 未检测（Q10）；`status` 的 referenced/orphan/missing 需 `doctor --chain` 补（Q11）。
- 下一步（M8/M9）：`APEX_TEST_CRASH_AT` 真实 kill 注入（K1–K7 全矩阵 ×20）、属性测试（随机树 × checkpoint 间隔）、fuzz 30 min、compact、跨平台构建验证。
---

## 2026-10-17 · M7 补充：命令面实测与修复

**实测发现的缺陷（已修）**

1. **位置参数之后的 flag 被忽略**：Go 标准库 `flag` 在遇到第一个非 flag 参数后停止解析，导致 spec 10.1 的写法 `apex restore <DestDir> --at <seq>`、`apex cat <path> --at <seq>` 静默失效（`--at` 被当成位置参数丢弃）。
   - 修复：`parseInterspersed` 先把已知 flag（含 `--k=v`、布尔 flag、未知 flag）搬到前面再解析；restore/ls/cat/show/note 全部改用它。
   - 回归测试：`TestCLISnapshotTravelWithTrailingFlags`（两次提交后 `cat a.txt --at 1` 必须返回旧内容、`restore dest --at 1` 必须还原旧内容）。
2. **META op 覆盖 state.db 的内容哈希**：META 只带 mode/mtime，原实现把 `content_sha256` 写成全零。修复：先读旧行并保留 hash/ctime。影响面仅限缓存质量，但会污染未来的 hash 加速路径。

**实测通过的场景（真实二进制 + 真实文件系统）**

~~~text
$ apex backup --source ... -m "second commit" --exclude '*.skip'
已提交 seq=2 · ADD 1 MODIFY 1 DELETE 1 META 0 DIR 2 LINK 0
$ apex note "手动注释一次"      → 已写入注释 journal seq=3
$ apex show 2                   → DELETE sub/b.txt / MKDIR newdir / MODIFY a.txt / ADD newdir/c.txt
$ apex cat a.txt --at 1         → hello apex          （修复前返回最新内容）
$ apex restore <dest> --at 1    → 旧快照正确
$ apex gc                       → 暂存区 0 / 孤儿 0
$ apex rebuild-state            → entries=4 dirs=2 last_seq=3
$ apex doctor --chain           → 9 项全 PASS（链 3 个 journal、锚点一致、无孤儿）
$ apex status --json            → schema=1、last_seq=3、anchor_short=1151-F618
$ apex verify --sample 2        → 本地 2 / 引用 2 / 缺失 0；抽样 2 个 pack 全通过
~~~

**Check（实际输出）**

- `go test ./...` → 16 个包全 `ok`（cli 3.0 s、pipeline 0.86 s，其余 ≤ 0.8 s）。
- `go vet ./...` → 无输出。
- `apex backup --exclude` 新增可重复 flag；`Makefile` 的 gofmt 范围收敛到 `./cmd ./internal ./tools`（避免扫到 `.cache/gomod`）。
---

## 2026-10-17 · 决策取证：checkpoint 到底值不值得做

**问题**：Q7 需要判断"扩展 checkpoint schema 支持符号链接"是否值得。单凭直觉容易高估收益，所以先量化成本。

**Do**

- 新增 `internal/journal/scaling_test.go`（`APEX_SCALE_TEST=1` 才运行，避免拖慢默认测试）：构造 N 个真实 journal（真加密、真文件），测量 `journal.Load` 的"链校验 + 重放"耗时。

**Check（实际输出）**

| 提交数 | 每提交 op | 总 op | build | **load（校验+重放）** |
|---|---|---|---|---|
| 100 | 10 | 1,000 | 720 ms | **4 ms** |
| 500 | 10 | 5,000 | 3.5 s | **27 ms** |
| 1000 | 10 | 10,000 | 7.1 s | **57 ms** |
| 1000 | 100 | 100,000 | 7.4 s | **86 ms** |
| 2000 | 10 | 20,000 | 14.4 s | **65 ms** |

（build 列是测试夹具生成时间，与用户无关。）

**Act**

- 结论修正：12.7 要求"1000 次提交 < 3 s"，当前**无 checkpoint 就已 < 0.1 s**；且 `prev_hash` 在密文内（04.2）使 checkpoint **无法**减少解密量，只能省 op 应用。
- Q7 推荐从"扩 schema"改为"**暂不扩**（维持 v1 不生成 checkpoint），未来历史库过大时再按方案 A 一次做对"；ADR-015 补充实测数据。
---

## 2026-10-17 · M8 验收：崩溃注入矩阵 + 属性测试 ✅

**Do**

- `internal/testhooks`：`Crash(stage)` 只在 `-tags testhooks` 下编译出 `os.Exit(137)`；release 构建是内联空函数（满足 12.2"release 中不存在"）。
- 注入点：K1 切片已写入未封包（`PackWriter.Append`）、K2 pack 刷盘后未 rename、K3 rename 后未 fsync 目录、K4 pack 发布后未写 journal、K5 journal 写入 `.tmp/` 后未 rename、K6 rename 后未 fsync、K7 journal 提交后未更新 state.db、K8 restore 写第一个文件后。
- 为 K2/K3、K5/K6 把发布流程拆成显式步骤（禁用了"一次 CommitStaged"的黑盒），提升可测性。
- `TestCrashInjectionMatrix`：用 `go build -tags testhooks` 构建真实二进制，逐阶段：注入崩溃（期望 137）→ `--break-lock` 恢复备份 → `doctor --chain` → restore → 与源树逐字节/mode/mtime 比对；K8 额外验证"中断后 `--overwrite if-changed` 续解"与进度文件删除。
- `TestRandomTreeRoundTrip`（12.5 属性测试）：固定种子，12 步随机增/改/删 → 每次提交记录快照 → 最新与中间快照各还原一次，逐文件比对内容并断言"没有多余文件"。

**Check（实际输出）**

- `go test ./internal/pipeline -run TestCrashInjectionMatrix -v` → **K1–K8 全部 PASS**（总 2.96 s）。
- `go test ./internal/pipeline -run TestRandomTreeRoundTrip -v` → PASS（0.18 s）。
- `go build ./...` 与 `go build -tags testhooks ./...` 均通过（证明 release 版不含钩子也能编译）。

---

## 2026-10-17 · M9 之一：`compact`（空间回收）✅

**Do**（ADR-019）

- `pipeline.Compact`：加载旧链（可 `--at`）→ 空间预检（`statfs`）→ 新 TargetDir 必须为空 → 逐文件读旧切片（校验 AEAD + `plain_sha256`）→ 按当前配置重新压缩 → 新 pack → 写 seq=1 的 journal（MKDIR/ADD/SYMLINK + 全量 dirs）→ **重新加载新链逐切片自检** → 交付。
- `--new-identity`：`--new-vault` + 新口令，走 `vault.Init`（新 salt/vault_id，KDF 重新校准），并把新 `state.db` 的锚点写成 seq=1；返回新 Armor Key。
- 缺 pack：默认 `E13` 中止；`--accept-data-loss` 才跳过并在结果与退出码中列出。
- CLI：`apex compact`，人类输出提示"旧库未改动 / 切换三步"。

**Check（实际输出）**

- `go test ./internal/pipeline -run TestCompact -v` → 5 个用例全 PASS：同身份重建（旧库 pack/journal 数不变）、新身份（新口令可解、旧口令被拒、新 state.db 有锚点）、缺 pack 的 strict/lossy 两条路径、非空输出目录拒绝 + dry-run 不落盘、`--at 1` 保留历史文件。
- CLI 实测（真实二进制）：
~~~text
$ apex compact --out ... --dry-run   → dry-run：4 个文件 / 2 目录 / 1 链接，逻辑 200.0 KiB
$ apex compact --out ...             → 已重建新库 seq=1 · 584 B in 1 packs · 用时 20ms
$ apex log（新目录）                  → 00000001 commit ops=7 dirs=2 packs=1 compact from seq 3
$ apex rebuild-state                 → entries=4 dirs=2 last_seq=1
$ apex restore <dest>                → 文件 4 目录 2 链接 1 · 200.0 KiB
$ diff -r source <dest>              → DIFF OK
$ apex verify --deep                 → 缺失 0 / 大小不符 0 / 深度校验失败 0
$ apex log（旧目录）                  → 仍是 3 条历史（旧库未被改动）
~~~
- `go test ./...`（17 个包）全绿，`go vet ./...` 无输出。

**遗留**

- 同身份 compact 后需要手工改配置 + `rebuild-state`（不自动改用户配置，见 ADR-019）。
- 仍未做：xattr/ACL 检测（Q10）、30 min fuzz、跨平台 CI、12.7 性能基线（当前只有链加载的实测）。
