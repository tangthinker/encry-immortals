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
