# eimmortal（encry-immortals）

**端到端加密的不可变追加式增量备份工具。** 面向"把备份丢进网盘，但完全不想让网盘看懂"这一场景。

- **数据平面**（TargetDir）只有密文：`data/**/pack_<ts>_<rand>.dat`、`meta/<seq>.journal`，没有密钥、没有明文、没有可读元数据。
- **控制平面**（`~/.eimmortal/eimmortal-vault/`）保存 `vault.meta`、`state.db`，**绝不放进同步目录**。
- **纯追加**：已写出的 pack 永不修改、永不删除；删除只在 journal 里留墓碑。网盘客户端永远只看到"新文件出现"。
- **密码学**：Argon2id → HKDF-SHA256（4 把子密钥）→ XChaCha20-Poly1305；每个切片独立随机 nonce，AAD 绑定 pack_id/offset/index/txn_id/codec。
- **可审计**：哈希链 + 本地锚点 + `verify` / `doctor` / 恢复演练。

设计文档：母方案 [docs/tech.md](docs/tech.md)，实现规范 [docs/spec/](docs/spec/README.md)，开发记录 [docs/dev/](docs/dev/README.md)。

> **名称变更（2026-10-17）**：工具由 `apex` 更名为 `eimmortal`。默认目录、锁文件名、Armor Key 前缀与环境变量同步改名；为不破坏已有数据，旧名称在**读取路径**上仍然兼容：
> - Armor Key：新导出为 `EIMMORTAL-KEY-V2-…`，`import-key` 仍接受旧的 `APEX-KEY-V2-…`；
> - 默认目录：`~/.eimmortal/eimmortal-vault`、`~/.config/eimmortal/config.toml`；若新路径不存在而旧路径存在，会自动沿用旧路径（`~/.config/eimmortal-vault`，再往前是 `~/.config/apex-vault`；也可用 `--vault/--config` 指定）；
> - 锁文件：写 `.eimmortal.lock`，旧的 `.apex.lock` 仍被视为"正在写入"，`--break-lock` 会同时清理；
> - 续解进度：读旧的 `.apex-restore-progress` 并自动迁移；
> - 环境变量：`EIMMORTAL_PASSWORD_FD` / `EIMMORTAL_TEST_CRASH_AT`，旧的 `APEX_*` 仍作为回退；
> - **线格式常量不变**：HKDF info（`apex-*-v2`）、genesis（`APEX-JOURNAL-GENESIS-v3`）、校验常量（`APEX_AEAD_VERIFY_OK`）、journal/pack 命名与 AAD 布局都保持原样——它们属于协议，改名会让已有库无法解密。

## 当前状态

| 能力 | 状态 |
|---|---|
| `init`（KDF 校准一次即冻结）、`export-key` / `import-key`（Armor Key） | ✅ |
| `backup`（增量、读期一致性、dry-run、session 上限）、`note` | ✅ |
| `restore`（快照穿梭 `--at`、覆盖策略、路径安全、断点续解） | ✅ |
| `log` / `show` / `ls` / `cat` / `status`（`--chain` 可算引用/孤儿/缺失）/ `doctor` / `verify` / `gc` / `rebuild-state` | ✅ |
| `compact`（重建回收已删除历史，支持 `--new-identity`） | ✅ |
| checkpoint journal 生成 | ⏳ v1 不生成（实测：1000 次提交链校验仅 57 ms；规范对符号链接有缺口，见 Q7） |
| `watch` / `mount` / 改密码 / 去重 / eviction | ❌ 规范明确不做 |

## 快速开始

```bash
# 1. 构建
make build            # 产物：bin/eimmortal

# 2. 配置：复制示例，至少把 target_dir 改成你的网盘目录（权限必须 0600）
mkdir -p ~/.config/eimmortal
cp config.example.toml ~/.config/eimmortal/config.toml
chmod 600 ~/.config/eimmortal/config.toml
$EDITOR ~/.config/eimmortal/config.toml

# 3. 初始化（会打印 Armor Key，请存进密码管理器）
eimmortal init

# 4. 备份 / 查看 / 还原
eimmortal backup --source ~/Documents -m "日常增量" --exclude '*.log'
eimmortal log
eimmortal status
eimmortal restore /tmp/restore-check          # 省略 --at 即最新快照

# 5. 校验
eimmortal verify --deep
eimmortal doctor --chain            # 链、锚点、孤儿
eimmortal doctor --camouflage       # 伪装命名/文件头审计（06.7）

# 云端还没同步完？先看缺哪些 pack，再逐步恢复
eimmortal restore --list-packs
eimmortal restore /tmp/restore-check --skip-missing-packs
eimmortal restore /tmp/restore-check --wait-for-packs 5m

# 6. 回收已删除历史（旧库保持不动，验证后再手工删）
eimmortal compact --out /path/to/new-target
```

非交互（脚本 / CI）：

```bash
printf '%s' "$EIMMORTAL_PASSWORD" > /run/secrets/eimmortal && chmod 600 /run/secrets/eimmortal
eimmortal --password-file /run/secrets/eimmortal backup --source /data --json
```

## 文件布局

每个配置项（取值范围、默认值，以及当前版本尚未实现的项）都在 [config.example.toml](config.example.toml) 里有逐行注释。macOS 上请保留 `scan.ignore_xattr = true`，否则 `com.apple.provenance` 一类扩展属性会让 `backup` 直接以 E21 失败。

```text
~/.eimmortal/eimmortal-vault/     # 控制平面（0700）
  vault.meta                 # salt / KDF 参数 / auth_verifier / vault_id
  state.db                   # 缓存：seq 水位、锚点、路径 HMAC 索引
  lock                       # flock
  RECOVERY.txt               # 可打印的恢复须知

<TargetDir>/                 # 网盘同步的根目录
  .tmp/                      # 同卷暂存区（原子换入）
  .eimmortal.lock            # 跨机写者记录（旧版 .apex.lock 仍被识别）
  output/                    # 真正被网盘同步的盲盒
    data/YYYY-MM/pack_*.dat  # 加密数据包（≤128 MiB）
    meta/00000001.journal    # 加密增量日志（哈希链）
    meta/manifests/*.manifest # 每个 pack 的加密记录（新备份生成）
```

每个 pack 都会在 `output/meta/manifests/` 下生成一个加密 manifest，记录该 pack 的切片和涉及的文件。`eimmortal manifest <pack>` 可以查看它；旧库没有 manifest 时会自动忽略。

旧布局（`data/`、`meta/` 直接在 `<TargetDir>/` 下）仍然能读。想切到新布局，停止所有 eimmortal 进程后执行：

```bash
cd /Volumes/Backups/quark-backup
mkdir output
mv data meta output/
eimmortal doctor
```

如果网盘客户端同步整个 `<TargetDir>`，`.tmp` 和 lock 仍会被它看到；把同步范围指向 `<TargetDir>/output`（或排除 `.tmp` 与 `.eimmortal.lock`）即可让云端只看到盲盒内容。lock 只在写入期间存在。

macOS Finder 可能在 `<TargetDir>/` 顶层生成 `.DS_Store`；它不含备份内容，程序会忽略它，不会因此中断备份。

## 安全边界（请务必读）

1. **主密码不可更改**。忘记 = 永久无法恢复；唯一补救是 `compact --new-identity` 重建全库。
2. **Armor Key 与密码必须分开存放**，且都不要放进 TargetDir 或任何同步目录。
3. **不做去重**：同一文件改一版就多占一份空间，这是不可变追加的固有代价。
4. **单写者**：同一 TargetDir 只允许一个 eimmortal 进程/主机写入（flock + `.eimmortal.lock` + 严格 seq）。
5. **不支持项 fail-fast**：硬链接、xattr/ACL（`com.apple.*`、`security.*` 等）、设备文件/FIFO/socket、非法 UTF-8 路径、超长路径、大小写折叠冲突都会直接报错（退出码 21）。xattr 可用 `scan.ignore_xattr = true` 显式降级；macOS 的 ACL 与资源分叉不在 xattr 接口内，属于已知缺口。
6. **不看网盘状态**：程序无法感知同步是否完成；跨机恢复用 `verify --size` 确认 pack 齐了再 restore。

## 压缩

所有内容在**加密之前**压缩（zstd），每个切片独立压缩，因此随机读取不需要解压整包。压缩参数可调：

| 级别 | 相对速度 | 相对体积 | 适用 |
|---|---|---|---|
| 1–3 | 最快 | 较大 | 追速度的日常增量 |
| **5（默认）** | 快 | 中 | 规格默认值 |
| 9 | 中 | 小 5–15% | 文档 / 源码为主 |
| 19 | 慢（约 1/10 吞吐） | 最小 | 只写一次的长期归档 |

- 已压缩数据（JPEG / MP4 / ZIP / 密文）会被 64 KiB 采样探测识别，直接以 `codec=none` 存储，不浪费 CPU。
- 日志（journal）同样压缩；zstd 帧 CRC 已关闭——每个切片已有 Poly1305 与 `plain_sha256`，重复校验只增加字节与 CPU。
- `eimmortal backup` 会打印 `明文 → 落盘（比例）`，`--json` 中为 `plain_bytes` / `pack_bytes`。
- `eimmortal status --chain` 会给出 `Logical`（明文总量）与当前压缩比（`bytes.logical_source`）。
- 临时覆盖：`eimmortal backup --zstd-level 9`、`eimmortal compact --zstd-level 19`。
- **已有库想压缩得更小**：`eimmortal compact --out <新目录> --zstd-level 19` 会按新级别重新打包整个快照（旧库不改动，验证后再删）。

## 性能（本机实测，128 MiB 不可压缩数据）

| 场景 | 吞吐 |
|---|---|
| 增量 backup（新数据） | ≈ 280 MiB/s |
| restore（全量） | ≈ 420 MiB/s |
| 链加载（1000 次提交 / 1 万 op） | ≈ 57 ms |

跑法：`EIMMORTAL_PERF_TEST=1 go test ./internal/pipeline -run TestPerformanceBaseline -v`；规模测量：`make scale-test`。

## 退出码（稳定契约）

| 码 | 含义 |
|---|---|
| 0 | 成功（含"无变更"） |
| 2 | 用法 / 参数 / 配置错误 |
| 10 | 密码错误或 vault.meta 损坏（不区分） |
| 11 | 链断裂 / 回滚 / 截断 |
| 12 | 数据损坏 / 格式非法 / Armor CRC 失败 |
| 13 | 数据不完整（pack 缺失、可能未同步完成） |
| 20 | 锁被占用 / 并发写者 |
| 21 | 不受支持的内容 |
| 130 | 被 SIGINT 中断 |

## 开发

```bash
make build     # 构建 bin/eimmortal
make test      # go test ./...
make vet       # go vet ./...
make fuzz      # 15s 级 fuzz（FUZZTIME 可覆盖）
make golden    # 校验 golden vectors
```

- golden vectors 在 `testdata/golden/`，由 `go run ./tools/goldengen` 生成。**改动任何一个字节都意味着线格式或依赖行为变了**，必须显式评估是否升 wire version。
- 若本机全局 Go 缓存不可写（受限环境），用仓库内缓存：`export GOCACHE=$PWD/.cache/go-build GOMODCACHE=$PWD/.cache/gomod GOSUMDB=off`。
- CI 分层见 [.github/workflows/ci.yml](.github/workflows/ci.yml)：push 跑 gofmt/vet/全量测试/崩溃矩阵/golden，夜间跑 3×30 min fuzz，另有三平台编译与 Windows 核心单测。
- 实现级决策见 [docs/dev/decisions.md](docs/dev/decisions.md)（ADR-001…），待决策事项见 [docs/dev/open-questions.md](docs/dev/open-questions.md)。

## 发布

推送 `v*` 标签会触发 [.github/workflows/release.yml](.github/workflows/release.yml)，自动完成：

- 跑 `go vet ./...` 与 `go test ./...`
- 交叉编译 linux/darwin 的 amd64/arm64 与 windows/amd64（`CGO_ENABLED=0`）
- 把二进制、`README.md`、`config.example.toml` 打包成 `tar.gz`（Windows 为 `zip`）
- 生成 `checksums.txt`（SHA-256）
- 用 GitHub 自动生成的 release notes 创建 Release；带 `-` 的标签（如 `v0.1.0-rc.1`）自动标记为 prerelease
- 版本号通过 `-ldflags "-X main.version=<tag>"` 注入，`eimmortal version` 显示去掉 `v` 后的版本

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

想先在本地看产物：`make release-snapshot`，输出在 `dist/`，不会影响远端。

## 许可证

未定（待补）。