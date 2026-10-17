# apex（encry-immortals）

**端到端加密的不可变追加式增量备份工具。** 面向"把备份丢进网盘，但完全不想让网盘看懂"这一场景。

- **数据平面**（TargetDir）只有密文：`data/**/pack_<ts>_<rand>.dat`、`meta/<seq>.journal`，没有密钥、没有明文、没有可读元数据。
- **控制平面**（`~/.config/apex-vault/`）保存 `vault.meta`、`state.db`，**绝不放进同步目录**。
- **纯追加**：已写出的 pack 永不修改、永不删除；删除只在 journal 里留墓碑。网盘客户端永远只看到"新文件出现"。
- **密码学**：Argon2id → HKDF-SHA256（4 把子密钥）→ XChaCha20-Poly1305；每个切片独立随机 nonce，AAD 绑定 pack_id/offset/index/txn_id/codec。
- **可审计**：哈希链 + 本地锚点 + `verify` / `doctor` / 恢复演练。

设计文档：母方案 [docs/tech.md](docs/tech.md)，实现规范 [docs/spec/](docs/spec/README.md)，开发记录 [docs/dev/](docs/dev/README.md)。

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
make build            # 产物：bin/apex

# 2. 配置（~/.config/apex/config.toml，权限 0600）
cat > ~/.config/apex/config.toml <<'EOF'
[storage]
target_dir = "/Users/me/QuarkDrive/apex"

[codec]
zstd_level = 5            # 1..22：文本多可调到 9，压缩更小但更慢
min_compress_bytes = 4096 # 小于该值的切片不压缩

[scan]
exclude = [".git/**", "node_modules/**", "*.tmp", ".DS_Store"]
EOF
chmod 600 ~/.config/apex/config.toml

# 3. 初始化（会打印 Armor Key，请存进密码管理器）
apex init

# 4. 备份 / 查看 / 还原
apex backup --source ~/Documents -m "日常增量" --exclude '*.log'
apex log
apex status
apex restore /tmp/restore-check --at-latest

# 5. 校验
apex verify --deep
apex doctor --chain            # 链、锚点、孤儿
apex doctor --camouflage       # 伪装命名/文件头审计（06.7）

# 云端还没同步完？只有 restore 允许等待
apex restore /tmp/restore-check --wait-for-packs 5m

# 6. 回收已删除历史（旧库保持不动，验证后再手工删）
apex compact --out /path/to/new-target
```

非交互（脚本 / CI）：

```bash
printf '%s' "$APEX_PASSWORD" > /run/secrets/apex && chmod 600 /run/secrets/apex
apex --password-file /run/secrets/apex backup --source /data --json
```

## 文件布局

```text
~/.config/apex-vault/        # 控制平面（0700）
  vault.meta                 # salt / KDF 参数 / auth_verifier / vault_id
  state.db                   # 缓存：seq 水位、锚点、路径 HMAC 索引
  lock                       # flock
  RECOVERY.txt               # 可打印的恢复须知

<TargetDir>/                 # 数据平面（可放网盘）
  .tmp/                      # 同卷暂存区（原子换入）
  .apex.lock                 # 跨机写者记录
  data/YYYY-MM/pack_*.dat    # 加密数据包（≤128 MiB）
  meta/00000001.journal      # 加密增量日志（哈希链）
```

## 安全边界（请务必读）

1. **主密码不可更改**。忘记 = 永久无法恢复；唯一补救是 `compact --new-identity` 重建全库。
2. **Armor Key 与密码必须分开存放**，且都不要放进 TargetDir 或任何同步目录。
3. **不做去重**：同一文件改一版就多占一份空间，这是不可变追加的固有代价。
4. **单写者**：同一 TargetDir 只允许一个 apex 进程/主机写入（flock + `.apex.lock` + 严格 seq）。
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
- `apex backup` 会打印 `明文 → 落盘（比例）`，`--json` 中为 `plain_bytes` / `pack_bytes`。
- `apex status --chain` 会给出 `Logical`（明文总量）与当前压缩比（`bytes.logical_source`）。
- 临时覆盖：`apex backup --zstd-level 9`、`apex compact --zstd-level 19`。

## 性能（本机实测，128 MiB 不可压缩数据）

| 场景 | 吞吐 |
|---|---|
| 增量 backup（新数据） | ≈ 280 MiB/s |
| restore（全量） | ≈ 420 MiB/s |
| 链加载（1000 次提交 / 1 万 op） | ≈ 57 ms |

跑法：`APEX_PERF_TEST=1 go test ./internal/pipeline -run TestPerformanceBaseline -v`；规模测量：`make scale-test`。

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
make build     # 构建 bin/apex
make test      # go test ./...
make vet       # go vet ./...
make fuzz      # 15s 级 fuzz（FUZZTIME 可覆盖）
make golden    # 校验 golden vectors
```

- golden vectors 在 `testdata/golden/`，由 `go run ./tools/goldengen` 生成。**改动任何一个字节都意味着线格式或依赖行为变了**，必须显式评估是否升 wire version。
- 若本机全局 Go 缓存不可写（受限环境），用仓库内缓存：`export GOCACHE=$PWD/.cache/go-build GOMODCACHE=$PWD/.cache/gomod GOSUMDB=off`。
- CI 分层见 [.github/workflows/ci.yml](.github/workflows/ci.yml)：push 跑 gofmt/vet/全量测试/崩溃矩阵/golden，夜间跑 3×30 min fuzz，另有三平台编译与 Windows 核心单测。
- 实现级决策见 [docs/dev/decisions.md](docs/dev/decisions.md)（ADR-001…），待决策事项见 [docs/dev/open-questions.md](docs/dev/open-questions.md)。

## 许可证

未定（待补）。