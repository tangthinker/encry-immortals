# 运维指南

本文覆盖定时备份、云端同步、校验节奏、灾备恢复、容量与压缩。命令细节见 [usage.md](usage.md)。

## 1. 定时备份

非交互需要 0600 密码文件：

```bash
install -m 600 /dev/null ~/.eimmortal/backup.pw
printf '%s' "$EIMMORTAL_PASSWORD" > ~/.eimmortal/backup.pw
```

cron 示例：

```cron
30 2 * * * /usr/local/bin/eimmortal --password-file /Users/me/.eimmortal/backup.pw \
  backup --source /Users/me/Documents -m nightly --json >> /Users/me/Library/Logs/eimmortal.log 2>&1
```

macOS 注意：

- `cron` / `launchd` 需要「完全磁盘访问权限」才能读 `~/Documents` 等目录。
- 更稳的是 launchd，把密码文件放在控制平面目录或独立 0600 文件中。
- 不要并发跑两个 `backup`；同一 TargetDir 只允许一个写者。

密码文件不要放进同步目录，也不要和 Armor Key 放一起。

## 2. 云端同步

程序**不感知**网盘同步状态：

- 写入成功只代表本地完成；云端何时同步完由客户端决定。
- 新机器恢复前先 `eimmortal verify --size` 确认 pack 齐全。
- 只有 `restore` 允许等待：`--wait-for-packs 5m`。
- 也可以渐进恢复：先同步 journal（很小），再用 `restore --list-packs` 和 `--skip-missing-packs` 边下边恢复。

同步范围：

```text
<TargetDir>/output/     ← 建议只同步这里
<TargetDir>/.tmp/       ← 本地暂存，排除
<TargetDir>/.eimmortal.lock  ← 写入期间的本地锁，排除
```

如果客户端只能同步整个 `<TargetDir>`，请在客户端排除 `.tmp/` 和 `.eimmortal.lock`。注意：只同步 `output/` 时，另一台机器看不到 `.eimmortal.lock` 这个跨机写者记录；跨机并发仍会被 journal 的严格 seq 在提交时发现，但不会提前阻止。

云盘客户端可能：

- 乱序上传/下载 → 恢复时按 journal 链和 pack 大小校验，不依赖到达顺序。
- 把文件驱逐出本地（如 iCloud「优化存储」）→ pack 缺失时 restore 报 E13，先下载或使用渐进恢复。
- 秒传/去重 → 不影响密文内容校验。
- 在目录里留下 `.DS_Store` 等系统文件 → 顶层白名单忽略普通 `.DS_Store`。

## 3. 校验节奏

不做恢复演练的备份不算备份。建议：

| 频率 | 动作 |
|---|---|
| 每次 backup 后 | 看退出码；`status` 看锚点/容量 |
| 每周 | `verify --sample 8` |
| 每月 | `doctor --chain`、抽查若干文件 `cat` 对比 |
| 每季度 | 空目录完整 `restore`，抽样比对内容、mode、mtime |
| 每半年 | 完整 restore 到外部磁盘一次 |
| 每年 | 用 Armor Key 重新 `import-key` 一次，证明抄件仍可用 |

`verify` 三档：

- `verify`：pack 存在性、大小与 journal 引用一致（默认，快）
- `verify --sample N`：随机抽 N 个 pack 做整包 SHA-256
- `verify --deep`：全量解密、逐切片校验（最彻底，最慢）

`doctor` 检查控制平面位置、TargetDir 白名单、布局（`output/` 或旧布局）、暂存区同卷/残留、journal 序号、哈希链、锚点、孤儿 pack。`doctor --camouflage` 额外检查扩展名和 pack 文件头。

## 4. 灾备恢复

需要三样东西，缺一不可：

1. TargetDir 里同步出去的 `output/data` + `output/meta`
2. Armor Key（`EIMMORTAL-KEY-V2-…`）
3. 主密码

新机器步骤：

```bash
eimmortal init --join /path/to/target
eimmortal import-key --key-file ~/armor-key.txt
eimmortal verify --size
eimmortal doctor --chain
eimmortal restore /data/restore --wait-for-packs 10m
```

如果 pack 很多、还没同步完：

```bash
eimmortal restore --list-packs
eimmortal restore /data/restore --skip-missing-packs
# 继续下载，重复直到退出码 0
```

恢复后建议再跑一次 `eimmortal verify --deep`，并抽查文件内容。

## 5. 容量、压缩与 compact

### 容量

- 不做去重：同一文件改一版就多占一份空间，这是不可变追加的固有代价。
- pack 上限 128 MiB；大文件按 32 MiB 切片。
- `session_max_mib` 限制单次写入的明文总量（默认 256 MiB），不是磁盘配额；单文件大于它时永远不会被写入。
- `status --chain` 会显示 `Logical`（明文总量）和当前压缩比。

### 压缩

压缩发生在**加密之前**，每个切片独立压缩，随机读取不需要解压整包。

| zstd 级别 | 相对速度 | 相对体积 | 适用 |
|---|---|---|---|
| 1–3 | 最快 | 较大 | 追速度的日常增量 |
| **5（默认）** | 快 | 中 | 均衡 |
| 9 | 中 | 小 5–15% | 文档 / 源码为主 |
| 19 | 慢（约 1/10 吞吐） | 最小 | 只写一次的长期归档 |

已压缩格式（JPEG / MP4 / ZIP / 密文）会被采样探测识别，直接以 `codec=none` 存储，不浪费 CPU。`backup --zstd-level 9` 和 `compact --zstd-level 19` 可以临时覆盖。

### 性能（本机实测，128 MiB 不可压缩数据）

| 场景 | 吞吐 |
|---|---|
| 增量 backup（新数据） | ≈ 280 MiB/s |
| restore（全量） | ≈ 420 MiB/s |
| 链加载（1000 次提交 / 1 万 op） | ≈ 57 ms |

跑法：`EIMMORTAL_PERF_TEST=1 go test ./internal/pipeline -run TestPerformanceBaseline -v`；规模测量：`make scale-test`。实际速度受磁盘、zstd 级别、文件类型影响。

### compact

`compact` 生成一个只含当前快照的新 TargetDir：

```bash
eimmortal compact --out /path/to/new-target --zstd-level 19
```

- 旧库保持不动；验证新库后再手工删除旧库。
- 会为新 pack 生成 manifest。
- `--new-identity` 会换 salt/vault_id，需要 `--new-vault`，之后必须重新 `export-key`。
- 适合回收已删除历史、重新压缩、换密钥身份。

## 6. 清理与排障

```bash
eimmortal gc --dry-run
eimmortal gc --prune-orphans --yes
```

`gc` 清理 `.tmp` 里超过 24h 的残留、从未被 journal 引用的孤儿 pack，以及孤儿 manifest；它**不会**删除云端文件。

常见错误：

| 错误 | 常见原因 | 处理 |
|---|---|---|
| E10 | 密码错 / `vault.meta` 损坏 | 确认密码；换机用 `import-key` |
| E11 | journal 缺失/被替换、回滚 | 停止写入，`doctor --chain`，从备份恢复 |
| E12 | pack 损坏、格式非法、TargetDir 顶层有非白名单条目 | 先看错误条目；`verify --deep` |
| E13 | pack 缺失/未同步完、渐进恢复未完成 | 同步后重试；`--wait-for-packs` 或 `--skip-missing-packs` |
| E14 | 本地磁盘满 | 清理空间 |
| E20 | 另一进程/主机在写 | 确认后 `--break-lock` |
| E21 | 硬链接、xattr、设备文件、外部符号链接等 | 排除或显式降级（见下） |

不支持的项默认 fail-fast：

- 硬链接：`scan.follow_hardlinks = "split"` 显式接受降级
- xattr/ACL：`scan.ignore_xattr = true`（macOS 建议）
- 稀疏文件：`scan.sparse_max_bytes`
- 外部符号链接：backup 默认直接拒绝，用 `--exclude` 排除；`restore --allow-external-symlink` 只影响快照里已经存在的绝对链接
- 设备文件/FIFO/socket、非法 UTF-8、超长路径、大小写折叠冲突：只能排除

## 7. 多机器与单写者

- 同一 TargetDir 只允许一个写者；本地用 flock + `.eimmortal.lock`，提交时用严格 seq 再检查一次。
- 换机器恢复用 `init --join` + `import-key`；不要复制 `state.db`，它只是缓存，`rebuild-state` 可以重建。
- 控制平面（`~/.eimmortal/eimmortal-vault`）每台机器各自一份，**绝不同步**。
- 如果只同步 `output/`，跨机锁文件不会出现在云端；不要让两台机器同时写同一个 TargetDir。
