# eimmortal（encry-immortals）

[![CI](https://github.com/tangthinker/encry-immortals/actions/workflows/ci.yml/badge.svg)](https://github.com/tangthinker/encry-immortals/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tangthinker/encry-immortals?display_name=tag)](https://github.com/tangthinker/encry-immortals/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/tangthinker/encry-immortals)](go.mod)

**端到端加密的不可变追加式增量备份工具。** 面向「把备份丢进网盘，但完全不想让网盘看懂」这一场景：文件内容、文件名、目录结构都加密后再同步，云端只看到 pack、journal 和 manifest 这些密文文件。

> 适合用 iCloud Drive、Dropbox、OneDrive、夸克、坚果云等同步备份，但不信任云盘能读到内容的人。
> 也适合想要「备份只追加、不被同步客户端改坏、还能验证完整性」的场景。

## 特性

- **端到端加密**：Argon2id → HKDF-SHA256 → XChaCha20-Poly1305；密钥和主密码永不进入同步目录。
- **纯追加、不可变**：已写出的 pack 永不修改、永不删除；删除只在 journal 里留墓碑。网盘客户端只会看到「新文件出现」。
- **增量 + 快照**：按 mtime/size 增量，`--strict` 可全量 hash 比对；`restore --at <seq>` 回到任意历史提交。
- **可验证**：SHA-256 哈希链 + 本地锚点 + `verify` / `doctor`；能发现 pack 损坏、链断裂和云端回滚。
- **渐进恢复**：每个 pack 有独立加密 manifest，`restore --list-packs` 看缺哪些 pack，`--skip-missing-packs` 边下边恢复。
- **可审计的恢复演练**：断点续解、`verify --deep`、`doctor --chain`、`compact` 重建。
- **纯 Go、单二进制**：Linux / macOS / Windows；无守护进程，`backup` 由 cron/launchd 或手工触发。

## 工作原理

```text
源目录 ──scan/hash──► eimmortal backup ──encrypt──► <TargetDir>/
                                                       data/YYYY-MM/pack_*.dat
                                                       meta/00000001.journal
                                                       meta/manifests/*.manifest
                                                       .eimmortal.lock
                                                              │
                                                              │ 网盘同步（只看得到密文）
                                                              ▼
                                      ~/.eimmortal/eimmortal-vault/
                                        vault.meta / state.db / RECOVERY.txt
                                        （控制平面，绝不同步）
```

- **pack** 是数据块（≤128 MiB），只追加。
- **journal** 是提交记录，记录 ADD/MODIFY/DELETE/MKDIR 等操作和 pack 指纹；多个 journal 用哈希链串起来。
- **manifest** 是每个 pack 的加密小索引，记录这个 pack 里有哪些文件/切片，用于渐进恢复。
- **锚点** 保存在本地 `state.db`，用来发现云端把 journal 回滚到旧版本。
- **控制平面与数据平面分离**：`vault.meta`、`state.db` 只在本地，TargetDir 只有密文。

## 快速开始

### 1. 安装

从 [Releases](https://github.com/tangthinker/encry-immortals/releases) 下载对应平台的压缩包，解压后安装：

```bash
sudo install -m 755 eimmortal /usr/local/bin/eimmortal
eimmortal version
```

或从源码构建（Go 1.26+）：

```bash
git clone https://github.com/tangthinker/encry-immortals.git
cd encry-immortals
make build
sudo install -m 755 bin/eimmortal /usr/local/bin/eimmortal
```

### 2. 写配置

```bash
mkdir -p ~/.config/eimmortal
cp config.example.toml ~/.config/eimmortal/config.toml
chmod 600 ~/.config/eimmortal/config.toml
$EDITOR ~/.config/eimmortal/config.toml
```

至少把 `[storage] target_dir` 改成你的网盘目录，例如：

```toml
[storage]
target_dir = "/Users/me/QuarkDrive/eimmortal"
```

- 配置项逐行说明见 [config.example.toml](config.example.toml)。
- macOS 请保留 `scan.ignore_xattr = true`，否则 `com.apple.provenance` 一类属性会让 backup 直接报 E21。
- 暂存区在 TargetDir 同级的 `<TargetDir>.tmp`；如果客户端同步的是 TargetDir，它不会被带进去；如果同步的是父目录，请排除它，或用 `storage.staging_dir` 指到同卷、同步范围外的路径。lock 只在写入期间出现在 TargetDir 根目录。

### 3. 初始化

```bash
eimmortal init
```

会输入两遍主密码，并打印 **Armor Key**。把 Armor Key 存进密码管理器，并和主密码分开保存。

- 主密码不可更改；忘记 = 永久无法恢复。
- 解锁 KDF 内存峰值约 1 GiB，耗时约 1–2 秒。
- 恢复须知写在 `~/.eimmortal/eimmortal-vault/RECOVERY.txt`。

### 4. 备份

```bash
eimmortal backup --source ~/Documents --dry-run          # 先看会改什么
eimmortal backup --source ~/Documents -m "首次备份"
```

- 只有变化才产生新提交；没有变化输出 `no changes`。
- 一个 TargetDir 只对应一个源根目录；多目录请备份共同父目录。
- 默认 `session_max_mib = 256` 限制单次写入量；首次全量可调大，或分多次跑。

### 5. 查看与校验

```bash
eimmortal status
eimmortal log
eimmortal verify --sample 8
eimmortal doctor --chain
```

### 6. 恢复演练

```bash
eimmortal restore /tmp/eimmortal-restore
```

建议先还原到空目录，确认内容后再替换原目录。**不做恢复演练的备份不算备份。**

## 渐进恢复（边下载边恢复）

云端还没同步完也可以先恢复已下载的部分：

```bash
# 看快照需要哪些 pack、是否已下载
eimmortal restore --list-packs

# 已下载的先恢复，缺 pack 的文件跳过并列出（退出码 13）
eimmortal restore /tmp/eimmortal-restore --skip-missing-packs

# 补齐 pack 后重跑，已恢复的文件会跳过
eimmortal restore /tmp/eimmortal-restore --skip-missing-packs

# 全部齐了，退出码 0
```

每个 pack 的加密记录可以单独查看：

```bash
eimmortal manifest data/2026-10/pack_1789..._abc123.dat
```

## 常用命令

| 命令 | 作用 |
|---|---|
| `init` / `init --join <TargetDir>` | 初始化 / 加入已有库 |
| `backup --source <dir>` | 增量备份（`--dry-run`、`--exclude`、`--strict`） |
| `restore <DestDir>` | 还原（`--at`、`--overwrite`、`--wait-for-packs`、`--skip-missing-packs`） |
| `log` / `show <seq>` | 提交历史 / 变更明细 |
| `ls [path] --at <seq>` / `cat <path> --at <seq>` | 查看快照 / 输出文件 |
| `status` / `status --chain` | 水位、锚点、容量、链统计 |
| `verify` / `doctor` | 完整性 / 一致性自检 |
| `manifest <pack>` | 查看某个 pack 的加密记录 |
| `export-key` / `import-key` | Armor Key 导出 / 导入 |
| `gc` / `compact` / `rebuild-state` | 清理孤儿 / 重建库 / 重建缓存 |
| `note <msg>` | 写一条纯注释 journal |

完整参数、退出码、非交互用法见 [docs/usage.md](docs/usage.md)。

## 安全边界（请务必读）

1. **主密码不可更改**。忘记 = 永久无法恢复；唯一补救是 `compact --new-identity` 重建全库。
2. **Armor Key 与主密码必须分开存放**，且都不要放进 TargetDir 或任何同步目录。
3. **云端仍能看到元数据**：pack/journal 的数量、大小、写入时间和同步模式可见；保护的是内容、文件名和目录树，不是「你在备份」这件事。
4. **不做去重**：同一文件改一版就多占一份空间，这是不可变追加的代价。
5. **单写者**：同一 TargetDir 只允许一个进程/主机写入；不要两台机器同时写。
6. **不支持项 fail-fast**：硬链接、xattr/ACL、设备文件/FIFO/socket、非法 UTF-8、超长路径、大小写冲突等默认直接报错（E21）；xattr 可用 `scan.ignore_xattr = true` 显式降级。
7. **不感知网盘状态**：程序不知道同步是否完成；跨机恢复前先 `verify --size`，或用渐进恢复。

更完整的威胁模型和密钥管理见 [docs/security.md](docs/security.md)。

## 项目状态

当前是 **0.1.x 早期版本**。建议先在小数据集上完整跑通「备份 → 校验 → 空目录恢复 → 对比」，再用于重要数据。

| 能力 | 状态 |
|---|---|
| `init` / `backup` / `restore` / 快照穿梭 / 断点续解 | ✅ |
| `log` / `show` / `ls` / `cat` / `status` / `verify` / `doctor` / `gc` | ✅ |
| `compact`（含 `--new-identity`）/ `rebuild-state` / `note` | ✅ |
| 每 pack manifest / 渐进恢复 / 进度与吞吐 | ✅ |
| checkpoint journal | ⏳ v1 不生成（链加载实测 1000 次提交约 57 ms） |
| `watch` / `mount` / 改密码 / 去重 / eviction | ❌ 规范明确不做 |

## 文档

| 文档 | 内容 |
|---|---|
| [docs/usage.md](docs/usage.md) | 安装、配置、命令、退出码、非交互、渐进恢复 |
| [docs/operations.md](docs/operations.md) | 定时备份、云端同步、校验节奏、灾备、容量/压缩/性能 |
| [docs/security.md](docs/security.md) | 威胁模型、密钥管理、已知限制 |
| [docs/migration.md](docs/migration.md) | 旧 `output/` 布局迁回根目录、apex 旧名兼容、升级检查 |
| [docs/development.md](docs/development.md) | 构建、测试、CI、发布、贡献 |
| [config.example.toml](config.example.toml) | 所有配置项和默认值 |
| [docs/spec/](docs/spec/README.md) | 字节级格式、协议、崩溃恢复、验收标准 |
| [docs/dev/](docs/dev/README.md) | ADR、执行日志、待决问题 |
| [docs/tech.md](docs/tech.md) | 产品级设计（是什么 / 为什么） |

## 开发

```bash
make build     # bin/eimmortal
make test      # go test ./...
make vet       # go vet ./...
make fuzz      # 15s 级 fuzz（FUZZTIME 可覆盖）
make golden    # 校验 golden vectors
```

CI 分层见 [.github/workflows/ci.yml](.github/workflows/ci.yml)；推送 `v*` 标签会触发自动 Release。细节见 [docs/development.md](docs/development.md)。

## 许可证

尚未选择许可证。在许可证确定前，默认保留所有权利（All rights reserved）；使用/分发前请先联系作者。

---

如果这个项目对你有用，欢迎 Star、提交 Issue 或参与测试。最重要的贡献方式之一，是在你自己的数据上跑一次完整恢复演练并反馈结果。
