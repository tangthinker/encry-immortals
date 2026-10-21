# 使用指南

本文覆盖安装、配置、备份、恢复、校验和日常命令。运维策略（定时任务、云端同步、灾备演练、容量与压缩）见 [operations.md](operations.md)。

## 1. 安装

### 从 Release 安装

在 [Releases](https://github.com/tangthinker/encry-immortals/releases) 下载对应平台的压缩包（Linux/macOS amd64/arm64、Windows amd64），解压后把 `eimmortal` 放进 `PATH`：

```bash
tar -xzf eimmortal_<version>_darwin_arm64.tar.gz
sudo install -m 755 eimmortal_<version>_darwin_arm64/eimmortal /usr/local/bin/eimmortal
eimmortal version
```

### 从源码构建

需要 Go 1.26+：

```bash
git clone https://github.com/tangthinker/encry-immortals.git
cd encry-immortals
make build          # 产物 bin/eimmortal
sudo install -m 755 bin/eimmortal /usr/local/bin/eimmortal
```

## 2. 目录与配置

### 两个平面

| 平面 | 默认位置 | 是否进网盘 |
|---|---|---|
| 控制平面 | `~/.eimmortal/eimmortal-vault/` | **绝不** |
| 配置 | `~/.config/eimmortal/config.toml` | 否 |
| 数据平面（TargetDir） | 配置里的 `target_dir` | 是，同步 `<TargetDir>/output/` |

控制平面含 `vault.meta`（salt/KDF 参数/auth_verifier/vault_id）、`state.db`（seq 水位、锚点、路径 HMAC 索引）、`RECOVERY.txt`。**它绝不能放进任何同步目录**，否则多台机器会共享锁和状态。

### 写配置

```bash
mkdir -p ~/.config/eimmortal
cp config.example.toml ~/.config/eimmortal/config.toml
chmod 600 ~/.config/eimmortal/config.toml
$EDITOR ~/.config/eimmortal/config.toml
```

最少改 `[storage] target_dir`。所有配置项都有逐行注释，见 [../config.example.toml](../config.example.toml)。

```toml
[storage]
target_dir = "/Users/me/QuarkDrive/eimmortal"

[scan]
# macOS 必须（否则 com.apple.provenance 会让 backup 直接 E21）
ignore_xattr = true
```

注意：

- 配置文件权限必须是 `0600`，否则拒绝启动。
- `target_dir` 不能是源目录本身，也不能与源目录互相包含。
- 配置文件里**不能**出现 `password` / `passphrase` / `secret` 等字段。
- `[vault] dir` 默认 `~/.eimmortal/eimmortal-vault`，一般不用写。

### TargetDir 布局

```text
<TargetDir>/
  .tmp/                       # 同卷暂存区，留在根目录
  .eimmortal.lock             # 写锁，写入期间存在
  output/                     # 给网盘同步的盲盒
    data/YYYY-MM/pack_*.dat
    meta/00000001.journal
    meta/manifests/*.manifest
```

新库使用 `output/`。旧库如果 `data/`、`meta/` 直接在根目录，会自动识别并继续工作；迁移见 [migration.md](migration.md)。如果网盘客户端同步整个 `<TargetDir>`，请排除 `.tmp/` 和 `.eimmortal.lock`，或直接把同步范围设为 `<TargetDir>/output`。

## 3. 初始化

```bash
eimmortal init
```

- 交互输入两遍主密码（不回显）。
- 主密码至少 12 字节；更短会被视为弱密码，需要 `--accept-weak-password` 显式确认。推荐 4 个以上随机单词。
- KDF 会校准一次并冻结：Argon2id，内存峰值约 1 GiB，解锁耗时约 1–2 秒。
- 初始化会打印 **Armor Key**（`EIMMORTAL-KEY-V2-…`）。立刻存进密码管理器，并打印/手抄一份。
- **主密码不可更改**。忘记 = 永久无法恢复；唯一补救是用 `compact --new-identity` 重建全库。

加入已有库（第二台机器 / 灾备）：

```bash
eimmortal init --join /path/to/target
eimmortal import-key --key-file ~/armor-key.txt   # 或从 stdin 粘贴
```

## 4. 备份

```bash
eimmortal backup --source ~/Documents -m "日常增量"
eimmortal backup --source ~/Documents --dry-run          # 只扫描，不落盘
eimmortal backup --source ~/Documents --exclude '*.log'  # 可重复
eimmortal backup --source ~/Documents --strict           # 全量 hash 比对
eimmortal backup --source ~/Documents --zstd-level 9     # 临时覆盖压缩级别
```

行为：

- 增量：用 mtime + size 判断变化；`--strict` 忽略 mtime 做内容 hash 比对。
- 只有变化才产生新提交；没有变化输出 `no changes`，退出码 0。
- **一个 TargetDir 只对应一个源根目录**。不要今天备份 `~/Documents`、明天备份 `~/Pictures` 到同一个库；要备份多个目录，请备份它们的共同父目录。
- `session_max_mib`（默认 256）限制**单次 backup 写入的明文总量**。达到上限后，本次提交截断，剩余文件留给下次；被跳过的文件会汇总提示。
- **如果单个文件大于 `session_max_mib`，它永远不会被写入**（每次都会被跳过）。要么把 `session_max_mib` 调到大于最大文件，要么用 `--exclude` 排除它。
- 首次全量备份大目录时，建议临时把 `session_max_mib` 调大（例如 `10240`），或分多次运行直到不再出现截断提示。
- 备份进度和吞吐（`MiB/s`）输出到 stderr；`--json` 的结果数据在 stdout。

macOS 上 Finder 可能在 TargetDir 顶层生成 `.DS_Store`，程序会忽略它；其他扩展属性（xattr/ACL）默认 fail-fast，可用 `scan.ignore_xattr = true` 显式接受降级。

## 5. 查看与查询

```bash
eimmortal status                 # 水位、锚点、容量、健康度（不需要密码）
eimmortal status --chain         # 额外计算引用/孤儿/缺失并校验锚点（需要密码）
eimmortal log                    # 提交历史（需要密码）
eimmortal show 2                 # 某次提交的变更明细
eimmortal ls --at 2              # 快照文件树
eimmortal ls docs --at 2         # 只看某个前缀
eimmortal cat readme.txt --at 2  # 输出某文件内容，不落盘
```

`ls` / `cat` 的快照号用 `--at`，不是位置参数。

## 6. 恢复

```bash
eimmortal restore /tmp/eimmortal-restore              # 最新快照
eimmortal restore /tmp/eimmortal-restore --at 1       # 指定快照
eimmortal restore /tmp/eimmortal-restore --dry-run    # 只统计
eimmortal restore /tmp/eimmortal-restore --overwrite if-changed
```

- 默认 `--overwrite never`：目标已存在同名文件就跳过，不覆盖。
- 建议还原到空目录或尚不存在的目录；确认内容后再替换原目录。
- 中断后重跑同一条命令会断点续解（目标目录里的 `.eimmortal-restore-progress` 记录进度）；全部完成后该文件删除。
- `restore` 会每秒打印进度、字节百分比和当前文件；进度在 stderr。
- `restore` 本身不做回滚检测；怀疑云端被回滚时先跑 `doctor --chain`。

### 逐步下载 / 渐进恢复

journal 很小，先全部同步；pack 很大，可以按需下载：

```bash
# 1. 看快照需要哪些 pack、大小、文件数、是否已下载
eimmortal restore --list-packs

# 2. 已下载的 pack 先恢复；缺 pack 的文件跳过并列出来
eimmortal restore /tmp/eimmortal-restore --skip-missing-packs

# 3. 补齐一些 pack 后重跑，已恢复的文件会跳过
eimmortal restore /tmp/eimmortal-restore --skip-missing-packs

# 4. 全部 pack 齐了，最后一次退出码 0
eimmortal restore /tmp/eimmortal-restore --skip-missing-packs
```

- 缺 pack 时退出码是 **13**；这不是数据损坏，而是"还不完整"。
- 想等同步完成，也可以 `--wait-for-packs 5m`；不要和 `--skip-missing-packs` 同时依赖。
- 每个 pack 都有一个加密 manifest，记录它包含的切片和文件：

```bash
eimmortal manifest output/data/2026-10/pack_1792342339377_vpal8n.dat
eimmortal --json manifest pack_1792342339377_vpal8n
```

旧库的旧 pack 没有 manifest；`--list-packs` / `--skip-missing-packs` 仍从 journal 计算，只有 `manifest` 命令会提示没有记录。新 backup 和 `compact` 会生成 manifest。

## 7. 校验与维护

```bash
eimmortal verify                    # 默认按大小/引用校验
eimmortal verify --sample 8         # 随机抽 8 个 pack 做整包 SHA-256
eimmortal verify --deep             # 全量解密逐切片（最慢）
eimmortal verify --at 3             # 只校验到 seq=3

eimmortal doctor                    # 结构自检
eimmortal doctor --chain            # 链、序号、锚点、孤儿、白名单
eimmortal doctor --camouflage       # 伪装命名/文件头审计

eimmortal gc --dry-run              # 看 .tmp 残留、孤儿 pack/manifest
eimmortal gc --prune-orphans --yes  # 真删孤儿（不可逆）

eimmortal rebuild-state             # state.db 丢失/换机后从 journal 重建

eimmortal compact --out /path/to/new-target --zstd-level 19
eimmortal compact --out /path/to/new-target --new-identity
```

`compact` 会生成一个只含当前快照的新库，**旧库不动**；验证新库后再手工删旧库。`--new-identity` 会换 salt/vault_id，之后必须重新 `export-key`。

## 8. 非交互 / 脚本

```bash
# 密码文件必须是 0600
install -m 600 /dev/null /etc/eimmortal.pw
printf '%s' "$EIMMORTAL_PASSWORD" > /etc/eimmortal.pw

eimmortal --password-file /etc/eimmortal.pw backup --source /data --json
```

也支持 `--password-fd <n>` 和 `EIMMORTAL_PASSWORD_FD`。**不存在也不允许** `--password 明文`。

- `--json` 的结果走 stdout，人类进度走 stderr，可以直接 `| jq`。
- 危险操作（`gc --prune-orphans`、`compact` 覆盖）在非 TTY 下需要显式 `--yes`。

## 9. 退出码（稳定契约）

| 码 | 含义 | 脚本建议 |
|---|---|---|
| 0 | 成功（含"无变更"） | |
| 1 | 未分类错误 | 看 stderr |
| 2 | 用法 / 参数 / 配置错误 | 修命令 |
| 10 | 密码错误或 `vault.meta` 损坏（不区分） | 让用户重输 |
| 11 | 链断裂 / 回滚 / 截断 | 停止，人工介入 |
| 12 | 数据损坏 / 格式非法 / Armor CRC 失败 | 停止，跑 `verify --deep` |
| 13 | 数据不完整（pack 缺失，可能未同步完） | 同步后重跑；或渐进恢复 |
| 14 | 本地磁盘空间不足 | 清理后重试 |
| 20 | 锁被占用 / 并发写者 | 检查另一进程/主机 |
| 21 | 不受支持的内容（硬链接/xattr/设备文件等） | 调整参数或排除 |
| 130 | 被 SIGINT 中断 | 幂等重跑 |

## 10. 常用命令总览

| 命令 | 作用 | 需要密码 |
|---|---|---|
| `init` / `init --join` | 初始化 / 加入已有库 | 是 / 否 |
| `backup --source <dir>` | 增量备份 | 是 |
| `restore <dest>` | 还原（`--at`、`--skip-missing-packs`） | 是 |
| `log` / `show <seq>` | 提交历史 / 变更明细 | 是 |
| `ls [path] --at <seq>` / `cat <path> --at <seq>` | 查看快照 / 输出文件 | 是 |
| `status` / `status --chain` | 水位与健康度 / 链统计 | 否 / 是 |
| `verify` / `doctor` | 校验 / 自检 | 是（`doctor` 结构检查部分否） |
| `manifest <pack>` | 查看某个 pack 的记录 | 是 |
| `export-key` / `import-key` | 导出 / 导入 Armor Key | 是 / 否 |
| `gc` / `compact` / `rebuild-state` | 清理 / 重建 / 重建缓存 | 是 |
| `note <msg>` | 写一条纯注释 journal | 是 |
| `version` | 版本号 | 否 |

每个命令都支持 `eimmortal <command> --help`。
