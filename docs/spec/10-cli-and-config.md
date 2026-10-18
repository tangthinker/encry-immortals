# 10 · 命令行与配置面（新增章节）

> 母方案没有定义命令面。命令面不是装饰——密码怎么传进来、失败怎么表达、脚本怎么判错，直接决定了这个工具在真实机器上是安全可用还是危险可用。

## 10.1 命令表

| 命令 | 作用 | 是否写 `TargetDir` |
|---|---|---|
| `apex init` | 初始化新 vault（生成 salt / vault_id / vault.meta，并派生校验 auth_verifier） | 否 |
| `apex init --join <TargetDir>` | 加入已有 TargetDir（等待 import-key） | 否 |
| `apex backup` | 执行一次增量备份 | **是** |
| `apex restore <DestDir>` | 还原（可 `--at <seq>`） | 否 |
| `apex log` | 列出提交历史（seq / 时间 / msg / 变更计数） | 否 |
| `apex show <seq>` | 查看某次提交的变更明细 | 否 |
| `apex ls <seq> [path]` | 以该快照的视角列出文件树 | 否 |
| `apex cat <seq> <path>` | 输出某文件在该快照下的内容（不落盘） | 否 |
| `apex verify` | 本地与"云端副本"的完整性校验 | 否 |
| `apex status` | 水位、锚点短码、容量、健康度、演练提醒 | 否 |
| `apex doctor` | 一致性自检（孤儿、链、锚点、目录白名单、同卷、控制平面位置） | 否 |
| `apex export-key` / `import-key` | Armor Key 导出 / 导入 | 否 |
| `apex gc` | 清理 `.tmp/` 残留；报告孤儿 | 是（仅 `.tmp/` 与可选孤儿） |
| `apex rebuild-state` | 从 journal 重建 `state.db` | 否 |
| `apex compact` | 生成一个全新的、只含当前快照的 vault | 是（新目录） |
| `apex note <msg>` | 写一条纯注释 journal（无 ops） | 是 |

**必须**：每个命令都支持 `--help`，且 help 中显式写出"该命令是否会修改 TargetDir"。

**必须**：不存在 `rekey` / `change-password` 命令。主密码不可变更（02 章 2.8）；更换口令的唯一途径是 `apex compact --new-identity`，且它改变 vault 身份、需要重新 export-key。

## 10.2 关键 flag

| flag | 命令 | 语义 |
|---|---|---|
| `--config <path>` | 全局 | 配置文件位置（默认 `~/.config/eimmortal/config.toml`） |
| `--vault <dir>` | 全局 | 控制平面目录（默认 `~/.eimmortal/eimmortal-vault`） |
| `--json` | 全局 | 输出机器可读 JSON 到 stdout；人类进度信息走 stderr |
| `--dry-run` | backup / restore / gc / compact | 只报告不落盘 |
| `--message <msg>` | backup | 提交信息（等同 `git commit -m`） |
| `--strict` | backup | 全量内容 hash 比对，不依赖 mtime |
| `--exclude <glob>` | backup | 可重复 |
| `--at <seq>` | restore / ls / show / cat | 快照穿梭 |
| `--anchor <短码>` | restore | 校验云端未回滚 |
| `--i-accept-unverified` | restore | 显式承担无法验证回滚的风险（07 章） |
| `--overwrite <never\|if-changed\|always>` | restore | 默认 `never` |
| `--accept-rollback` | restore / backup | 确认已知的 seq 回退 |
| `--break-lock` | backup | 清除 `.eimmortal.lock`（旧的 `.apex.lock` 一并清理） |
| `--password-fd <n>` / `--password-file <path>` | 全部需要密钥的命令 | 见 10.4 |
| `--jobs <n>` | verify / restore | 并发度 |

## 10.3 配置文件

`~/.config/eimmortal/config.toml`（权限 `0600`；**必须**拒绝 `0644`，避免被其他用户读到目标路径）：

~~~toml
[vault]
dir = "~/.eimmortal/eimmortal-vault"

[storage]
target_dir   = "/Users/me/QuarkDrive/eimmortal"
staging_dir  = ""              # 空 = <target_dir>/.tmp （推荐，见 01 章 D-06）
pack_max_bytes       = 134217728   # 128 MiB（D-08）
slice_plain_bytes    = 33554432    # 32 MiB
small_file_bytes     = 67108864    # 64 MiB
session_max_mib      = 256         # 单次 backup 上限，超出则分批

[codec]
zstd_level          = 5
min_compress_bytes  = 4096

[scan]
mode     = "fast"          # fast | strict
exclude  = [".git/**", "node_modules/**", "*.tmp", ".DS_Store"]
follow_hardlinks     = "error"     # error | split
ignore_xattr         = false
sparse_max_bytes     = 0           # 0 = 不支持稀疏文件（fail-fast）

[on_change_during_read]
strategy = "retry"         # retry | skip | fail（05 章 5.4）

[concurrency]
hashers      = 4
pack_writers = 2

[checkpoint]
every_commits = 256
max_age_days  = 30

[verify]
auto_strict_every = 30     # 每 N 次 backup 自动跑一次 strict
~~~

**必须**：配置里**永不出现**密码字段。若检测到 `password` / `passphrase` / `secret` 之类键，直接 `E2` 拒绝启动并提示用 `--password-fd`。

## 10.4 密码输入规范（**安全关键**）

| 规则 | 说明 |
|---|---|
| **禁止** `--password <明文>` | 会进入 shell 历史、进程列表（`ps`）、系统审计日志。**必须**不存在这个 flag |
| 默认 | 从控制终端读，无回显（`golang.org/x/term.ReadPassword`）；`init` 时读两次并要求一致 |
| 非交互 | `--password-fd <n>` 从指定 fd 读一行；或 `--password-file <path>`（**必须**校验该文件权限为 `0600` 且非常规路径） |
| 环境变量 | 支持 `APEX_PASSWORD_FD`，不支持 `APEX_PASSWORD=xxx` |
| 进程内 | 读入后立刻转成 `[]byte` 并锁定（02 章 2.10），用后清零；**禁止**转成 `string`（不可清零） |
| 提示语 | 固定 `请输入主密码：`，不回显也不回显 `*`（避免泄露长度） |

## 10.5 退出码

| 码 | 含义 | 脚本处理建议 |
|---|---|---|
| 0 | 成功（含"无变更"） | |
| 1 | 未分类错误 | 展示 stderr |
| 2 | 用法/参数/配置错误 | 修命令 |
| 10 | 密码错误或 `vault.meta` 损坏（**不区分**） | 让用户重输 |
| 11 | 链断裂 / 检测到回滚 / 检测到截断 | **停止**，人工介入 |
| 12 | 数据损坏（解密失败、明文 hash 不符、格式非法） | **停止**，考虑 `verify --deep` |
| 13 | 数据不完整（pack 缺失、可能未同步完成） | 等待同步后重试 |
| 14 | 本地磁盘空间不足 | 清理后重试 |
| 20 | 锁被占用 | 检查另一进程/主机 |
| 21 | 不受支持的内容（硬链接/xattr/稀疏/设备文件等，01 章 D-18） | 调整参数或排除 |
| 130 | 被 SIGINT 中断 | 幂等重跑即可 |

**必须**：退出码与错误是**稳定契约**，不得因版本升级而改变含义（只能新增）。

## 10.6 输出契约

- 人类可读输出 → **stderr**（进度、日志、警告）。
- 结果数据（`--json` 或默认的最终报告）→ **stdout**。
- 这样 `apex log --json | jq` 永远可用，而进度条不会污染管道。

`apex status --json` 的 schema（**必须**稳定）：

~~~json
{
  "schema": 1,
  "vault_id": "...",
  "last_seq": 42,
  "anchor_short": "A3F9-1C2D",
  "verified": true,
  "packs": { "local": 128, "referenced": 128, "orphan": 0, "missing": 0 },
  "bytes": {
    "pack_total": 16106127360,
    "journal_total": 8388608,
    "staging": 0,
    "logical_source": 214748364800
  },
  "tmp_entries": 0,
  "warnings": [],
  "last_drill_unix": 1772900000,
  "last_export_unix": 1772800000
}
~~~

## 10.7 错误消息规范

**必须**满足三条：说清发生了什么、说清影响范围、给出一条可直接执行的下一步。

| 反例 | 正例 |
|---|---|
| `解密失败` | `E12 切片解密失败：data/2026-03/pack_1773...dat 偏移 33554486 处 MAC 校验不通过。该 pack 可能被云端截断。建议：apex verify --deep --pack data/2026-03/pack_1773...dat` |
| `链错误` | `E11 哈希链断裂于 seq=37：00000037.journal 的 prev_hash 与 00000036.journal 不匹配。这通常意味着 00000036.journal 被替换或损坏。建议：apex doctor --chain` |
| `密码错误` | `E10 无法解封 vault.meta：密码错误，或 vault.meta 已损坏。建议：确认密码后重试；若刚更换过机器，请用 apex import-key 重新导入。` |

**禁止**：错误里出现"未知原因"、把 panic 栈直接抛给用户（`--debug` 时除外）、泄露密钥材料片段。

## 10.8 交互与非交互

- 所有可能进入脚本的命令必须支持完全非交互模式（`--json` + `--password-fd` + 无 TTY）。
- 危险操作（`gc --prune-orphans`、`--break-lock`、`compact` 覆盖）**必须**在 TTY 下要求输入 `yes`，非 TTY 下要求显式 `--yes`。
- **禁止**用 `[Y/n]` 默认回车即执行的模式处理破坏性操作。

## 10.9 待确认

1. 是否需要 `apex watch`（基于 fsnotify 的自动备份）？**结论**：v1 不做（01 章 1.5）。若做，**必须**是"周期触发 `backup` 子进程"而非常驻持有密钥。
2. 是否支持 `apex mount`（FUSE 只读挂载）？**结论**：不做。会引入常驻进程与内核依赖，且与"最小暴露面"冲突。
