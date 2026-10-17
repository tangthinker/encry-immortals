# 05 · 业务管线补充（对应母方案第五章）

> 母方案的 ASCII 流程图方向正确，但没定义"哪一步 fsync、崩溃在第几步会怎样、重跑会不会写出重复数据、源文件在读取中被改了怎么办"。本文把这些变成可实现的协议。

## 5.1 决策 D-07：提交协议（严格阶段表）

**必须**严格按此顺序执行。任一阶段失败，回滚范围仅限于该阶段自身的产物。

| 阶段 | 动作 | 必须的持久化 | 崩溃后的状态 |
|---|---|---|---|
| S0 | 取 `flock`、检查 `.apex.lock`、读 `vault.meta`、派生 MasterKey 与 4 把子密钥、`doctor` 预检 | — | 无副作用 |
| S1 | 扫描源目录，生成候选清单与 `txn_id` | — | 无副作用 |
| S2 | 打开 `Target/.tmp/pack_<...>.dat`，逐切片写入 | 每封一包：`f.Sync()` → `f.Close()` | `.tmp/` 内残片，孤儿清理回收 |
| S3 | `rename(.tmp/pack_X, data/YYYY-MM/pack_X)` | **`fsync(父目录 data/YYYY-MM)`** | 已出现的 pack 是完整的；若 rename 完成而目录未 fsync，掉电后可能丢失该 pack 而 journal 尚未写 → 无引用，安全 |
| S4 | 生成 journal 明文 → 压缩 → 加密；记录 `packs[]` 的 sha256（**此时 pack 已完整落盘**） | — | 无副作用 |
| S5 | 写 `Target/.tmp/<seq>.journal.tmp` | `f.Sync()` → `f.Close()` | 残片，孤儿清理回收 |
| S6 | `rename(.tmp/<seq>.journal.tmp, meta/<seq>.journal)` | **`fsync(父目录 meta)`** | **提交点**。此后数据可被任何 restore 读到 |
| S7 | 更新 `state.db`（水位、锚点、路径 HMAC 索引） | `PRAGMA synchronous=FULL` 或显式事务 + WAL checkpoint | state.db 落后 → 下次 backup 重新计算差异，会重复写 pack（浪费但正确）；见 5.3 |

**必须**：S3 的 `fsync(父目录)` 与 S6 的 `fsync(父目录)` 不可省略。`os.Rename` 只保证目录项在内存中替换，不保证落盘；不 fsync 目录时掉电可能让 rename 消失，而此时 journal 已写入 → 出现"journal 引用了不存在的 pack"。这是本系统**唯一**会造成数据不可恢复的失败模式，必须靠 fsync 目录消灭。

实现细节（Go）：

~~~go
func renameDurable(from, to string) error {
    if err := os.Rename(from, to); err != nil { return err }
    d, err := os.Open(filepath.Dir(to))
    if err != nil { return err }
    defer d.Close()
    return d.Sync()      // Linux: fsync(dirfd)；Windows: FlushFileBuffers 对目录需特殊处理，见 5.8
}
~~~

## 5.2 崩溃点分析表（12 章崩溃注入测试的期望值）

| Kill 点 | 磁盘上留下什么 | 下次 backup 行为 | 用户可见后果 |
|---|---|---|---|
| K1 写 pack 中 | `.tmp/pack_X` 残片 | 孤儿清理删除（>24h 或本次启动即清） | 无 |
| K2 pack 已 fsync 未 rename | 同上 | 同上 | 无 |
| K3 pack 已 rename，目录未 fsync | 可能回退为"无该 pack" | 无引用，无需处理 | 无 |
| K4 pack 已 rename + fsync，journal 未写 | `data/` 有孤儿 pack | **检测到并报告**；不自动删（可能用户想留着）；重跑时同一文件会再写一份 | 云盘多一份无效 pack |
| K5 journal 已写 `.tmp`，未 rename | `.tmp/<seq>.journal.tmp` | 孤儿清理 | 无 |
| K6 journal 已 rename，目录未 fsync | 可能回退为"无该 journal"，对应 pack 变孤儿 | 同 K4 | 无 |
| K7 journal 已提交，state.db 未更新 | 数据完整，缓存滞后 | 差异重算，会多写一份重复 pack | 云盘多一份冗余数据（**正确性无损**） |

**必须**：任何 kill 点之后，`apex doctor` 都能给出确定结论（`OK` / `ORPHAN_PACKS n` / `CHAIN_BROKEN`），不允许出现"未知状态"。

## 5.3 幂等性与孤儿

- `txn_id` 在 S1 生成，贯穿 pack 的 AAD 与 journal 的 body。重跑同一次备份会得到**新的** `txn_id`，因此重复写出的 pack 在密码学上不可互换——这正是我们想要的：不需要去重，只需要"不出错"。
- **孤儿 pack 定义**：`data/` 中存在但没有任何 journal 的 `packs[]` 引用它。
- `apex gc` 只做三件事，且**全部是本地操作**：
  1. 清理 `.tmp/` 中 mtime > 24h 的残留；
  2. 报告（不删除）孤儿 pack 列表与总字节数；
  3. 报告 `meta/` 中无法解密的文件（密码错或损坏），不删除。
- **必须**：`gc --prune-orphans` 需要 `--yes` 二次确认，且只删**本地**文件。删云端由用户自己决定——程序不去碰网盘。
- 是否有"目标目录自己写出孤儿"的可能？会。因此孤儿判定必须在**完整读过所有 journal** 之后做，不能在增量扫描中间态做（否则会把刚写完还没被 journal 引用的 pack 误判为孤儿）。这条是 `gc` 最容易写错的地方。

## 5.4 变更检测

| 模式 | 判据 | 用于 |
|---|---|---|
| `fast`（默认） | `(size, mtime_ns)` 与 state.db 一致则跳过 | 日常 |
| `strict` | 额外算内容 SHA-256 比对 | `--strict` 或定期校对 |

**必须**注意 `fast` 的漏检场景，并在 `--help` 中写明：`tar` / `unzip` / `cp -p` / 部分同步工具会**保留 mtime**，内容变了而 size 恰好相同（等长替换）时 `fast` 检测不到。缓解：
- `backup` 每 N 次（默认 30）自动跑一次 `strict`；
- `apex verify --deep` 可随时全量校验。

### 读取期一致性（母方案未覆盖，**必须**补）

大文件（>32 MiB）读取耗时可达数秒，期间源文件可能被改写。**必须**在读取每个文件前后各做一次 `stat`，比对 `(size, mtime_ns, ctime_ns, inode)`：

~~~text
st1 := stat(path)
if 读到的字节数 != st1.size:            → STALE，跳过该文件
st2 := stat(path)
if st1 与 st2 的 (size, mtime, ctime, inode) 任一不同:  → STALE
~~~

处理策略（三选一，**必须**在配置里定死）：
- `retry`（默认）：重试最多 3 次，间隔 200ms/500ms/1s；
- `skip`：记录一条 warning，该文件本次不备份（下次会再被 `fast` 判定为变动）；
- `fail`：整体失败，退出码 12。

**禁止**把"读的过程中变了"的数据写进 pack 并声称成功——那会产出一个 checksum 自洽但内容拼错的快照，是最难排查的 bug。

## 5.5 并发与内存

| 阶段 | 并发度 | 默认 |
|---|---|---|
| 扫描 + stat | 1（顺序） | 单线程；IO 密集，并发收益低且难保证顺序稳定 |
| 内容哈希（strict 模式） | N | `concurrency.hashers = 4` |
| 压缩 + 加密 | M | `concurrency.pack_writers = 2`；每个 writer 一个独立 pack |
| pack 写入 | 每个 writer 串行 | 结构上串行是必须的（offset 必须连续） |

内存上限：`pack_writers × (slice_plain_bytes × 2 + 16 MiB)`。默认 `2 × 80 MiB = 160 MiB`，加上 Argon2 的 256 MiB，峰值约 420 MiB。**必须**在 `init` 时提示用户这个数值。

**多 writer 的正确性**：每个 writer 独占一个 pack 与一个独立文件名，互不影响；提交顺序无关（journal 里 `packs[]` 顺序不影响语义）。因此并行安全。

## 5.6 Restore 管线与安全边界

### 路径安全（**必须**，zip-slip 的同构问题）

还原每条路径前校验：
1. `filepath.IsAbs(path)` 为真 → 拒绝，`E12`；
2. 路径经 `path.Clean` 后仍包含 `..` 段 → 拒绝；
3. 路径含 `\x00` → 拒绝；
4. Windows：拒绝保留名（`CON`, `PRN`, `AUX`, `NUL`, `COM1`…）、结尾空格与点；
5. 归一化后 `strings.HasPrefix(clean, destRoot+sep)` 必须成立；
6. **符号链接逃逸**：还原 `SYMLINK` 时，若目标解析后落在 `destRoot` 之外，**默认拒绝**，`--allow-external-symlink` 可放开；且**必须**在创建任何符号链接之前完成全部普通文件的还原，避免"先建了个指向外部的链接再往里写"。

### 覆盖策略

| `--overwrite` | 行为 |
|---|---|
| `never`（默认） | 目标已存在且内容 SHA-256 不同 → 跳过并报告；相同 → 跳过（幂等） |
| `if-changed` | 内容不同才覆盖（需先算现有文件 hash） |
| `always` | 直接覆盖 |

**必须**：无论哪种策略，都先写 `<dest>/<path>.apex-tmp` 再 `rename`，保证目标文件不会出现半截内容。

### 还原顺序（**必须**）

~~~text
1. 建目录树（按路径深度升序），设 mode 与 modtime（modtime 最后设，因为建文件会改动它）
2. 还原普通文件内容（流式：seek → 解密 → 解压 → write）
3. 还原符号链接
4. 再次遍历，统一设置所有文件与目录的 mode
5. 最后统一设置 modtime（深→浅，否则改子文件会刷新父目录 mtime）
~~~

**必须**：目录的 modtime 要在所有子孙都落盘之后才能生效，否则前功尽弃。

### 断点续解

- restore 维护一个 `.apex-restore-progress`（在目标目录内，完成后删除）：记录已完成路径的 HMAC 与对应切片的 sha 校验结果。
- 中断后重跑：已完成且校验通过的文件走 `--overwrite=if-changed` 快速跳过。
- 单切片失败（sha 不符）→ 重试该切片 3 次 → 仍失败则把该**文件**标为 `CORRUPT`，继续还原其余文件，最终退出码 12 并列出清单。

### 快照穿梭

`--at <seq>` 与 `--at-latest` 互斥；`--at` 时只重放到该 seq。**必须**处理 `--at` 指向一个 `is_final=false` 的 journal 的情形：取该 `txn_id` 的**第一个** journal 之前的状态（因为半个事务没有意义），并提示用户。

## 5.7 决策 D-13 / D-17：`state.db` schema

`state.db` 是**纯缓存**，任何情况下都必须能从 journal 全量重建（`apex rebuild-state`，不变量 I7）。

~~~sql
CREATE TABLE meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);  -- vault_id, last_seq, schema_version, params_snapshot

CREATE TABLE anchor (
  seq INTEGER PRIMARY KEY,
  journal_sha256 BLOB NOT NULL,
  mac BLOB NOT NULL
);

CREATE TABLE entries (
  path_hmac BLOB PRIMARY KEY,   -- HMAC-SHA256(PathKey, nfc_path)
  size INTEGER NOT NULL,
  mtime_ns INTEGER NOT NULL,
  ctime_ns INTEGER NOT NULL,
  content_sha256 BLOB NOT NULL,
  last_seq INTEGER NOT NULL
);

CREATE TABLE dirs (
  path_hmac BLOB PRIMARY KEY,
  mode INTEGER NOT NULL,
  last_seq INTEGER NOT NULL
);

CREATE TABLE checkpoints ( seq INTEGER PRIMARY KEY );
~~~

**决策 D-13**：`entries` 表**不存明文路径**，只存 `path_hmac`。理由：`state.db` 在 `~/.config` 下是明文 SQLite，若存明文路径，等于在本地留下"你备份了哪些文件"的完整清单（文件名的信息量往往比内容还敏感）。代价：`fast` 模式下扫描需要为每个源路径算一次 HMAC（SHA-256，约 200 ns/条，100 万文件 = 0.2 s，可接受）。

**必须**：`state.db` 打开时校验 `meta.vault_id` 与当前 `vault.meta` 一致；不一致则视为"别人的缓存"，直接丢弃重建（不报错）。

## 5.8 跨平台注意

| 平台 | 问题 | 处理 |
|---|---|---|
| Windows | `os.Rename` 到**已存在**目标会失败 | 本方案的 pack/journal 名都唯一，不触发；但 restore 的临时文件命名必须带随机后缀 |
| Windows | 目录 fsync 不可靠 | 打开目录得到的是句柄，`FlushFileBuffers` 对目录句柄支持有限；**建议**退化策略：rename 后 `Sleep(0)` + 依赖 NTFS 的 journal。**必须**在文档中标注"Windows 上 S3/S6 的持久化保证弱于 Linux/macOS" |
| macOS | HFS+/APFS 用 **NFD** 分解 Unicode | 入库前统一 `golang.org/x/text/unicode/norm`.NFC；restore 时按 NFC 写出（APFS 会自动存储为 NFD，属正常） |
| 全平台 | 大小写不敏感 FS | 扫描期做 case-fold 冲突检测，冲突则 fail-fast（见 01 章 D-18） |
| 全平台 | 长路径 | Windows 需 `\\?\` 前缀或启用 LongPathsEnabled；`MAX_PATH` 超限时 fail-fast |

## 5.9 `--dry-run`

**必须**支持。`--dry-run` 时：
- 完成 S1（扫描）与差异计算；
- 输出将产生的 pack 数量、预估字节、`ADD/MODIFY/DELETE` 计数、被跳过/失败的文件清单；
- **不**创建任何文件，**不**占用写锁之外的资源，也**不**推进 `state.db`。

## 5.10 待确认

1. `restore` 是否需要支持"还原到当前用户无写权限的位置"（例如 systemd 单元）？**结论**：不支持。fail-fast 并提示。
2. 是否需要 `restore --verify-only`（只校验数据完整性、不落盘）？**结论**：需要，等价于 `verify --deep`，两者共用实现。
