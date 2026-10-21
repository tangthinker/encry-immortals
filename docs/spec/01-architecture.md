# 01 · 架构根基补充（对应母方案第一章）

> 母方案第一章确立了"控制平面 / 数据源区 / 存储平面"三分与单向流动。本文把目录布局、staging 区位置、并发写者、平面边界全部定死到可编码粒度。

## 1.1 目录布局定稿

~~~text
~/.config/apex-vault/                  # 控制平面（绝不进入网盘同步目录）
  vault.meta                           # 见 02，JSON，含 kdf / auth_verifier / vault_id
  state.db                             # 本地缓存：seq 水位、锚点、路径 HMAC 索引
  lock                                 # flock 目标（本地互斥）

<SourceDir>/                           # 数据源区，任意位置，只读访问

<TargetDir>/                           # 存储平面根目录（网盘同步）
  .eimmortal.lock                      # 跨机持有者记录（不参与 flock，见 1.4）
  data/
    2026-03/                           # 目录分片，见 06
      pack_1773000000123_a1b2c3.dat
      pack_1773000045678_d4e5f6.dat
  meta/
    00000001.journal
    00000002.journal
    manifests/                         # 每个 pack 一个加密记录

<TargetDir>.tmp/                       # [同卷暂存区] 与 TargetDir 同级，见 1.2
~~~

**必须**：
- 控制平面目录权限 `0700`，`vault.meta` 权限 `0600`。
- `TargetDir` 根目录只允许 `.eimmortal.lock`、`data/**`、`meta/**`（旧版本的 `.tmp/` 仍允许；v0.1.3/0.1.4 的 `output/**` 兼容布局仍可读）；出现任何其他条目视为污染，`backup` 与 `restore` 必须拒绝继续（防止用户在 Target 里放了自己的文件导致同步语义混乱）。
- `data/` 与 `meta/` 的关系是**单向引用**：journal 引用 pack，pack 永不引用 journal。反向依赖会破坏"pack 是哑存储"的性质。

**禁止**：
- 禁止在 `TargetDir` 内放置任何配置文件、README、`.gitkeep`——母方案"网盘盲盒化"的直接推论。
- 禁止把 `state.db` 或 `vault.meta` 放进 `TargetDir`（母方案硬要求，此处复述以防实现时图省事）。

## 1.2 决策 D-06：staging 区的位置

结论：默认放在 **TargetDir 同级的 `<TargetDir>.tmp/`**，不再放进 TargetDir 内部。

理由：
1. 暂存区不进入网盘同步范围，避免半截 pack/journal 被客户端上传。
2. 同级的兄弟目录与 TargetDir 共享父目录，正常布局下天然同卷；仍强制做同卷校验，防止挂载点/符号链接例外。
3. 若用户把 TargetDir 放在某个同步根的子目录里，兄弟目录可能仍在同步根内；此时可用 `storage.staging_dir` 指向同步根之外的路径，但必须与 TargetDir 同卷。

代价与缓解：

| 代价 | 缓解 |
|---|---|
| 暂存区在 TargetDir 外，备份开始时需要创建兄弟目录 | `Ensure` 以 0700 创建；`gc` 清理 24h 残留 |
| 同级目录不一定在用户的同步范围之外 | 文档明确建议排除；`storage.staging_dir` 可覆盖 |
| 跨卷时 `rename` 退化为 copy+delete | 启动时强制同卷校验；不一致 fail-fast |

同卷校验（默认与 `storage.staging_dir` 生效时都执行）：

~~~
dev(target/data) == dev(staging)
且 rename(staging/x -> target/data/x) 不返回 EXDEV
~~~

向上查找最近的已存在父目录取 `dev`；不一致则 fail-fast 并输出提示文案，禁止"警告后继续"。

旧版本曾在 TargetDir 内使用 `.tmp/`；该目录仍被白名单接受，但新版本不再写入。v0.1.3/0.1.4 的 `output/**` 布局作为兼容读取，不再作为默认。

## 1.3 控制平面与数据平面的边界（信息流图）

~~~text
        ┌────────── 控制平面（明文，本地） ──────────┐
        │ vault.meta  : salt / kdf / verifier / id  │
        │ state.db    : seq 水位 / 锚点 / path HMAC  │
        │ 进程内存    : MasterKey → 4 把子密钥      │
        └───────────────────────────────────────────┘
                    │ 只读派生密钥                    ▲ 写水位与锚点
                    ▼                                │
        ┌────────── 存储平面（全密文，可上云） ───────┐
        │ data/pack_*.dat  (StorageKey)             │
        │ meta/*.journal   (JournalKey)             │
        └───────────────────────────────────────────┘
~~~

**必须**：从存储平面流回控制平面的只有两类信息——(a) 已提交的 `seq` 与 journal 密文 SHA-256；(b) 用于加速的路径 HMAC 索引。**禁止**任何来自 ping 平面的内容参与密钥派生，包括"从云端下载的 vault.meta"——母方案要求 import 走 Armor 字符串，正是这个规则的体现。

## 1.4 决策 D-15：单写者与锁

母方案未提及并发。现实里至少三种并发：同机两个终端、同一份 Target 被两台机器同步（网盘双向同步的典型误用）、备份与 restore 并发。

三层防御：

| 层 | 机制 | 覆盖场景 |
|---|---|---|
| 进程级 | `flock(LOCK_EX\|LOCK_NB)` on `~/.config/apex-vault/lock` | 同机多进程（跨 `APEX_VAULT` 配置的不同进程也互斥，因为锁在控制平面） |
| vault 级 | `<TargetDir>/.apex.lock`：JSON `{host_id, pid, boot_id, started_unix, tool_version}`，创建时 O_EXCL，退出删除 | 试图连接两台的机器不会共享 flock（flock 不跨机器），因此必须靠读这个文件人工/程序判定 |
| 内容级 | journal 文件名 `O_EXCL` 创建 + `seq` 必须等于 `max(data/meta 现有 seq)+1` | 即使上面两层都失效，序列号冲突会使第二个写者失败而不是分叉 |

规矩：
- `.apex.lock` 存在时，`backup` **必须**中止并提示：`检测到另一台主机正在写入：host=... started=... 。如确认该主机已失效，执行 apex backup --break-lock`。
- `--break-lock` 只是删除该文件，不做任何"确认对方死了"的推断（无法可靠推断）。
- `restore` 与 `list/log/status` 是只读操作，**不**需要写锁；但 `restore` 期间若有 `backup` 在跑，必须提示"你正在读取一个正在变动的 vault，已提交的 journal 不受影响，但最新一次可能未完成"。
- 锁文件**不放入** `.tmp/`，也不参与网盘语义——放 `.tmp/` 会导致备用主机看到旧的锁文件而永久阻塞。

## 1.5 进程模型

**建议**：v1 为纯 CLI、无守护进程、无网络端口。所有状态通过文件系统表达。原因：守护进程会引入"内存中常驻主密钥"的长期暴露面，与母方案"本地工作区受保护"的目标冲突。若未来要加 `fsnotify` 自动备份，也**建议**以 cron / launchd / Task Scheduler 周期调用 `apex backup` 的形式，而非常驻。

若确需常驻：主密钥驻留时间必须不超过单次备份周期，空闲 5 min 后 `memguard` 销毁并将进程自退，且常驻进程**不得**监听网络。

## 1.6 决策 D-18：显式不支持项

母方案的"100% 完美无损还原"只在声明范围内成立。以下项 v1 **不支持**，且**必须 fail-fast**（扫描阶段检出即报错并退出码 12，不得静默跳过）：

| 项 | 若静默跳过的后果 | v1 行为 |
|---|---|---|
| 符号链接 | 备份成目标内容或空文件，用户不知情 | `SYMLINK` op（D-09）备份链接本身；目标逃逸出 SourceDir 时 fail-fast |
| 硬链接 | 还原后变成两份独立文件，语义丢失 | fail-fast，提示改用 `--follow-hardlinks=split` 显式接受降级 |
| xattr / ACL / 资源分叉 | macOS `com.apple.*`、Linux `security.*` 丢失 | 默认 fail-fast（检测到即报错），`--ignore-xattr` 可显式降级 |
| 稀疏文件 | 还原后膨胀为全量大小，可能撑爆磁盘 | 按逻辑大小读取（可能很慢/很大）；超过 `scan.sparse_max_bytes` 则 fail-fast |
| 设备文件 / FIFO / socket | 打开会阻塞或产生副作用 | fail-fast |
| 大小写不敏感 FS 上的同名异写 | `a.txt` 与 `A.txt` 冲突覆盖 | 路径表内做 case-fold 检测，冲突则 fail-fast |
| 多源根 | 母方案只描述单 SourceDir | 一次 backup 只接受一个 `--source`；多根需建多个 vault |
| 多写者 | 序列号分叉 | 见 1.4，fail-closed |

## 1.7 决策记录（摘要）

- **D-06**：staging 默认是 TargetDir 同级的 `<TargetDir>.tmp/`，强制同卷校验；`storage.staging_dir` 可覆盖。
- **D-15**：三层写者互斥（flock / `.apex.lock` / journal `O_EXCL` + seq 连续性）。
- **D-18**：不支持项必须 fail-fast，不得静默降级——这是"无损"承诺能成立的边界条件。

## 1.8 待确认

1. 是否允许 `TargetDir` 与 `SourceDir` 重叠？（结论：必须禁止，并在启动时用路径前缀 + `st_dev/ino` 双重判定；否则会备份到自己写出的 pack 上，无限自指。）
2. 是否支持"源目录在可移动盘 / 网络盘"？（结论：支持只读扫描，但 `mtime` 精度不可靠，建议强制 `scan.mode=strict`。）
