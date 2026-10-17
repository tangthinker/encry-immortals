# 04 · Journal 引擎与状态机（对应母方案第四章）

> 母方案给了 Header / Operations 的字段直觉，但没有序列化选型、没有 pack 指纹、没有目录与符号链接、没有链首锚点、没有 checkpoint。本文补齐，并把"防篡改"从"前向 hash chain"升级为"前向 hash chain + 本地锚点"。

## 4.1 决策 D-03：Journal 密文文件布局

~~~text
偏移   长度   字段
 0      1    ver_alg     = 0x11
 1      1    codec       0=none 1=zstd
 2      2    reserved    必须 0x0000
 4      24   nonce       CSPRNG
28      n    ciphertext  = XChaCha20Poly1305(JournalKey, zstd(body))
28+n    16   tag

AAD_journal = ver_alg(1) || codec(1) || u64be(seq) || vault_id(16)     // 26 B
~~~

`seq` **必须**与文件名解析出的序号严格一致；不一致即 `E12`（把文件重编号直接判死）。
`vault_id` 进 AAD：把 A 库 journal 拷进 B 库 `meta/` 会解密失败，而不是"重放成功但内容诡异"。

**为什么 body 要压缩**：10 万条 op 的 journal 未压缩可达 40 MiB，zstd 通常压到 3–6 MiB。对上传时间与 restore 启动时间都是 10 倍级收益。

## 4.2 决策 D-10：序列化选型

母方案写"JSON / MessagePack 经加密包装"，二选一未定。**结论：MessagePack，固定位置数组 schema，不用 map。**

理由：
1. JSON 的数字精度与转义规则在多语言/多版本间有坑，体积大 30–50%。
2. map 的字段顺序在不同库实现下不保证稳定 → 虽然 hash 是在密文上算的，但 golden vector 与跨实现互操作要求稳定编码。
3. 数组 schema 更小（无字段名），顺序天然稳定。

**必须**：整数用最短 MessagePack 编码（`0..127` → 1 字节），**禁止** float，**禁止**非规范表示。所有实现共用一份字段序号表。

### Journal body（顶层，7 元素数组）

~~~text
[ format_version, seq, txn_id, ts_unix, msg, prev_hash, flags, payload ]
   0: u8     = 3（journal body 版本，独立于 ver_alg）
   1: u64    seq
   2: bin16  txn_id
   3: i64    ts（Unix 秒，本地时钟；仅展示，不参与排序）
   4: str    msg（Git 风格提交信息，可为空串）
   5: bin32  prev_hash
   6: u8     flags（bit0 = is_final）
   7: payload
~~~

### payload（普通提交 `kind=0`）

~~~text
payload = [ kind, vault_params, packs, dirs, ops ]
vault_params = [ slice_plain_bytes, small_file_bytes, pack_max_bytes, session_max_mib ]
~~~

### `packs[]`（决策 D-05，**本次新增**）

~~~text
pack_entry = [ name, size_u64, sha256_32B, slice_count_u32 ]
~~~

母方案只在 slice 里记 `PackID`，pack 本身的大小与哈希无处可查。后果：云端 pack 被截断/损坏时无法定位；也没有 `verify` 的数据基础。加 `packs[]` 之后：

- `verify` 可只下载 `packs[]` 的 sha256 比对（甚至只比 size，秒级）；
- restore 打开 pack 前先 `stat` 比 size，不符立即 `E12`，而不是读到一半才发现 tag 错；
- pack 与 journal 的引用关系可双向审计（孤儿检测）。

### `dirs[]`（决策 D-09，**本次新增**）

~~~text
dir_entry = [ path, mode_u32, modtime_ns_i64 ]
~~~

用于空目录与目录权限。非空目录的 mode 也在这里记录——目录 mode 与文件 mode 是两套位，不能靠父路径推导。

### `ops[]`

~~~text
op_entry = [ op_type, path, mode_u32, size_u64, modtime_ns_i64,
             content_sha256_32B, slices, extra ]
~~~

| `op_type` | 含义 | `slices` | 备注 |
|---|---|---|---|
| 0 `ADD` | 新文件 | 有 | |
| 1 `MODIFY` | 覆盖已有文件 | 有 | |
| 2 `DELETE` | 删除文件（墓碑，物理数据保留） | 空 | 母方案已定义 |
| 3 `MKDIR` | 建目录（含空目录） | 空 | `size=0` |
| 4 `RMDIR` | 删目录 | 空 | 应用规则见 4.5 |
| 5 `SYMLINK` | 符号链接 | 空 | `extra` = 链接目标串 |
| 6 `META` | 只改 mode/modtime，内容不变 | 空 | 典型场景 `chmod` / `touch` |

第 8 个字段 `extra` 在非 `SYMLINK` 时为空串。代价是每 op 多 1 字节，远低于把链接目标塞进数据池带来的复杂度。

### `slices[]`（决策 D-17）

~~~text
slice_entry = [ pack_idx, offset_u64, env_len_u32, plain_len_u32,
                index_u32, codec_u8, plain_sha256_32B ]
~~~

## 4.3 决策 D-04：Genesis 与锚点

母方案只说 `PrevJournalHash` 构成哈希链，但没说链首是什么，也没说链尾锚在哪里。

### Genesis

~~~text
prev_hash(seq=1) = SHA-256( "APEX-JOURNAL-GENESIS-v3" )        // 32 字节常量
prev_hash(seq=N) = SHA-256( 整个 0000000(N-1).journal 文件的字节 )
~~~

**必须**：hash 覆盖**密文文件全部字节**（含 header 与 tag），任何一处改动都会断裂。

### 链尾锚点（anti-rollback / anti-truncation）

哈希链只防"中间插入/篡改"，**不防"删掉最后一页"**。攻击者（或网盘回滚）把 `meta/` 恢复到上周，重放系统会认为一切正常，静默交出一个旧世界。

| 位置 | 内容 | 强度 | 说明 |
|---|---|---|---|
| `state.db` 的 `anchor` 表 | `(seq, journal_sha256, HMAC(AnchorKey, seq \|\| sha256))` | 强（本地可信存储） | 每次成功提交后写入。restore 前比对：云端最新 seq > 本地锚点 seq → `E11 疑似回滚`，需 `--accept-rollback` 显式确认 |
| 用户可见的"水位码" | `apex status --anchor` 输出 8 字符短码 | 中（人肉记录） | 用户可截图或抄在 Armor Key 旁边，作为跨机恢复时的外部锚 |
| journal 内嵌 | 无 | — | 不能自锚（自锚等于没锚） |

**必须**在 08 章威胁模型里明说：**若攻击者同时能写本地 `state.db`，本机制失效**。这是诚实的边界声明，不是缺陷。

### 无锚点情形（灾难恢复）

新机 restore 时本地没有 `state.db`。此时：
1. 用户提供 `--anchor <短码>` → 正常校验；
2. 否则**必须**输出醒目警告并把输出标记 `UNVERIFIED_ROLLBACK_POSSIBLE`，要求显式 `--i-accept-unverified` 才继续（详见 07 章）。

## 4.4 决策 D-14：Checkpoint Journal

问题：一次备份一个 journal，一年后 `meta/` 有 365+ 文件，restore 要**全部解密**才能知道最新树——启动时间随历史线性增长（1000 次提交 × 2 MiB = 2 GB 解密）。

方案：引入 `checkpoint`，仍是**纯追加、不可变、不删任何东西**，只是让重放有了起点。

~~~text
payload = [ kind=1, vault_params, packs, dirs, tree ]
tree       = [ file_node... ]
file_node  = [ path, mode_u32, size_u64, modtime_ns_i64, content_sha256_32B, slices ]
packs      = 全量重列（checkpoint 之后重放需要能寻址任何仍被引用的 pack）
~~~

规则：
- **生成策略**：每 256 次普通提交生成一个（可配），或距上个 checkpoint 超过 30 天。
- **命名**：序号照常连排（checkpoint 也占一个 seq），无特殊后缀——防止外部观察者区分"哪一次是全量"。
- **重放算法**：

~~~text
last_ckpt := 满足 seq <= target 的最大 checkpoint
if last_ckpt == nil: 从 genesis 全量重放
else: 用 last_ckpt.tree 初始化虚拟树，再从 last_ckpt.seq+1 重放到 target
~~~

- **不变量**：`last_ckpt.tree § 重放区间 == 全量重放结果` **必须**逐字节相同（属性测试，见 09 章 I4 / 12 章）。
- **代价**：checkpoint 本身体积大（全量树），但压缩后通常只有增量 journal 的 3–10 倍；每 256 次出现一次，可接受。

## 4.5 确定性重放规则（**必须**逐条实现）

| 规则 | 说明 |
|---|---|
| 有序性 | 先按 `seq` 升序，再按 `ops[]` 下标升序。数组顺序即应用顺序 |
| 同路径多 op | 同一 journal 内同 path 多次 → 依次应用，后者胜。**建议**写入端合并为最后一次 |
| `ADD` 到已存在 | 幂等覆盖（不报错），用于重试场景 |
| `MODIFY` 到不存在 | **必须**容忍并视为 `ADD`。灾备场景严格报错会让系统变脆 |
| `DELETE` 不存在 | 幂等忽略 |
| `MKDIR` 已存在 | 幂等，mode 以最新为准 |
| `RMDIR` 非空 | **必须**失败并 `E12`。写入端应保证 `RMDIR` 前已发出所有 `DELETE` |
| 路径冲突 file vs dir | `E12`。写入端应保证不会发生，重放端做防御性拒绝 |
| 大小写 | 重放按原样保留，不做 case-fold；冲突检测只在写入端扫描阶段做（见 01 章 D-18） |
| 时间 | `modtime_ns` 直接采用 journal 记录值，**禁止**用当前时间 |

## 4.6 Journal 的体积与拆分

| 约束 | 值 | 处理 |
|---|---|---|
| 单 journal `ops` 上限 | 200,000 | 超出则**同一 txn 内**拆成多个 journal（连续 seq，`txn_id` 相同，最后一条 `flags.bit0=1`） |
| 单 journal 明文字节上限 | 256 MiB | 同上 |
| 拆分的完整性 | — | restore 必须校验：同 `txn_id` 的连续 journal 要么全在要么全不在，缺一条即 `E12` |

## 4.7 空变更

- 源目录无任何变化 → **不产生 journal**（不变量 I8）。`backup` 输出 `no changes` 并退出码 0。
- `--message` 非空时？**结论**：仍不产生（避免用空 journal 刷序号）。用户若要记录事件，用 `apex note`，写一个 `kind=2` 的纯注释 journal（不含任何 ops），语义上与"备份提交"区分。

## 4.8 时钟与命名

- `ts` 只作展示，**禁止**参与排序。
- 时钟回拨导致新 journal 的 `ts` 小于上一条时，**必须**照常写入并记 warning（不能因此拒绝提交，否则用户改完系统时间就无法备份）。
- 序号来源：`max(现有 meta/*.journal 解析出的 seq) + 1`，而不是本地 `state.db` 的计数（后者可能滞后）。创建时用 `O_EXCL`，冲突即 `E20`。

## 4.9 待确认

1. checkpoint 是否独立目录（`meta/ckpt/`）以便快速定位？**结论**：不。分目录会暴露"哪些是全量"的结构信息，且破坏"按名排序即时间序"的简洁。改为在 `state.db` 缓存最后一个 checkpoint 的 seq（本来就是缓存，丢了只是变慢）。
2. `msg` 是否加密？已在 journal 密文内，天然加密。但**必须**提醒用户不要写敏感信息——它会长期留在云端密文文件中。
