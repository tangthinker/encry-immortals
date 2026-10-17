# 03 · 物理存储层与线格式（对应母方案第三章）

> 母方案给了"自解释分片信封"的 ASCII 图，但缺字节语义、缺版本号、缺压缩层、缺 rollover 规则，且 pack 上限与整存阈值撞车。本文全部钉死。

## 3.1 命名与目录分片

| 对象 | 格式 | 规则 |
|---|---|---|
| Pack | `pack_<unix_ms 13位>_<6位36进制>.dat` | 例 `pack_1773000000123_a1b2c3`。时间戳毫秒，随机后缀 36^6 ≈ 2.18e9，同毫秒碰撞可忽略；仍需 `O_EXCL` 兜底 |
| Journal | `<seq 8位零填充>.journal` | `00000001.journal` … `99999999.journal`。**必须**固定 8 位，否则字典序 `10 < 9` |
| 目录分片 | `data/YYYY-MM/`、`meta/`（不按时间分片） | 见 06 章。meta 必须保持单层，因为 restore 需要按文件名全局排序 |

**必须**：
- pack 文件名**不含**任何语义（不编码源路径、不含扩展名、不含序号）。
- 时间戳取 `time.Now().UnixMilli()`，允许单调回退（用随机后缀兜底），**禁止**用它排序——排序只认 journal 的 `seq`。
- `.dat` 扩展名与母方案一致；journal 后缀无前导点。两者都不含 `.enc` / `.crypt` 等特征词。

## 3.2 Pack 文件整体布局

~~~text
+--------------------------------------------------------------+ 0
| PackHeader  32 B                                             |
+--------------------------------------------------------------+ 32
| SliceEnvelope #0                                             |
| SliceEnvelope #1                                             |
| ...                                                          |
+--------------------------------------------------------------+ S
| Footer（可选，默认写）                                        |
|   body  = nonce(24) || ciphertext || tag(16)                 |
|   tail  = u32be(footer_total_len)      ← 文件最后 4 字节      |
+--------------------------------------------------------------+ file_size
~~~

### PackHeader（32 B，明文）

| 偏移 | 长度 | 字段 | 值 / 说明 |
|---|---|---|---|
| 0 | 16 | `pack_id` | CSPRNG。**是** AAD 的组成部分；与文件名中的随机串**无关**（故意的：文件名可被网盘改名，AAD 不能）。放在最前是为了让文件前 16 字节完全随机，不形成可扫描的固定前缀 |
| 16 | 1 | `ver_alg` | `0x11` |
| 17 | 1 | `flags` | bit0 = has_footer；其余必须为 0（读到未知位 → 拒绝解析） |
| 18 | 2 | `reserved` | 必须 `0x0000` |
| 20 | 4 | `created_unix` | 秒级 |
| 24 | 8 | `padding` | CSPRNG 随机字节。让文件头熵分布均匀，且 32 B 内不出现任何固定模板 |

**为什么不加密 header**：读一个 slice 需要先知道 `pack_id` 才能构造 AAD。若 header 加密，就需要额外的"header 密钥绑定"，复杂度和风险都上升；而 header 里没有任何秘密（时间与随机数），明文是正确取舍。

### Footer（可选但默认写）

目的：让单个 pack 具备**自描述 + 可自证完整**的能力，用于 `verify` 与 journal 损坏时的抢救。

~~~text
footer_plaintext = ver_alg(1) || u32be(entry_count) || entries
entries[i]       = u64be(slice_offset) || u32be(env_len) || u32be(plain_len) || u32be(slice_index)

footer_body      = nonce(24) || XChaCha20Poly1305(StorageKey, footer_plaintext)
footer_tail      = u32be(24 + len(ct) + 16 + 4)      // 含自身

AAD_footer = ver_alg(1) || pack_id(16) || u64be(S)   // S = footer 起始偏移
~~~

定位算法（**必须**按此实现，防止尾巴被截断后仍"解析成功"）：
1. `size := stat().Size()`；要求 `size >= 36`；
2. 读最后 4 字节 → `L`；要求 `L >= 44 && L <= size - 32`；
3. `seek(size-L)`，读 `L` 字节，按上面的结构解；
4. AAD 中的 `S = size - L`；解不开 → footer 损坏（可能被截断）→ 降级为"无 footer 模式"，交给 journal 索引，并记 `E12` 警告。

## 3.3 Slice Envelope v1（字节级）

~~~text
偏移  长度  字段
 0     1    ver_alg      = 0x11
 1     4    env_len      u32be，本信封总长（含全部字段）= 50 + ct_len
 5     4    plain_len    u32be，压缩前明文长度（不得超过 MaxSlicePlain）
 9     1    codec        0=none 1=zstd
10     24   nonce        CSPRNG
34     n    ciphertext   长度 n = env_len - 50
34+n   16   tag
~~~

**注意**：母方案图里的 `[Len][Nonce][Payload][MAC]` 顺序映射为 `env_len, nonce, ciphertext, tag`；`plain_len` 与 `codec` 是本次新增，且 `plain_len` 被移到前部，便于解析器在解密前做上界检查（防 OOM）。

### AAD（54 B，见 02 章）

~~~text
AAD = ver_alg(1) || u32be(env_len) || u32be(plain_len)
    || pack_id(16) || u64be(slice_offset) || u32be(slice_index)
    || txn_id(16) || codec(1)
~~~

**必须**：`slice_offset` 等于信封在 pack 内的**实际**偏移，写入时由 writer 的 `cur_offset` 给出，读取时由 seek 位置给出，两者不一致即解密失败。这条让"从别处拷一段过来"无法通过。

### 解析器防御清单（每条都要有单测）

| 检查 | 失败处理 |
|---|---|
| `50 <= env_len <= 50 + MaxCompressedLen` | 拒绝，`E12` |
| `plain_len <= MaxSlicePlain`（默认 32 MiB） | 拒绝，`E12`。**必须在解密前**检查，否则解压炸弹打爆内存 |
| `codec` ∈ {0,1} | 拒绝 |
| `slice_offset + env_len <= footer_start`（或 `file_size`） | 拒绝 |
| `slice_offset` 单调递增、紧邻（无空洞） | **不允许留白**，空洞即 `E12` |
| `slice_index` 在 journal 中连续 0..k | 拒绝 |
| 解密后 `len(plaintext) == plain_len` | 拒绝 |
| 解压后 `len(decompressed) == plain_len` | 拒绝 |

**必须**：所有长度字段读入后立刻用 `uint64` 中间量做溢出检查，断言 `<= 1<<40`。Go 的 `uint32` 相加不会溢出，但转 `int64` 做偏移计算会。

## 3.4 决策 D-11：压缩层

母方案的 zstd 只用在 Armor Key 上（几百字节 JSON，压缩率≈1.0，纯负收益）。真正该压缩的是**加密前的明文**。

| 决策 | 内容 |
|---|---|
| 算法 | zstd，level 5（`klauspost/compress/zstd`） |
| 阈值 | `plain_len < 4096` 直接 `codec=0`（zstd 帧头开销不划算） |
| 不可压缩检测 | 先压缩前 64 KiB 样本，压缩率 > 0.98 则整片用 `codec=0`，省 CPU |
| 语义 | `plain_len` 是**压缩前**长度；`compressed_len = env_len - 50`；`codec=0` 时两者相等 |
| 顺序 | 读源 → 压缩 → 加密。**绝不能**先加密再压缩 |
| AAD | `codec` 与 `plain_len` 都进 AAD（防"声明 100 KiB 实解压出 10 GiB"的炸弹） |
| 流式 | 大文件按 32 MiB 片独立压缩，片间不共享字典（否则随机读取依赖前片） |

## 3.5 空文件与超小文件

- **0 字节文件**：**不写任何 slice**。journal 中 `size=0, slices=[]`。restore 直接 `create(0)`。理由：省掉 `env_len=50` 的纯开销，且避开"空切片"边界。
- **`plain_len < 4096`**：仍写切片（`codec=0`），多个小文件**必须**打包进同一 pack——这是母方案"小文件整存"价值所在。

## 3.6 决策 D-08：阈值与 rollover

母方案冲突：整存阈值 64 MiB，pack 上限也是 64 MiB → 一个 64 MiB 文件永远塞不进新 pack（`env_len = 64 MiB + 50`）。

修订参数（写入 `config.toml`，**必须**同时在 journal 的 `vault_params` 里留快照，否则改配置后老 pack 无法解释）：

| 参数 | 值 | 依据 |
|---|---|---|
| `slice_plain_bytes` | 32 MiB | 母方案 32/64 二选一，取小以获得更好的随机读取粒度与更低内存峰值 |
| `small_file_bytes` | 64 MiB | 母方案值，保留 |
| `pack_max_bytes` | **128 MiB** | 必须 > `small_file_bytes + 50`。也给"一个大文件 + 若干小文件"留余量 |
| `max_slices_per_pack` | 100000 | footer 条目数上限，防 footer 过大 |

**Rollover 算法**（**必须**在写任何字节前决策）：

~~~text
for each unit in [(file, slice0), (file, slice1), ..., (smallfile, whole)]:
    need = 50 + compressed_len_upper_bound(unit)
    if cur_offset + need > pack_max_bytes || slices_in_pack >= max_slices_per_pack:
        seal_pack()            // 写 footer、fsync、rename
        start_new_pack()
    write(unit, at=cur_offset)
    cur_offset += actual_env_len
~~~

**必须**：`compressed_len_upper_bound` 无法精确预知时取 `plain_len + plain_len/128 + 256`（zstd worst-case 上界），宁可浪费几百字节也不能溢出。

**边界**：若 `slice_plain_bytes + 50 > pack_max_bytes`（例如用户把 `slice_plain_bytes` 配成 256 MiB），**必须**在启动时校验并拒绝非法配置，而不是运行中动态退化。

## 3.7 决策 D-05 / D-17：切片元数据（写入 journal，详见 04）

每个切片在 journal 里记录（**必须**全套）：

| 字段 | 用途 |
|---|---|
| `pack_idx` | 指向同一 journal 的 `packs[]` 下标（省空间，替代重复写文件名） |
| `offset` u64 | pack 内绝对偏移 |
| `env_len` u32 | 信封总长，用于 Seek 后一次读 |
| `plain_len` u32 | 还原时预分配 / 校验 |
| `index` u32 | 文件内序号 |
| `codec` u8 | 冗余（env 头里也有），用于不解密就统计压缩率 |
| `plain_sha256` 32 B | **该切片解密后明文**的 SHA-256（D-17）。用于局部校验、损坏时只丢一段、restore 断点续解 |

母方案只有文件级 `Checksum`，某段坏掉只能整文件失败——D-17 是必要的粒度细化。代价：每切片 +32 B，以 32 MiB 切片计开销 0.00001%，可忽略。

## 3.8 示例：100 MiB 文件的切片表

参数：`slice_plain_bytes = 32 MiB`，pack 上限 128 MiB。

| 切片 | plain_len | 位置 |
|---|---|---|
| 0 | 33,554,432（32 MiB） | pack_A @ 32 |
| 1 | 33,554,432 | pack_A @ 33,554,514 |
| 2 | 33,554,432 | pack_A @ 67,108,996 |
| 3 | 4,194,304（4 MiB，末片变长） | pack_A @ 100,663,478 |

pack_A 总计 ≈ 100.0 MiB（含 footer）< 128 MiB，一个 pack 装完。若再塞一个 30 MiB 文件，则 `100.0 + 30 + 50 > 128`，触发 rollover，新开 pack_B。

## 3.9 为什么不用一个大 tar / 一个大 pack

- 单 pack 无限大 → 网盘单文件大小限制（百度非会员 4 GB，部分客户端 2 GB）+ 单次上传失败要整包重传 + 无法随机读取。
- pack 太小（如 4 MiB）→ 文件数爆炸，网盘目录条目与同步元数据开销压垮客户端（详见 06 章）。
- 128 MiB 是经验折中：单文件上传可控、目录条目数可控、随机读取粒度合理。

## 3.10 待确认

1. 是否在 pack 内再写一个整包校验和？**结论**：不。journal 的 `packs[].sha256` 已足够，文件内再加会引入"这是完整文件"的结构特征，且需要额外一次全量读。
2. `created_unix` 是否泄露信息？**结论**：可接受（文件名已含毫秒时间）。
