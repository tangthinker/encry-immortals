# 02 · 密码学体系补充（对应母方案第二章）

> 母方案给了 Argon2id + HKDF + XChaCha20-Poly1305 的骨架，但没有 AAD，auth_verifier 的格式也不可实现。本文修掉这两处。
>
> **修订记录**：初稿曾提出引入 KEK/DEK 两层封装（当时的 D-01），主要动机是"改密码不重写历史数据"。经确认**本系统不需要修改密码**，该动机消失，故 **D-01 撤回**，改为直接派生（见 2.1），并新增 D-01R 补齐校验点与参数冻结契约。

## 2.1 决策：直接派生（D-01R，替代已撤回的 D-01）

### 背景

初稿的 D-01 用 `KEK = Argon2id(password)` 封装一个随机 `DEK`，再由 `DEK` 派生各子密钥。它买到的能力只有一个：**改密码 / 调 KDF 参数时只需重新封装 32 字节，不碰历史数据**。

### 结论：不需要，撤回

既然口令在整个生命周期内固定不变，DEK 这一层就只剩"多一次 AEAD"的成本而没有收益。按 YAGNI 原则移除：

~~~text
password ──Argon2id(salt, t, m, p)──► MasterKey (32B，不落盘)
                                          │  HKDF-SHA256(salt=vault_id)
                    ┌──────────────┬──────┴───────┬──────────────┐
                    ▼              ▼              ▼              ▼
               StorageKey     JournalKey      PathKey       AnchorKey
              (pack 数据)     (journal)   (state.db 索引)   (锚点 MAC)
~~~

**必须**：口令派生是**单向且不可撤销**的。这条约束的后果必须在 init 阶段就明确告知用户，见 2.8。

### 撤回的代价（必须诚实记录）

| 场景 | 有 DEK 时 | 撤回后 |
|---|---|---|
| 改密码 | 秒级 | **不支持** |
| 升级 Argon2 参数 | 秒级 | **不支持**（除非全库重写） |
| 口令泄漏后的补救 | 换密码 | **只能**用 `compact --new-identity` 重建全库（小时级 + 重新 export-key + 人工删旧库） |
| 密码校验点 | dek_wrap 免费提供 | 需要显式 auth_verifier（见 2.4） |
| 抗爆破强度 | 一次 Argon2 + 一次 AEAD 才能试解密 | **完全相同**（同样是一次 Argon2 后才能试解密） |

最后一行是关键：DEK 层**不提供**任何额外的抗爆破强度。撤回它不降低安全上限，只降低运维灵活性——而这个灵活性已被确认不需要。

### 撤回后必须补上的两件事

1. **密码校验点**：母方案的 auth_verifier 只有密文没有 nonce，格式不成立。D-01R 明确它的完整契约（2.4）。
2. **KDF 参数冻结**：参数一旦写进 vault.meta 就必须永恒不变，且**不存在**升级路径。这必须在 config.toml 与 init 输出里讲清楚（2.7）。

## 2.2 子密钥派生表

**必须**逐字一致，否则跨实现不兼容：

| 子密钥 | HKDF info 字符串 | 长度 | 用途 |
|---|---|---|---|
| StorageKey | `apex-storage-payload-v2` | 32 B | pack 内 slice envelope |
| JournalKey | `apex-journal-manifest-v2` | 32 B | journal 密文文件 |
| PathKey | `apex-path-hmac-v2` | 32 B | state.db 的路径索引 HMAC-SHA256 |
| AnchorKey | `apex-anchor-v2` | 32 B | 本地锚点 MAC |

HKDF 用法：`HKDF-SHA256(ikm=MasterKey, salt=vault_id, info=<上表>)`，两段（Extract + Expand）都用。vault_id 作 salt 顺带把密钥绑到 vault 身份上——即使两个 vault 用了**同一个密码**，密钥也不会相同。

## 2.3 vault.meta v2 契约

~~~json
{
  "version": 2,
  "vault_id": "<Base64URL_16B>",
  "created_unix": 1773000000,
  "kdf": {
    "algorithm": "argon2id",
    "time": 3,
    "memory_kiB": 262144,
    "threads": 4,
    "keylen": 32,
    "salt": "<Base64URL_16B>",
    "calibrated_at_unix": 1773000000
  },
  "auth_verifier": {
    "algorithm": "xchacha20poly1305",
    "nonce": "<Base64URL_24B>",
    "ciphertext": "<Base64URL_35B>"
  }
}
~~~

| 字段 | 规则 |
|---|---|
| `version` | 读到大于 2 的值必须拒绝（禁止"尽力而为"解析） |
| `vault_id` | 16 字节 CSPRNG。同时作为 (a) journal/slice AAD 的组成部分、(b) HKDF salt、(c) state.db 与 TargetDir 的绑定 |
| `kdf.memory_kiB` | **单位 KiB**。硬下限 131072（128 MiB），默认 262144（256 MiB）。见 2.7 |
| `kdf.salt` | 16 B，**只**在 init 时生成一次，此后永不改变 |
| `auth_verifier` | 唯一的密码校验点，契约见 2.4。**必须**含 nonce（母方案此处缺失） |

## 2.4 auth_verifier：完整契约（补母方案缺口）

母方案写"用 JournalKey 加密固定明文常量 APEX_AEAD_VERIFY_OK"，但没有 nonce 字段，也没有 AAD——格式上不成立，且可被跨库重放。

**必须**按以下定义实现：

~~~text
明文         = "APEX_AEAD_VERIFY_OK"                 // 19 B 定长常量
nonce        = CSPRNG 24 B，存于 vault.meta
AAD_verifier = ver_alg(1B = 0x11) || vault_id(16B) || SHA-256(canon_kdf_block)
                                                      // 合计 49 B
ciphertext   = XChaCha20-Poly1305(JournalKey, nonce, 明文, AAD_verifier)
                                                      // 19 + 16 = 35 B
~~~

其中 `canon_kdf_block` 是**固定格式的 ASCII 字符串**（不用 JSON，避免序列化歧义）：

~~~text
argon2id|t=<time>|m=<memory_kiB>|p=<threads>|k=<keylen>|salt=<Base64URL(salt)>
~~~

例：`argon2id|t=3|m=262144|p=4|k=32|salt=aB9xQ...`

### 为什么 AAD 里要塞 kdf 摘要

| 不加 | 加了 |
|---|---|
| 攻击者把 vault.meta 里的 memory_kiB 改成 4 GiB，用户每次解锁 OOM（拒绝服务） | 改了就解不开，用户立刻察觉 vault.meta 被动过 |
| 某实现若对参数解释不同（KiB 读成 MiB），会静默派生出错误密钥，错误被推迟到"数据解不开"才暴露 | 在解锁阶段就失败，故障定位点前移 |
| 跨库重放：把 A 库的 auth_verifier 拷进 B 库（同密码时可能通过） | vault_id 进 AAD，跨库必然失败 |

**注意**：因为 2.9 要求"密码错"与"文件损坏"共用同一条错误，参数被篡改时用户看到的仍是 E10，不产生"你被攻击了"的区分。这是有意的取舍：**宁可提示模糊，也不给 oracle**。

## 2.5 AAD 设计（决策 D-02 / D-03）

### Slice envelope 的 AAD（54 字节，逐字拼接，无分隔符）

~~~text
AAD_slice = ver_alg(1) || u32be(env_len) || u32be(plain_len)
          || pack_id(16) || u64be(slice_offset) || u32be(slice_index)
          || txn_id(16) || codec(1)                        // 合计 54 B
~~~

| 字段 | 挡的攻击 |
|---|---|
| `ver_alg` | 降级攻击（改版本号触发更弱解析路径） |
| `env_len` / `plain_len` | 长度炸弹（声明小、实解压大导致 OOM）；解析边界歧义 |
| `pack_id` | 跨 pack 搬运切片；把 pack A 的切片塞进 pack B 后伪造 offset |
| `slice_offset` | 包内重排、截断后重新拼接 |
| `slice_index` | 文件内切片乱序（把第 3 段换到第 1 段位置） |
| `txn_id` | 把旧版本切片混入新版本的引用（时间旅行） |
| `codec` | 把 zstd 段当裸段解析，触发解压炸弹或垃圾输出 |

### Journal 的 AAD（决策 D-03）

~~~text
AAD_journal = ver_alg(1) || codec(1) || u64be(seq) || vault_id(16)   // 26 B
~~~

seq 进 AAD 的效果：**把 journal 从 00000007 改名成 00000003 会导致解密失败**，直接封杀"重编号攻击"。

### Footer 的 AAD

见 03 章：绑定 pack_id 与 footer 之前的字节长度，使截断可检测。

## 2.6 Nonce 策略

| 上下文 | 策略 | 理由 |
|---|---|---|
| Slice envelope | 每切片 24 B CSPRNG 随机 | 数量级 10^5–10^7，192 bit 空间下碰撞可忽略 |
| Journal 文件 | 每文件 24 B 随机 | 同上 |
| auth_verifier | 24 B 随机，**只在 init 时生成一次** | 只加密一次，永不复用 |

**禁止**计数器 nonce：本系统是"不可变追加 + 可多机恢复"，计数器一旦在 restore 后重放或跨机续写就会复用。随机 nonce 不依赖任何状态，这是选 XChaCha20 的核心收益。

**禁止**用 slice_index / offset 拼 nonce——pack 一旦被部分重写或重排就会复用。

## 2.7 Argon2 参数：校准一次，然后冻结

母方案的 Time=3, Memory=64MB 对"云端被全量拖库 + 离线撞库"这个明确威胁偏弱。

| 参数 | 默认 | 硬下限 | 硬上限 | 说明 |
|---|---|---|---|---|
| time | 3 | 3 | 8 | 迭代次数 |
| memory_kiB | 262144（256 MiB） | **131072** | 1048576（1 GiB） | 内存是抗 GPU 的主参数 |
| threads | min(4, NumCPU) | 1 | 4 | 不占满移动设备全部核 |
| keylen | 32 | 32 | 32 | 固定 |

**校准流程**（仅 init 执行一次）：
1. 从 256 MiB 起，固定 time=3，测单次派生耗时；
2. 落在 1.0s – 2.0s 即采用；不足 1.0s 则 doubling 直到超过阈值或命中 1 GiB；
3. 超过 2.0s 则回退到 128 MiB 并接受更慢的解锁；
4. 结果写回 vault.meta，**此后永不更改**。

**必须**：
- **禁止**在 import / restore / 任何后续命令中重新校准或用本机值覆盖 vault.meta 的参数。参数必须可复现，否则同一密码派生出不同 MasterKey，灾难恢复必然失败。这是最容易写错的一处。
- **禁止**提供 argon2-params 之类的运行时覆盖 flag。
- init 结束时**必须**打印实际采用的参数，让用户知道自己在什么强度上。
- 因为参数永不升级（见 2.8），下限检查在 init **必须**是硬拒绝，而不是警告。

## 2.8 口令不可更改：约束与补救路径

因为 D-01 撤回，**口令在整个 vault 生命周期内不可变更**。这带来三条硬约束，**必须**写进 init 输出与 RECOVERY.txt：

| 情形 | 后果 | 补救 |
|---|---|---|
| 忘记主密码 | **永久不可恢复**。Armor Key 里没有密钥，只有盐与参数 | 无 |
| 怀疑密码已泄漏 / 强度不足 | 数据在攻击者手中可被离线尝试 | 唯一途径：`apex compact --new-identity --out <新目录>` 重建全库（新 salt、新 vault_id、新 key），完成后重新 export-key 并**手工删除旧库**。耗时与数据量成正比 |
| 想升级 Argon2 参数 | 不支持 | 同上 |

**必须**：
- init 时的密码强度检查因此从"建议"升级为"**必须**"：长度、字符集、是否命中常见密码字典前 10 万条。命中弱密码时**必须**要求输入 yes 二次确认已知风险。
- init 完成后**必须**提示：主密码无法更改，请确认已存入密码管理器，并已完成 Armor Key 的异地保存。
- status 与 doctor **必须**定期重述这条约束（新用户最容易在这里踩坑）。
- **禁止**在 CLI 中提供任何 rekey / change-password 命令——存在但不生效，比不存在更危险。

## 2.9 错误处理与 oracle 防护

- 解锁失败 → 统一错误 `E10 密码错误或 vault.meta 损坏`，退出码 10。**禁止**输出"MAC 不匹配"与"密文长度异常"的区分信息。
- 单次 backup / restore 内失败尝试用指数退避（1s, 2s, 4s…上限 30s），连续 5 次退出。目的不是防在线爆破（本地无此威胁），而是防止脚本化试错打穿 KDF 校准假设。
- 所有 MAC 比较走 `subtle.ConstantTimeCompare`（chacha20poly1305 内部已保证，自定义比较处必须自查）。

## 2.10 决策 D-16：Armor Key 编码

母方案：JSON → zstd → Base64。问题：Base64 含 `+ / =`，手抄/打印极易错；无校验位，抄错一个字符要到 restore 时才炸。

~~~text
APEX-KEY-V2-<payload>
payload = Crockford-Base32( zstd(vault.meta JSON) || CRC32C(前段) )
输出格式：每 5 字符一组，用连字符分隔，每行 72 列
~~~

- 字母表用 **Crockford Base32**（去掉 I L O U），大小写不敏感，人眼友好。
- 末尾 4 字节 CRC32C：import 时**必须**先验 CRC，失败立即 `E16 Armor 字符串损坏（CRC 校验失败）`。
- import 校验顺序：CRC → zstd 解压（有大小上限）→ JSON 解析 → version → vault_id → 用解出的 key 试解任一 journal 的 AAD（成功即证明 vault_id 匹配）。
- 前缀 `APEX-KEY-V2-` 便于密码管理器检索；**不**包含盐值以外的敏感信息。

## 2.11 内存安全（Go 的现实边界）

**必须承认**：Go 的 GC 会复制对象，无法保证清零；字节切片在 GC 后可能留下副本。分层处理：

| 对象 | 处理 |
|---|---|
| MasterKey 与 4 个子密钥 | 驻留在 memguard 风格锁定页（或 `syscall.Mlock` + 显式清零）；用后**必须** Destroy |
| 明文切片缓冲 | 复用 sync.Pool 的 32 MiB 缓冲，退出前显式清零；不追求完美（量太大，收益低） |
| 单文件明文 | **禁止**落盘到临时文件。restore 直接流式写到目标 |
| 命令行 / 日志 | 只在对密码无关的输出中出现 |

**必须**：panic 恢复路径与 SIGINT 处理路径都要走同一套 SecureWipe。

## 2.12 待确认

1. 是否预留"未来的分享 / 多设备只读凭证"？**结论**：不做，但 HKDF info 命名空间 apex-* 已预留，未来加第五把子密钥不需要改任何已有格式。
2. 是否需要"可否认性（duress password）"？**结论**：不。在"不支持改密码、无多密钥封装"的前提下，加它等于要求 DEK 层回来，与本次撤回冲突。
3. 撤回 D-01 后，若将来确实需要改密码，代价是"全库重写"（compact）。**建议**在 README 中把它标为"已知的、被接受的取舍"，而不是缺陷。
