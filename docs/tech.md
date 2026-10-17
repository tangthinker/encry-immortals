APEX：

在剔除数据释放（Eviction）的前提下，系统回归至最纯粹、最稳固的**单向不可变流水线架构（Unidirectional Immutable Pipeline）**。

整个系统的核心矛盾被收敛为两点：**“本地工作区与网盘盲盒的彻底物理隔离”**，以及**“以磁盘物理极限速度将文件变动转化为防篡改的追加日志与定长密文包”**。

以下是专为该场景定制的完整工程技术方案规范（技术栈基于 Go 生态）。

---

### 一、 架构根基：控制平面与数据平面的绝对解耦

为了确保网盘端哪怕被全量拖库也无法展开离线撞库，系统在拓扑上强制划分为**控制平面**与**存储平面**：

```text
[ 用户操作系统 ]
  │
  ├── 【控制平面】本地受保护工作区 (~/.config/apex-vault/)
  │     ├── vault.meta              # [高危/隔离] 盐值、Argon2id参数、密钥验证锚点
  │     └── state.db                # [本地缓存] 记录源文件元数据缓存与 Journal 历史快照
  │
  ├── 【数据源区】源文件目录 (Source Dir - 原始数据)
  │
  └── 【存储平面】加密输出目录 (Target Dir - 面向网盘的自动同步目录)
        ├── .tmp/                   # [临时隔离区] 仅用于同卷原子写入，网盘需忽略
        ├── meta/                   # [日志池] 类似 git message 的时序执行日志 (00000001.journal...)
        └── data/                   # [数据池] 纯追加、只增不减的加密包 (pack_*.dat)
```

**核心法则**：
*   **网盘盲盒化**：`Target Dir` 内严禁出现任何关于密码、算法、盐值、校验位的标记。网盘服务器仅能观察到无序的、高熵的二进制包不断生成。
*   **单向不可逆流动**：源目录变动 $\to$ 写入本地临时区 $\to$ 原子移动至 Target Dir $\to$ 网盘客户端静默单向抓取上云。

---

### 二、 密码学体系与密钥衍生协议

#### 1. 密钥衍生分层（Key Hierarchy）
系统采用两级密钥派生架构，防止单一密钥在不同上下文（数据与元数据）中产生密码学交叉泄露。

*   **根密钥派生（Argon2id）**：
    *   用户输入主密码（Master Password）。
    *   读取 `vault.meta` 中的 16 字节强随机盐（CSPRNG 生成）。
    *   算法参数：`Argon2id (Time=3, Memory=64MB, Threads=4, KeyLen=32B)`。计算得出 256 位 `MasterKey`。
*   **子密钥派生（HKDF-SHA256）**：
    利用 `MasterKey` 通过 HKDF 派生两把专用独立密钥：
    *   `StorageKey = HKDF_Expand(MasterKey, "apex-storage-payload-v1", 32)`
    *   `JournalKey = HKDF_Expand(MasterKey, "apex-journal-manifest-v1", 32)`

#### 2. 对称加密与认证基语
*   **算法选用**：**XChaCha20-Poly1305**（AEAD）。
*   **选用原因**：其 Nonce 长度高达 192-bit（24 字节）。由于增量备份会产生数以万计的独立切片，AES-GCM 的 96-bit Nonce 随随机生成次数上升存在碰撞死穴（一旦碰撞密钥直接失效），而 XChaCha20 的 192-bit 随机 Nonce 在概率上永远不会碰撞，保障在免中心协调状态下的分布式安全性。

#### 3. `vault.meta` 数据契约与导出规范
存储于 `~/.config/apex-vault/vault.meta`，数据结构规范为：

```json
{
  "version": 1,
  "kdf_params": {
    "algorithm": "argon2id",
    "time": 3,
    "memory": 65536,
    "threads": 4,
    "salt": "<Base64_16Bytes_Salt>"
  },
  "auth_verifier": "<Base64_XChaCha20_Poly1305_Ciphertext>"
}
```
*   `auth_verifier`：初始化时由 `JournalKey` 加密固定明文常量字符串（如 `"APEX_AEAD_VERIFY_OK"`）。用户输入密码后，程序首先尝试解密此字段，若解密失败（MAC 校验不通过），立即熔断退出并提示密码错误，无需扫描任何数据包。
*   **导出格式（Armor Key）**：
    提供 `export` 命令，将上述 JSON 经过 Zstandard 极度压缩后输出为纯文本 Base64 字符串（形如 `APEX-KEY-V1-XXXX...`），便于用户手抄、打印或存入密码管理器。

---

### 三、 物理存储层与二进制封装协议

#### 1. 切片策略（决策点 1-B 的工程落地）
*   **小文件（$\le 64\text{MB}$）**：完全以物理文件为最小单元，流式塞入当前未封顶的 `Data Pack` 中。不拆分文件，直接保留连续内存块，极大提升 I/O 吞吐。
*   **超大文件（$> 64\text{MB}$）**：以固定步长（默认 32MB 或 64MB）进行生硬切片，每段切片作为一个独立单元存入 Pack。切片指针串联交由 Journal 记录。

#### 2. Data Pack 二进制布局（随机读取友好型 AEAD）
每个 Pack 文件（`data/pack_<timestamp>_<rand>.dat`）大小上限为 64MB。
**Pack 内部拒绝整包加密，采用“自解释分片信封（Slice Envelope）”线性串联**：

```
+-----------------------------------------------------------------------------------+
| Slice 1: [Len: 4B] [Nonce: 24B] [Encrypted Slice Payload: N Bytes] [MAC: 16B]    |
+-----------------------------------------------------------------------------------+
| Slice 2: [Len: 4B] [Nonce: 24B] [Encrypted Slice Payload: M Bytes] [MAC: 16B]    |
+-----------------------------------------------------------------------------------+
| ...                                                                               |
+-----------------------------------------------------------------------------------+
```
*   `Len`（4 字节大端序）：记录当前分片的 `Nonce + Payload + MAC` 总字节数。
*   **第一性原理优势**：读取文件时，程序只需根据 Journal 提供的偏移地址 `file.Seek(offset)`，单次 I/O 即可抓取并解密对应切片，**解密速度达到 $O(1)$ 寻址，完全规避整包载入解密的内存暴涨与延迟**。

---

### 四、 状态机设计与时序增量日志规范（The Journal Engine）

每次执行备份，在 `meta/` 下产生一个纯增量的、单调递增的 Journal 文件（如 `00000001.journal`），这就是加密版的“Git Commit”。

#### 1. Journal 协议模型（序列化后经 `JournalKey` 整体加密）
内部为结构化二进制数据（JSON/MessagePack 经加密包装）：

*   **Header 区**：
    *   `Sequence`（uint64）：自增版本号（1, 2, 3...）。
    *   `Timestamp`（int64）：提交时间戳。
    *   `Message`（string）：类似 Git 提交信息（如“修改了财务报表”或“常规增量”）。
    *   `PrevJournalHash`（string）：上一个 Journal 密文文件的 SHA-256 哈希值，构成**防篡改哈希链（Hash Chain）**。
*   **Operations 变更向量区（Delta List）**：
    数组内包含本次提交的所有文件变动条目：
    *   `OpType`：枚举（`ADD` | `MODIFY` | `DELETE`）。
    *   `Path`：相对路径（统一使用跨平台的正斜杠，如 `photos/2026/img001.jpg`）。
    *   `Mode`：系统权限位（POSIX FileMode）。
    *   `ModTime`：纳秒级最后修改时间。
    *   `Size`：文件真实大小。
    *   `Checksum`：文件内容真实 SHA-256。
    *   `Slices`（有序切片寻址列表）：
        *   `PackID`（string）：数据存放在哪个包（如 `pack_177300000_a1b2.dat`）。
        *   `Offset`（int64）：在该 Pack 内的绝对物理字节偏移。
        *   `Length`（int64）：切片信封总字节长度。

---

### 五、 核心业务管线流转机制

#### 1. 增量备份执行管线（Backup Pipeline）

```
[源文件目录] 
     │
     ▼ (利用本地 state.db 快速跳过 mtime & size 未变文件)
[计算变动差异 (Delta)]
     │
     ├── 识别到 DELETE ──> 仅写入 Journal 的 DELETE 动作（老数据块物理保留）
     │
     └── 识别到 ADD / MODIFY
           │
           ▼ (小文件整存 / 大文件 32MB 等长切割)
     [流式组装 Data Pack]
           │
           ▼ (XChaCha20-Poly1305 独立信封加密)
     [写入 Target/.tmp/pack_temp.dat]
           │
           ▼ (刷盘 fsync 完毕)
     [原子 Rename 进 Target/data/pack_xxx.dat]
           │
           ▼ (所有新数据落盘)
     [生成本次 Journal 结构并加密]
           │
           ▼ (写入 Target/.tmp/journal_temp)
     [原子 Rename 进 Target/meta/0000000X.journal]
           │
           ▼
     [更新本地 state.db 状态快照]
```

**为什么老文件绝对不发生修改？**
*   **ADD**：产生新 Pack 写入新数据，Journal 记录新路径及新 Pack 指针。
*   **MODIFY**：产生新 Pack 写入新版本数据，Journal 记录该路径指向新 Pack 指针（旧 Pack 留在网盘绝不触碰）。
*   **DELETE**：不产生任何 Pack，不删除任何旧 Pack，仅在新的 Journal 里写入一条针对该路径的 `DELETE` 墓碑标记。
*   **结果**：网盘同步客户端**永远只会感应到目录里有全新的、写好的文件被添加**，绝无“重命名旧文件”或“覆盖旧文件”的操作，从物理根源上根绝网盘冲突与版本覆盖死锁。

#### 2. 解密还原状态机管线（Restore Pipeline）

还原工具本质上是一个 **确定性日志重放状态机（Deterministic Journal Replayer）**：

1.  **认证与密钥就绪**：
    *   输入主密码，结合本地（或导入的）`vault.meta` 解密 `auth_verifier` 通过验证，派生 `JournalKey` 与 `StorageKey`。
2.  **日志拓扑链重放**：
    *   按文件名严格升序（`00000001.journal` $\to$ `0000000N.journal`）依次解密所有 Journal。
    *   校验每份 Journal 的 `PrevJournalHash`，保证日志链无缺失、无颠倒、未被云端中间人篡改。
    *   在内存中维护一颗轻量级的虚拟文件树（Virtual FS Tree）：
        *   遇到 `ADD` / `MODIFY`：在树中插入或替换文件节点及其分块指针。
        *   遇到 `DELETE`：在树中将该路径节点抹除。
    *   *注：此状态机天生支持“快照穿梭”，若用户指定还原到第 5 次备份，重放执行到 `00000005.journal` 停止即可。*
3.  **按需数据拉取与解密还原**：
    *   遍历最终内存虚拟文件树。
    *   对每个文件：根据其记录的 `Slices` 列表，打开对应的 `data/pack_*.dat`。
    *   执行 `Seek` 寻址，逐块解密并拼装为原始文件。
    *   调用系统 API 还原原始文件的 `FileMode`（权限位）与 `ModTime`（修改时间戳）。

---

### 六、 网盘对抗与工程鲁棒性保障机制

1.  **消除上传截流（Atomic Swap 机制）**：
    *   夸克和百度网盘会监控目录变动，若程序直接往 `data/` 下写大文件，网盘客户端可能在文件写到一半时尝试锁定并上传，导致传上云端的是半截损坏文件，同时引起本地文件句柄冲突（Access Denied）。
    *   **规避方案**：程序在 `TargetDir` 同级目录下建立 `.tmp/`。所有 Pack 和 Journal 文件在 `.tmp/` 里完成所有写入与 `file.Sync()`，写完关闭文件句柄后，使用 `os.Rename()` 原子性地瞬间划入 `data/` 和 `meta/`。在操作系统底层，同卷 Rename 仅仅是元数据 Inode 指针修改，网盘感知到文件出现的瞬间，该文件在物理上就已经是完整闭合的。
2.  **规避文件名与内容审查标记（DPI & Static Analysis Defense）**：
    *   云端自动扫描对文件名带有 `.docx`、`.mp4`、`backup`、`.zip` 等敏感扩展名极其敏锐；同时对后缀为 `.enc`、`.crypto` 的文件容易标记为勒索软件或重点分析对象。
    *   **规避方案**：本方案中所有数据文件完全统一伪装为 `pack_<timestamp>_<6位随机字符>.dat`，日志统一命名为 `0000000X.journal`。无特征扩展名，无固定文件长度，全文件内容呈现均匀的高熵分布，在云端审查系统看来等同于常规的游戏客户端分包数据或未公开格式的数据库本地镜像文件。

---

### 七、 凭证导出与灾难恢复（Disaster Recovery）闭环

为了落实“`vault.meta` 不存放在目标目录”的硬性安全要求，整个灾备生命周期的操作流转如下：

```
[日常状态]
本地生成 vault.meta ──(执行导出)──> 获取 Armor 密钥字符串 ──> 存入离线安全区 (密码库/打印)
本地源文件变动 ──(执行备份)──> TargetDir 自动产生增量 ──> 网盘客户端自动同步上云

──────────────────────────────── 发生灾难：原电脑物理损毁 ────────────────────────────────

[重建恢复状态]
全新电脑环境安装本工具
      │
      ├── 1. 从网盘下载全部加密数据 (得到包含 data/ 和 meta/ 的 TargetDir)
      │
      ├── 2. 从密码库调出 Armor 密钥字符串，执行 import 导入本机
      │
      ├── 3. 执行 restore 命令，键入主密码
      │
      └── 系统校验无误，内存重放全部 Journals，100% 完美无损还原源目录
```

此方案在保持高吞吐和绝对纯量增量的同时，达成了**数据不可见性、防篡改性与抗网盘扫描**的最优工程平衡。
