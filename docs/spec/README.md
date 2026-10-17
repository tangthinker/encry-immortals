# APEX 工程规范补充文档集

> 母方案：[../tech.md](../tech.md)（下称"母方案"）。**母方案不改动**，本目录只做细节补充与决策落地。
> 定位差异：母方案回答"是什么 / 为什么"，本目录回答"字节长什么样 / 出错怎么办 / 怎么验收"。

## 索引

一个章节一个文档。01–07 与母方案七章一一对应；08–12 是实现阶段必须拍板、但母方案覆盖不到的新增章节。

| 文档 | 对应母方案 | 主题 | 含一次性线格式变更 |
|---|---|---|---|
| [01-architecture.md](01-architecture.md) | 第一章 架构根基 | 目录布局定稿、staging 区位置、单写者与锁、平面边界 | 是 |
| [02-crypto.md](02-crypto.md) | 第二章 密码学体系 | 直接派生（D-01R）、auth_verifier 契约、AAD 全绑定、KDF 校准与冻结、Armor Key 编码 | **是** |
| [03-storage-format.md](03-storage-format.md) | 第三章 物理存储层 | Slice Envelope 字节级、Pack 布局、footer、rollover、命名 | **是** |
| [04-journal-engine.md](04-journal-engine.md) | 第四章 日志引擎 | Journal 线格式、packs 指纹、目录 op、genesis/锚点、checkpoint | **是** |
| [05-pipeline.md](05-pipeline.md) | 第五章 业务管线 | 提交协议、崩溃恢复、幂等、变更检测、restore 安全边界 | 否 |
| [06-cloud-adversarial.md](06-cloud-adversarial.md) | 第六章 网盘对抗 | 同步语义假设、目录膨胀、远端校验、秒传、乱序到达 | 部分 |
| [07-disaster-recovery.md](07-disaster-recovery.md) | 第七章 灾备闭环 | Armor 可用性、vault.meta 冗余、无锚点恢复、演练 | 否 |
| [08-threat-model.md](08-threat-model.md) | —（新增） | 威胁模型与"防 / 不防"矩阵、破解成本估算 | 否 |
| [09-invariants.md](09-invariants.md) | —（新增） | 系统不变量清单 I1–I15 及其强制点、对应测试 | 否 |
| [10-cli-and-config.md](10-cli-and-config.md) | —（新增） | 命令面、配置项、退出码、密码输入、输出契约 | 否 |
| [11-capacity-and-compaction.md](11-capacity-and-compaction.md) | —（新增） | 容量公式、压缩、去重取舍、无回收的出口 compact | 否 |
| [12-testing-and-acceptance.md](12-testing-and-acceptance.md) | —（新增） | 崩溃注入矩阵、golden vectors、跨平台、验收标准 | 否 |

## 阅读顺序建议

- 只想知道"要不要改设计"：读 08 → 02 → 03 → 04 的"决策记录"小节。
- 要开始写代码：09（不变量）→ 03/04（线格式）→ 05（提交协议）→ 10（命令面）。
- 要评审安全：08 → 02 → 04（锚点 / hash chain）。

## 全局约定（所有文档共用）

| 项 | 约定 |
|---|---|
| 字节序 | 多字节整数一律**大端**（network order）；线格式内**禁止出现浮点数** |
| 整数宽度 | 显式写出（u8 / u16 / u32 / u64 / i64），禁止隐式平台宽度（Go 的 `int` 不入线格式） |
| 单位 | `*_kiB` 为 KiB；`*_bytes` 为字节；`*_ns` 为纳秒；`*_unix` 为秒 |
| 版本字节 | `ver_alg`：高 4 位 = wire version（当前 `1`），低 4 位 = 算法 ID（`1` = XChaCha20-Poly1305）。当前值为 `0x11` |
| 路径 | 入库前统一 **NFC 归一化** + 分隔符强制 `/` + 相对 vault root + 禁止 `..` / 绝对路径 / 前导 `/` / 空段 |
| 哈希 | 一律 SHA-256；在线格式中存 32 字节**原始字节**，在人读输出中存 Base64URL（无填充） |
| 随机 | 一律 `crypto/rand`（CSPRNG）；禁止 `math/rand` 出现在任何安全相关路径 |
| 密码学基元 | 只组合 Argon2id / HKDF-SHA256 / XChaCha20-Poly1305，**不自创基元、不改参数组合方式** |
| "必须" / "建议" | "必须" = 不满足即实现缺陷，可写测试；"建议" = 可按平台裁剪 |

## 决策索引

| ID | 决策 | 落点 | 影响面 |
|---|---|---|---|
| ~~D-01~~ | ~~引入 KEK/DEK 两层封装以便改密码~~ **已撤回**：确认本系统不需要修改密码 | 02 | — |
| D-01R | 直接派生 + auth_verifier 补齐 nonce/AAD + KDF 参数 init 后冻结；换口令唯一途径是 compact | 02 | vault.meta 契约 |
| D-02 | 每个切片 envelope 全字段 AAD 绑定 | 02 / 03 | 线格式 |
| D-03 | Journal 的 AAD 绑定序列号与 vault_id | 02 / 04 | 线格式 |
| D-04 | Genesis 常量 + 本地锚点，检测截断 / 回滚 | 04 / 07 | 线格式 + 本地状态 |
| D-05 | Journal 记录每个新 pack 的 (name, size, sha256) | 04 | 线格式 |
| D-06 | staging 区必须在 Target 内（同卷）+ `st_dev` 校验 | 01 / 06 | 目录布局 |
| D-07 | 固定提交顺序 + 父目录 fsync | 05 | 管线 |
| D-08 | pack 上限 128 MiB、大文件切片 32 MiB、整存阈值 64 MiB | 03 | 参数 |
| D-09 | 新增 MKDIR / RMDIR / SYMLINK / META 操作类型；空文件零切片 | 04 | 线格式 |
| D-10 | Journal 用 MessagePack 紧凑数组 schema（非 map） | 04 | 线格式 |
| D-11 | 加密前对明文做 zstd 压缩，codec 字节入 envelope 与 AAD | 03 / 11 | 线格式 |
| D-12 | 保持"无回收"，但提供 `compact` 作为唯一出口 | 11 | 运维 |
| D-13 | state.db 不存明文路径，只存 `HMAC(PathKey, path)` | 05 | 本地状态 |
| D-14 | 引入 checkpoint journal，避免 restore 全链解密 | 04 | 线格式 |
| D-15 | 单写者约束：进程内 flock + vault.lock 持有者记录 | 01 | 运维 |
| D-16 | Armor Key 改用 Crockford Base32 + CRC32C + 分组 | 02 / 07 | 用户可见格式 |
| D-17 | 每个切片单独记 SHA-256（局部校验 / 抢救） | 04 | 线格式 |
| D-18 | 显式"不支持项"清单，遇到即 fail-fast 而非静默丢弃 | 01 | 行为 |

## 已接受的取舍（是决策，不是缺陷）

评审时这几条最容易被反复提出，在此一次性钉死。任何一条若被推翻，应新增决策号，而不是就地改文档措辞。

| 取舍 | 代价 | 出口 |
|---|---|---|
| 不支持修改主密码（D-01R） | 忘记即永久丢失；密码泄漏后无法补救 | `apex compact --new-identity` 重建全库（小时级） |
| 不做内容去重（11 章） | 同一文件改一版就多占一份空间 | 同上 |
| 不做 eviction / 不删历史（母方案原定） | 已删除文件的切片永久占用云盘 | 同上 |
| 单写者，多写者 fail-closed（01 章 D-15） | 两台机器不能同时写同一 Target | 只用一台，或各用各的 Target |
| 无前向保密（08 章） | 一次口令泄漏即影响全部历史版本 | 无。若要历史隔离，需 compact 分段归档 |
| 不支持符号链接以外的特殊文件（01 章 D-18） | 硬链接 / xattr / 稀疏文件会 fail-fast | 显式排除，或接受降级 |

## 与母方案不一致之处（需要回填母方案或确认）

| 母方案位置 | 冲突 | 本目录结论 |
|---|---|---|
| 第一章 L24 vs 第六章 L191 | `.tmp` 在 Target 内 / Target 同级，两者矛盾 | 01：定死为 Target 内，见 D-06 |
| 第三章 L79 vs L83 | 整存阈值 64 MiB，但 pack 上限也是 64 MiB，64 MiB 文件永远塞不进 | 03：pack 上限提到 128 MiB，见 D-08 |
| 第二章 L70 | `auth_verifier` 只有密文没有 nonce 字段，格式不可实现 | 02：保留 auth_verifier，补齐 nonce 与 AAD 绑定，见 D-01R |
| 第二章 L44 | `Memory=64MB` 对"全量拖库离线撞库"偏弱 | 02：默认 256 MiB 并做单机校准 |
| 第四章 L102/L153 | journal 文件名出现 7 位与 8 位两种写法，字典序会错乱 | 04：固定 8 位零填充，且 seq 与文件名必须一致 |
