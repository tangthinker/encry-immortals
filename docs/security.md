# 安全模型

本文是面向使用者的安全说明。完整的威胁矩阵、破解成本与不变量见 [spec/08-threat-model.md](spec/08-threat-model.md)、[spec/02-crypto.md](spec/02-crypto.md)、[spec/09-invariants.md](spec/09-invariants.md)。

## 1. 保护什么

eimmortal 的目标是：**把备份交给不完全信任的网盘，同时不让网盘看到文件内容、文件名或目录结构。**

| 对象 | 云端可见性 |
|---|---|
| 文件内容 | 密文（XChaCha20-Poly1305） |
| 文件路径 / 目录树 | 不出现在 pack 命名中；加密在 journal/manifest 里 |
| 密钥 / 主密码 | 永不进入 TargetDir |
| pack 数量、大小、写入时间 | **可见**（元数据泄露） |
| journal 数量、提交时间 | **可见** |
| 是否在使用 eimmortal | 可见（目录/文件名特征） |

它**不防**：

- 已经控制你本机、能读控制平面或键盘的恶意软件
- 你主动把主密码/Armor Key 交给别人
- 网盘侧对你**本地**目录的删除、勒索或不可用（只保证密文完整性和可验证性）
- 流量分析、写入频率、备份规模等侧信道

## 2. 密码学流程

```text
主密码
  └─ Argon2id（salt/KDF 参数存在 vault.meta，init 时校准一次并冻结）
       └─ HKDF-SHA256 → 4 把子密钥（journal/storage/path/anchor）
            ├─ Storage key：加密每个 slice（XChaCha20-Poly1305）
            ├─ Journal key：加密 journal 与 per-pack manifest
            ├─ Path key：state.db 里的路径 HMAC 索引
            └─ Anchor key：本地回滚锚点 MAC
```

- 每个切片独立随机 nonce；AAD 绑定 `ver_alg/env_len/plain_len/pack_id/offset/index/txn_id/codec`。
- journal 的 AAD 绑定 `seq` 与 `vault_id`；journal 之间用 SHA-256 哈希链。
- 本地锚点记录最新 `(seq, journal_sha256)` 的 MAC，用来检测云端截断/回滚。
- 压缩发生在加密之前；zstd 帧 CRC 关闭，因为每个切片已有 Poly1305 与 `plain_sha256`。

## 3. 三件套与存放

| 材料 | 位置 | 要求 |
|---|---|---|
| 主密码 | 只在你的脑子里/密码管理器 | **不可更改**；忘记即永久无法恢复 |
| Armor Key | `eimmortal export-key` 输出 | 只含 salt/KDF 参数 + CRC，**不含密钥**；与密码分开存放 |
| 控制平面 | `~/.eimmortal/eimmortal-vault/`（0700） | **绝不放进同步目录**；`vault.meta` 0600 |
| 密文数据 | `<TargetDir>/`（`data/`、`meta/`） | 可以放网盘；不要放密钥/明文提示 |

最低要求：

1. Armor Key 打印/抄写一份，和密码分两个地方保存。
2. 控制平面不要进 iCloud/Dropbox/OneDrive。
3. 定期做恢复演练；不做演练等于没有备份。

## 4. 完整性 / 回滚检测

- **哈希链**：每个 journal 的 `prev_hash` 指向前一个 journal；缺一个、换一个、截断都会被 `verify` / `doctor --chain` 发现。
- **本地锚点**：`state.db` 保存最新 journal 的 MAC；云端回滚到旧版本会被锚点发现。
- **pack 指纹**：journal 记录每个 pack 的 `(name, size, sha256)`；`verify --sample` / `--deep` 校验内容。
- **manifest**：每个 pack 的小型加密索引，便于渐进恢复；它不替代 journal 的提交语义。

检测到 E11/E12 时应停止写入，先 `doctor --chain` / `verify --deep`，不要盲目 `rebuild-state` 覆盖证据。

## 5. 已知限制

- **主密码不可更改**。换密码的唯一途径是 `compact --new-identity` 重建全库。
- **不做去重**：同一文件改一版就多占一份空间；这是不可变追加的代价。
- **单写者**：同一 TargetDir 只允许一个进程/主机写；本地 flock + `.eimmortal.lock` + 严格 seq。
- **纯追加**：已写出的 pack 永不修改/删除；`compact` 生成新库，旧库需手工删。
- **不支持项 fail-fast**：硬链接、xattr/ACL、设备文件/FIFO/socket、非法 UTF-8、超长路径、大小写折叠冲突等，默认直接报错（E21），避免静默丢元数据。
- **不感知同步**：程序不知道云端是否同步完成；跨机恢复前用 `verify --size` / 渐进恢复。
- **没有常驻进程**：没有 `watch`、`mount`、自动改密码；备份由 cron/launchd 或手工触发。
- **元数据泄露**：pack/journal 的数量、大小、时间和写入模式对云端可见；隐藏文件名和内容，不隐藏"你在备份"。

## 6. 推荐实践

- 主密码用 4 个以上随机单词，或密码管理器生成的长密码。
- Armor Key 与密码分开存放；至少一份离线/打印件。
- 网盘开启版本历史/回收站，防止误删；但不要依赖它做回滚检测。
- 每月 `verify --sample 8`，每季度做一次空目录 restore 演练。
- 怀疑密码泄露：用 `compact --new-identity` 生成新库，重新 `export-key`，再删旧库。
- 不要把 `.tmp`、`.eimmortal.lock`、控制平面放进同步目录。
