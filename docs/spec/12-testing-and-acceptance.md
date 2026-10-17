# 12 · 测试与验收（新增章节）

> 母方案没有任何测试与验收定义。对一个"备份工具"来说，没有崩溃注入测试与 golden vector 就等于没有质量保证——这类软件的 bug 不会在开发时暴露，只会在用户最需要它的那天暴露。

## 12.1 测试金字塔

| 层 | 内容 | 目标覆盖率 | 运行时长 |
|---|---|---|---|
| 单元 | 信封编解码、AAD 拼装、journal 编解码、路径归一化、Base32/CRC | ≥ 90% | < 5 s |
| 属性测试 | 随机文件树 × 随机 checkpoint 间隔 → 还原等价（I4） | — | < 60 s |
| 集成 | 完整 backup → restore → 逐字节比对（含 mode/mtime/目录/空文件） | — | < 120 s |
| 故障注入 | 在 7 个提交阶段 kill -9；篡改/截断/删除/替换 | — | < 180 s |
| 跨平台 | Linux / macOS / Windows CI | — | — |
| 规模 | 100 万文件 / 500 GB 慢速基线（每周一次） | — | 小时级 |

## 12.2 崩溃注入矩阵（与 05 章 5.2 对应）

实现方式：环境变量 `APEX_TEST_CRASH_AT=<stage>` 在指定阶段结束前 `os.Exit(137)`（**必须**只在 `-tags testhooks` 构建下编译进去，release 构建中不存在）。

| 用例 | 注入点 | 断言 |
|---|---|---|
| C1 | 写 pack 中途 | `.tmp/` 有残片；随后补齐的 backup 成功；最终 restore 结果 == 无注入的对照组 |
| C2 | pack fsync 后、rename 前 | 同 C1 |
| C3 | pack rename 后、目录 fsync 前 | 同 C1（允许该 pack 丢失，重新生成） |
| C4 | pack 落盘后、journal 写入前 | `doctor` 报 `ORPHAN_PACKS 1`；重复 backup 不报错；restore 结果正确 |
| C5 | journal 写 `.tmp/` 后、rename 前 | 同 C1 |
| C6 | journal rename 后、目录 fsync 前 | 若 journal 丢失：恢复到前一 seq 且 `doctor` 无错误；若保留：一切正常 |
| C7 | journal 提交后、state.db 更新前 | 数据完整；`rebuild-state` 后行为与无注入一致 |
| C8 | restore 写到一半 | 重跑可续解；最终结果 == 一次跑完 |
| C9 | `compact --new-identity` 写到一半 | 旧库完全不受影响；新目录可整体删除后重跑 |

**必须**：每个用例跑 20 次（随机化注入 Timing），全部通过才算稳定。

## 12.3 Golden vectors

目的：防止依赖升级（`x/crypto`、zstd 库）静默改变输出，导致"以前写的 vault 新版本读不出来"。

| Vector | 内容 |
|---|---|
| GV-1 | 固定 key/nonce/AAD 下的 slice envelope 字节 + 解密结果 |
| GV-2 | 固定 key/nonce 下的 journal 密文文件字节 + 明文 |
| GV-3 | 固定的 vault.meta（含 salt / 参数 / auth_verifier）与其密码校验结果 |
| GV-4 | Crockford Base32 + CRC32C 的 5 组对照（含手抄错一位的拒绝用例） |
| GV-5 | HKDF 派生的 4 个子密钥 hex（固定 MasterKey + vault_id） |

**必须**：GV 文件随仓库提交，且 CI 中任一字节变化即失败。若确实需要改变，只能通过**显式升级 wire version**，不能静默改。

**注意**：GV-1/GV-2 依赖 XChaCha20-Poly1305 的实现细节，只对**同一算法**有效。未来换算法时新增 GV，不复用旧编号。

## 12.4 Fuzz 目标

| 目标 | 输入 | 断言 |
|---|---|---|
| `FuzzSliceEnvelope` | 随机字节流当作 pack 内容 | 永不 panic；永不分配超过 max 声明大小的内存；要么返回明确错误，要么返回长度正确的明文 |
| `FuzzJournalDecode` | 随机字节流当作 journal | 同上 |
| `FuzzArmorKey` | 随机字符串 | 永不 panic；CRC 校验先于解压；解压有大小上限 |
| `FuzzPathNormalize` | 随机 Unicode 与分隔符 | NFC 后 idempotent；永不产出 `..` 或绝对路径 |
| `FuzzRestoreTarget` | 恶意路径（zip-slip 变种） | 必须在写盘前拒绝 |

**必须**：fuzz 各跑 30 min（nightly），种子语料入库。

## 12.5 属性测试

~~~text
property RoundTrip(tree):
    backup(tree) → restore → assert 逐字节相等
    且 assert 每个文件的 (mode & 0o777) 相等、mtime 相等（容差 0）
    且 assert 目录集合相等（含空目录）
    且 assert 不存在的路径仍然不存在

property DeterministicReplay(tree, checkpointInterval):
    A = 全量重放
    B = 最近 checkpoint + 增量
    assert A == B（结构相等，逐字段）

property TamperDetection(pack, byteIndex):
    篡改任一字节 → 解密或校验必须失败（不得静默通过）

property IdempotentBackup(tree):
    backup(tree); backup(tree)  → 第二次不产生 journal（I8）

property FastModeMissIsStrictModeHit(tree):
    构造"等长 + 保留 mtime"的内容替换 → fast 漏检、strict 检出
~~~

## 12.6 跨平台矩阵

| 维度 | Linux (ext4/xfs) | macOS (APFS) | Windows (NTFS) |
|---|---|---|---|
| 文件名 Unicode | 直接 | **NFD 归一化**必测 | 直接 |
| 大小写敏感 | 是 | 默认否（可配） | 否 |
| 长路径 | `PATH_MAX` | 1024 | `MAX_PATH` 需 `\\?\` |
| 目录 fsync | 支持 | 支持 | **弱**（05 章 5.8） |
| rename 到已存在 | 覆盖 | 覆盖 | **失败** |
| 权限位 | 完整 | 部分（忽略 group/other 的某些位） | 几乎无意义 |
| 时间精度 | ns | ns | 100 ns（但 FAT/SMB 会截断） |

**必须**：CI 至少覆盖三者；Windows 上的"mtime 还原"用例需放宽为"秒级相等"并在报告中标注。

## 12.7 性能基线（P50，单机 SSD）

| 场景 | 数据量 | 目标 |
|---|---|---|
| 增量 backup（无变更，100 万文件） | — | < 60 s（stat 密集型） |
| 增量 backup（1 GB 新数据，可压缩 0.3） | 1 GB | < 90 s，内存峰值 < 600 MiB |
| 增量 backup（10 GB 不可压缩） | 10 GB | > 200 MB/s 吞吐 |
| restore（全量 50 GB） | 50 GB | > 300 MB/s，内存峰值 < 600 MiB |
| restore 单文件（100 MB，随机位置） | — | < 1 s（O(1) 寻址的核心收益） |
| 启动到可 restore（1000 次提交，含 checkpoint） | — | < 3 s |
| 启动到可 restore（1000 次提交，无 checkpoint） | — | 允许慢，但需 < 5 min 且给出进度 |

**必须**：若"无 checkpoint"路径超过 5 min，说明 checkpoint 策略必须默认开启。

## 12.8 验收标准（DoD）

1. 12.2 全部崩溃注入用例 20/20 通过。
2. 12.3 golden vectors 全绿，且跨版本 CI 中"旧二进制读新数据"与"新二进制读旧数据"均有覆盖。
3. 12.4 的 5 个 fuzz 目标各跑满 30 min 无崩溃、无 OOM。
4. 12.5 属性测试在 10,000 次随机树上无失败。
5. 12.6 三平台 CI 全绿。
6. 12.7 的性能目标全部达标（允许 ±20% 余量）。
7. 09 章的不变量中有运行时检查手段的，全部接入 `apex doctor --self-check`。
8. 一次"演练式"的完整灾难恢复（新机器 + Armor Key + 空目录）通过，且恢复后的抽查 100 个文件的 SHA-256 与源一致。
9. 一次"恶意输入"审计：手工构造 20 个恶意 pack/journal（截断、位翻转、切片交换、序号重排、路径穿越），全部被正确拒绝且错误信息符合 10.7。

## 12.9 CI 分层

| 触发 | 内容 |
|---|---|
| 每次 push | 单元 + 属性（小规模）+ golden vectors + 交叉编译 |
| 每次 PR | 上述 + 集成 + 崩溃注入（每用例 3 次） |
| nightly | 崩溃注入 20 次全跑 + fuzz 30 min + 三平台 |
| weekly | 规模测试（100 万文件 / 500 GB） |

## 12.10 待确认

1. 是否需要"双进程并发写同一 Target"的自动化测试？**结论**：需要（I15），但只能在本机 fork 两个进程（跨机器场景无法自动化，靠 `.apex.lock` 逻辑单测 + 人工演练）。
2. 是否引入基于真实网盘客户端的端到端测试？**结论**：不做（不可自动化、依赖第三方）。用一个"模拟延迟与乱序的本地同步器"代替，见 12.11。
3. **建议**实现一个 `apex-test-sync` 内部工具：把 Target 目录以"随机延迟 + 随机顺序 + 偶发丢弃一个文件"的方式复制到另一个目录，再用 restore 验证最终一致性。这是唯一能真正验证 06 章假设的手段。
