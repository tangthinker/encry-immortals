# 迁移与升级

本文覆盖三类迁移：TargetDir 新布局（`output/`）、旧名 `apex` 的兼容、以及跨版本升级时需要注意的点。

## 1. 把旧布局迁到 output/

v0.1.3 起，新库使用：

```text
<TargetDir>/
  .tmp/
  .eimmortal.lock
  output/
    data/
    meta/
      manifests/
```

旧库的 `data/`、`meta/` 直接在 `<TargetDir>/` 下。程序会自动识别旧布局并继续工作，**不会自动搬**；要切换：

```bash
# 1. 停掉所有 eimmortal 进程
pgrep -fl eimmortal

# 2. 暂停网盘客户端，避免把目录搬动当成删除 + 重传

# 3. 同卷重命名，瞬时完成
cd /path/to/target
mkdir output
mv data meta output/

# 4. 验证
eimmortal doctor
```

预期：

```text
PASS TargetDir 白名单  只包含 .tmp/、.eimmortal.lock、output/（忽略 .DS_Store）
PASS TargetDir 布局    output/data + output/meta
```

说明：

- `vault.meta`、`state.db`、锚点都不需要改；journal 内部路径是相对 `output/` 的 `data/...`、`meta/...`。
- 只同步 `output/` 的客户端，请在迁移前就把同步根指向 `<TargetDir>/output`；同步整个根目录的客户端会看到一次"删除 data/meta + 新增 output/data/meta"的大变更。
- 迁移前不要创建空的 `output/` 后继续备份：旧布局检测到根目录 `data/meta` 时仍按旧布局工作，此时根目录多出的 `output/` 会被当成污染。
- 迁移后旧 pack 没有 manifest；新备份和 `compact` 会生成。`restore --list-packs` / `--skip-missing-packs` 仍从 journal 计算，不受影响。

## 2. apex → eimmortal 旧名兼容

工具在 2026-10-17 由 `apex` 更名为 `eimmortal`。为了不破坏已有数据，旧名称在**读取路径**上仍然兼容：

| 项目 | 新 | 旧（仍可读） |
|---|---|---|
| 二进制 | `eimmortal` | `apex` 仅作为历史名 |
| 默认控制平面 | `~/.eimmortal/eimmortal-vault` | `~/.config/eimmortal-vault`，再往前 `~/.config/apex-vault` |
| 默认配置 | `~/.config/eimmortal/config.toml` | `~/.config/apex/config.toml` |
| Armor Key | `EIMMORTAL-KEY-V2-…` | `import-key` 仍接受 `APEX-KEY-V2-…` |
| TargetDir 锁 | `.eimmortal.lock` | `.apex.lock` 仍被视为"正在写入"，`--break-lock` 同时清理 |
| 续解进度 | `.eimmortal-restore-progress` | 读 `.apex-restore-progress` 并自动迁移 |
| 密码 FD | `EIMMORTAL_PASSWORD_FD` | `APEX_PASSWORD_FD` 作为回退 |
| 崩溃注入 | `EIMMORTAL_TEST_CRASH_AT` | `APEX_TEST_CRASH_AT` 作为回退 |

**线格式常量故意没有改名**：HKDF info（`apex-*-v2`）、genesis（`APEX-JOURNAL-GENESIS-v3`）、校验常量（`APEX_AEAD_VERIFY_OK`）、journal/pack 命名、AAD 布局都保持原样。改名会让已有库无法解密。详见 [dev/decisions.md](dev/decisions.md) ADR-022。

配置/控制平面路径的自动回退只在"新路径不存在、旧路径存在"时生效。用 `--config` / `--vault` 可以显式指定。

## 3. 版本升级注意事项

### v0.1.3 / v0.1.4

- 新库使用 `output/`；旧布局仍可读。
- 每个 pack 生成加密 manifest；旧 pack 没有。
- 新增 `restore --list-packs`、`restore --skip-missing-packs`、`manifest <pack>`。
- `restore` / `backup` 增加进度和吞吐输出（stderr）。
- v0.1.4 仅修复发布流程里的测试路径，功能与 v0.1.3 相同。

### 通用

- 升级前先确认 `eimmortal version`；控制平面和密文格式向后兼容，但**不要用旧版本写新库**。
- 换机器不要复制 `state.db`；它只是缓存，用 `eimmortal rebuild-state` 从 journal 重建。
- 跨机恢复前先 `eimmortal verify --size`，或用渐进恢复。
- 如果新版启动后 `doctor` 报布局/白名单错误，先确认是不是只迁移了一半（例如只有 `output/data`，没有 `output/meta`）。

## 4. 升级检查清单

```bash
eimmortal version
eimmortal status
eimmortal doctor --chain
eimmortal verify --sample 8
```

确认：

- 控制平面仍在 `~/.eimmortal/eimmortal-vault`（或旧路径自动回退）
- `TargetDir` 布局是 `output/` 或可识别的旧布局
- 锚点 `Anchor` 与 `Last commit` 一致
- 没有缺失/孤儿 pack（`status --chain` / `doctor --chain`）
