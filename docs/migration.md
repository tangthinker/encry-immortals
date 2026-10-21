# 迁移与升级

本文覆盖三类迁移：TargetDir 布局（`output/` → 根目录）、旧名 `apex` 的兼容、以及跨版本升级时需要注意的点。

## 1. 从 output/ 迁回根目录

v0.1.3 / v0.1.4 曾使用：

```text
<TargetDir>/
  .tmp/
  .eimmortal.lock
  output/
    data/
    meta/
```

当前布局回到根目录，暂存区移到 TargetDir 同级：

```text
<TargetDir>/
  .eimmortal.lock
  data/
  meta/
    manifests/

<TargetDir>.tmp/        # 同级暂存区，不在同步目录内
```

程序会自动识别 `output/` 兼容布局，不会自动搬；`doctor` 会给出 WARN。迁移：

```bash
# 1. 停掉所有 eimmortal 进程
pgrep -fl eimmortal

# 2. 暂停网盘客户端，避免把目录搬动当成删除 + 重传

# 3. 同卷重命名，瞬时完成
cd /path/to/target
mv output/data output/meta .
rmdir output

# 4. 验证
eimmortal doctor
```

预期：

```text
PASS TargetDir 白名单  只包含 .eimmortal.lock、data/、meta/（旧 .tmp/ 允许；.DS_Store 忽略）
PASS TargetDir 布局    data/meta 在 TargetDir 根目录；暂存区在同级 <TargetDir>.tmp
```

说明：

- `vault.meta`、`state.db`、锚点都不需要改；journal 内部路径就是 `data/...`、`meta/...`。
- 旧版本可能在 TargetDir 里留下 `.tmp/`；确认没有进程后可以手工删除。新版本使用同级 `<TargetDir>.tmp`，会在下一次 backup 时创建。
- 如果根目录和 `output/` 同时存在 data/meta，程序优先使用根目录，`output/` 会被白名单拒绝；迁移时不要只搬一半。
- 如果网盘客户端之前同步的是 `<TargetDir>/output`，迁移后把同步根改回 `<TargetDir>`（或让客户端重新映射）。同步整个根目录的客户端会看到一次目录改名/移动；如果同步的是父目录，记得排除同级 `<TargetDir>.tmp`。
- 只迁移数据目录，不需要重新 `init`。

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

- 新库使用 `output/`；当前源码/下一次发布已改回根目录。
- 每个 pack 生成加密 manifest；旧 pack 没有。
- 新增 `restore --list-packs`、`restore --skip-missing-packs`、`manifest <pack>`。
- `restore` / `backup` 增加进度和吞吐输出（stderr）。
- v0.1.4 仅修复发布流程里的测试路径，功能与 v0.1.3 相同。

### 通用

- 升级前先确认 `eimmortal version`；控制平面和密文格式向后兼容，但**不要用旧版本写新库**。
- 换机器不要复制 `state.db`；它只是缓存，用 `eimmortal rebuild-state` 从 journal 重建。
- 跨机恢复前先 `eimmortal verify --size`，或用渐进恢复。
- 如果新版启动后 `doctor` 报布局/白名单错误，先确认是不是只迁移了一半（例如只有根目录 `data`，没有 `meta`，或 `output/` 还残留）。

## 4. 升级检查清单

```bash
eimmortal version
eimmortal status
eimmortal doctor --chain
eimmortal verify --sample 8
```

确认：

- 控制平面仍在 `~/.eimmortal/eimmortal-vault`（或旧路径自动回退）
- `TargetDir` 布局是根目录（或可识别的 `output/` 兼容布局）
- 暂存区是同级 `<TargetDir>.tmp`，且与 TargetDir 同卷
- 锚点 `Anchor` 与 `Last commit` 一致
- 没有缺失/孤儿 pack（`status --chain` / `doctor --chain`）
