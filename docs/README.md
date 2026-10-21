# eimmortal 文档

[项目首页](../README.md) 是安装与快速上手；本目录放细节。

## 我想……

| 目标 | 看这里 |
|---|---|
| 第一次安装、初始化、备份、恢复 | [usage.md](usage.md) |
| 日常运维、定时备份、云端同步、灾备演练、容量/压缩/性能 | [operations.md](operations.md) |
| 评估安全性、密钥管理、威胁模型 | [security.md](security.md) |
| 从旧版本升级、把旧布局迁到 `output/`、apex 旧名兼容 | [migration.md](migration.md) |
| 参与开发、跑测试、CI、发布流程 | [development.md](development.md) |
| 所有配置项和默认值 | [../config.example.toml](../config.example.toml) |
| 字节级格式、协议、崩溃恢复、验收标准 | [spec/README.md](spec/README.md) |
| 产品级设计（是什么 / 为什么） | [tech.md](tech.md) |
| 实现决策（ADR）、执行日志、待决问题 | [dev/README.md](dev/README.md) |

## 权威顺序

1. **线格式与不变量**：[spec/](spec/README.md)（字节级契约）
2. **实现决策**：[dev/decisions.md](dev/decisions.md)（ADR）
3. **代码注释**

`docs/spec/` 成文时工具名为 `apex`；现在二进制是 `eimmortal`，文中的 `apex <command>` 请按 `eimmortal <command>` 理解。协议常量（HKDF info `apex-*-v2`、genesis、`APEX_AEAD_VERIFY_OK`）**故意保持不变**，改名会让已有库无法解密。详见 [dev/decisions.md](dev/decisions.md) ADR-022。
