# 开发指南

## 1. 环境

- Go 1.26+
- Linux / macOS / Windows 均可构建（纯 Go，`CGO_ENABLED=0`）
- `make`（可选；直接 `go build` 也行）

```bash
git clone https://github.com/tangthinker/encry-immortals.git
cd encry-immortals
make build          # bin/eimmortal
make test
make vet
```

## 2. 常用命令

| 命令 | 作用 |
|---|---|
| `make build` | 构建 `bin/eimmortal` |
| `make test` | `go test ./...` |
| `make test-race` | `go test -race ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -l -w ./cmd ./internal ./tools` |
| `make fuzz` | `FuzzSliceEnvelope`，默认 60s（`FUZZTIME` 可覆盖） |
| `make golden` | 校验 `testdata/golden/` |
| `make crash-test` | 崩溃注入矩阵 K1–K8 |
| `make scale-test` | 链加载规模测量 |
| `make release-snapshot` | 本地打 release 包到 `dist/`，不推送 |

受限环境里全局 Go 缓存可能不可写，用仓库内缓存：

```bash
export GOCACHE=$PWD/.cache/go-build
export GOMODCACHE=$PWD/.cache/gomod
export GOSUMDB=off
```

## 3. 代码布局

```text
cmd/eimmortal/          CLI 入口
internal/apexerr/       错误码 / 退出码
internal/crypto/        口令派生、子密钥、AEAD、AAD
internal/armor/         Armor Key（Crockford Base32 + CRC32C）
internal/codec/         zstd 压缩层
internal/pathx/         路径归一化与安全校验
internal/wire/          线格式：Slice Envelope、Pack、Journal
internal/vault/         vault.meta、控制平面、锁
internal/store/         TargetDir 布局、pack I/O、原子换入
internal/journal/       链校验、重放状态机
internal/index/         state.db
internal/pipeline/      backup / restore / compact / manifest 管线
internal/config/        config.toml
internal/cli/           命令面
testdata/golden/        Golden vectors
tools/goldengen/        golden 生成器
```

更细的三层文档关系（spec > dev decisions > 代码注释）见 [dev/README.md](dev/README.md)。

## 4. 测试与 CI

CI 分层见 [.github/workflows/ci.yml](../.github/workflows/ci.yml)：

- push / PR：gofmt、`go vet`、全量测试、崩溃注入矩阵、golden vectors
- 夜间：3 × 30 min fuzz
- Windows：构建 + 核心包单测（symlink 相关套件在 Windows 上跳过）
- 交叉编译：linux/darwin/windows，amd64/arm64

macOS 本机跑测试时，系统可能给新建文件打 `com.apple.provenance`，导致扫描类测试报 E21；测试配置里可加 `scan.ignore_xattr = true`，CI 的 Linux/macOS runner 不会带这个属性。

### Golden vectors

`testdata/golden/` 由 `go run ./tools/goldengen` 生成。**改动任何一个字节都意味着线格式或依赖行为变了**，必须显式评估是否升 wire version，并同步更新 `docs/spec/` 与相关测试。

## 5. 发布

推送 `v*` 标签会触发 [.github/workflows/release.yml](../.github/workflows/release.yml)：

1. `go vet ./...` + `go test ./...`
2. 交叉编译 linux/darwin amd64/arm64、windows amd64
3. 打包二进制、`README.md`、`config.example.toml`、`docs/`；Windows 用 zip
4. 生成 `checksums.txt`（SHA-256）
5. 创建 GitHub Release（自动 notes；带 `-` 的标签为 prerelease）
6. 通过 `-ldflags "-X main.version=<tag>"` 注入版本号

```bash
git tag -a v0.1.x -m "v0.1.x"
git push origin v0.1.x
```

本地先看产物：`make release-snapshot`，输出在 `dist/`。

## 6. 贡献

- 提交前跑 `gofmt`、`go vet`、相关测试。
- 涉及线格式、AAD、journal/pack 布局、manifest 的改动，先读 [spec/](spec/README.md) 并更新文档；不要改已冻结的协议常量。
- 实现级决策写进 [dev/decisions.md](dev/decisions.md)；未决问题写进 [dev/open-questions.md](dev/open-questions.md)。
- 破坏性变更（格式、默认布局、退出码含义）必须显式说明迁移路径。
