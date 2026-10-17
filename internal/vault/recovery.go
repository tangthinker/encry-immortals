package vault

import (
	"fmt"
	"time"

	vaultcrypto "github.com/tangthinker/encry-immortals/internal/crypto"
)

// recoveryTemplate renders the printable RECOVERY.txt (spec 07.1, 07.7).
func recoveryTemplate(m *Meta, params vaultcrypto.KDFParams, toolVersion string) string {
	created := time.Unix(m.CreatedUnix, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	return fmt.Sprintf(`APEX 灾难恢复须知（请打印或存入密码管理器）

生成时间   %s
工具版本   %s
vault_id   %s
KDF        argon2id t=%d m=%d KiB p=%d k=%d

== 必须保存的三件东西 ==
1) 加密数据目录：TargetDir 下的 data/ 与 meta/（网盘同步的那份）
2) Armor Key：以 EIMMORTAL-KEY-V2- 开头的一长串，由 eimmortal export-key 生成
3) 主密码本身

缺少任意一件，数据都无法恢复。

== 硬约束（请务必读完） ==
- 主密码不可更改。忘记即永久无法恢复：Armor Key 里没有密钥，只有盐与 KDF 参数。
- 控制平面目录（%s）绝不能放进 Dropbox / iCloud / OneDrive 或任何同步目录。
- 怀疑密码泄漏时，唯一补救是 eimmortal compact --new-identity 重建全库（小时级，
  并需要重新 export-key 与手工删除旧库）。

== 新机器恢复步骤 ==
1. eimmortal init --join <TargetDir>
2. eimmortal import-key            # 粘贴 Armor Key，先验 CRC
3. eimmortal verify --size         # 确认 pack 都同步完整
4. eimmortal restore <DestDir> --at-latest --anchor <水位码>
5. eimmortal verify --deep --source <DestDir>

== 定期演练（不做演练等于没有备份） ==
- 每月：eimmortal verify --sample 8
- 每季度：在空临时目录 restore 并抽样比对内容、mode、mtime
- 每半年：完整 restore 到外部磁盘一次
- 每年：用 Armor Key 重新 import-key 一次，证明抄件仍可用
`, created, toolVersion, m.VaultID, params.Time, params.MemoryKiB, params.Threads, params.KeyLen, MetaFileName)
}
