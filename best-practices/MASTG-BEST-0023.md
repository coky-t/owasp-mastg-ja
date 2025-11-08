---
title: バックアップから機密情報を除外する (Exclude Sensitive Information from Backups)
alias: exclude-sensitive-information-from-backups
id: MASTG-BEST-0023
platform: ios
knowledge: [MASTG-KNOW-0102]
---

iOS はバックアップからファイルを除外するための保証されたメカニズムを提供していません。[`NSURLIsExcludedFromBackupKey`](https://developer.apple.com/documentation/foundation/urlresourcekey/isexcludedfrombackupkey) を設定すると、システムはバックアップにファイルを含めないように指示しますが、除外を保証するわけではありません。データの露出を減らすには、以下の技法を適用します。

## 現在のデバイスにデータをバインドする

機密データをキーチェーンに保存し、[`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly) または [`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) でマークして、シークレットを現在のデバイスに限定します。これを実装する場合は、新しいキーチェーンエントリを作成し、アイテムを挿入するときに `kSecAttrAccessible` 属性を `ThisDeviceOnly` 値のいずれかに設定します。

### 大きなファイルを処理するには

大きなファイルの場合は、アプリコンテナ内に暗号化して保存し、`ThisDeviceOnly` アクセシビリティクラスを使用してキーチェーンに復号鍵を保持します。ファイルを使用する必要があるときは、RAM 内、または `/Library/Caches` や `/tmp` などのバックアップされない場所にのみ復号します。これらの場所は [_purgeable_](https://developer.apple.com/documentation/foundation/optimizing-your-app-s-data-for-icloud-backup) であり、システムはいつでもそれらのコンテンツを削除する可能性があることに注意してください。永続的なストレージとして扱うことは避けます。ファイルが消去された場合は、必要に応じて再復号するように準備しておきます。

## サーバー管理鍵を介してユーザーにデータをバインドする

デバイスへのバインドが不十分である場合、復号鍵をサーバーに保存し、認証が成功した後にのみ解放することで、データをユーザーにバインドできます。この鍵はデバイス上に永続化せず、RAM 内にのみ保持し、上述のようにファイルを復号してください。
