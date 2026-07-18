---
title: Android のストレージ完全性チェックを実装する (Implementing Storage Integrity Checks on Android)
alias: implementing-storage-integrity-checks-android
id: MASTG-BEST-0066
platform: android
knowledge: [MASTG-KNOW-0036]
---

Android アプリにストレージ完全性チェックを実装して、デバイス上に保存されたデータ (たとえば、`SharedPreferences`、ファイル、データベースなど) への不正な改変を検出します。これらのチェックは、特にルート化されたデバイス上や、バックアップを通じて、あるいはアプリのデータディレクトリを直接操作することにより、保存されたデータを改竄しようとする攻撃者にとってコストを高めます。

## ストレージ完全性

デバイスにデータを書き込む前にそのデータの HMAC を計算して、読み戻す前に HMAC を検証します。アプリパッケージやバックアップから抽出できないように [Android Keystore](https://developer.android.com/privacy-and-security/keystore) で生成され保存された鍵を使用します。

```kotlin
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun hmac(data: ByteArray, key: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

fun verify(data: ByteArray, tag: ByteArray, key: ByteArray): Boolean {
    return hmac(data, key).contentEquals(tag)
}
```

あるいは、共有シークレットよりも公開鍵/秘密鍵ペアのほうが適切な場合、セキュリティフレームワークは保存データの非対称署名と検証のために `java.security.Signature` を提供します。

データを暗号化する場合は、[Encrypt-then-MAC](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html) パターンに従います。まず暗号化し、次に暗号文に対して HMAC を計算します。

> [!WARNING]
> 攻撃者が HMAC キーを抽出できる場合 (たとえば、アプリにハードコードされていたり、ルート化されたデバイス上で復元可能であるなど) あるいは実行時に検証ロジックを傍受できる場合、ストレージ完全性チェックはバイパス可能になります。これらは単独での保証ではなく多層防御策としてこれらを扱います。`SharedPreferences` ストレージの詳細については [共有プリファレンス (Shared Preferences)](../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036.md) を参照してください。
