---
masvs_category: MASVS-STORAGE
platform: android
title: 内部ストレージ (Internal Storage)
---

デバイスの [内部ストレージ](https://developer.android.com/training/data-storage#filesInternal "Using Internal Storage") にファイルを保存できます。内部ストレージに保存されたファイルはデフォルトでコンテナ化され、デバイス上の他のアプリからアクセスすることはできません。ユーザーがアプリをアンインストールすると、これらのファイルは削除されます。

たとえば、以下の Kotlin スニペットは機密情報を平文で内部ストレージ上のファイル `sensitive_info.txt` に保存します。

```kotlin
val fileName = "sensitive_info.txt"
val fileContents = "This is some top-secret information!"
File(filesDir, fileName).bufferedWriter().use { writer ->
    writer.write(fileContents)
}
```

ファイルモードをチェックし、アプリのみがファイルにアクセスできることを確認します。このアクセスは `MODE_PRIVATE` で設定できます。`MODE_WORLD_READABLE` (非推奨) や `MODE_WORLD_WRITEABLE` (非推奨) などのモードはセキュリティリスクをもたらす可能性があります。

**Android セキュリティガイドライン**: Android では、内部ストレージのデータはアプリ専用であり、他のアプリはアクセスできないことを強調しています。また、IPC ファイルでは `MODE_WORLD_READABLE` モードと `MODE_WORLD_WRITEABLE` モードの使用を避け、代わりに [コンテンツプロバイダ](https://developer.android.com/privacy-and-security/security-tips#content-providers) を使用することを推奨しています。[Android セキュリティガイドライン](https://developer.android.com/privacy-and-security/security-tips#internal-storage "Android Security Guidelines") を参照してください。Android では内部ストレージを安全に使用する方法に関する [ガイド](https://developer.android.com/privacy-and-security/security-best-practices#internal-storage "Store data in internal storage based on use case") も提供しています。
