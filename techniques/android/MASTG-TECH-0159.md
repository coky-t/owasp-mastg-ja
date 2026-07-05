---
title: ファイルベースのコンテンツプロバイダの使用の検証 (Verify Usage of File-Based Content Providers)
alias: verify-usage-of-file-based-content-providers
id: MASTG-TECH-0159
platform: android
---

# MASTG-TECH-0159 ファイルベースのコンテンツプロバイダの使用の検証 (Verify Usage of File-Based Content Providers)

URI 構造、アクセス制御、クエリ処理など、Android ContentProvider の概要については [Android コンテンツプロバイダ (Android ContentProvider)](https://github.com/coky-t/owasp-mastg-ja/blob/master/knowledge/android/MASVS-CODE/MASTG-KNOW-0117.md) を参照してください。

この技法ではファイルベースのコンテンツプロバイダを識別する方法を説明します。

### AndroidManifest の使用

[Android コンテンツプロバイダ (Android ContentProvider)](https://github.com/coky-t/owasp-mastg-ja/blob/master/knowledge/android/MASVS-CODE/MASTG-KNOW-0117.md) を使用して、`android:exported="true"` に設定されているエクスポートされたアクティビティを識別します。

`res/xml/*.xml` を抽出し、`FileProvider` パス宣言をチェックします。以下の使用をフラグ付けします。

* `path="."`
* `path=""`
* `path="/"`
* `<root-path>`

### 逆コンパイルされたソースコードの使用

[Java コードの逆コンパイル (Decompiling Java Code)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0017.md) を使用して APK を逆コンパイルし、リバースされたコード内の各 `FileProvider.getUriForFile(...)` 呼び出しについて、File 引数のそのソースを追跡します。引数が URI クエリパラメータなどの攻撃者が制御する入力から派生している呼び出しをフラグ付けします。
