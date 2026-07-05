---
platform: android
title: WebView におけるローカルファイルアクセスへの参照 (References to Local File Access in WebViews)
alias: references-to-local-file-access-in-webviews
id: MASTG-TEST-0252
apis:
  - WebView
  - WebSettings
  - getSettings
  - setAllowFileAccess
  - setAllowFileAccessFromFileURLs
  - setAllowUniversalAccessFromFileURLs
type:
  - static
  - code
weakness: MASWE-0069
best-practices:
  - MASTG-BEST-0010
  - MASTG-BEST-0011
  - MASTG-BEST-0012
profiles:
  - L1
  - L2
knowledge:
  - MASTG-KNOW-0018
---

# MASTG-TEST-0252 WebView におけるローカルファイルアクセスへの参照 (References to Local File Access in WebViews)

### 概要

このテストではローカルファイルを含むさまざまなソースからコンテンツをロードすることを可能にする Android WebView で使用される [`WebSettings`](https://developer.android.com/reference/android/webkit/WebSettings.html) クラスのメソッドへの参照をチェックします。不適切に設定されている場合、これらのメソッドは不正ファイルアクセスやデータ流出などのセキュリティリスクを引き起こす可能性があります。これらのメソッドは以下のとおりです。

* `setAllowFileAccess`: WebView がアプリの内部ストレージまたは外部ストレージからローカルファイルをロードすることを許可します。
* `setAllowFileAccessFromFileURLs`: ローカルファイル内の JavaScript が他のローカルファイルにアクセスできるようにします。
* `setAllowUniversalAccessFromFileURLs`: クロスオリジン制限を解除し、JavaScript がオリジンを越えてデータを読み取ることを許可します。JavaScript はこの設定に関わらず、**常に任意のオリジンにデータを送信できます** (例: `POST` 経由)。この設定はデータの読み取りにのみ影響します (例: コードは `POST` リクエストへのレスポンスを得られませんが、データは依然として送信されます)。

これらの設定を組み合わせると、悪意のある HTML ファイルが昇格した権限を獲得し、ローカルリソースにアクセスし、通常は同一オリジンポリシーによって強制されるセキュリティ境界を効果的にバイパスして、ネットワーク経由でデータを流出するような攻撃が可能になります。

これらのメソッドは安全なデフォルトがあり、**Android 10 (API レベル 29) 以上では非推奨** となっていますが、明示的に `true` に設定したり、古いバージョンの Android で動作する (`minSdkVersion` による) アプリで安全でないデフォルトを依然として使用できます。

これらのメソッド (デフォルト値、非推奨ステータス、セキュリティへの影響)、アクセスできる特定のファイル、アクセスできる条件の詳細については [Android WebView のローカルファイルアクセス設定](../../../Document/0x05h-Testing-Platform-Interaction.md#webview-local-file-access-settings) を参照してください。

**注 1**: 攻撃が機能するには、`setAllowFileAccessFromFileURLs` または `setAllowUniversalAccessFromFileURLs` のいずれかを `true` に設定しなければなりません。両方の設定が `false` に設定されている場合、`logcat` に以下のエラーが表示されます。

```bash
[INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'file:///data/data/org.owasp.mastestapp/files/api-key.txt' from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported for protocol schemes: http, data, chrome, https, chrome-untrusted.", source: file:/// (0)
[INFO:CONSOLE(31)] "File content sent successfully.", source: file:/// (31)
```

そして、サーバーはファイルコンテンツを受信できません。

```bash
[*] Received POST data from 127.0.0.1:

Error reading file: 0
```

**注 2**: Android のドキュメントに記載されているように、`allowUniversalAccessFromFileURLs=true` の場合、[**`setAllowFileAccessFromFileURLs` の値は無視されます**](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs\(boolean\))。

### 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、関連する API を探します。
3. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を使用して、AndroidManifest.xml を取得します。
4. [AndroidManifest の解析 (Analyzing the AndroidManifest)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0150.md) を使用して、AndroidManifest.xml ファイルから `minSdkVersion` を取得します。

### 結果

出力には上記したメソッドを使用する WebView インスタンスのリストを含む可能性があります。特に以下のようなものです。

* `WebView` クラス。
* `WebSettings` クラス。
* `setJavaScriptEnabled` メソッド。
* `WebSettings` クラスの `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` メソッド。

この場合、**`setAllow*` メソッドへの参照がないことが特に重要であり**、確認する必要があることに注意してください。これは、アプリがデフォルト値を使用している可能性があり、場合によっては安全でない可能性があるためです。このため、 アプリ内のすべての WebView インスタンスを識別することを強くお勧めします。

### 評価

以下のすべてが当てはまる場合、そのテストケースは不合格です ([異なる Android バージョン間での API の動作](../../../Document/0x05h-Testing-Platform-Interaction.md#webview-local-file-access-settings) に基づいています)。

* `setJavaScriptEnabled` が明示的に `true` に設定されている。
* `setAllowFileAccess` が明示的に `true` に設定されている (または、`minSdkVersion` < 30 の場合は、デフォルト値 `true` を継承して、一切使用されていない)。
* `setAllowFileAccessFromFileURLs` または `setAllowUniversalAccessFromFileURLs` のいずれかが明示的に `true` に設定されている (または、`minSdkVersion` < 16 の場合は、デフォルト値 `true` を継承して、一切使用されていない)。

> \[!NOTE] `AllowFileAccess` が `true` であること自体はセキュリティ脆弱性を表すものではありませんが、他の脆弱性と組み合わせて使用することで攻撃の影響を拡大する可能性があります。
