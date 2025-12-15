---
platform: android
title: WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)
alias: references-to-content-provider-access-in-webviews
id: MASTG-TEST-0250
apis: [WebView, WebSettings, getSettings, ContentProvider, setAllowContentAccess, setAllowUniversalAccessFromFileURLs, setJavaScriptEnabled]
type: [static]
weakness: MASWE-0069
best-practices: [MASTG-BEST-0011, MASTG-BEST-0012, MASTG-BEST-0013]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0018]
---

## 概要

このテストでは WebView におけるコンテンツプロバイダアクセスへの参照をチェックします。これはデフォルトで有効になっており、`WebSettings` クラスの `setAllowContentAccess` メソッドを使用して無効にできます。不適切に構成すると、不正なファイルアクセスやデータ流出などのセキュリティリスクを引き起こす可能性があります。

JavaScript コードは以下のようにデバイス上のあらゆるコンテンツプロバイダにアクセスできます。

- そのアプリで宣言されたもの、**エクスポートされていない場合でも**。
- 他のアプリで宣言されたもの、**エクスポートされている場合のみ**、およびアクセス制限に関して推奨される [ベストプラクティス](https://developer.android.com/privacy-and-security/security-tips#content-providers) に従っていない場合。

`setAllowContentAccess` メソッド、アクセスできる特定のファイル、アクセスできる条件の詳細については、[WebView コンテンツプロバイダアクセス](../../../Document/0x05h-Testing-Platform-Interaction.md#webview-content-provider-access) を参照してください。

**攻撃シナリオの例:**

ある銀行アプリが WebView を使用して動的コンテンツを表示しているとします。開発者は `setAllowContentAccess` メソッドを明示的に設定していないため、デフォルトで `true` です。さらに、WebView で JavaScript が有効であり、`setAllowUniversalAccessFromFileURLs` メソッドも有効になっています。

1. 攻撃者は脆弱性 (XSS 欠陥など) を悪用し、WebView に悪意のある JavaScript を注入します。これは、WebView が適切なバリデーションなしでロードする、危殆化したリンクや悪意のあるリンクによって発生する可能性があります。
2. `setAllowUniversalAccessFromFileURLs(true)` のおかげで、悪意のある JavaScript は `content://` URI へのリクエストを発行し、ローカルに保存されているファイルやコンテンツプロバイダで公開されているデータを読み取ることができます。悪意のあるコードは信頼できるコードと同じプロセスと同じオリジンで実行されているため、アプリからエクスポートされていないコンテンツプロバイダにもアクセスできます。
3. 攻撃者が制御するスクリプトがデバイスから外部サーバーに機密データを流出します。

**注 1:** Android バージョンに関係なく `setAllowContentAccess` はデフォルトで `true` になるため、`minSdkVersion` は考慮しません。

**注 2:** プロバイダの `android:grantUriPermissions` 属性は、アプリ自体が自身のコンテンツプロバイダにアクセスする際には影響しないため、このシナリオでは無関係です。`permission` 属性や `android:exported="false"` などの制限が設定されている場合でも、**他のアプリ** がプロバイダから URI に一時的にアクセスできるようになります。また、アプリが `FileProvider` を使用する場合、[定義](https://developer.android.com/reference/androidx/core/content/FileProvider#:~:text=Set%20the%20android:grantUriPermissions%20attribute%20to%20true%2C%20to%20allow%20you%20to%20grant%20temporary%20access%20to%20files.%20) によって `android:grantUriPermissions` 属性が `true` に設定されていなければなりません (そうしないと `SecurityException: Provider must grant uri permissions"` が発生します)。

**注 3:** `allowUniversalAccessFromFileURLs` はデフォルトの制限を緩和し、`file://` からロードされたページが `content://` URI を含む任意のオリジンからコンテンツにアクセスできるようにするため、攻撃において重要です。

この設定が有効でない場合、`logcat` に以下のエラーが表示されます。

```text
[INFO:CONSOLE(0)] "Access to XMLHttpRequest at 'content://org.owasp.mastestapp.provider/sensitive.txt'
from origin 'null' has been blocked by CORS policy: Cross origin requests are only supported
for protocol schemes: http, data, chrome, https, chrome-untrusted.", source: file:/// (0)
```

外部サーバーへの `fetch` リクエストは依然として機能しますが、`content://` 経由でのファイルコンテンツの取得は失敗します。

## 手順

1. semgrep などのツールを使用して、以下への参照を探します。
      - `WebView` クラス。
      - `WebSettings` クラス。
      - `setJavaScriptEnabled` メソッド。
      - `WebSettings` クラスの `setAllowContentAccess` メソッド。
      - `WebSettings` クラスの `setAllowUniversalAccessFromFileURLs` メソッド。
2. アプリの AndroidManifest.xml ファイルで宣言されているすべてのコンテンツプロバイダを取得します。

## 結果

出力には以下を含む可能性があります。

- 以下のメソッドとその引数を含む WebView インスタンスのリスト:
    - `setAllowContentAccess`
    - `setJavaScriptEnabled`
    - `setAllowUniversalAccessFromFileURLs`
- アプリの AndroidManifest.xml ファイルで宣言されているコンテンツプロバイダのリスト。

## 評価

**不合格:**

以下のすべてが当てはまる場合、そのテストは不合格です。

- `setJavaScriptEnabled` が明示的に `true` に設定されている。
- `setAllowContentAccess` が明示的に `true` に設定されているか、_まったく使用されていない_ (デフォルト値 `true` を継承している)。
- `setAllowUniversalAccessFromFileURLs` メソッドが明示的に `true` に設定されている。

結果ステップで取得したコンテンツプロバイダのリストを使用して、コンテンツプロバイダが機密データを処理しているかどうかを検証する必要があります。

**注:** `setAllowContentAccess` メソッドを `true` に設定されていること自体はセキュリティ脆弱性を表すものではありませんが、他の脆弱性と組み合わせて使用することで攻撃の影響を拡大する可能性があります。したがって、アプリがコンテンツプロバイダにアクセスする必要がない場合は、明示的に `false` を設定することをお勧めします。

**合格:**

以下のいずれかが当てはまる場合、そのテストは合格です。

- `setJavaScriptEnabled` が明示的に false` に設定されているか、_まったく使用されていない_ (デフォルト値 `false` を継承している)。
- `setAllowContentAccess` メソッドが明示的に `false` に設定されている。
- `setAllowUniversalAccessFromFileURLs` メソッドが明示的に `false` に設定されている。
