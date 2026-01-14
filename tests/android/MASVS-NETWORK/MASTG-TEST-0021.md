---
masvs_v1_id:
- MSTG-NETWORK-3
masvs_v2_id:
- MASVS-NETWORK-1
platform: android
title: エンドポイント同一性検証のテスト (Testing Endpoint Identify Verification)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0282, MASTG-TEST-0283, MASTG-TEST-0284, MASTG-TEST-0285, MASTG-TEST-0286]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

ネットワーク上で機密情報を転送するために TLS を使用することはセキュリティにとって不可欠です。しかし、モバイルアプリケーションとバックエンド API との間の通信を暗号化することは簡単ではありません。開発者は開発プロセスを容易にするために、よりシンプルではあるもののセキュアではない (任意の証明書を受け入れるなどの) ソリューションを選ぶことが多く、時にはこれらの脆弱なソリューションが [製品バージョンとなり](https://saschafahl.de/static/paper/androidssl2012.pdf "Hunting Down Broken SSL in Android Apps") 、潜在的にユーザーを [中間マシン (Machine-in-the-Middle (MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃に晒す可能性があります。["CWE-295: Improper Certificate Validation"](https://cwe.mitre.org/data/definitions/295.html "CWE-295: Improper Certificate Validation") を参照してください。

二つの重要な問題に対処する必要があります。

- 証明書が信頼できるソース、つまり信頼できる CA (Certificate Authority, 認証局) に由来することを検証します。
- エンドポイントサーバーが正しい証明書を提示しているかどうかを判別します。

ホスト名と証明書自体が正しく検証されていることを確認します。事例と一般的な落とし穴が [Android の公式ドキュメント](https://developer.android.com/training/articles/security-ssl.html "Android Documentation - SSL") にあります。`TrustManager` および `HostnameVerifier` の使用例のコードを探します。下記のセクションには、あなたが探しているようなセキュアではない事例があります。

### !!! 注記
Android 8.0 (API レベル 26) 以降、SSLv3 はサポートされなくなり、`HttpsURLConnection` はセキュアではない TLS/SSL プロトコルへのフォールバックを実行しません。

### ターゲット SDK バージョンの検証

Android 7.0 (API レベル 24) 以降をターゲットとするアプリケーションでは **ユーザーが提供する CA を一切信頼しないデフォルトの Network Security Configuration** を使用し、悪意のある CA をインストールするようにユーザーを誘導して行われる MITM 攻撃の可能性を減らします。

apktool を使用してアプリをデコード ([アプリパッケージの調査 (Exploring the App Package)](../../../techniques/android/MASTG-TECH-0007.md)) して、apktool.yml の `targetSdkVersion` が `24` 以上であることを検証します。

```txt
grep targetSdkVersion UnCrackable-Level3/apktool.yml
  targetSdkVersion: '28'
```

ただし、`targetSdkVersion >=24` であっても、開発者は **アプリがユーザー提供の CA を信頼するように強制する** カスタムトラストアンカーを定義したカスタム Network Security Configuration を使用して、デフォルトの保護を無効にできます。 ["カスタムトラストアンカーの解析"](#analyzing-custom-trust-anchors) を参照してください。

### カスタムトラストアンカーの解析

[Network Security Configuration](../../../Document/0x05g-Testing-Network-Communication.md#android-network-security-configuration) ファイルを探して、 (避けるべき) `<certificates src="user">` を定義しているカスタム `<trust-anchors>` を検査します。

[エントリの優先順位](https://developer.android.com/training/articles/security-config#ConfigInheritance) を注意深く解析する必要があります。

- `<domain-config>` エントリや親の `<domain-config>` に値を設定していない場合、設定は `<base-config>` をもとにして行われます。
- このエントリが定義されていない場合、 [デフォルト設定](../../../Document/0x05g-Testing-Network-Communication.md#default-configurations) が使用されます。

Android 9 (API レベル 28) をターゲットとしたアプリの Network Security Configuration の例を見てみましょう。

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="false">owasp.org</domain>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </domain-config>
</network-security-config>
```

以下のようなものが観察できます。

- `<base-config>` がありません。つまり Android 9 (API レベル 28) 以降では [デフォルト設定](../../../Document/0x05g-Testing-Network-Communication.md#default-configurations) を他のすべての接続に使用します (原則的に `system` CA のみを信頼します) 。
- しかし、`<domain-config>` がデフォルト設定を上書きし、指定された `<domain>` (owasp.org) に対して `system` と `user` の両方の CA をアプリが信頼するようにしています。
- `includeSubdomains="false"` のため、サブドメインには影響しません。

すべてをまとめると上記の Network Security Configuration は次のように _翻訳_ できます。「このアプリはサブドメインを除く owasp.org ドメインに対してシステム CA とユーザー CA を信頼します。他のドメインではこのアプリはシステム CA のみを信頼します。」

### サーバー証明書の検証

`TrustManager` は Android で信頼できる接続を確立するために必要な条件を検証する手段です。この時点で以下の条件を確認する必要があります。

- 証明書は信頼できる CA により署名されていますか？
- 証明書は有効期限切れではありませんか？
- 証明書は自己署名されていませんか？

以下のコードスニペットは開発中に使用されることがあり、`checkClientTrusted`, `checkServerTrusted`, `getAcceptedIssuers` 関数を上書きして、任意の証明書を受け入れます。そのような実装は避けるべきであり、必要であれば、セキュリティ上の欠陥が組み込まれることを避けるために、それらを製品ビルドから明確に分離する必要があります。

```java
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }
    }
 };

// SSLContext context
context.init(null, trustAllCerts, new SecureRandom());
```

### WebView サーバー証明書検証

場合によってはアプリケーションは WebView を使用して、アプリケーションに関連付けられたウェブサイトを表示します。これはアプリケーションのやり取りに内部 WebView を使用する Apache Cordova などの HTML/JavaScript ベースのフレームワークに当てはまります。WebView を使用すると、モバイルブラウザがサーバー証明書の検証を実行します。WebView がリモートウェブサイトに接続しようとしたときに発生する TLS エラーを無視するのはバッドプラクティスです。

以下のコードは TLS の問題を無視しています。WebView を提供する WebViewClient のカスタム実装と同様です。

```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        //Ignore TLS certificate errors and instruct the WebViewClient to load the website
        handler.proceed();
    }
});
```

### Apache Cordova 証明書検証

アプリケーションマニフェストで `android:debuggable` フラグが有効になっている場合、Apache Cordova フレームワークの内部 WebView 使用の実装は `onReceivedSslError` メソッドの [TLS エラー](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java "TLS errors ignoring by Apache Cordova in WebView") を無視します。したがって、アプリがデバッグ可能ではないことを確認します。テストケース「アプリがデバッグ可能かどうかのテスト」を参照してください。

### ホスト名検証

クライアントサイドの TLS 実装におけるもう一つのセキュリティ上の欠陥はホスト名検証の欠如です。開発環境では通常有効なドメイン名ではなく内部アドレスを使用するため、開発者はホスト名検証を無効化 (またはアプリケーションに任意のホスト名を許可するよう強制) したり、アプリケーションを実稼働環境に移行する際に変更することを忘れたりします。以下のコードはホスト名検証を無効化します。

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

組み込みの `HostnameVerifier` を使うことで、任意のホスト名を受け入れることが可能です。

```java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

信頼できる接続を設定する前にアプリケーションがホスト名を検証していることを確認します。

## 動的解析

Android 7.0 (API レベル 24) 以降をターゲットとするアプリをテストする場合、事実上 Network Security Configuration が適用されているはずであり、HTTPS トラフィックを復号してみることはまずできないはずです。しかし、API レベル 24 未満のアプリをターゲットとしている場合、アプリはインストールされているユーザー証明書を自動的に受け入れます。

不適切な証明書検証をテストするには Burp などの傍受プロキシを使用して MITM 攻撃を行います。以下のオプションを試してください。

- **自己署名証明書:**
  1. Burp で、**Proxy** タブに移動し、**Options** タブを選択します。
  2. **Proxy Listeners** セクションに移動し、listener をハイライトして、**Edit** をクリックします。
  3. **Certificate** タブに移動し、**Use a self-signed certificate** をチェックして、**Ok** をクリックします。
  4. アプリケーションを実行します。HTTPS トラフィックを見ることができる場合、アプリケーションは自己署名証明書を受け入れています。
- **信頼できない CA の証明書の受け入れ:**
  1. Burp で、**Proxy** タブに移動し、**Options** タブを選択します。
  2. **Proxy Listeners** セクションに移動し、listener をハイライトして、**Edit** をクリックします。
  3. **Certificate** タブに移動し、**Generate a CA-signed certificate with a specific hostname** をチェックして、バックエンドサーバーのホスト名を入力します。
  4. アプリケーションを実行します。HTTPS トラフィックを見ることができる場合、アプリケーションは信頼できない CA の証明書を受け入れています。
- **不正なホスト名の受け入れ:**
  1. Burp で、**Proxy** タブに移動し、**Options** タブを選択します。
  2. **Proxy Listeners** セクションに移動し、listener をハイライトして、**Edit** をクリックします。
  3. **Certificate** タブに移動し、**Generate a CA-signed certificate with a specific hostname** をチェックして、不正なホスト名、例えば example.org を入力します。
  4. アプリケーションを実行します。HTTPS トラフィックを見ることができる場合、アプリケーションはすべてのホスト名を受け入れています。

それでも HTTPS トラフィックを復号してみることができない場合には、アプリケーションが [証明書のピン留め](../../../Document/0x04f-Testing-Network-Communication.md#restricting-trust-identity-pinning) を実装している可能性があります。
