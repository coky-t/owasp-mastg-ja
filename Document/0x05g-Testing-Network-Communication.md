# Android のネットワーク API

## エンドポイント同一性検証のテスト (MSTG-NETWORK-3)

ネットワーク上で機密情報を転送するために TLS を使用することはセキュリティにとって不可欠です。しかし、モバイルアプリケーションとバックエンド API との間の通信を暗号化することは簡単ではありません。開発者は開発プロセスを容易にするために、よりシンプルではあるもののセキュアではない (任意の証明書を受け入れるなどの) ソリューションを選ぶことが多く、時にはこれらの脆弱なソリューションが [製品バージョンとなり](https://saschafahl.de/static/paper/androidssl2012.pdf "Hunting Down Broken SSL in Android Apps") 、潜在的にユーザーを [中間者攻撃](https://cwe.mitre.org/data/definitions/295.html "CWE-295: Improper Certificate Validation") に晒す可能性があります。

二つの主要な問題に対処する必要があります。

- 証明書が信頼できるソース、つまり信頼できる CA (Certificate Authority, 認証局) に由来することを検証します。
- エンドポイントサーバーが正しい証明書を提示するかどうかを判別します。

ホスト名と証明書自体が正しく検証されていることを確認します。事例と一般的な落とし穴が [Android の公式ドキュメント](https://developer.android.com/training/articles/security-ssl.html "Android Documentation - SSL") にあります。`TrustManager` および `HostnameVerifier` の使用例のコードを探します。下記のセクションには、あなたが探しているようなセキュアではない事例があります。

> Android 8.0 (API level 26) 以降、SSLv3 はサポートされなくなり、HttpsURLConnection はセキュアではない TLS/SSL プロトコルへのフォールバックを実行しないことに注意します。

### 静的解析

#### サーバー証明書の検証

`TrustManager` は Android で信頼できる接続を確立するために必要な条件を検証する手段です。この点について以下の条件を確認する必要があります。

- 証明書は信頼できる CA により署名されていますか
- 証明書は有効期限切れではありませんか
- 証明書は自己署名されていませんか

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

#### WebView サーバー証明書検証

場合によってアプリケーションは WebView を使用して、アプリケーションに関連付けられたウェブサイトを表示します。これはアプリケーションのやり取りに内部 WebView を使用する Apache Cordova などの HTML/JavaScript ベースのフレームワークに当てはまります。WebView を使用すると、モバイルブラウザがサーバー証明書の検証を実行します。WebView がリモートウェブサイトに接続しようとしたときに発生する TLS エラーを無視するのはバッドプラクティスです。

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

#### Apache Cordova 証明書検証

アプリケーションマニフェストで `android:debuggable` フラグが有効になっている場合、Apache Cordova フレームワークの内部 WebView 使用の実装は `onReceivedSslError` メソッドの [TLS エラー](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java "TLS errors ignoring by Apache Cordova in WebView") を無視します。したがって、アプリがデバッグ可能ではないことを確認します。テストケース「アプリがデバッグ可能かどうかのテスト」を参照してください。

#### ホスト名検証

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

### 動的解析

動的解析には傍受プロキシが必要です。不適切な証明書の検証をテストするには、以下のコントロールを確認します。

- 自己署名証明書

Burp で **Proxy** タブに移動し、**Options** タブを選択し、**Proxy Listeners** セクションに移動し、リスナを強調表示にしてから **Edit** をクリックします。それから **Certificate** タブに移動し **Use a self-signed certificate** をチェックして **Ok** をクリックします。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが自己署名証明書を受け入れていることを意味します。

- 無効な証明書の受け入れ

Burp で **Proxy** タブに移動し、**Options** タブを選択し、**Proxy Listeners** セクションに移動し、リスナを強調表示にしてから **Edit** をクリックします。それから **Certificate** タブに移動し **Generate a CA-signed certificate with a specific hostname** をチェックしてバックエンドサーバーのホスト名を入力します。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが信頼できない CA の証明書を受け入れていることを意味します。

- 間違ったホスト名の受け入れ

Burp で **Proxy** タブに移動し、**Options** タブを選択し、**Proxy Listeners** セクションに移動し、リスナを強調表示にしてから **Edit** をクリックします。それから **Certificate** タブに移動し **Generate a CA-signed certificate with a specific hostname** をチェックして example.org などの無効なホスト名を入力します。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが任意のホスト名を受け入れていることを意味します。

さらに MITM 解析を行う場合や傍受プロキシの設定に問題がある場合には、[Tapioca](https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html "Announcing CERT Tapioca for MITM Analysis") の使用を検討します。これは MITM ソフトウェア解析のために CERT が事前設定した [VM アプライアンス](http://www.cert.org/download/mitm/CERT_Tapioca.ova "CERT Tapioca Virtual Machine Download") です。行うべきことは [テストされるアプリケーションをエミュレータにデプロイしてトラフィックのキャプチャを開始する](https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html "Finding Android SSL vulnerabilities with CERT Tapioca") だけです。

## カスタム証明書ストアおよび証明書ピンニングのテスト (MSTG-NETWORK-4)

### 概要

証明書ピンニングは信頼できる認証局により署名された証明書を受け入れる代わりに、バックエンドサーバーを特定の X.509 証明書または公開鍵に関連付けるプロセスです。サーバー証明書または公開鍵を格納 (「ピンニング」) した後、モバイルアプリはその既知のサーバーにのみ接続します。外部認証局からの信頼を取り下げることで、アタックサーフェイスを縮小します (結局のところ、認証局が侵害されたり、偽者に証明書を発行するよう騙されたりという既知の事例が多くあります) 。

証明書はアプリにピン留めおよびハードコードされるか、またはアプリが最初にバックエンドに接続するときに取り出されます。後者の場合には、ホストが最初に参照されるときに証明書がホストに関連付け (「ピン留め」) られます。この方法はあまりセキュアではありません。最初の接続を傍受する攻撃者が自身の証明書を注入できるためです。

#### ピンが失敗する場合

失敗したピンに対処する場合にはさまざまなオプションがあることに注意します。

- バックエンドに接続できないことをユーザーに通知し、すべての操作を停止します。アプリは更新があるかどうかを確認し、利用可能である場合にはアプリの最新バージョンへの更新についてユーザーに通知します。アプリが更新されるか、ピンが再び機能するまで、アプリはユーザーとのやり取りを一切許可しません。
- 失敗したピンに関する情報を含むクラッシュレポートサービスを呼び出します。開発責任者は潜在的なセキュリティの誤設定について通知を受ける必要があります。
- ピンニングの失敗をバックエンドに通知するために、アプリはピンニングなしで TLS を有効にした呼び出しを使用してバックエンドを呼び出します。呼び出しはユーザーエージェント、JWT トークンコンテンツで代えるか、ピンニング失敗を示すフラグを有効にした他のヘッダを持たせます。
- 失敗したピンニングについて通知するためにバックエンドまたはクラッシュレポートサービスを呼び出した後、アプリは機密機能や機密データの処理を含まない制限された機能を依然として提供できます。通信は SSL ピンニングなしで行われ、それに応じて X.509 証明書の妥当性確認を行います。

どのオプションを選択するかは、可用性の重要度合とアプリケーションの保守の複雑さにより異なります。

大量のピン失敗がバックエンドまたはクラッシュレポートサービスに報告された場合、開発者はおそらく誤設定があることを理解する必要があります。TLS 終端エンドポイント (サーバー、ロードバランサなど) で使用される主要なマテリアルが、アプリが期待しているものと異なる可能性が大いにあります。その場合、主要なマテリアルの更新またはアプリの更新のいずれかをプッシュする必要があります。

ごく少数のピン失敗のみが報告された場合、ネットワークは正常であり、TLS 終端エンドポイントの設定も正常でしょう。代わりに、ピンが失敗しているアプリインスタンスで中間者攻撃が進行している可能性があります。

### 静的解析

#### Network Security Configuration

ネットワークセキュリティ設定を安全な宣言型設定ファイルでアプリコードの修正なしにカスタマイズするには、Android がバージョン 7.0 およびそれ以降で提供している [Network Security Configuration](https://developer.android.com/training/articles/security-config.html "Network Security Configuration documentation") を使用できます。

Network Security Configuration を使用して [宣言型証明書](https://developer.android.com/training/articles/security-config.html#CertificatePinning "Certificate Pinning using Network Security Configuration") を特定のドメインにピン留めすることもできます。アプリケーションがこの機能を使用する場合、定義された設定を識別するために二つのことをチェックする必要があります。

最初に、 application タグの `android:networkSecurityConfig` 属性による Android アプリケーションマニフェストの Network Security Configuration ファイルを見つけます。

  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owasp.com.app">
      <application android:networkSecurityConfig="@xml/network_security_config">
          ...
      </application>
  </manifest>
  ```

識別されたファイルを開きます。この場合、ファイルは "res/xml/network_security_config.xml" にあります。

  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <network-security-config>
      <domain-config>
          Use certificate pinning for OWASP website access including sub domains
          <domain includeSubdomains="true">owasp.org</domain>
          <pin-set expiration="2018/8/10">
              <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
              the Intermediate CA of the OWASP website server certificate -->
              <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
              <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
              the Root CA of the OWASP website server certificate -->
              <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
          </pin-set>
      </domain-config>
  </network-security-config>
  ```

> pin-set には公開鍵ピンのセットが含まれています。各セットは有効期限を定義できます。有効期限が切れると、ネットワーク通信は機能し続けますが、影響を受けるドメインでは証明書ピンニングが無効になります。

設定が存在する場合、以下のイベントがログに表示されることがあります。

```bash
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

証明書ピンニング妥当性確認が失敗した場合、以下のイベントがログ出力されます。

```bash
I/X509Util: Failed to validate the certificate chain, error: Pin verification failed
```

逆コンパイラ (jadx や apktool など) や apktool を使用することで、/res/xml/ フォルダにある network_security_config.xml ファイルに `<pin>` エントリが存在するかどうかを確認できます。

#### TrustManager

証明書ピンニングの実装には主に三つのステップがあります。

- 目的のホストの証明書を取得します。
- 証明書が .bks フォーマットであることを確認します。
- 証明書をデフォルトの Apache Httpclient のインスタンスにピン留めします。

証明書ピンニングの正しい実装を解析するには、HTTP クライアントがキーストアをロードする必要があります。

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

キーストアがロードされると、キーストアの CA を信頼する TrustManager を使用できます。

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
// Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

アプリの実装は証明書の公開鍵のみに対してピンニング、証明書全体に対して、証明書チェーン全体に対してとさまざまです。

#### ネットワークライブラリと WebView

サードパーティーネットワークライブラリを使用するアプリケーションはライブラリの証明書ピンニング機能を利用できます。例えば、[okhttp](https://github.com/square/okhttp/wiki/HTTPS "okhttp library") では `CertificatePinner` を使用して以下のようにセットアップできます。

```java
OkHttpClient client = new OkHttpClient.Builder()
        .certificatePinner(new CertificatePinner.Builder()
            .add("example.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
            .build())
        .build();
```

WebView コンポーネントを使用するアプリケーションは WebViewClient のイベントハンドラを利用して、ターゲットリソースがロードされる前に各リクエストの何かしらの「証明書ピンニング」を行います。以下のコードは検証例を示しています。

```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
    private String expectedIssuerDN = "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US;";

    @Override
    public void onLoadResource(WebView view, String url)  {
        //From Android API documentation about "WebView.getCertificate()":
        //Gets the SSL certificate for the main top-level page
        //or null if there is no certificate (the site is not secure).
        //
        //Available information on SslCertificate class are "Issuer DN", "Subject DN" and validity date helpers
        SslCertificate serverCert = view.getCertificate();
        if(serverCert != null){
            //apply either certificate or public key pinning comparison here
                //Throw exception to cancel resource loading...
            }
        }
    }
});
```

あるいは、設定されたピンで OkHttpClient を使用し、それを `WebViewClient` の `shouldInterceptRequest` をオーバーライドするプロキシとして機能させるのがよいでしょう。

#### Xamarin アプリケーション

Xamarin で開発されたアプリケーションは一般的に ServicePointManager を使用してピンニングを実装します。

通常、証明書をチェックする関数を作成し、ServerCertificateValidationCallback メソッドにブール値を返します。

```cs
[Activity(Label = "XamarinPinning", MainLauncher = true)]
    public class MainActivity : Activity
    {
        // SupportedPublicKey - 公開鍵の16進数値
        // GetPublicKeyString() メソッドを使用して、ピン留めしたい証明書の公開鍵を決定します。最初に ValidateServerCertificate 関数のデバッグコードのコメントを外して、ピン留めする値を決定します。
        private const string SupportedPublicKey = "3082010A02820101009CD30CF05AE52E47B7725D3783B..."; // Shortened for readability

        private static bool ValidateServerCertificate(
                object sender,
                X509Certificate certificate,
                X509Chain chain,
                SslPolicyErrors sslPolicyErrors
            )
        {
            //Log.Debug("Xamarin Pinning",chain.ChainElements[X].Certificate.GetPublicKeyString());
            //return true;
            return SupportedPublicKey == chain.ChainElements[1].Certificate.GetPublicKeyString();
        }

        protected override void OnCreate(Bundle savedInstanceState)
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback += ValidateServerCertificate;
            base.OnCreate(savedInstanceState);
            SetContentView(Resource.Layout.Main);
            TesteAsync("https://security.claudio.pt");

        }
```

この例では証明書チェーンの中間 CA をピンニングしています。HTTP レスポンスの出力はシステムログにあります。

前述の例のサンプル Xamarin アプリは [MSTG リポジトリ](https://github.com/OWASP/owasp-mstg/raw/master/Samples/Android/02_CertificatePinning/certificatePinningXamarin.apk "Xamarin app with certificate pinning") から入手できます。

APK ファイルを展開した後、dotPeak, ILSpy, dnSpy などの .NET 逆コンパイラを使用して、'Assemblies' フォルダ内に格納されているアプリ dll を逆コンパイルし、ServicePointManager の使用状況を確認します。

#### Cordova アプリケーション

Cordova ベースのハイブリッドアプリケーションはネイティブに証明書ピンニングをサポートしていないため、プラグインを使用してこれを達成します。もっとも一般的なものは PhoneGap SSL Certificate Checker です。`check` メソッドを使用してフィンガープリントを確認し、コールバックが次のステップを決定します。

```javascript
  // Endpoint to verify against certiticate pinning.
  var server = "https://www.owasp.org";
  // SHA256 Fingerprint (Can be obtained via "openssl s_client -connect hostname:443 | openssl x509 -noout -fingerprint -sha256"
  var fingerprint = "D8 EF 3C DF 7E F6 44 BA 04 EC D5 97 14 BB 00 4A 7A F5 26 63 53 87 4E 76 67 77 F0 F4 CC ED 67 B9";

  window.plugins.sslCertificateChecker.check(
          successCallback,
          errorCallback,
          server,
          fingerprint);

   function successCallback(message) {
     alert(message);
     // Message is always: CONNECTION_SECURE.
     // Now do something with the trusted server.
   }

   function errorCallback(message) {
     alert(message);
     if (message === "CONNECTION_NOT_SECURE") {
       // There is likely a man in the middle attack going on, be careful!
     } else if (message.indexOf("CONNECTION_FAILED") >- 1) {
       // There was no connection (yet). Internet may be down. Try again (a few times) after a little timeout.
     }
   }
```

APK ファイルを展開した後、Cordova/Phonegap ファイルは /assets/www フォルダに置かれます。'plugins' フォルダに使用するプラグインがあります。アプリケーションの JavaScript コードでこのメソッドを検索して、その使用状況を確認する必要があります。

### 動的解析

動的解析は好みの傍受プロキシを使用して MITM 攻撃を開始することで実行できます。これにより、クライアント (モバイルアプリケーション) とバックエンドサーバー間のトラフィックを監視できます。プロキシが HTTP リクエストおよびレスポンスを傍受できない場合、SSL ピンニングは正しく実装されています。

#### 証明書ピンニングのバイパス

デバイスで利用可能なフレームワークに応じて、ブラックボックステストのために証明書ピンニングをバイパスする方法がいくつかあります。

- Cydia Substrate: [Android-SSL-TrustKiller](https://github.com/iSECPartners/Android-SSL-TrustKiller "Android-SSL-TrustKiller") パッケージをインストールします。
- Frida: [Universal Android SSL Pinning Bypass with Frida](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/ "Universal Android SSL Pinning Bypass with Frida") スクリプトを使用します。
- Objection: `android sslpinning disable` コマンドを使います。
- Xposed: [TrustMeAlready](https://github.com/ViRb3/TrustMeAlready "TrustMeAlready") または [SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "SSLUnpinning") モジュールをインストールします。

ほとんどのアプリケーションでは、証明書ピンニングは数秒以内にバイパスできますが、これはアプリがこれらのツールでカバーしている API 関数を使用している場合に限られます。アプリがカスタムフレームワークまたはカスタムライブラリを使用して SSL ピンニングを実装している場合には、SSL ピンニングを手動でパッチ適用および無効化する必要があるため、時間がかかります。

##### カスタム証明書ピンニングの静的なバイパス

アプリケーション内のどこかで、エンドポイントと証明書 (またはそのハッシュ) の両方を定義する必要があります。アプリケーションを逆コンパイルした後、以下のものを検索します。

- 証明書ハッシュ: `grep -ri "sha256\|sha1" ./smali` 識別されたハッシュをプロキシの CA のハッシュで置き換えます。あるいは、ハッシュにドメイン名が付随している場合には、元のドメインがピン留めされないようにドメイン名を存在しないドメイン名に改変してみることができます。これは難読化された OkHTTP 実装ではうまく機能します。
- 証明書ファイル: `find ./assets -type f \( -iname \*.cer -o -iname \*.crt \)` これらのファイルをプロキシの証明書で置き換え、正しい形式であることを確認します。
- トラストストアファイル: `find ./ -type f \( -iname \*.jks -o -iname \*.bks \)` プロキシの証明書をトラストストアに追加し、それらが正しい形式であることを確認します。

> アプリには拡張子のないファイルが含まれる可能性があることに気を付けます。最も一般的なファイルの場所は `assets` ディレクトリおよび `res` ディレクトリであり、これらも調査すべきです。

例として、BKS (BouncyCastle) トラストストアを使用するアプリケーションを見つけ、`res/raw/truststore.bks` ファイルに保存されているとしましょう。SSL ピンニングをバイパスするには、コマンドラインツール `keytool` を使用してプロキシの証明書をトラストストアに追加する必要があります。`keytool` は Java SDK に付属しており、コマンドを実行するには以下の値が必要です。

- password - キーストア用のパスワード。逆コンパイルされたアプリコードからハードコードされたパスワードを探します。
- providerpath - BouncyCastle Provider jar ファイルの場所。[The Legion of the Bouncy Castle](https://www.bouncycastle.org/latest_releases.html "https://www.bouncycastle.org/latest_releases.html") からダウンロードできます。
- proxy.cer - プロキシの証明書。
- aliascert - プロキシの証明書のエイリアスとして使用される一意の値。

プロキシの証明書を追加するには以下のコマンドを使用します。

```bash
$ keytool -importcert -v -trustcacerts -file proxy.cer -alias aliascert -keystore "res/raw/truststore.bks" -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath "providerpath/bcprov-jdk15on-164.jar" -storetype BKS -storepass password
```

BKS トラストストア内の証明書をリストするには以下のコマンドを使用します。

```bash
$ keytool -list -keystore "res/raw/truststore.bks" -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath "providerpath/bcprov-jdk15on-164.jar"  -storetype BKS -storepass password
```

これらの改変を行った後、apktool を使用してアプリケーションを再パッケージ化してデバイスにインストールします。

アプリケーションがネットワーク通信を実装するためにネイティブライブラリを使用する場合は、さらにリバースエンジニアリングが必要です。このようなアプローチの例がブログ記事 [smali コードでの SSL ピンニングロジックの識別、パッチ適用、および APK の再構築](https://serializethoughts.wordpress.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/ "Bypassing SSL Pinning in Android Applications")  にあります。

##### カスタム証明書ピンニングの動的なバイパス

ピンニングロジックを動的にバイパスすると、整合性チェックをバイパスする必要がなくなり、試行錯誤の実施がはるかに高速になるため、より便利になります。

フックする正しいメソッドを見つけることは通常最も難しい部分であり、難読化のレベルによってはかなりの時間がかかることがあります。開発者は一般的に既存のライブラリを再利用するので、使用されているライブラリを識別する文字列およびライセンスファイルを検索するのがよいアプローチです。ライブラリを特定したら、難読化されていないソースコードを調べて動的計装に適したメソッドを見つけます。

例として、難読化された OkHTTP3 ライブラリを使用するアプリケーションを見つけたとします。[ドキュメント](https://square.github.io/okhttp/3.x/okhttp/ "OkHTTP3 documentation") は CertificatePinner.Builder クラスが特定のドメインのピンを追加する責任があることを示しています。[Builder.add メソッド](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.Builder.html#add-java.lang.String-java.lang.String...- "Builder.add method") の引数を改変できるのであれば、ハッシュを自分の証明書に属する正しいハッシュに変更できます。正しいメソッドを見つけるには二つの方法があります。

- 前のセクションで説明したようにハッシュとドメイン名を検索します。実際のピンニングメソッドは一般的にこれらの文字列に近接して使用または定義されます。
- SMALI コードでメソッドシグネチャを検索します。

Builder.add メソッドの場合、次の grep コマンド `grep -ri java/lang/String;\[Ljava/lang/String;)L ./` を実行して可能なメソッドを見つけることができます。

このコマンドは文字列と文字列の可変リストを引数として取るすべてのメソッドを検索し、複雑なオブジェクトを返します。アプリケーションのサイズに応じて、これはコード内で一つあるいは複数の一致を持つ可能性があります。

Frida で各メソッドをフックして引数を出力します。そのうちの一つはドメイン名と証明書ハッシュを表示します。その後、実装されたピンニングを回避するために引数を改変できます。

## Network Security Configuration 設定のテスト (MSTG-NETWORK-4)

### 概要

Network Security Configuration は Android 7.0 (API level 24) で導入され、カスタムトラストアンカーや証明書ピンニングなどのアプリのネットワークセキュリティ設定をカスタマイズできます。

#### トラストアンカー

Android 7.0 (API level 24) 以降で実行している場合、これらの API レベルをターゲットとするアプリはデフォルトの Network Security Configuration を使用します。それはユーザーが提供する CA を信頼せず、ユーザーに悪意のある CA をインストールさせることによる MITM 攻撃の可能性を減らします。

この保護はカスタムの Network Security Configuration を使用することでバイパスできます。アプリはユーザーが提供する CA を信頼することを示すカスタムトラストアンカーを用います。

### 静的解析

ターゲット SDK のバージョンを確認するには逆コンパイラ (jadx や apktool など) を使用します。アプリをデコードした後、出力フォルダに作成された apktool.yml ファイルに存在する `targetSDK` の存在を探します。

Network Security Configuration を解析して、どの設定が構成されているかを判断します。このファイルは APK 内の /res/xml/ フォルダに network_security_config.xml という名前で格納されています。

`<base-config>` または `<domain-config>` にカスタムの `<trust-anchors>` が存在する場合、`<certificates src="user">` を定義するアプリケーションは特定のドメインまたはすべてのドメインに対してユーザーが提供する CA を信頼します。以下に例を示します。

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="false">owasp.org</domain>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
        <pin-set expiration="2018/8/10">
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Intermediate CA of the OWASP website server certificate -->
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Root CA of the OWASP website server certificate -->
            <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

エントリの順位を理解することが重要です。`<domain-config>` エントリまたは親の `<domain-config>` に値が設定されていない場合、その構成は `<base-config>` をベースに行われます。また、最終的にこのエントリに定義されていない場合、デフォルト構成が使用されます。

Android 9 (API レベル 28) 以上をターゲットとするアプリのデフォルト構成は以下のとおりです。

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

Android 7.0 (API レベル 24) から Android 8.1 (API レベル 27) をターゲットとするアプリのデフォルト構成は以下のとおりです。

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

Android 6.0 (API レベル 23) 以下をターゲットとするアプリのデフォルト構成は以下のとおりです。

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

### 動的解析

動的なアプローチを使用することにより、通常は Burp などの傍受プロキシを使用して、ターゲットアプリの Network Security Configuration 設定をテストできます。但し、例えば、Android 7.0 (API level 24) 以上をターゲットとし、Network Security Configuration を効果的に適用するアプリをテストする場合には、最初はトラフィックを見ることができない可能性があります。そのような状況では、Network Security Configuration ファイルにパッチを適用する必要があります。必要な手順は「Android セキュリティテスト入門」の章の「[Network Security Configuration のバイパス](0x05b-Basic-Security_Testing.md#bypassing-the-network-security-configuration "Bypassing the Network Security Configuration")」のセクションにあります。

これを必要としないシナリオや、パッチをあてずに MITM 攻撃をできるシナリオがまだあるかもしれません。

- Android 7.0 (API level 24) 以降の Android デバイス上でアプリが実行されているが、アプリが 24 未満の API レベルをターゲットにしている場合、Network Security Configuration ファイルを使用しません。代わりに、アプリはユーザー提供の CA を信頼します。
- Android 7.0 (API level 24) 以降の Android デバイス上でアプリが実行されており、アプリにカスタム Network Security Configuration が実装されていない場合。

## セキュリティプロバイダのテスト (MSTG-NETWORK-6)

### 概要

Android はセキュリティプロバイダに依存して SSL/TLS ベースの接続を提供しています。この種のセキュリティプロバイダの問題 (一例では [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")) は、デバイスに付随するもので、多くの場合バグや脆弱性があります。
既知の脆弱性を回避するために、開発者はアプリケーションが適切なセキュリティプロバイダをインストールすることを確認する必要があります。
2016年7月11日以降、Google は脆弱なバージョンの OpenSSL を使用する [Play ストアのアプリケーション提出を拒否しています](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (新規アプリケーションおよび更新の両方) 。

### 静的解析

Android SDK をベースとするアプリケーションは GooglePlayServices に依存する必要があります。例えば、gradle ビルドファイルには、dependencies ブロックに `compile 'com.google.android.gms:play-services-gcm:x.x.x'` があります。`ProviderInstaller` クラスは `installIfNeeded` または `installIfNeededAsync` のどちらかで呼び出されていることを確認する必要があります。`ProviderInstaller` はできるだけ早期にアプリケーションのコンポーネントにより呼び出される必要があります。これらのメソッドによりスローされる例外は正しく捕捉および処理されるべきです。
アプリケーションがそのセキュリティプロバイダにパッチを適用することができない場合、そのセキュアではない状態の API を通知するかユーザー操作を制限します (すべての HTTPS トラフィックがこの状況ではより危険であるとみなすべきであるため) 。

SSL エクスプロイトを防ぐためにセキュリティプロバイダをアップデートする方法を示す二つの [Android 開発者ドキュメントの例](https://developer.android.com/training/articles/security-gms-provider.html "Updating Your Security Provider to Protect Against SSL Exploits") があります。どちらの場合でも、開発者は例外を適切に処理する必要があり、アプリケーションがパッチを適用されていないセキュリティプロバイダで動作している場合にはバックエンドに報告することが賢明かもしれません。

同期的なパッチ適用:

```java
//this is a sync adapter that runs in the background, so you can run the synchronous patching.
public class SyncAdapter extends AbstractThreadedSyncAdapter {

  ...

  // This is called each time a sync is attempted; this is okay, since the
  // overhead is negligible if the security provider is up-to-date.
  @Override
  public void onPerformSync(Account account, Bundle extras, String authority,
      ContentProviderClient provider, SyncResult syncResult) {
    try {
      ProviderInstaller.installIfNeeded(getContext());
    } catch (GooglePlayServicesRepairableException e) {

      // Indicates that Google Play services is out of date, disabled, etc.

      // Prompt the user to install/update/enable Google Play services.
      GooglePlayServicesUtil.showErrorNotification(
          e.getConnectionStatusCode(), getContext());

      // Notify the SyncManager that a soft error occurred.
      syncResult.stats.numIOExceptions++;
      return;

    } catch (GooglePlayServicesNotAvailableException e) {
      // Indicates a non-recoverable error; the ProviderInstaller is not able
      // to install an up-to-date Provider.

      // Notify the SyncManager that a hard error occurred.
      //in this case: make sure that you inform your API of it.
      syncResult.stats.numAuthExceptions++;
      return;
    }

    // If this is reached, you know that the provider was already up-to-date,
    // or was successfully updated.
  }
}
```

非同期的なパッチ適用:

```java
//This is the mainactivity/first activity of the application that's there long enough to make the async installing of the securityprovider work.
public class MainActivity extends Activity
    implements ProviderInstaller.ProviderInstallListener {

  private static final int ERROR_DIALOG_REQUEST_CODE = 1;

  private boolean mRetryProviderInstall;

  //Update the security provider when the activity is created.
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    ProviderInstaller.installIfNeededAsync(this, this);
  }

  /**
   * This method is only called if the provider is successfully updated
   * (or is already up-to-date).
   */
  @Override
  protected void onProviderInstalled() {
    // Provider is up-to-date, app can make secure network calls.
  }

  /**
   * This method is called if updating fails; the error code indicates
   * whether the error is recoverable.
   */
  @Override
  protected void onProviderInstallFailed(int errorCode, Intent recoveryIntent) {
    if (GooglePlayServicesUtil.isUserRecoverableError(errorCode)) {
      // Recoverable error. Show a dialog prompting the user to
      // install/update/enable Google Play services.
      GooglePlayServicesUtil.showErrorDialogFragment(
          errorCode,
          this,
          ERROR_DIALOG_REQUEST_CODE,
          new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
              // The user chose not to take the recovery action
              onProviderInstallerNotAvailable();
            }
          });
    } else {
      // Google Play services is not available.
      onProviderInstallerNotAvailable();
    }
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode,
      Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == ERROR_DIALOG_REQUEST_CODE) {
      // Adding a fragment via GooglePlayServicesUtil.showErrorDialogFragment
      // before the instance state is restored throws an error. So instead,
      // set a flag here, which will cause the fragment to delay until
      // onPostResume.
      mRetryProviderInstall = true;
    }
  }

  /**
   * On resume, check to see if we flagged that we need to reinstall the
   * provider.
   */
  @Override
  protected void onPostResume() {
    super.onPostResult();
    if (mRetryProviderInstall) {
      // We can now safely retry installation.
      ProviderInstall.installIfNeededAsync(this, this);
    }
    mRetryProviderInstall = false;
  }

  private void onProviderInstallerNotAvailable() {
    // This is reached if the provider cannot be updated for some reason.
    // App should consider all HTTP communication to be vulnerable, and take
    // appropriate action (e.g. inform backend, block certain high-risk actions, etc.).
  }
}

```

NDK ベースのアプリケーションは SSL/TLS 機能を提供する最新の正しくパッチ適用されたライブラリにのみバインドすることを確認します。

### 動的解析

ソースコードがある場合:

- デバッグモードでアプリケーションを実行し、アプリが最初にエンドポイントに接続するブレークポイントを作成します。
- 強調表示されたコードを右クリックし、`Evaluate Expression` を選択します。
- `Security.getProviders()` と入力し Enter キーを押します。
- プロバイダをチェックし `GmsCore_OpenSSL` を探してみます。これは新たにトップにリストアップされたプロバイダです。

ソースコードがない場合:

- Xposed を使用して `java.security` パッケージにフックし、`java.security.Security` の `getProviders` メソッド (引数なし) にフックします。戻り値は `Provider` の配列になります。
- 最初のプロバイダが `GmsCore_OpenSSL` であるかどうかを判断します。

### 参考情報

#### OWASP MASVS

- MSTG-NETWORK-2: "TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨される標準規格をサポートしていない場合には可能な限り近い状態である。"
- MSTG-NETWORK-3: "セキュアチャネルが確立されたときに、アプリはリモートエンドポイントのX.509証明書を検証している。信頼されたCAにより署名された証明書のみが受け入れられている。"
- MSTG-NETWORK-4: "アプリは自身の証明書ストアを使用するか、エンドポイント証明書もしくは公開鍵をピンニングしている。信頼されたCAにより署名された場合でも、別の証明書や鍵を提供するエンドポイントとの接続を確立していない。"
- MSTG-NETWORK-6: "アプリは最新の接続ライブラリとセキュリティライブラリにのみ依存している。"

#### Android 開発者ドキュメント

- Network Security Configuration - <https://developer.android.com/training/articles/security-config>
- Network Security Configuration (cached alternative) - <https://webcache.googleusercontent.com/search?q=cache:hOONLxvMTwYJ:https://developer.android.com/training/articles/security-config+&cd=10&hl=nl&ct=clnk&gl=nl>

#### Xamarin 証明書ピンニング

- Certificate and Public Key Pinning with Xamarin - <https://thomasbandt.com/certificate-and-public-key-pinning-with-xamarin>
- ServicePointManager - <https://msdn.microsoft.com/en-us/library/system.net.servicepointmanager(v=vs.110).aspx>

#### Cordova 証明書ピンニング

- PhoneGap SSL Certificate Checker plugin - <https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin>
