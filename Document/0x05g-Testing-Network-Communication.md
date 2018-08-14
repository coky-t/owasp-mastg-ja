
## Android のネットワーク API

### エンドポイント同一性検証のテスト

ネットワーク上で機密情報を転送するために TLS を使用することはセキュリティにとって不可欠です。しかし、モバイルアプリケーションとバックエンド API との間の通信を暗号化することは簡単ではありません。開発者は開発プロセスを容易にするために、よりシンプルではあるもののセキュアではない (任意の証明書を受け入れるなどの) ソリューションを選ぶことが多く、時にはこれらの脆弱なソリューションが [製品バージョンとなり](https://www.owasp.org/images/7/77/Hunting_Down_Broken_SSL_in_Android_Apps_-_Sascha_Fahl%2BMarian_Harbach%2BMathew_Smith.pdf "Hunting Down Broken SSL in Android Apps") 、潜在的にユーザーを [中間者攻撃](https://cwe.mitre.org/data/definitions/295.html "CWE-295: Improper Certificate Validation") に晒す可能性があります。

二つの主要な問題に対処する必要があります。

- 証明書が信頼できるソース (CA) に由来することを検証します。
- エンドポイントサーバーが正しい証明書を提示するかどうかを判別します。

ホスト名と証明書自体が正しく検証されていることを確認します。事例と一般的な落とし穴が [Android の公式ドキュメント](https://developer.android.com/training/articles/security-ssl.html "Android Documentation - SSL") にあります。`TrustManager` および `HostnameVerifier` の使用例のコードを探します。下記のセクションには、あなたが探しているようなセキュアではない事例があります。

#### 静的解析

##### サーバー証明書の検証

"TrustManager" は Android で信頼できる接続を確立するために必要な条件を検証する手段です。この点について以下の条件を確認する必要があります。

- 証明書は「信頼できる」CA により署名されていますか
- 証明書は有効期限切れではありませんか
- 証明書は自己署名されていませんか

以下のコードスニペットは開発中に使用されることがあり、`checkClientTrusted`, `checkServerTrusted`, `getAcceptedIssuers` 関数を上書きして、任意の証明書を受け入れます。そのような実装は避けるべきであり、必要であれば、セキュリティ上の欠陥が組み込まれることを避けるために、それらを製品ビルドから明確に分離する必要があります。

```Java
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

##### WebView サーバー証明書検証

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

##### Apache Cordova 証明書検証

アプリケーションマニフェストで `android:debuggable` フラグが有効になっている場合、Apache Cordova フレームワークの内部 WebView 使用の実装は `onReceivedSslError` メソッドの [TLS エラー](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java "TLS errors ignoring by Apache Cordova in WebView") を無視します。したがって、アプリがデバッグ可能ではないことを確認します。テストケース「アプリがデバッグ可能かどうかのテスト」を参照してください。

##### ホスト名検証

クライアントサイドの TLS 実装におけるもう一つのセキュリティ上の欠陥はホスト名検証の欠如です。開発環境では通常有効なドメイン名ではなく内部アドレスを使用するため、開発者はホスト名検証を無効化 (またはアプリケーションに任意のホスト名を許可するよう強制) したり、アプリケーションを実稼働環境に移行する際に変更することを忘れたりします。以下のコードはホスト名検証を無効化します。

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

組み込みの `HostnameVerifier` を使うことで、任意のホスト名を受け入れることが可能です。

```Java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

信頼できる接続を設定する前にアプリケーションがホスト名を検証していることを確認します。


#### 動的解析

動的解析には傍受プロキシが必要です。不適切な証明書の検証をテストするには、以下のコントロールを確認します。

- 自己署名証明書

Burp で `Proxy -> Options` タブに移動し、`Proxy Listeners` セクションに移動し、リスナを強調表示にしてから `Edit` をクリックします。それから `Certificate` タブに移動し `Use a self-signed certificate` をチェックして `Ok` をクリックします。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが自己署名証明書を受け入れていることを意味します。

- 無効な証明書の受け入れ

Burp で `Proxy -> Options` タブに移動し、`Proxy Listeners` セクションに移動し、リスナを強調表示にしてから `Edit` をクリックします。それから `Certificate` タブに移動し `Generate a CA-signed certificate with a specific hostname` をチェックしてバックエンドサーバーのホスト名を入力します。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが任意の証明書を受け入れていることを意味します。

- 間違ったホスト名の受け入れ

Burp で `Proxy -> Options` タブに移動し、`Proxy Listeners` セクションに移動し、リスナを強調表示にしてから `Edit` をクリックします。それから `Certificate` タブに移動し `Generate a CA-signed certificate with a specific hostname` をチェックして example.org などの無効なホスト名を入力します。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが任意のホスト名を受け入れていることを意味します。

さらに MITM 解析を行う場合や傍受プロキシの設定に問題がある場合には、[Tapioca](https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html "Announcing CERT Tapioca for MITM Analysis") の使用を検討します。これは MITM ソフトウェア解析のために CERT が事前設定した [VM アプライアンス](http://www.cert.org/download/mitm/CERT_Tapioca.ova "CERT Tapioca Virtual Machine Download") です。行うべきことは [テストされるアプリケーションをエミュレータにデプロイしてトラフィックのキャプチャを開始する](https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html "Finding Android SSL vulnerabilities with CERT Tapioca") だけです。


### カスタム証明書ストアおよび証明書ピンニングのテスト

#### 概要

証明書ピンニングは信頼できる認証局により署名された証明書を受け入れる代わりに、バックエンドサーバーを特定の X509 証明書または公開鍵に関連付けるプロセスです。サーバー証明書または公開鍵を格納 (「ピンニング」) した後、モバイルアプリはその既知のサーバーにのみ接続します。外部認証局からの信頼を取り下げることで、アタックサーフェイスを縮小します (結局のところ、認証局が侵害されたり、偽者に証明書を発行するよう騙されたりという既知の事例が多くあります) 。

証明書はアプリにピン留めおよびハードコードされるか、またはアプリが最初にバックエンドに接続するときに取り出されます。後者の場合には、ホストが最初に参照されるときに証明書がホストに関連付け (「ピン留め」) られます。この方法はあまりセキュアではありません。最初の接続を傍受する攻撃者が自身の証明書を注入できるためです。

#### 静的解析

##### Network Security Configuration

ネットワークセキュリティ設定を安全な宣言型設定ファイルでアプリコードの修正なしにカスタマイズするには、Android がバージョン 7.0 およびそれ以降で提供している [Network Security Configuration (NSC)](https://developer.android.com/training/articles/security-config.html "Network Security Configuration documentation") を使用できます。

Network Security Configuration 機能を使用して [宣言型証明書](https://developer.android.com/training/articles/security-config.html#CertificatePinning "Certificate Pinning using Network Security Configuration") を特定のドメインにピン留めすることもできます。アプリケーションが NSC 機能を使用する場合、定義された設定を識別するために二つのことをチェックする必要があります。

1. application タグの "android:networkSecurityConfig" 属性による Android アプリケーションマニフェストの NSC ファイル参照の指定

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owasp.com.app">
    <application android:networkSecurityConfig="@xml/network_security_config">
        ...
    </application>
</manifest>
```

2. "res/xml/network_security_config.xml" に格納されている NSC ファイルの内容

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <!-- Use certificate pinning for OWASP website access including sub domains -->
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

NSC 設定が存在する場合、以下のイベントがログに表示されることがあります。

```
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

証明書ピンニング妥当性確認が失敗した場合、以下のイベントがログ出力されます。

```
I/X509Util: Failed to validate the certificate chain, error: Pin verification failed
```

#### 静的解析
 * /res/xml/ フォルダにある network_security_config.xml ファイルに \<pin\> エントリが存在するかどうかを確認するには、逆コンパイラ (Jadx など) や apktool を使用します。

##### TrustManager

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
Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

アプリの実装は証明書の公開鍵のみに対してピンニング、証明書全体に対して、証明書チェーン全体に対してとさまざまです。

##### ネットワークライブラリと WebView

サードパーティーネットワークライブラリを使用するアプリケーションはライブラリの証明書ピンニング機能を利用できます。例えば、[okhttp](https://github.com/square/okhttp/wiki/HTTPS "okhttp library") では `CertificatePinner` を使用して以下のようにセットアップできます。

```java
OkHttpClient client = new OkHttpClient.Builder()
        .certificatePinner(new CertificatePinner.Builder()
            .add("example.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
            .build())
        .build();
```

WebView コンポーネントを使用するアプリケーションは WebViewClient のイベントハンドラを利用して、ターゲットリソースがロードされる前に各リクエストの何かしらの「証明書ピンニング」を行います。以下のコードはサーバーから送信された証明書の Issuer DN の検証例を示しています。

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
            //Apply check on Issuer DN against expected one
            SslCertificate.DName issuerDN = serverCert.getIssuedBy();
            if(!this.expectedIssuerDN.equals(issuerDN.toString())){
                //Throw exception to cancel resource loading...
            }
        }
    }
});
```

##### Xamarin アプリケーション

Xamarin で開発されたアプリケーションは一般的に ServicePointManager を使用してピンニングを実装します。

通常、証明書をチェックする関数を作成し、ServerCertificateValidationCallback メソッドにブール値を返します。

```c#
[Activity(Label = "XamarinPinning", MainLauncher = true)]
    public class MainActivity : Activity
    {
        // SupportedPublicKey - 公開鍵の16進数値
        // GetPublicKeyString() メソッドを使用して、ピン留めしたい証明書の公開鍵を決定します。最初に ValidateServerCertificate 関数のデバッグコードのコメントを外して、ピン留めする値を決定します。
        private const string SupportedPublicKey = "3082010A02820101009CD30CF05AE52E47B7725D3783B3686330EAD735261925E1BDBE35F170922FB7B84B4105ABA99E350858ECB12AC468870BA3E375E4E6F3A76271BA7981601FD7919A9FF3D0786771C8690E9591CFFEE699E9603C48CC7ECA4D7712249D471B5AEBB9EC1E37001C9CAC7BA705EACE4AEBBD41E53698B9CBFD6D3C9668DF232A42900C867467C87FA59AB8526114133F65E98287CBDBFA0E56F68689F3853F9786AFB0DC1AEF6B0D95167DC42BA065B299043675806BAC4AF31B9049782FA2964F2A20252904C674C0D031CD8F31389516BAA833B843F1B11FC3307FA27931133D2D36F8E3FCF2336AB93931C5AFC48D0D1D641633AAFA8429B6D40BC0D87DC3930203010001";

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

前述の例のサンプル Xamarin アプリは https://github.com/owasp-mstg/blob/master/Samples/Android/02_CertificatePinning/certificatePinningXamarin.apk?raw=true から入手できます。

#### 静的解析

APK ファイルを展開した後、dotPeak, ILSpy, dnSpy などの .NET 逆コンパイラを使用して、'Assemblies' フォルダ内に格納されているアプリ dll を逆コンパイルし、ServicePointManager の使用状況を確認します。


詳細については、[OWASP certificate pinning guide](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android "OWASP Certificate Pinning for Android") を確認してください。

#### 動的解析

動的解析は好みの傍受プロキシを使用して MITM 攻撃を開始することで実行できます。これにより、クライアント (モバイルアプリケーション) とバックエンドサーバー間のトラフィックを監視できます。プロキシが HTTP リクエストおよびレスポンスを傍受できない場合、SSL ピンニングは正しく実装されています。

### Network Security Configuration 設定のテスト

#### 概要
Network Security Configuration は Android 7 で導入され、カスタムトラストアンカーや証明書ピンニングなどのアプリのネットワークセキュリティ設定をカスタマイズできます。

##### トラストアンカー

アプリが API レベル 24 以上をターゲットとし、バージョン 7 以降の Android デバイス上で実行している場合、デフォルトの Network Security Configuration を使用します。それはユーザーが提供する CA を信頼せず、ユーザーに悪意のある CA をインストールさせることによる MiTM 攻撃の可能性を減らします。

この保護はカスタムの Network Security Configuration を使用することでバイパスできます。アプリはユーザーが提供する CA を信頼することを示すカスタムトラストアンカーを用います。

##### Pin-set 有効期限日付

Pin-set には公開鍵ピンのセットが含まれています。各セットには有効期限日付を定義できます。有効期限日付に達した場合、ネットワーク通信は引き続き機能しますが、影響を受けるドメインでは証明書ピンニングが無効になります。

#### 静的解析

Network Security Configuration を解析して、どの設定が構成されているかを判断します。このファイルは apk 内の /res/xml/ フォルダに network_security_config.xml という名前で格納されています。

<base-config> または <domain-config> にカスタムの <trust-anchors> が存在する場合、<certificates src="user"> を定義するアプリケーションは特定のドメインまたはすべてのドメインに対してユーザーが提供する CA を信頼します。以下に例を示します。
    
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="false">owasp.org</domain>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
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
エントリの順位を理解することが重要です。\<domain-config\> エントリまたは親の \<domain-config\> に値が設定されていない場合、その構成は \<base-config\> をベースに行われます。また、最終的にこのエントリに定義されていない場合、デフォルト構成が使用されます。

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

#### 動的解析

プロキシルート CA (Burp Suite など) をデバイス上にインストールし、この特定のアプリが targetSDK を API レベル 24 以上に設定し、バージョン 7 以降の Android デバイスで実行するシナリオでは、通信を傍受することはできてはいけません。できる場合、これはこのメカニズムのバイパスがあることを意味します。


### デフォルト Network Security Configuration のテスト

#### 概要
前のトピックで説明したように、API レベル 24 以上をターゲットとするアプリは、別途定義されない限り、ユーザーが提供する CA を信頼しないデフォルト Network Security Configuration を実装します。

アプリはバージョン 7 以上の Android デバイス上で実行するが、24 未満の API レベルをターゲットとするシナリオでは、この機能を使用せず、依然としてユーザーが提供する CA を信頼します。

#### 静的解析

* 逆コンパイラ (Jadx など) を使用して、AndroidManifest.xml ファイルにある targetSDK を確認します。
* apktool を使用してアプリをデコードし、出力フォルダの apktool.yml ファイルにある targetSDK を確認します。

#### 動的解析

プロキシルート CA (Burp Suite など) をデバイス上にインストールし、このアプリがバージョン 7 以降の Android デバイス上で実行し、カスタム Network Security Configuration を実装していないシナリオでは、アプリが証明書を正しく検証すると仮定すると、targetSDK は 24 未満の API レベルに設定されていることを示しています。

### セキュリティプロバイダのテスト

#### 概要
Android はセキュリティプロバイダに依存して SSL/TLS ベースの接続を提供しています。この種のセキュリティプロバイダの問題 (一例では [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")) は、デバイスに付随するもので、多くの場合バグや脆弱性があります。
既知の脆弱性を回避するために、開発者はアプリケーションが適切なセキュリティプロバイダをインストールすることを確認する必要があります。
2016年7月11日以降、Google は脆弱なバージョンの OpenSSL を使用する [Play ストアのアプリケーション提出を拒否しています](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (新規アプリケーションおよび更新の両方) 。

#### 静的解析

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

#### 動的解析

ソースコードがある場合:
- デバッグモードでアプリケーションを実行し、アプリが最初にエンドポイントに接続するブレークポイントを作成します。
- 強調表示されたコードを右クリックし、`Evaluate Expression` を選択します。
- `Security.getProviders()` と入力し Enter キーを押します。
- プロバイダをチェックし `GmsCore_OpenSSL` を探してみます。これは新たにトップにリストアップされたプロバイダです。

ソースコードがない場合:
- Xposed を使用して `java.security` パッケージにフックし、`java.security.Security` の `getProviders` メソッド (引数なし) にフックします。戻り値は `Provider` の配列になります。
- 最初のプロバイダが `GmsCore_OpenSSL` であるかどうかを判断します。


#### 参考情報

#### OWASP Mobile Top 10 2016
- M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication (日本語訳) - https://coky-t.github.io/owasp-mobile-top10-2016-ja/Mobile_Top_10_2016-M3-Insecure_Communication.html

##### OWASP MASVS
- V5.3: "セキュアチャネルが確立されたときに、アプリはリモートエンドポイントのX.509証明書を確認している。信頼されたCAにより署名された証明書のみが受け入れられている。"
- V5.4: "アプリは独自の証明書ストアを使用するか、エンドポイント証明書もしくは公開鍵を固定化しており、信頼できるCAにより署名された場合でも、別の証明書や鍵を提供するエンドポイントとの接続を確立していない。"
- V5.6: "アプリは最新の接続ライブラリとセキュリティライブラリにのみ依存している。"

##### CWE
- CWE-295 - Improper Certificate Validation
- CWE-296 - Improper Following of a Certificate's Chain of Trust - https://cwe.mitre.org/data/definitions/296.html
- CWE-297 - Improper Validation of Certificate with Host Mismatch - https://cwe.mitre.org/data/definitions/297.html
- CWE-298 - Improper Validation of Certificate Expiration - https://cwe.mitre.org/data/definitions/298.html

##### Android 開発者ドキュメント

- Network Security Config - https://developer.android.com/training/articles/security-config

##### Xamarin 証明書ピンニング

- Certificate and Public Key Pinning with Xamarin - https://thomasbandt.com/certificate-and-public-key-pinning-with-xamarin
- ServicePointManager - https://msdn.microsoft.com/en-us/library/system.net.servicepointmanager(v=vs.110).aspx
