---
masvs_v1_id:
- MSTG-NETWORK-4
masvs_v2_id:
- MASVS-NETWORK-2
platform: android
title: カスタム証明書ストアおよび証明書ピン留めのテスト (Testing Custom Certificate Stores and Certificate Pinning)
masvs_v1_levels:
- L2
---

## 概要

## 静的解析

### Network Security Configuration

Network Security Configuration を調べて `<pin-set>` 要素を探します。 `expiration` の日付がないか調べます。有効期限が切れると、影響を受けるドメインでは証明書ピン留めが無効になります。

> **テストのヒント**: 証明書ピン留めバリデーションチェックが失敗した場合、以下のイベントがシステムログ ([システムログの監視 (Monitoring System Logs)](../../../techniques/android/MASTG-TECH-0009.md) を参照) にログ記録されるはずです。

```bash
I/X509Util: Failed to validate the certificate chain, error: Pin verification failed
```

### TrustManager

証明書ピン留めの実装には主に三つのステップがあります。

- 目的のホストの証明書を取得します。
- 証明書が .bks フォーマットであることを確認します。
- 証明書をデフォルトの Apache Httpclient のインスタンスにピン留めします。

証明書ピン留めの正しい実装を解析するには、HTTP クライアントがキーストアをロードする必要があります。

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

アプリの実装は証明書の公開鍵のみに対してピン留め、証明書全体に対して、証明書チェーン全体に対してとさまざまです。

### ネットワークライブラリと WebView

サードパーティーネットワークライブラリを使用するアプリケーションはライブラリの証明書ピン留め機能を利用できます。例えば、[okhttp](https://github.com/square/okhttp/wiki/HTTPS "okhttp library") では `CertificatePinner` を使用して以下のようにセットアップできます。

```java
OkHttpClient client = new OkHttpClient.Builder()
        .certificatePinner(new CertificatePinner.Builder()
            .add("example.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
            .build())
        .build();
```

WebView コンポーネントを使用するアプリケーションは WebViewClient のイベントハンドラを利用して、ターゲットリソースがロードされる前に各リクエストの何かしらの「証明書ピン留め」を行います。以下のコードは検証例を示しています。

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

あるいは、ピンが設定された OkHttpClient を使用し、それを `WebViewClient` の `shouldInterceptRequest` をオーバーライドするプロキシとして機能させるのがよいでしょう。

### Xamarin アプリケーション

Xamarin で開発されたアプリケーションは一般的に `ServicePointManager` を使用してピン留めを実装します。

通常、証明書をチェックする関数を作成し、 `ServerCertificateValidationCallback` メソッドにブール値を返します。

```cs
[Activity(Label = "XamarinPinning", MainLauncher = true)]
    public class MainActivity : Activity
    {
        // SupportedPublicKey - Hexadecimal value of the public key.
        // Use GetPublicKeyString() method to determine the public key of the certificate we want to pin. Uncomment the debug code in the ValidateServerCertificate function a first time to determine the value to pin.
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

この例では証明書チェーンの中間 CA をピン留めしています。HTTP レスポンスの出力はシステムログにあります。

前述の例のサンプル Xamarin アプリは [MASTG リポジトリ](https://github.com/OWASP/owasp-mastg/raw/master/Samples/Android/02_CertificatePinning/certificatePinningXamarin.apk "Xamarin app with certificate pinning") から入手できます。

APK ファイルを展開した後、dotPeak, ILSpy, dnSpy などの .NET 逆コンパイラを使用して、'Assemblies' フォルダ内に格納されているアプリ dll を逆コンパイルし、ServicePointManager の使用箇所を確認します。

詳しくはこちら。

- Certificate and Public Key Pinning with Xamarin - <https://thomasbandt.com/certificate-and-public-key-pinning-with-xamarin>
- ServicePointManager - <https://msdn.microsoft.com/en-us/library/system.net.servicepointmanager(v=vs.110).aspx>

### Cordova アプリケーション

Cordova ベースのハイブリッドアプリケーションはネイティブに証明書ピン留めをサポートしていないため、プラグインを使用してこれを達成します。 もっとも一般的なものは [PhoneGap SSL Certificate Checker](https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin "PhoneGap SSL Certificate Checker plugin") です。`check` メソッドを使用してフィンガープリントを確認し、コールバックが次のステップを決定します。

```javascript
  // Endpoint to verify against certificate pinning.
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

APK ファイルを展開した後、Cordova/Phonegap ファイルは /assets/www フォルダに置かれます。'plugins' フォルダに使用するプラグインがあります。アプリケーションの JavaScript コードでこのメソッドを検索して、その使用箇所を確認する必要があります。

## 動的解析

[エンドポイント同一性検証のテスト (Testing Endpoint Identify Verification)](MASTG-TEST-0021.md) の指示に従います。これを行ってもトラフィックがプロキシされない場合、証明書ピン留めが実際に実装され、すべてのセキュリティ対策が実施されていることを意味しているかもしれません。すべてのドメインで同じことが起こるでしょうか？

簡単なスモークテストとしては、[証明書ピン留めのバイパス (Bypassing Certificate Pinning)](../../../techniques/android/MASTG-TECH-0012.md) で説明しているように [objection](../../../tools/generic/MASTG-TOOL-0038.md) を使用して証明書ピン留めをバイパスしてみることができます。objection によってフックされているピン留め関連の API は objection の出力に表示されるはずです。

<img src="../../../Document/Images/Chapters/0x05b/android_ssl_pinning_bypass.png" width="600px"/>

ただし、以下に注意してください。

- API は完全ではないかもしれません。
- 何もフックされていないとしても、必ずしもアプリがピン留めを実装していないとは限りません。

いずれの場合にも、アプリやそのコンポーネントの一部が [objection でサポートされている](https://github.com/sensepost/objection/blob/master/agent/src/android/pinning.ts) 方法でカスタムピン留めを実装している可能性があります。具体的なピン留めの指標やより詳細なテストについては静的解析のセクションをご確認ください。
