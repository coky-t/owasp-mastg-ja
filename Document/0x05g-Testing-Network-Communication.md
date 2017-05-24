## ネットワーク通信のテスト (Android アプリ)

### エンドポイント同一性検証のテスト

#### 概要

ネットワーク上で機密情報を転送するために TLS を使用することは、セキュリティの観点から不可欠です。しかし、モバイルアプリケーションとバックエンド API との間の暗号化通信の仕組みを実装することは簡単な作業ではありません。開発者はしばしば、開発プロセスを楽にするために、より簡単ではあるものの安全ではない(任意の証明書を受け入れるなどの)ソリューションを選びます。往々にして製造後に修正されず [1]、同時にアプリケーションを中間者攻撃に晒します [2]。

#### 静的解析

TLS 接続の妥当性確認には主に2つの問題があります。一つ目は証明書が信頼できるソースから取得されたかどうかの検証であり、二つ目はエンドポイントサーバーが正しい証明書を提示しているかどうかを確認することです [3]。

##### サーバー証明書の検証

Android で信頼できる接続を確立するための条件を検証するためのメカニズムは `TrustedManager` と呼ばれます。ここで確認される条件は、以下の通りです。

* 「信頼できる」CA が署名した証明書であるか
* 証明書は期限切れではないか
* 証明書は自己署名されていないか

前述の条件のコントロールチェックがあるかどうかコードを参照します。例えば、以下のコードは任意の証明書を受け入れます。

```
TrustManager[] trustAllCerts = new TrustManager[] {
new X509TrustManager()
{

    public java.security.cert.X509Certificate[] getAcceptedIssuers()
    {
        return new java.security.cert.X509Certificate[] {};
    }
    public void checkClientTrusted(X509Certificate[] chain,
    String authType) throws CertificateException
    {

    }
    public void checkServerTrusted(X509Certificate[] chain,
    String authType) throws CertificateException
    {

    }

}};

context.init(null, trustAllCerts, new SecureRandom());
```

##### ホスト名検証

TLS 実装のもう一つのセキュリティ違反はホスト名検証の欠如です。開発環境では通常、有効なドメイン名の代わりに内部アドレスを使用するため、開発者はホスト名の検証を無効にする(もしくはアプリケーションに任意のホスト名を許可する)ことがあり、アプリケーションが実稼働に移行する際に変更することを忘れてしまいます。以下のコードはホスト名の検証を無効にする役割を果たします。

```
final static HostnameVerifier NO_VERIFY = new HostnameVerifier()
{
    public boolean verify(String hostname, SSLSession session)
    {
              return true;
    }
};
```

ビルトインの `HostnameVerifier` を使用して任意のホスト名を受け入れることも可能です。

```
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

信頼できる接続を設定する前にアプリケーションがホスト名を検証することを確認します。


#### 動的解析

不適切な証明書の検証は静的解析または動的解析を使用して発見できます。

* 静的解析のアプローチはアプリケーションを逆コンパイルして単に TrustManager や HostnameVerifier を使用するコードを調べることです。上記の「静的解析」のセクションに安全でない使用例があります。このような不適切な証明書の検証の確認には、MalloDroid [4] というツールを使用して自動的に行うことができます。単にアプリケーションを逆コンパイルして何か不審なものがある場合には警告します。実行するには、以下のコマンドを入力します。

```bash
$ ./mallodroid.py -f ExampleApp.apk -d ./outputDir
```

ここで MalloDroid により `./outputDir` 内に不審なコードが見つかったか場合には、更に手動解析を行うために逆コンパイルされたアプリケーションを探します。

* 動的解析のアプローチは Burp Suite などの傍受プロキシの使用を必要とします。不適切な証明書の検証をテストするには、以下のコントロールチェックを実行する必要があります。

 1) 自己署名証明書

  Burp で Proxy -> Options タブに移動し、Proxy Listeners セクションに移動し、リスナを強調表示にしてから Edit ボタンをクリックします。それから Certificate タブに移動し 'Use a self-signed certificate' をチェックして Ok をクリックします。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが自己署名証明書を受け入れていることを意味します。

 2) 無効な証明書の受け入れ

  Burp で Proxy -> Options タブに移動し、Proxy Listeners セクションに移動し、リスナを強調表示にしてから Edit ボタンをクリックします。それから Certificate タブに移動し 'Generate a CA-signed certificate with a specific hostname' をチェックしてバックエンドサーバーのホスト名を入力します。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが任意の証明書を受け入れていることを意味します。

 3) 間違ったホスト名の受け入れ

  Burp で Proxy -> Options タブに移動し、Proxy Listeners セクションに移動し、リスナを強調表示にしてから Edit ボタンをクリックします。それから Certificate タブに移動し 'Generate a CA-signed certificate with a specific hostname' をチェックして 'example.org' などの無効なホスト名を入力します。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが任意のホスト名を受け入れていることを意味します。

> **注意** さらに MITM 分析を行う場合や傍受プロキシの設定に問題がある場合には、Tapioca [6] の使用を検討します。これはソフトウェアの MITM 分析を実行するために CERT が事前設定した VM アプライアンス [7] です。行うべきことはテストされるアプリケーションをエミュレータにデプロイしてトラフィックのキャプチャを開始するだけです [8]。

#### 改善方法

ホスト名と証明書が正しく検証されていることを確認します。一般的な TLS 証明書の問題を克服する方法についてはこちらを参照ください [2]。


#### 参考情報

#### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

#### OWASP MASVS
* V5.3: "セキュアチャネルが確立されたときに、アプリはリモートエンドポイントのX.509証明書を確認している。有効なCAにより署名された証明書のみが受け入れられている。"

#### CWE
* CWE-296 - Improper Following of a Certificate's Chain of Trust - https://cwe.mitre.org/data/definitions/296.html
* CWE-297 - Improper Validation of Certificate with Host Mismatch - https://cwe.mitre.org/data/definitions/297.html
* CWE-298 - Improper Validation of Certificate Expiration - https://cwe.mitre.org/data/definitions/298.html

#### その他
* [1] https://www.owasp.org/images/7/77/Hunting_Down_Broken_SSL_in_Android_Apps_-_Sascha_Fahl%2BMarian_Harbach%2BMathew_Smith.pdf
* [2] https://cwe.mitre.org/data/definitions/295.html
* [3] https://developer.android.com/training/articles/security-ssl.html
* [4] https://github.com/sfahl/mallodroid
* [5] https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
* [6] https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html
* [7] http://www.cert.org/download/mitm/CERT_Tapioca.ova
* [8] https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html

### カスタム証明書ストアおよび SSL ピンニングのテスト

#### 概要

証明書ピンニングはサーバーで使用されることが既知である証明書をクライアントにハードコードするものです。この技法は不正な CA や CA の危殆化の脅威を軽減するために使用されます。サーバー証明書のピンニングは CA のゲームを終わらせます。証明書ピンニングを実装するモバイルアプリケーションは限られた数のサーバーにのみ接続できます。信頼できる CA やサーバー証明書の小さなリストをアプリケーションにハードコードされるためです。

#### 静的解析

SSL ピンニングを実装するプロセスには以下で示す3つの主要な手順があります。

1. 目的のホストの証明書を取得します
1. 証明書が .bks 形式であることを確認します
1. 証明書をデフォルトの Apache Httpclient のインスタンスにピン留めします

SSL ピンニングの正しい実装を分析するには、HTTP クライアントを以下のようにします。

1. キーストアをロードする

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

キーストアがロードされると KeyStore の CA を信頼する TrustManager を使用できます。

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

#### 動的解析

動的解析は好みの傍受プロキシ <sup>[1]</sup> を使用して MITM 攻撃を開始することで実行できます。これによりクライアント(モバイルアプリケーション)とバックエンドサーバーとの間で交換されるトラフィックを監視することができます。プロキシが HTTP リクエストやレスポンスを傍受できない場合、SSL ピンニングは正しく実装されています。

#### 改善方法

SSL ピンニングプロセスは静的解析セクションで説明したように実装する必要があります。詳細については OWASP certificate pinning guide [2] を参照ください。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
* V5.4 "アプリは独自の証明書ストアを使用するか、エンドポイント証明書もしくは公開鍵を固定化しており、信頼できるCAにより署名された場合でも、別の証明書や鍵を提供するエンドポイントとの接続を確立していない。"

##### CWE
* CWE-295 - Improper Certificate Validation

##### その他

* [1] Setting Burp Suite as a proxy for Android Devices -  https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
* [2] OWASP Certificate Pinning for Android - https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android
