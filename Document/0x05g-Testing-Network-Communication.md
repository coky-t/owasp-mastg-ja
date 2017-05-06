## ネットワーク通信のテスト

### ネットワーク上の暗号化されていない機密データに関するテスト

#### 概要

ほとんどのモバイルアプリケーションの機能はインターネット上のサービスから情報を送信または受信することを要求します。これは途中のデータを対象とした攻撃の別の領域を明らかにします。攻撃者がネットワークインフラストラクチャ(WiFi アクセスポイントなど)の一部を制御する場合、暗号化されていない情報を盗聴または改変(MiTM 攻撃)する可能性があります [1]。このため、開発者は機密データを平文で送ることはできないという一般的なルールを立てるべきです [2]。

#### 静的解析

テスト対象のアプリケーションと通信するすべての外部エンドポイント(バックエンド API、サードパーティ Web サービス)を特定して、すべての通信チャネルが暗号化されていることを確認します。

#### 動的解析

推奨される方法はテスト対象のアプリケーションに出入りするすべてのネットワークトラフィックを傍受して、暗号化されているかどうかを確認することです。ネットワークトラフィックは以下のいずれかの方法を使用して傍受できます。

* Tcpdump を使用して、すべてのネットワークトラフィックをキャプチャします。ライブキャプチャを開始するには、以下のコマンドを使用します。
```
adb shell "tcpdump -s 0 -w - | nc -l -p 1234"
adb forward tcp:1234 tcp:1234
```

Wireshark を使用して、人間が判読可能な方法でキャプチャしたトラフィックを表示します。
```
nc localhost 1234 | sudo wireshark -k -S -i –
```

* OWASP ZAP <sup>[3]</sup> や Burp Suite <sup>[4]</sup> などの傍受プロキシを使用してすべてのネットワークをキャプチャして、すべてのリクエストが HTTP ではなく HTTPS を使用しているかどうかを確認します。

> 一部のアプリケーションでは Burp や ZAP などのプロキシでは(カスタマイズされた HTTP/HTTPS 実装や証明書ピンニングのため)動作しないことがあるので注意します。このような場合には VPN サーバーを使用してすべてのトラフィックを Burp/ZAP プロキシに転送することができます。Vproxy を使用して簡単にこれを行うことができます。

すべてのトラフィック(TCP および UDP)をキャプチャすることが重要ですので、傍受を開始した後にテスト対象のアプリケーションの可能な限りすべての機能を実行する必要があります。これにはアプリケーションにパッチを適用するプロセスが含まれている必要があります。HTTP 経由でアプリケーションにパッチを送信することにより、送信者が被害者のデバイスに任意のアプリケーションをインストールする可能性があるためです(MiTM攻撃)。

#### 改善方法

機密情報をセキュアチャネル経由で送信されていることを確認します。TLS を使用したソケットレベルの通信には HTTPS [5] または SSLSocket [6] を使用します。

> `SSLSocket` はホスト名を検証 **しない** ことに気をつけます。ホスト名検証には `getDefaultHostnameVerifier()` と期待されるホスト名を使用して行う必要があります。ここ [7] に正しい使い方の事例があります。

一部のアプリケーションでは 機密 IPC を処理するために localhost アドレスや INADDR_ANY にバインドすることがあります。このインタフェースはデバイスにインストールされている他のアプリケーションからアクセス可能であるため、セキュリティの観点からはよくありません。そのような目的のために開発者はセキュアな Android IPC メカニズム [8] の使用を検討すべきです。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

#### OWASP MASVS
* V5.1: "データはネットワーク上でTLSを使用して暗号化されている。セキュアチャネルがアプリ全体を通して一貫して使用されている。"

#### CWE
* CWE-319 - Cleartext Transmission of Sensitive Information

#### その他
* [1] https://cwe.mitre.org/data/definitions/319.html
* [2] https://developer.android.com/training/articles/security-tips.html#Networking
* [3] https://security.secure.force.com/security/tools/webapp/zapandroidsetup
* [4] https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
* [5] https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html
* [6] https://developer.android.com/reference/javax/net/ssl/SSLSocket.html
* [7] https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket
* [8] https://developer.android.com/reference/android/app/Service.html

#### ツール
* Tcpdump - http://www.androidtcpdump.com/
* Wireshark - https://www.wireshark.org/
* OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
* Burp Suite - https://portswigger.net/burp/
* Vproxy - https://github.com/B4rD4k/Vproxy



### TLS設定の検証

#### 概要

機密データを送信する場合、暗号化を使用することが不可欠です。ただし、十分に強力な暗号を使用する場合に限り、暗号化によってプライバシーが保護されます。この目標を達成するには、SSL ベースのサービスで脆弱な暗号スイートを選択してはいけません。暗号スイートは暗号化プロトコル(DES, RC4, AES など)、暗号鍵長(40, 56, 128 ビットなど)、完全性検査に使用されるハッシュアルゴリズム(SHA, MD5 など)によって明示されます。あなたの暗号化を容易に破られないようにするには、脆弱な暗号/プロトコル/鍵を使用していないことを TLS 設定で確認する必要があります [1]。

#### 静的解析

静的解析はこのテストケースでは適用されません。

#### 動的解析

アプリケーションと通信しているすべてのサーバーを(Tcpdump や Burp Suite などを使用して)特定した後、サーバーが脆弱な暗号/プロトコル/鍵の使用を許可しているかどうかを確認する必要があります。さまざまなツールを使用して実行します。

* testssl.sh: コマンドは以下のとおりです。

testssl.sh の Github リポジトリには **SSLv2 を含むすべての暗号スイートとプロトコル** をサポートするダウンロード用コンパイル済み openssl バージョンもあります。

```
testssl.sh www.example.com:443
```

このツールは潜在的な誤設定や脆弱性を赤で強調表示して特定するのにも役立ちます。

レポートの色や書式を保存するには `aha` を使用します。

```
$ OPENSSL=./bin/openssl.Linux.x86_64 bash ./testssl.sh yoursite.com | aha > output.html
```

これにより CLI 出力と一致する HTML ドキュメントが得られます。

* sslyze: コマンドは以下のとおりです。

```
sslyze --regular www.example.com:443
```
* O-Saft (OWASP SSL Advanced Forensic Tool): コマンドから GUI モードで実行します。

```
o-saft.tcl
```
またはコマンドで実行します。複数のオプションが指定できます [2]。証明書、暗号、SSL 接続を検証する最も一般的なものは以下のとおりです。

```
perl o-saft.pl +check www.example.com:443
```

#### 改善方法

サーバーのパッチ適用や再構成により脆弱性や誤構成を解決する必要があります。ネットワーク通信のためにトランスポート層保護を適切に構成するには、OWASP Transport Layer Protection cheat sheet <sup>[3]</sup> および Qualys TLS best practices <sup>[4]</sup> に準じます。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
* V5.2: "TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨された標準をサポートしていない場合には可能な限り近い状態である。"

##### CWE
* CWE-327 - Use of a Broken or Risky Cryptographic Algorithm - https://cwe.mitre.org/data/definitions/327.html

##### その他
* [1] Testing for Weak SSL/TLS Ciphers - https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)
* [2] O-Saft various tests - https://www.owasp.org/index.php/O-Saft/Documentation#COMMANDS
* [3] Transport Layer Protection Cheat Sheet - https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet
* [4] Qualys SSL/TLS Deployment Best Practices - https://dev.ssllabs.com/projects/best-practices/

##### ツール
* testssl.sh- https://testssl.sh
* sslyze - https://github.com/nabla-c0d3/sslyze
* O-Saft - https://www.owasp.org/index.php/O-Saft



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

> **注意** さらに MITM 分析を行う場合や傍受プロキシの設定に問題がある場合には、Tapioca [6] の使用を検討します。
これはソフトウェアの MITM 分析を実行するために CERT が事前設定した VM アプライアンス [7] です。
行うべきことはテストされるアプリケーションをエミュレータにデプロイしてトラフィックのキャプチャを開始するだけです [8]。

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

Certificate pinning allows to hard-code in the client the certificate that is known to be used by the server. This technique is used to reduce the threat of a rogue CA and CA compromise. Pinning the server’s certificate take the CA out of games. Mobile applications that implement certificate pinning only can connect to a limited numbers of servers, as a small list of trusted CAs or server certificates are hard-coded in the application.

#### 静的解析

The process to implement the SSL pinning involves three main steps outlined below:

1. Obtain a certificate for the desired host
1. Make sure certificate is in .bks format
1. Pin the certificate to an instance of the default Apache Httpclient.

To analyze the correct implementations of the SSL pinning the HTTP client should:

1. Load the keystore:

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

Once the keystore is loaded we can use the TrustManager that trusts the CAs in our KeyStore :

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

#### 動的解析

Dynamic analysis can be performed by launching a MITM attack using your preferred interception proxy<sup>[1]</sup>. This will allow to monitor the traffic exchanged between client (mobile application) and the backend server. If the Proxy is unable to intercept the HTTP requests and responses, the SSL pinning is correctly implemented.

#### 改善方法

The SSL pinning process should be implemented as described on the static analysis section. For further information please check the OWASP certificate pinning guide [2].

#### 参考情報

##### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
* V5.4 "The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."

##### CWE
* CWE-295 - Improper Certificate Validation

##### その他

* [1] Setting Burp Suite as a proxy for Android Devices -  https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
* [2] OWASP Certificate Pinning for Android - https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android


### 重要な操作が安全な通信チャネルを使用することの検証

#### 概要

For sensitive applications, like banking apps, OWASP MASVS introduces "Defense in Depth" verification level [1]. Critical operations (e.g. user enrollment, or account recovery) of such sensitive applications are the most attractive targets from attacker's perspective. This creates a need of implementing advanced security controls for such operations, like adding additional channels (e.g. SMS and e-mail) to confirm user's action. Additional channels may reduce a risk of many attacking scenarios (mainly phishing), but only when they are out of any security faults.

#### 静的解析

Review the code and identify those parts of a code which refers to critical operations. Verify if it uses additional channels to perform such operation. Examples of additional verification channels are following:

* token (e.g. RSA token, yubikey)
* push notification (e.g. Google Prompt)
* SMS
* email
* data from another website you had to visit/scan
* data from a physical letter or physical entry point (e.g.: data you receive only after signing a document at the office of a bank)

#### 動的解析

Identify all critical operations implemented in tested application (e.g. user enrollment, or account recovery, money transfer etc.). Ensure that each of critical operations, requires at least one additional channel (e.g. SMS, e-mail, token etc.). Verify if usage of such channel can be bypassed (e.g. turning off SMS confirmation without using any other channel).

#### 改善方法

Ensure that critical operations require at least one additional channel to confirm user's action. Each channel must not be bypassed to execute a critical operation. If you are going to implement additional factor to verify user's identity, you may consider usage of Infobip 2FA library [2], one-time passcodes via Google Authenticator [3].

#### 参考情報

##### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
* V5.5 "The app doesn't rely on a single insecure communication channel (email or SMS) for critical operations, such as enrollments and account recovery."

##### CWE
* CWE-956 - Software Fault Patterns (SFPs) within the Channel Attack cluster

##### その他
* [1] The Mobile Application Security Verification Standard - https://github.com/OWASP/owasp-masvs/blob/master/Document/0x03-Using_the_MASVS.md
* [2] Infobip 2FA library - https://2-fa.github.io/libraries/android-library.html
* [3] Google Authenticator for Android - https://github.com/google/google-authenticator-android
