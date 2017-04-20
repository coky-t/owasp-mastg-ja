## ネットワーク通信のテスト

### ネットワーク上の暗号化されていない機密データに関するテスト

#### 概要

ほとんどのモバイルアプリケーションの機能はインターネット上のサービスから情報を送信または受信することを要求します。これは途中のデータを対象とした攻撃の別の領域を明らかにします。攻撃者がネットワークインフラストラクチャ(WiFi アクセスポイントなど)の一部を制御する場合、暗号化されていない情報を盗聴または改変(MiTM 攻撃)する可能性があります [1]。このため、開発者は機密データを平文で送ることはできないという一般的なルールを立てるべきです [2]。

#### ホワイトボックステスト

テスト対象のアプリケーションと通信するすべての外部エンドポイント(バックエンド API、サードパーティ Web サービス)を特定して、すべての通信チャネルが暗号化されていることを確認します。

#### ブラックボックステスト

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

* OWASP ZAP [3] や Burp Suite [4] などの傍受プロキシを使用してすべてのネットワークをキャプチャして、すべてのリクエストが HTTP ではなく HTTPS を使用しているかどうかを確認します。

> 一部のアプリケーションでは Burp や ZAP などのプロキシでは(カスタマイズされた HTTP/HTTPS 実装や証明書ピンニングのため)動作しないことがあるので注意します。このような場合には VPN サーバーを使用してすべてのトラフィックを Burp/ZAP プロキシに転送することができます。Vproxy を使用して簡単にこれを行うことができます。

すべてのトラフィック(TCP および UDP)をキャプチャすることが重要ですので、傍受を開始した後にテスト対象のアプリケーションの可能な限りすべての機能を実行する必要があります。これにはアプリケーションにパッチを適用するプロセスが含まれている必要があります。HTTP 経由でアプリケーションにパッチを送信することにより、送信者が被害者のデバイスに任意のアプリケーションをインストールする可能性があるためです(MiTM攻撃)。

#### 改善方法

機密情報をセキュアチャネル経由で送信されていることを確認します。TLS を使用したソケットレベルの通信には HTTPS [5] または SSLSocket [6] を使用します。

> `SSLSocket` はホスト名を検証 **しない** ことに気をつけます。ホスト名検証には `getDefaultHostnameVerifier()` と期待されるホスト名を使用して行う必要があります。ここ [7] に正しい使い方の事例があります。

一部のアプリケーションでは 機密 IPC を処理するために localhost アドレスや INADDR_ANY にバインドすることがあります。このインタフェースはデバイスにインストールされている他のアプリケーションからアクセス可能であるため、セキュリティの観点からはよくありません。そのような目的のために開発者はセキュアな Android IPC メカニズム [8] の使用を検討すべきです。

#### OWASP MASVS

V5.1: "データはネットワーク上でTLSを使用して暗号化されている。セキュアチャネルがアプリ全体を通して一貫して使用されている。"

#### CWE

- CWE-319 - Cleartext Transmission of Sensitive Information - https://cwe.mitre.org/data/definitions/319.html

#### OWASP Mobile Top 10 2014

M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

#### 参考情報

- [1] https://cwe.mitre.org/data/definitions/319.html
- [2] https://developer.android.com/training/articles/security-tips.html#Networking
- [3] https://security.secure.force.com/security/tools/webapp/zapandroidsetup
- [4] https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
- [5] https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html
- [6] https://developer.android.com/reference/javax/net/ssl/SSLSocket.html
- [7] https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket
- [8] https://developer.android.com/reference/android/app/Service.html

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

静的解析はここでは適用されません。

#### 動的解析

アプリケーションと通信しているすべてのサーバーを(Tcpdump や Burp Suite などを使用して)特定した後、サーバーが脆弱な暗号/プロトコル/鍵の使用を許可しているかどうかを確認する必要があります。さまざまなツールを使用して実行します。

* testssl.sh: コマンドは以下のとおりです。

```
testssl.sh www.example.com:443
```

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

ネットワーク通信のためにトランスポート層保護を適切に構成するには、OWASP Transport Layer Protection cheat sheet に準じます [3]。

#### 参考情報

##### OWASP Mobile Top 10 2014

M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- V5.2: "TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨された標準をサポートしていない場合には可能な限り近い状態である。"

##### CWE

- CWE-327 - Use of a Broken or Risky Cryptographic Algorithm - https://cwe.mitre.org/data/definitions/327.html

##### Info

- [1] Testing for Weak SSL/TLS Ciphers - https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)
- [2] O-Saft various tests - https://www.owasp.org/index.php/O-Saft/Documentation#COMMANDS
- [3] Transport Layer Protection Cheat Sheet - https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet

##### ツール

* testssl.sh- https://testssl.sh
* sslyze - https://github.com/nabla-c0d3/sslyze
* O-Saft - https://www.owasp.org/index.php/O-Saft

### エンドポイント同一性検証のテスト

#### 概要

ネットワーク上で機密情報を転送するために TLS を使用することは、セキュリティの観点から不可欠です。しかし、モバイルアプリケーションとバックエンド API との間の暗号化通信の仕組みを実装することは簡単な作業ではありません。開発者はしばしば、開発プロセスを楽にするために、より簡単ではあるものの安全ではない(任意の証明書を受け入れるなどの)ソリューションを選びます。往々にして製造後に修正されず [1]、同時にアプリケーションを中間者攻撃に晒します [2]。

#### ホワイトボックステスト

TLS 接続の妥当性確認には主に2つの問題があります。一つ目は証明書が信頼できるソースから取得されたかどうかの検証であり、二つ目はエンドポイントサーバーが正しい証明書を提示しているかどうかを確認することです [3]。

##### サーバー証明書の検証

A mechanism responsible for verifying conditions to establish a trusted connection in Android is called `TrustedManager`. Conditions to be checked at this point, are the following:

* is the certificate signed by a "trusted" CA?
* is the certificate expired?
* Is the certificate self-sgined?

You should look in a code if there are control checks of aforementioned conditions. For example, the following code will accept any certificate:

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

Another security fault in TLS implementation is lack of hostname verification. A development environment usually uses some internal addresses instead of valid domain names, so developers often disable hostname verification (or force an application to allow any hostname) and simply forget to change it when their application goes to production. The following code is responsible for disabling hostname verification:

```
final static HostnameVerifier NO_VERIFY = new HostnameVerifier()
{
    public boolean verify(String hostname, SSLSession session)
    {
              return true;
    }
};
```

It's also possible to accept any hostname using a built-in `HostnameVerifier`:

```
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

Ensure that your application verifies a hostname before setting trusted connection.


#### ブラックボックステスト

Improper certificate verification may be found using static or dynamic analysis.

* Static analysis approach is to decompile an application and simply look in a code for TrustManager and HostnameVerifier usage. You can find insecure usage examples in a "White-box Testing" section above. Such checks of improper certificate verification, may be done automatically, using a tool called MalloDroid [4]. It simply decompiles an application and warns you if it finds something suspicious. To run it, simply type this command:

```
./mallodroid.py -f ExampleApp.apk -d ./outputDir
```

Now, you should be warned if any suspicious code was found by MalloDroid and in `./outputDir` you will find decompiled application for further manual analysis.

* Dynamic analysis approach will require usage of intercept proxy, e.g. Burp Suite. To test improper certificate verification, you should go through following control checks:

 1) Self-signed certificate.

  In Burp go to Proxy -> Options tab, go to Proxy Listeners section, highlight you listener and click Edit button. Then go to Certificate tab and check 'Use a self-signed certificate' and click Ok. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting self-signed certificates.

 2) Accepting invalid certificate.

  In Burp go to Proxy -> Options tab, go to Proxy Listeners section, highlight you listener and click Edit button. Then go to Certificate tab, check 'Generate a CA-signed certificate with a specific hostname' and type hostname of a backend server. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting any certificate.

 3) Accepting wrong hostname.

  In Burp go to Proxy -> Options tab, go to Proxy Listeners section, highlight you listener and click Edit button. Then go to Certificate tab, check 'Generate a CA-signed certificate with a specific hostname' and type invalid hostname, e.g. 'example.org'. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting any hostname.

> **Note**, if you are interested in further MITM analysis or you face any problems with configuration of your intercept proxy, you may consider using Tapioca [6]. It's a CERT preconfigured VM appliance [7] for performing MITM analysis of software. All you have to do is deploy a tested application on emulator and start capturing traffic [8].

#### 改善方法

Ensure, that the hostname and certificate is verified correctly. You can find a help how to overcome common TLS certificate issues here [2].

#### OWASP MASVS

V5.3: "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a valid CA are accepted."

#### CWE

- CWE-296 - Improper Following of a Certificate's Chain of Trust - https://cwe.mitre.org/data/definitions/296.html
- CWE-297 - Improper Validation of Certificate with Host Mismatch - https://cwe.mitre.org/data/definitions/297.html
- CWE-298 - Improper Validation of Certificate Expiration - https://cwe.mitre.org/data/definitions/298.html

#### OWASP Mobile Top 10 2014

M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

#### 参考情報

- [1] https://www.owasp.org/images/7/77/Hunting_Down_Broken_SSL_in_Android_Apps_-_Sascha_Fahl%2BMarian_Harbach%2BMathew_Smith.pdf
- [2] https://cwe.mitre.org/data/definitions/295.html
- [3] https://developer.android.com/training/articles/security-ssl.html
- [4] https://github.com/sfahl/mallodroid
- [5] https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
- [6] https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html
- [7] http://www.cert.org/download/mitm/CERT_Tapioca.ova
- [8] https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html

### カスタム証明書ストアおよび SSL ピンニングのテスト

#### 概要

Certificate pinning allows to hard-code in the client the certificate that is known to be used by the server. This technique is used to reduce the threat of a rogue CA and CA compromise. Pinning the server’s certificate take the CA out of games. Mobile applications that implements certificate pinning only have to connect to a limited numbers of server, so a small list of trusted CA can be hard-coded in the application.

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

Black-box Testing can be performed by launching a MITM attack using your prefered Web Proxy to intercept [1] the traffic exchanged between client (mobile application) and the backend server. If the Proxy is unable to intercept the HTTP requests/responses, the SSL pinning is correctly implemented.

#### 改善方法

The SSL pinning process should be implemented as described on the static analysis section. For further information please check the OWASP certificate pinning guide [2].

#### 参考情報

##### OWASP Mobile Top 10 2014

M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- V5.4 "The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."

##### CWE

- CWE-295 - Improper Certificate Validation - https://cwe.mitre.org/data/definitions/295.html

##### その他

- [1] - Setting Burp Suite as a proxy for Android Devices: https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
- [2] - OWASP Certificate Pinning for Android:  https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android


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

##### OWASP Mobile Top 10 2014

M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- V5.5 "The app doesn't rely on a single insecure communication channel (email or SMS) for critical operations, such as enrollments and account recovery."

##### CWE

- CWE-956 - Software Fault Patterns (SFPs) within the Channel Attack cluster - https://cwe.mitre.org/data/definitions/956.html

##### その他

- [1] The Mobile Application Security Verification Standard - https://github.com/OWASP/owasp-masvs/blob/master/Document/0x03-Using_the_MASVS.md
- [2] Infobip 2FA library - https://2-fa.github.io/libraries/android-library.html
- [3] Google Authenticator for Android - https://github.com/google/google-authenticator-android

