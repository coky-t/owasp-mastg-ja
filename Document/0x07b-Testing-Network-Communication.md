## ネットワーク通信のテスト

以下の章ではテクニカルテストケースでの MASVS のネットワーク通信要件について説明します。この章に記載されるテストケースはサーバー側に焦点を当てているため、iOS や Android の特定の実装に依存しません。

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

### 重要な操作が安全な通信チャネルを使用することの検証

#### 概要

銀行業務アプリなどの機密性の高いアプリケーションでは、OWASP MASVS は「多層防御」検証レベル [1] を導入しています。そのような機密性の高いアプリケーションの(ユーザー登録やアカウント回復などの)重要な操作は攻撃者の視点から最も魅力的なターゲットです。ユーザーの行動を確認するために(SMSや電子メールなどの)追加のチャネルを加えるなどの、このような操作のために高度なセキュリティコントロールを実装する必要が生じます。追加のチャネルは多くの攻撃シナリオ(主にフィッシング)のリスクを軽減することができますが、セキュリティ上の障害が発生していない場合に限ります。

#### 静的解析

コードをレビューして重要な操作を参照するコードの部分を特定します。そのような操作を実行するために追加のチャネルを使用するかどうかを確認します。追加の検証チャネルの例として以下があります。

* トークン (RSAトークン, yubikey など)
* プッシュ通知 (Google Prompt など)
* SMS
* 電子メール
* 訪問/スキャンした他のウェブサイトからのデータ
* 物理的な文字や物理的なエントリポイントからのデータ (銀行のオフィスで書類に署名した後にのみ受け取るデータなど)

#### 動的解析

テストされるアプリケーションで実装されているすべての重要な操作(ユーザー登録、アカウント回復、送金など)を特定します。重要な操作のそれぞれに少なくとも一つの追加のチャネル(SMS、電子メール、トークンなど)が必要であることを確認します。そのようなチャネルの使用を回避できるかどうか検証します(他のチャネルを使用せずに SMS 確認をオフにするなど)。

#### 改善方法

重要な操作ではユーザーの操作を確認するために少なくとも一つの追加のチャネルが必要であることを確認します。重要な操作を実行するためにそれぞれのチャネルがバイパスできてはいけません。ユーザーの身元を検証するための追加要素を実装する場合には、Infobip 2FA ライブラリ [2] や Google Authenticator [3] を介したワンタイムパスワードの使用を検討します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
* V5.5 "アプリは登録やアカウントリカバリーなどの重要な操作において（電子メールやSMSなどの）一つの安全でない通信チャネルに依存していない。"

##### CWE
* CWE-956 - Software Fault Patterns (SFPs) within the Channel Attack cluster

##### その他
* [1] The Mobile Application Security Verification Standard - https://github.com/OWASP/owasp-masvs/blob/master/Document/0x03-Using_the_MASVS.md
* [2] Infobip 2FA library - https://2-fa.github.io/libraries/android-library.html
* [3] Google Authenticator for Android - https://github.com/google/google-authenticator-android
