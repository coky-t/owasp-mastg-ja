## ネットワーク通信のテスト

ネットワークに接続されたすべてのモバイルアプリは Hypertext Transfer Protocol (HTTP) または HTTP over Transport Layer Security (TLS), HTTPS を使用してリモートエンドポイントとの間でデータを送受信します。その結果、ネットワークベースの攻撃 (パケットスニッフィングや中間者攻撃など) が問題になります。この章ではモバイルアプリとエンドポイント間のネットワーク通信に関する潜在的な脆弱性、テスト技法、ベストプラクティスについて説明します。

### HTTP(S) トラフィックの傍受

多くの場合、HTTP(S) トラフィックがホストマシン上で実行されている *傍受プロキシ* 経由でリダイレクトされるように、モバイルデバイス上にシステムプロキシを設定することが最も実用的です。モバイルアプリクライアントとバックエンドの間のリクエストを監視することにより、利用可能なサーバーサイド API を簡単にマップし、通信プロトコルの情報を得ることができます。さらに、サーバー側のバグをテストするためにリクエストを再生および操作できます。

フリーおよび商用のプロキシツールがいくつかあります。最も人気のあるものは以下のとおりです。

- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
- [Charles Proxy](https://www.charlesproxy.com)

傍受プロキシを使用するには、それを PC/MAC 上で実行し、HTTP(S) リクエストをプロキシにルーティングするようモバイルアプリを設定する必要があります。ほとんどの場合、モバイルデバイスのネットワーク設定でシステム全体のプロキシを設定するだけで十分です。アプリが標準の HTTP API や `okhttp` などの一般的なライブラリを使用する場合、自動的にシステム設定を使用します。

プロキシを使用すると SSL 証明書の検証が中断され、アプリは通常 TLS 接続を開始できません。この問題を回避するには、プロキシの CA 証明書をデバイスにインストールします。OS 固有の「テスト環境構築」の章でこれを行う方法について説明します。

![Intercepting HTTP requests with BURP Suite Pro](Images/Chapters/0x04f/BURP.jpg)

### ネットワーク層でのトラフィックの傍受

傍受プロキシを使用することによる動的解析は、標準ライブラリがアプリで使用され、すべての通信が HTTP 経由で行われる場合には簡単です。しかしこれが動作しないいくつかのケースがあります。

- システムプロキシ設定を無視する [Xamarin](https://www.xamarin.com/platform "Xamarin") などのモバイルアプリケーション開発プラットフォームが使用されている場合。
- モバイルアプリケーションがシステムプロキシが使用されているかどうかを確認し、プロキシを介してリクエストを送信することを拒否する場合。
- Android の GCM/FCM などのプッシュ通信を傍受したい場合。
- XMPP や他の非 HTTP プロトコルが使用されている場合。

このような場合は、次に何をすべきかを決めるために、まずネットワークトラフィックを監視および解析する必要があります。幸いにも、ネットワーク通信をリダイレクトおよび傍受するための選択肢がいくつかあります。

- トラフィックをホストマシンにルーティングします。Mac/PC をネットワークゲートウェイとして設定します。例えば、オペレーティングシステムに内蔵のインターネット共有機能を使用します。それから、[Wireshark](https://www.wireshark.org) を使用して、モバイルデバイスからインターネットに送られる任意のトラフィックを傍受できます。

- [ettercap](https://ettercap.github.io/ettercap/ "Ettercap") を使用して、モバイルデバイスからホストマシンへネットワークトラフィックをリダイレクトします (下記参照) 。

- ルート化デバイスでは、フックやコードインジェクションを使用して、ネットワーク関連の API コール (HTTP リクエストなど) を傍受したり、これらのコールの引数をダンプしたり操作することも可能です。これにより実際のネットワークデータを検査する必要がなくなります。これらの技法については「リバースエンジニアリングと改竄」の章で詳しく説明します。

- iOS では、代わりに "Remote Virtual Interface" を作成できます。「iOS アプリのテスト環境構築」の章でこの手法を説明します。

#### 中間者攻撃のシミュレーション

[Ettercap](https://ettercap.github.io/ettercap/ "Ettercap") はネットワークペネトレーションテストの中で使用して、中間者攻撃をシミュレートします。これは [ARP ポイズニングやスプーフィング](https://en.wikipedia.org/wiki/ARP_spoofing "ARP poisoning/spoofing") をターゲットマシンに実行することで実現します。このような攻撃が成功すると、二つのマシン間のすべてのパケットは第三のマシンにリダイレクトされます。これは中間者の役割を果たし、解析のためにトラフィックを傍受できます。

モバイルアプリの完全な動的解析には、すべてのネットワークトラフィックを傍受する必要があります。メッセージを傍受できるようにするには、準備としていくつかの手順を検討する必要があります。

**Ettercap のインストール**

Ettercap はすべての主要な Linux および Unix オペレーティングシステムで利用可能であり、それぞれのパッケージインストールメカニズムの一部である必要があります。中間者としての役割を果たすマシンにそれをインストールする必要があります。macOS では brew を使用してインストールできます。

```shell
$ brew install ettercap
```

Ettercap は Debian ベースの linux ディストリビューションで `apt-get` を使ってインストールすることもできます。

```shell
$ sudo apt-get install zlib1g zlib1g-dev
$ sudo apt-get install build-essential
$ sudo apt-get install ettercap
```

**ネットワーク解析ツール**

マシンにリダイレクトされるネットワークトラフィックを監視および解析できるツールをインストールします。二つの最も一般的なネットワーク監視 (またはキャプチャ) ツールは以下のとおりです。

- [Wireshark](https://www.wireshark.org "Wireshark") (CLI pendant: [tshark](https://www.wireshark.org/docs/man-pages/tshark.html "TShark")) 
- [tcpdump](https://www.tcpdump.org/tcpdump_man.html "tcpdump")

Wireshark は GUI を提供しており、コマンドラインに慣れていなくても簡単です。コマンドラインツールを探している場合には TShark または tcpdump のいずれかを使用する必要があります。これらのツールはすべての主要な Linux および Unix オペレーティングシステムで利用可能であり、それぞれのパッケージインストールメカニズムの一部である必要があります。

**ネットワークのセットアップ**

中間者のポジションを得るには、モバイルフォンおよびそれと通信するゲートウェイと同じワイヤレスネットワークにマシンがある必要があります。これが完了すると以下の情報が必要です。

- モバイルフォンの IP アドレス
- ゲートウェイの IP アドレス

#### Ettercap による ARP ポイズニング

以下のコマンドで ettercap を開始し、最初の IP アドレスをワイヤレスネットワークのネットワークゲートウェイに置き換え、二つ目のものをモバイルデバイスのものと置き換えます。

```shell
$ sudo ettercap -T -i en0 -M arp:remote /192.168.0.1// /192.168.0.105//
```

モバイルフォンでブラウザを起動して example.com に移動すると、以下のような出力が表示されます。

```shell
ettercap 0.8.2 copyright 2001-2015 Ettercap Development Team

Listening on:
   en0 -> AC:BC:32:81:45:05
	  192.168.0.105/255.255.255.0
	  fe80::c2a:e80c:5108:f4d3/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Privileges dropped to EUID 65534 EGID 65534...

  33 plugins
  42 protocol dissectors
  57 ports monitored
20388 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services

Scanning for merged targets (2 hosts)...

* |=========================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : 192.168.0.1 F8:E9:03:C7:D5:10

 GROUP 2 : 192.168.0.102 20:82:C0:DE:8F:09
Starting Unified sniffing...

Text only Interface activated...
Hit 'h' for inline help

Sun Jul  9 22:23:05 2017 [855399]
  :::0 --> ff02::1:ff11:998b:0 | SFR (0)


Sun Jul  9 22:23:10 2017 [736653]
TCP  172.217.26.78:443 --> 192.168.0.102:34127 | R (0)

Sun Jul  9 22:23:10 2017 [737483]
TCP  74.125.68.95:443 --> 192.168.0.102:35354 | R (0)
```

それで、モバイルフォンで送受信される完全なネットワークトラフィックを確認できるようになります。これには DNS, DHCP およびその他の形式の通信も含まれるため、非常に「ノイズが多い」かもしれません。したがって、関連するトラフィックだけに集中するために、[Wireshark の DisplayFilter](https://wiki.wireshark.org/DisplayFilters "DisplayFilters") の使い方や [tcpdump でフィルタする方法](https://danielmiessler.com/study/tcpdump/#gs.OVQjKbk "A tcpdump Tutorial and Primer with Examples") を知る必要があります。

> 中間者攻撃は ARP スプーフィングを通じて OSI レイヤ 2 上で攻撃が実行されるため、あらゆるデバイスやオペレーティングシステムに対して機能します。あなたが MITM である場合、通過するデータは TLS を使用して暗号化されている可能性があるため、平文データを見ることができないかもしれません。しかし、それは関与するホスト、使用されるプロトコルおよびアプリが通信しているポートに関する貴重な情報をあなたに提供します。

例として、次のセクションで Xamarin アプリからのすべてのリクエストを傍受プロキシにリダイレクトします。

#### SPAN ポート / ポートフォワーディング

ettercap による MITM 攻撃の代わりに、Wifi アクセスポイント (AP) やルーターを代わりに使うこともできます。設定には AP の設定にアクセスする必要があります。これはやりとりする前に明確にする必要があります。再構成が可能な場合は、まず AP が以下のいずれかをサポートしているかどうかを確認する必要があります。

- ポートフォワーディング
- SPAN またはミラーポートがある

どのシナリオでも、AP はマシン IP を指すように設定する必要があります。それから Wireshark などのツールを使用して、さらなる調査のためにトラフィックを監視および記録します。

#### 実行時計装によるプロキシの設定

ルート化または脱獄済みデバイスでは、ランタイムフックを使用して、新しいプロキシを設定したりネットワークトラフィックをリダイレクトすることが可能です。これは [Inspeckage](https://github.com/ac-pm/Inspeckage) などのフックツールや [frida](https://www.frida.re) および [cycript](http://www.cycript.org) などのコードインジェクションフレームワークで実現できます。実行時計装についての詳細はこのガイドの「リバースエンジニアリングと改竄」の章で参照できます。

#### 例: Xamarin の扱い

Xamarin は Visual Studio と C# をプログラミング言語として使用して [ネイティブ Android](https://developer.xamarin.com/guides/android/getting_started/ "Getting Started with Android") および [iOS アプリ](https://developer.xamarin.com/guides/ios/ "Getting Started with iOS") を作成できるモバイルアプリケーション開発プラットフォームです。

Xamarin アプリをテストするときに WiFi 設定でシステムプロキシを設定しようとすると、傍受プロキシで HTTP リクエストを見ることができなくなります。Xamarin により作成されたアプリは電話のローカルプロキシ設定を使用しないためです。これを解決する方法は二つあります。

- [アプリにデフォルトプロキシ](https://developer.xamarin.com/api/type/System.Net.WebProxy/ "System.Net.WebProxy Class") を追加します。`OnCreate()` または `Main()` に以下のコードを追加してアプリを再作成します。

```csharp
WebRequest.DefaultWebProxy = new WebProxy("192.168.11.1", 8080);
```

- ettercap を使用して中間者ポジション (MITM) を取得します。MITM 攻撃のセットアップ方法については上記のセクションを参照してください。MITM であれば、ポート 443 を localhost 上で動作する傍受プロキシにリダイレクトするだけです。これは macOS で `rdr` コマンドを使うことにより行えます。

```shell
$ echo "
rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

傍受プロキシは上記のポートフォワーディングルールで指定されたポート 8080 をリッスンする必要があります。

**CA 証明書**

まだ行われていなければ、HTTPS リクエストの傍受を許可するモバイルデバイスに CA 証明書をインストールします。

- [Android フォンに傍受プロキシの CA 証明書をインストールする](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp's CA Certificate in an Android Device").
- [iOS フォンに傍受プロキシの CA 証明書をインストールする](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp")

**トラフィックの傍受**

アプリの使用を開始し、その機能を動かします。傍受プロキシに HTTP メッセージが表示されるはずです。

> ettercap を使用する場合は、Proxy タブ / Options / Edit Interface で "Support invisible proxying" を有効にする必要があります

### ネットワーク上のデータ暗号化の検証

#### 概要

コアとなるモバイルアプリの機能のひとつはインターネットなどの信頼できないネットワーク上でデータを送受信することです。データが転送中に正しく保護されない場合、攻撃者はネットワークインフラストラクチャの任意の部分 (Wi-Fi アクセスポイントなど) にアクセスできる攻撃者は、傍受、読み取り、改変の可能性があります。これが平文のネットワークプロトコルがほとんど推奨されない理由です。

大部分のアプリはバックエンドとの通信に HTTP に依存しています。HTTPS は暗号化された接続で HTTP をラップします (略語の HTTPS はもともと HTTP over Secure Socket Layer (SSL) と呼ばれていました。SSL は TLS の前身で廃止予定です) 。TLS はバックエンドサービスの認証を可能にし、ネットワークデータの機密性と完全性を保証します。

##### 推奨される TLS 設定

サーバー側で適切な TLS 設定を確保することも重要です。SSL は廃止予定であり、もはや使用すべきではありません。TLS v1.2 および v1.3 はセキュアであると考えられますが、多くのサービスではいまだに TLS v1.0 および v1.1 が古いクライアントとの互換性のために許可されています。

クライアントとサーバーの両方が同じ組織により制御され、互いに通信するためだけに使用される場合、[設定を堅牢にすること](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices") によりセキュリティを向上できます。

モバイルアプリケーションが特定のサーバーに接続している場合、そのネットワークスタックを調整して、サーバーの構成に対して可能な限り高いセキュリティレベルを確保できます。基盤となるオペレーティングシステムのサポートがない場合、モバイルアプリケーションがより脆弱な構成を使用するように強制する可能性があります。

例えば、一般的な Android ネットワークライブラリ okhttp は以下の暗号スイートの推奨セットを使用しますが、これらは Android バージョン 7.0 および以降でのみ利用可能です。

- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

以前のバージョンの Android をサポートするためには、`TLS_RSA_WITH_3DES_EDE_CBC_SHA` など、あまりセキュアではないと考えられているいくつかの暗号を追加します。

同様に、iOS ATS (App Transport Security) の設定には以下の暗号のいずれかが必要です。

- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`
- `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`

#### 静的解析

ソースコード内のすべての API やウェブサービスリクエストを特定し、プレーンの HTTP URL が要求されていないことを確認します。機密情報は [HttpsURLConnection](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html "HttpsURLConnection") や [SSLSocket](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html "SSLSocket") (TLS を使用したソケットレベル通信用) を使用することによりセキュアなチャネルを介して送信されていることを確認します。

`SSLSocket` はホスト名を検証 **しない** ことに注意します。ホスト名を検証するには `getDefaultHostnameVerifier` を使用します。Android 開発者ドキュメントには [コード例](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket "Warnings About Using SSLSocket Directly") があります。

ベストプラクティスに従ってサーバーが構成されていることを確認します。[OWASP Transport Layer Protection チートシート](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet "Transport Layer Protection Cheat Sheet") および [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices") も参照してください。

静的解析には HTTPS 接続が終端するウェブサーバーやリバースプロキシの構成ファイルが必要です。[OWASP Transport Layer Protection チートシート](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet "Transport Layer Protection Cheat Sheet") および [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices") も参照してください。

#### 動的解析

テストされるアプリの着信および発信するネットワークトラフィックを傍受し、このトラフィックが暗号化されていることを確認します。以下のいずれかの方法でネットワークトラフィックを傍受できます。

- [OWASP ZAP](https://security.secure.force.com/security/tools/webapp/zapandroidsetup "OWASP ZAP") や [Burp Suite Professional](https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp "Configuring an Android device to work with Burp") などの傍受プロキシですべての HTTP および Websocket トラフィックをキャプチャし、すべてにリクエストが HTTP ではなく HTTPS 経由で行われていることを確認します。

Burp や OWASP ZAP などの傍受プロキシは HTTP トラフィックのみを表示します。しかし、[Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension) や [mitm-relay](https://github.com/jrmdev/mitm_relay) などの Burp プラグインを使用すると、XMPP や他のプロトコルによる通信をデコードおよび視覚化できます。

> 一部のアプリケーションでは証明書ピンニングのために Burp や ZAP などのプロキシでは動作しない可能性があります。このようなシナリオでは、「カスタム証明書ストアおよび SSL ピンニングのテスト」を参照してください。Vproxy などのツールを使用すると、すべての HTTP(S) トラフィックをマシンにリダイレクトし、暗号化されていないリクエストに対して盗聴や調査を行うことができます。


### クリティカルな操作がセキュアな通信チャネルを使用することの確認

#### 概要

銀行業務アプリなどの機密性の高いアプリケーションでは、[OWASP MASVS](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x03-Using_the_MASVS.md "The Mobile Application Security Verification Standard") では「多層防御」検証レベルを導入しています。そのようなアプリケーションのクリティカルな操作 (ユーザー登録やアカウント回復など) は攻撃者にとって最も魅力的なターゲットです。ユーザー操作を確認するための追加のチャネル (SMS や電子メールなど) のような高度なセキュリティコントロールを実装する必要があります。

#### 静的解析

コードをレビューして、クリティカルな操作を参照する部分を特定します。そのような操作に追加のチャネルを使用していることを確認します。追加の検証チャネルの例には以下があります。

- トークン (RSA トークン, yubikey など)
- プッシュ通知 (Google Prompt など)
- SMS
- 電子メール
- 訪問またはスキャンした他のウェブサイトからのデータ
- 物理的な文字や物理的なエントリポイントからのデータ (銀行で書類に署名した後にのみ受け取るデータなど)

#### 動的解析

テストされるアプリケーションのクリティカルな操作 (ユーザー登録、アカウント回復、送金など) をすべて特定します。それぞれのクリティカルな操作に少なくとも一つの追加チャネル (SMS、電子メール、トークンなど)  が必要であることを確認します。関数を直接呼び出すことでこれらのチャネルの使用をバイパスするかどうかを確認します。

#### 改善方法

クリティカルな操作ではユーザーの操作を確認するために少なくとも一つの追加チャネルの使用が必要であることを確認します。クリティカルな操作を実行する際にこれらのチャネルがバイパスできてはいけません。ユーザーの身元を検証するための追加要素を実装する場合には、[Infobip 2FA ライブラリ](https://2-fa.github.io/libraries/android-library.html "Infobip 2FA library") や [Google Authenticator](https://github.com/google/google-authenticator-android "Google Authenticator for Android") を介したワンタイムパスコード (OTP) を検討します。

### 参考情報

#### OWASP Mobile Top 10 2016
- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

#### OWASP MASVS
- V5.1: "データはネットワーク上でTLSを使用して暗号化されている。セキュアチャネルがアプリ全体を通して一貫して使用されている。"
- V5.5: "アプリは登録やアカウントリカバリーなどの重要な操作において（電子メールやSMSなどの）単方向のセキュアでない通信チャネルに依存していない。"

#### CWE
- CWE-308 - Use of Single-factor Authentication
- CWE-319 - Cleartext Transmission of Sensitive Information

#### ツール

- Tcpdump - https://www.androidtcpdump.com/
- Wireshark - https://www.wireshark.org/
- OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
- Burp Suite - https://portswigger.net/burp/
- Vproxy - https://github.com/B4rD4k/Vproxy
