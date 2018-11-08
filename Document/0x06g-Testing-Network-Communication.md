## iOS のネットワーク API

ほぼすべての iOS アプリは一つ以上のリモートサービスのクライアントとして機能します。このネットワーク通信は通常、公衆 Wi-Fi などの信頼できないネットワークで行われるため、従来のネットワークベースの攻撃が潜在的な問題になります。

ほとんどの最新のモバイルアプリは HTTP ベースのウェブサービスのバリエーションを使用しています。これらのプロトコルは十分に文書化されサポートされています。iOS では、`NSURLConnection` クラスが URL リクエストを非同期および同期的にロードするクラスメソッドを提供します。

### App Transport Security

#### 概要

[App Transport Security (ATS)](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys") は [NSURLConnection](https://developer.apple.com/reference/foundation/nsurlconnection "API Reference NSURLConnection"), [NSURLSession](https://developer.apple.com/reference/foundation/urlsession "API Reference NSURLSession"), [CFURL](https://developer.apple.com/reference/corefoundation/cfurl-rd7 "API Reference CFURL") でパブリックホスト名に接続する際にオペレーティングシステムが強制する一連のセキュリティチェックです。iOS SDK 9 および以降のアプリケーションビルドでは ATS がデフォルトで有効になっています。

ATS はパブリックホスト名に接続する際にのみ強制されます。したがって、IP アドレス、不完全なドメイン名、.local の TLD への接続は ATS で保護されません。

以下は [App Transport Security Requirements](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys") の要約リストです。

- HTTP 接続は許可されない。
- X.509 証明書には SHA256 フィンガープリントがあり、少なくとも 2048 ビットの RSA 鍵または 256 ビットの楕円曲線暗号 (ECC) 鍵で署名する必要がある。
- Transport Layer Security (TLS) バージョンは 1.2 もしくは以降が必要であり、Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) 鍵交換および AES-128 もしくは AES-256 対称暗号により Perfect Forward Secrecy (PFS) をサポートする必要がある。

暗号スイートは以下のいずれかが必要である。

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

##### ATS 例外

ATS の制限は Info.plist ファイルの `NSAppTransportSecurity` キーに例外を設定することで無効にできます。これらの例外には以下を適用できます。
- セキュアではない接続 (HTTP) の許可
- 最小 TLS バージョンの引き下げ
- PFS の無効化
- ローカルドメインへの接続の許可

ATS 例外はグローバルまたはドメイン単位で適用できます。アプリケーションは ATS をグローバルに無効化できますが、個々のドメインをオプトインできます。Apple Developer ドキュメントの以下のリストでは `[NSAppTransportSecurity](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/plist/info/NSAppTransportSecurity "API Reference NSAppTransportSecurity")` Dictionary の構造を示しています。

```
NSAppTransportSecurity : Dictionary {
    NSAllowsArbitraryLoads : Boolean
    NSAllowsArbitraryLoadsForMedia : Boolean
    NSAllowsArbitraryLoadsInWebContent : Boolean
    NSAllowsLocalNetworking : Boolean
    NSExceptionDomains : Dictionary {
        <domain-name-string> : Dictionary {
            NSIncludesSubdomains : Boolean
            NSExceptionAllowsInsecureHTTPLoads : Boolean
            NSExceptionMinimumTLSVersion : String
            NSExceptionRequiresForwardSecrecy : Boolean   // Default value is YES
            NSRequiresCertificateTransparency : Boolean
        }
    }
}
```

情報源: [Apple Developer Documentation](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys").

以下の表はグローバル ATS 例外をまとめたものです。これらの例外の詳細については、[公式の Apple Developer ドキュメントの Table 2](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW34 "App Transport Security dictionary primary keys") を参照してください。

| キー | 説明 |
| -----| -----|
| `NSAllowsArbitraryLoads` | `NSExceptionDomains` の下に指定された個々のドメインを除いてグローバルに ATS 制限を無効化する |
| `NSAllowsArbitraryLoadsInWebContent` | WebView から作成されたすべての接続に対して ATS 制限を無効化する |
| `NSAllowsLocalNetworking` | 非修飾ドメイン名と .local ドメインへの接続を許可する |
| `NSAllowsArbitraryLoadsForMedia` | AV Foundation フレームワークからロードされたメディアのすべての ATS 制限を無効化する |

以下の表はドメインごとの ATS 例外をまとめたものです。これらの例外の詳細については、[公式の Apple Developer ドキュメントの Table 3](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW44 "App Transport Security dictionary primary keys") を参照してください。

| キー | 説明 |
| -----| -----|
| `NSIncludesSubdomains` | ATS 例外を名前付きドメインのサブドメインに適用すべきかどうかを示す |
| `NSExceptionAllowsInsecureHTTPLoads` | 名前付きドメインへの HTTP 接続を許可するが、TLS 要件には影響しない |
| `NSExceptionMinimumTLSVersion` | TLS バージョン 1.2 未満のサーバーへの接続を許可する |
| `NSExceptionRequiresForwardSecrecy` | Perfect Forward Secrecy (PFS) を無効化する |

2017年1月1日から Apple App Store レビューでは以下の ATS 例外の一つが定義されている場合に正当な理由を要求します。

- `NSAllowsArbitraryLoads`
- `NSAllowsArbitraryLoadsForMedia`
- `NSAllowsArbitraryLoadsInWebContent`
- `NSExceptionAllowsInsecureHTTPLoads`
- `NSExceptionMinimumTLSVersion`

しかし、この不同意は延期されました。後に Apple は [「準備期間を増やすためにこの期限を延長し、新しい締め切りが確定したときに別のアップデートを提供する」](https://developer.apple.com/news/?id=12212016b "Apple Developer Portal Announcement - Supporting App Transport Security") と述べています。

#### ATS 設定の解析

ソースコードが利用可能である場合、アプリケーションバンドルディレクトリの `Info.plist` ファイルを開き、アプリケーション開発者が設定した例外を探します。このファイルはアプリケーションコンテキストを考慮して調べる必要があります。

以下のリストは ATS 制限をグローバルに無効化するように設定された例外の例です。

```xml
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
	</dict>
```

ソースコードが利用可能ではない場合、`Info.plist` ファイルは脱獄済みデバイスから取得するか、アプリケーション IPA ファイルから抽出する必要があります。

IPA ファイルは ZIP アーカイブであるため、任意の zip ユーティリティを使用して抽出できます。

```shell
$ unzip app-name.ipa
```

`Info.plist` ファイルは抽出した `Payload/BundleName.app/` ディレクトリにあります。これはバイナリエンコードされたファイルであり、解析には人が読める形式に変換する必要があります。

[`plutil`](https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/plutil.1.html "OS X Man Pages - Plutil") はこの目的のために設計されたツールです。Mac OS 10.2 およびそれ以降のバージョンでネイティブに提供されます。

以下のコマンドは Info.plist ファイルを XML 形式に変換する方法を示しています。

```shell
$ plutil -convert xml1 Info.plist
```

このファイルを人が読める形式に変換すると、例外を解析できます。アプリケーションには通常の機能を許可するために ATS 例外が定義されている場合があります。例えば、Firefox iOS アプリケーションでは ATS がグローバルに無効化されています。さもないとアプリケーションがすべての ATS 要件を満たしていない任意の HTTP ウェブサイトに接続できなくなるため、この例外は許容されます。

一般に以下のように要約できます。

- ATS は Apple のベストプラクティスに従って設定し、特定の状況下でのみ無効化する必要があります。
- アプリケーションはアプリケーション所有者が管理する定義された数のドメインに接続する場合、ATS 要件をサポートするようにサーバーを構成し、アプリ内の ATS 要件をオプトインします。以下の例では、`example.com` はアプリケーション所有者が所有し、そのドメインに対して ATS が有効になっています。

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

- (アプリ所有者の管理下にない) サードパーティのドメインとの接続が行われる場合、サードパーティのドメインでサポートされていない ATS 設定と、それらが無効化できるかどうかを評価する必要があります。
- アプリケーションが WebView でサードパーティのウェブサイトを開く場合、iOS 10 以降では NSAllowsArbitraryLoadsInWebContent を使用して、WebView でロードされるコンテンツの ATS 制限を無効化できます。


### カスタム証明書ストアと証明書ピンニングのテスト

#### 概要

証明書ピンニングは、信頼できる認証局により署名された任意の証明書を受け入れる代わりに、モバイルアプリを特定の X509 証明書に関連付けるプロセスです。サーバー証明書や公開鍵を格納 (「ピン留め」) するモバイルアプリは既知のサーバーへの接続のみを確立します。外部認証局の信頼を除くことで、攻撃面が縮小されます (結局のところ、認証局が侵害されたり、偽者に証明書を発行するよう騙されたりという既知の事例が多くあります) 。

証明書は開発中またはアプリが最初にバックエンドに接続するときにピン留めできます。
その場合、証明書は初回に見たときにホストに関連付けられるか「ピン留め」されます。この二つ目のバリエーションはあまりセキュアではなくなります。攻撃者は最初の接続を傍受して自身の証明書を注入する可能性があるためです。

#### 静的解析

サーバー証明書がピン留めされていることを確認します。ピンニングは複数の方法で実装できます。

1. サーバーの証明書をアプリケーションバンドルに含め、各接続で検証を実行します。これにはサーバーの証明書が更新されるたびに更新メカニズムが必要です。
2. 証明書発行者を例えば一つのエンティティに制限し、中間 CA の公開鍵をアプリケーションにバンドルします。このようにして攻撃面を制限し、有効な証明書を取得します。
3. 独自の PKI を所有および管理します。アプリケーションには中間 CA の公開鍵が含まれます。これにより、例えば期限切れのために、サーバー上の証明書を変更するごとにアプリケーションを更新することがなくなります。独自の CA を使用すると証明書が自己署名されることに注意します。

以下に示すコードはサーバーによって提供された証明書がアプリに格納されている証明書と一致しているかどうかを確認する方法を示しています。以下のメソッドは接続認証を実装して、接続が認証チャレンジの要求を送信することをデリゲートに通知します。

デリゲートは `connection:canAuthenticateAgainstProtectionSpace:` と `connection: forAuthenticationChallenge` を実装する必要があります。`connection: forAuthenticationChallenge` では、デリゲートは `SecTrustEvaluate` をコールして一般的な X509 チェックを実行する必要があります。以下のスニペットは証明書のチェックを実装しています。

```objc
(void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
  SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
  NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
  NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"MyLocalCertificate" ofType:@"cer"];
  NSData *localCertData = [NSData dataWithContentsOfFile:cerPath];
  The control below can verify if the certificate received by the server is matching the one pinned in the client.
  if ([remoteCertificateData isEqualToData:localCertData]) {
  NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
  [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
}
else {
  [[challenge sender] cancelAuthenticationChallenge:challenge];
}
```

[TrustKit](https://github.com/datatheorem/TrustKit "TrustKit") など SSL ピンニングを実装するための API を提供するライブラリがあります。TrustKit は Swift と Objective-C アプリの両方をサポートしています。

#### 動的解析

##### サーバー証明書の妥当性確認

私たちのテストアプローチは SSL ハンドシェイクネゴシエーションのセキュリティを少しずつ緩めて、どのセキュリティメカニズムが有効であるかを確認することです。

1. Burp をプロキシとして設定した後、トラストストア (Settings -> General -> Profiles) に証明書が追加されていないこと、および SSL キルスイッチなどのツールが無効であることを確認します。アプリケーションを起動して、Burp にトラフィックが表示されるかどうかを確認します。問題がある場合は 'Alerts' タブに報告されます。トラフィックが見える場合、証明書検証がまったく実行されていないことを意味します。そうではなく、トラフィックを見ることができず、SSL ハンドシェイクの失敗に関する情報がある場合には、次の項目に従います。
2. 次に、[PortSwigger ユーザードキュメント](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp's CA Certificate in an iOS Device") で説明されているように、Burp 証明書をインストールします。ハンドシェイクが成功して Burp でトラフィックを見ることができる場合、デバイスのトラストストアに対して証明書が検証されているが、ピンニングが実行されていないことを意味します。
3. 前のステップでの指示を実行してもトラフィックが burp 経由でプロキシされない場合、証明書は実際にピン留めされ、すべてのセキュリティ対策が実行されていることを意味します。但し、アプリケーションをテストするには依然としてピンニングをバイパスする必要があります。この詳細については「iOS アプリのテスト環境構築」を参照してください。

##### クライアント証明書の妥当性確認

アプリケーションによっては双方向 SSL ハンドシェイクを使用するものがあります。つまり、アプリケーションがサーバーの証明書を検証し、サーバーがクライアントの証明書を検証します。Burp 'Alerts' タブにクライアントが接続のネゴシエーションに失敗したことを示すエラーがあるかどうかを確認します。

注目すべきことがいくつかあります。

1. クライアント証明書には鍵交換で使用される秘密鍵 (private key) が含まれています。
2. 一般的にこの証明書は使用 (復号) するためにパスワードも必要です。
3. 証明書はバイナリ自体、データディレクトリ、もしくはキーチェーンに格納できます。

双方向ハンドシェイクを行う最も一般的で不適切な方法は、アプリケーションバンドル内にクライアント証明書を格納し、パスワードをハードコードすることです。すべてのクライアントが同じ証明書を共有するため、これはほとんどセキュリティをもたらさないことが明らかです。

証明書 (および場合によってはパスワード) を格納する第二の方法はキーチェーンを使用するものです。最初のログイン時に、アプリケーションは個人証明書をダウンロードし、キーチェーンにセキュアに格納する必要があります。

アプリケーションにはハードコードされ最初のログイン時に使用される一つの証明書を持ち、それから個人証明書がダウンロードされることがあります。この場合、サーバーに接続するために「汎用」証明書を使用できるかどうかを確認します。

(Cycript や Frida を使用して) アプリケーションから証明書を抽出し、Burp のクライアント証明書としてそれを追加すると、トラフィックを傍受することが可能となります。


#### 参考情報

##### OWASP Mobile Top 10 2016

- M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication (日本語訳) - https://coky-t.github.io/owasp-mobile-top10-2016-ja/Mobile_Top_10_2016-M3-Insecure_Communication.html

##### OWASP MASVS

- V5.1: "データはネットワーク上でTLSを使用して暗号化されている。セキュアチャネルがアプリ全体を通して一貫して使用されている。"
- V5.2: "TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨された標準をサポートしていない場合には可能な限り近い状態である。"
- V5.3: "セキュアチャネルが確立されたときに、アプリはリモートエンドポイントのX.509証明書を確認している。信頼されたCAにより署名された証明書のみが受け入れられている。"
- V5.4: "アプリは独自の証明書ストアを使用するか、エンドポイント証明書もしくは公開鍵を固定化しており、信頼できるCAにより署名された場合でも、別の証明書や鍵を提供するエンドポイントとの接続を確立していない。"

##### CWE

- CWE-319 - Cleartext Transmission of Sensitive Information
- CWE-326 - Inadequate Encryption Strength
- CWE-295 - Improper Certificate Validation
