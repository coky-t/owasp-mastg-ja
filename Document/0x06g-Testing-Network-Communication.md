# iOS のネットワーク API

ほぼすべての iOS アプリは一つ以上のリモートサービスのクライアントとして機能します。このネットワーク通信は通常、公衆 Wi-Fi などの信頼できないネットワークで行われるため、従来のネットワークベースの攻撃が潜在的な問題になります。

最新のモバイルアプリの多くは HTTP ベースのウェブサービスに類するものを使用しています。これらのプロトコルは十分に文書化されサポートされているためです。
iOS 12.0 以降 [Network フレームワーク](https://developer.apple.com/documentation/network "API Reference Network") および [`URLSession`](https://developer.apple.com/documentation/foundation/urlsession "API Reference URLSession") クラスは非同期的および同期的にネットワークおよび URL リクエストをロードするメソッドを提供しています。古い iOS バージョンでは [Sockets API](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/UsingSocketsandSocketStreams.html "Using Sockets and Socket Streams") を利用できます。

## Network Framework

2018 年の [Apple Worldwide Developers Conference (WWDC)](https://developer.apple.com/videos/play/wwdc2018/715 "Introducing Network.framework: A modern alternative to Sockets") で紹介された Network フレームワークは Sockets API に代わるものです。この低レベルのネットワークフレームワークは動的なネットワーキング、セキュリティ、パフォーマンスサポートが組み込まれた、データを送受信するクラスを提供します。

引数 `using: .tls` が使用されている場合、Network フレームワークでは TLS 1.3 がデフォルトで有効になっています。これは従来の [Secure Transport](https://developer.apple.com/documentation/security/secure_transport "API Reference Secure Transport") フレームワークよりも推奨されるオプションです。

## URLSession

`URLSession` は Network フレームワーク上に構築され、同じトランスポートサービスを利用します。エンドポイントが HTTPS の場合、このクラスもデフォルトで TLS 1.3 を使用します。

`URLSession` は HTTP および HTTPS 接続で Network フレームワークを直接利用する代わりに使用すべきです。このクラスはネイティブに両方の URL スキームをサポートしており、そのような接続に最適化されています。定型コードが少なく済むため、エラーを生みにくくなり、デフォルトでセキュアな接続が確保されます。Network フレームワークは低レベルネットワーキングや高度なネットワーキング要件がある場合にのみ使用すべきです。

Apple の公式ドキュメントには Network フレームワークを使用して [netcat を実装する](https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework "Implementing netcat with Network Framework") 例と、 `URLSession` を使用して [ウェブサイトデータをメモリにフェッチする](https://developer.apple.com/documentation/foundation/url_loading_system/fetching_website_data_into_memory "Fetching Website Data into Memory") 例があります。

## App Transport Security (MSTG-NETWORK-2)

### 概要

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

#### ATS 例外

ATS の制限は Info.plist ファイルの `NSAppTransportSecurity` キーに例外を設定することで無効にできます。これらの例外には以下を適用できます。

- セキュアではない接続 (HTTP) の許可
- 最小 TLS バージョンの引き下げ
- PFS の無効化
- ローカルドメインへの接続の許可

ATS 例外はグローバルまたはドメイン単位で適用できます。アプリケーションは ATS をグローバルに無効化できますが、個々のドメインをオプトインできます。Apple Developer ドキュメントの以下のリストでは [`NSAppTransportSecurity`](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/plist/info/NSAppTransportSecurity "API Reference NSAppTransportSecurity") Dictionary の構造を示しています。

```objectivec
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
| --------------| ------------|
| `NSAllowsArbitraryLoads` | `NSExceptionDomains` の下に指定された個々のドメインを除いてグローバルに ATS 制限を無効化する |
| `NSAllowsArbitraryLoadsInWebContent` | WebView から作成されたすべての接続に対して ATS 制限を無効化する |
| `NSAllowsLocalNetworking` | 非修飾ドメイン名と .local ドメインへの接続を許可する |
| `NSAllowsArbitraryLoadsForMedia` | AV Foundation フレームワークからロードされたメディアのすべての ATS 制限を無効化する |

以下の表はドメインごとの ATS 例外をまとめたものです。これらの例外の詳細については、[公式の Apple Developer ドキュメントの Table 3](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW44 "App Transport Security dictionary primary keys") を参照してください。

| キー | 説明 |
| --------------| ------------|
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

### ATS 設定の解析

ソースコードが利用可能である場合、アプリケーションバンドルディレクトリの `Info.plist` ファイルを開き、アプリケーション開発者が設定した例外を探します。このファイルはアプリケーションコンテキストを考慮して調べる必要があります。

以下のリストは ATS 制限をグローバルに無効化するように設定された例外の例です。

```xml
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
```

ソースコードが利用可能ではない場合、`Info.plist` ファイルは脱獄済みデバイスから取得するか、アプリケーション IPA ファイルから抽出する必要があります。「iOS セキュリティテスト入門」の章の「Info.plist ファイル」のセクションで説明されているように、必要であれば人間が読める形式に変換します (例えば `plutil -convert xml1 Info.plist`) 。

アプリケーションには通常の機能を許可するために ATS 例外が定義されている場合があります。例えば、Firefox iOS アプリケーションでは ATS がグローバルに無効化されています。さもないとアプリケーションがすべての ATS 要件を満たしていない任意の HTTP ウェブサイトに接続できなくなるため、この例外は許容されます。

### ATS の使用に関する推奨事項

特定のエンドポイントと通信するときに使用できる ATS 設定を検証することが可能です。macOS ではコマンドラインユーティリティ `nscurl` が同じことを確認するために利用できます。このコマンドは以下のように使用できます。

```bash
/usr/bin/nscurl --ats-diagnostics https://www.example.com
Starting ATS Diagnostics

Configuring ATS Info.plist keys and displaying the result of HTTPS loads to https://www.example.com.
A test will "PASS" if URLSession:task:didCompleteWithError: returns a nil error.
Use '--verbose' to view the ATS dictionaries used and to display the error received in URLSession:task:didCompleteWithError:.
================================================================================

Default ATS Secure Connection
---
ATS Default Connection
Result : PASS
---

================================================================================

Allowing Arbitrary Loads

---
Allow All Loads
Result : PASS
---

================================================================================

Configuring TLS exceptions for www.example.com

---
TLSv1.3
2019-01-15 09:39:27.892 nscurl[11459:5126999] NSURLSession/NSURLConnection HTTP load failed (kCFStreamErrorDomainSSL, -9800)
Result : FAIL
---
```

上記の出力は nscurl の最初のいくつかの結果のみを示しています。指定されたエンドポイントに対してさまざまな設定の組み合わせが実行および検証されます。デフォルトの ATS セキュア接続テストに合格した場合、ATS をデフォルトのセキュア構成で使用できます。

> nscurl の出力に不合格がある場合には、クライアント側の ATS の構成を弱くするのではなく、サーバー側をよりセキュアにするために TLS のサーバー側構成を変更してください。

このトピックに関する詳細は [ATS に関する NowSecure によるブログ投稿](https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/ "A guide to ATS") を参照してください。

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

## カスタム証明書ストアと証明書ピンニングのテスト (MSTG-NETWORK-3 および MSTG-NETWORK-4)

### 概要

認証局はセキュアなクライアントサーバー通信に不可欠な要素であり、各オペレーティングシステムのトラストストアに事前定義されています。iOS では自動的に膨大な量の証明書を信頼しています。これらは Apple のドキュメント [iOS バージョンごとの利用可能な信頼されたルート証明書のリスト](https://support.apple.com/en-gb/HT204132 "Lists of available trusted root certificates in iOS") で詳細を調べることができます。

CA はトラストストアに追加できます。ユーザーを介して手動で、エンタープライズデバイスを管理する MDM により、もしくはマルウェアを介して行われます。問題はそれらのすべての CA を信頼できるかどうか、そしてアプリはトラストストアに頼るべきかどうかということです。

このリスクに対処するために、証明書ピンニングを使用できます。証明書ピンニングは、信頼できる認証局により署名された任意の証明書を受け入れる代わりに、モバイルアプリをサーバーの特定の X.509 証明書に関連付けるプロセスです。サーバー証明書や公開鍵を格納するモバイルアプリは、その後、既知のサーバーへの接続のみを確立し、それによりサーバーを「ピンニング」します。外部の認証局 (CA) への信頼を排除することで、攻撃対象となる面が少なくなります。結局のところ、認証局が侵害されたり、偽者に証明書を発行するよう騙されたりという既知の事例が多くあります。CA 違反や失敗の詳細なタイムラインは [sslmate.com](https://sslmate.com/certspotter/failures "Timeline of PKI Security Failures") で見つけることができます。

証明書は開発中またはアプリが最初にバックエンドに接続するときにピン留めできます。
その場合、証明書は初回に見たときにホストに関連付けられるか「ピン留め」されます。この二つ目のバリエーションはあまりセキュアではなくなります。攻撃者は最初の接続を傍受して自身の証明書を注入する可能性があるためです。

#### ピンが失敗する場合

ピンニングの失敗はさまざまな理由で発生する可能性があります。サーバーやロードバランサーが提供するものとは別の鍵または証明書をアプリが期待しているか、中間者攻撃が行われている可能性があります。どちらの場合でも Android の場合と同様に、このような状況に対応するさまざまな方法があります。「Android のネットワーク API」の章の "[ピンが失敗する場合](0x05g-Testing-Network-Communication.md#when-the-pin-fails)" セクションを参照ください。

### 静的解析

サーバー証明書がピン留めされていることを確認します。サーバーにより提示された証明書ツリーに関して、ピンニングはさまざまなレベルで実装できます。

1. サーバーの証明書をアプリケーションバンドルに含め、各接続で検証を実行します。これにはサーバーの証明書が更新されるたびに更新メカニズムが必要です。
2. 証明書発行者を例えば一つのエンティティに制限し、中間 CA の公開鍵をアプリケーションにバンドルします。このようにして攻撃面を制限し、有効な証明書を取得します。
3. 独自の PKI を所有および管理します。アプリケーションには中間 CA の公開鍵が含まれます。これにより、例えば期限切れのために、サーバー上の証明書を変更するごとにアプリケーションを更新することがなくなります。独自の CA を使用すると証明書が自己署名されることに注意します。

Apple が推奨する最新のアプローチは `Info.plist` ファイルの App Transport Security Settings にピン留めされた CA 公開鍵を指定することです。記事 [Identity Pinning: How to configure server certificates for your app](https://developer.apple.com/news/?id=g9ejcf8y "Identity Pinning: How to configure server certificates for your app") に例があります。

もう一つの一般的なアプローチは `NSURLConnectionDelegate` の [`connection:willSendRequest ForAuthenticationChallenge:`](https://developer.apple.com/documentation/foundation/nsurlconnectiondelegate/1414078-connection?language=objc "connection:willSendRequestForAuthenticationChallenge:") メソッドを使用して、サーバーから提供された証明書が有効で、アプリに保存されている証明書と一致するかどうかを確認することです。詳細については [HTTPS Server Trust Evaluation](https://developer.apple.com/library/archive/technotes/tn2232/_index.html#//apple_ref/doc/uid/DTS40012884-CH1-SECNSURLCONNECTION "HTTPS Server Trust Evaluation") テクニカルノートをご覧ください。

ローカルとリモートの証明書を比較する場合、リモートの証明書が変更されるときにアプリを更新する必要があることに注意します。予備の証明書をアプリに保存しておくと移行がスムーズに行えます。また、ピンを公開鍵比較ベースとすることもできます。この場合、リモートの証明書が変更されても、公開鍵は同じままです。

以下のサードパーティライブラリにはピンニング機能が含まれています。

- [TrustKit](https://github.com/datatheorem/TrustKit "TrustKit"): ここでは Info.plist に公開鍵ハッシュを設定するか、辞書にハッシュを提供することでピンニングできます。詳細は readme を見てください。
- [AlamoFire](https://github.com/Alamofire/Alamofire "AlamoFire"): ここではピンニング方法を定義するドメインごとに `ServerTrustPolicy` を定義します。
- [AFNetworking](https://github.com/AFNetworking/AFNetworking "AfNetworking"): ここではピンニングを構成するために `AFSecurityPolicy` を設定します。

### 動的解析

#### サーバー証明書の妥当性確認

私たちのテストアプローチは SSL ハンドシェイクネゴシエーションのセキュリティを少しずつ緩めて、どのセキュリティメカニズムが有効であるかを確認することです。

1. Burp をプロキシとして設定した後、トラストストア (**Settings** -> **General** -> **Profiles**) に証明書が追加されていないこと、および SSL キルスイッチなどのツールが無効であることを確認します。アプリケーションを起動して、Burp にトラフィックが表示されるかどうかを確認します。問題がある場合は 'Alerts' タブに報告されます。トラフィックが見える場合、証明書検証がまったく実行されていないことを意味します。そうではなく、トラフィックを見ることができず、SSL ハンドシェイクの失敗に関する情報がある場合には、次の項目に従います。
2. 次に、[Burp のユーザードキュメント](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp\'s CA Certificate in an iOS Device") で説明されているように、Burp 証明書をインストールします。ハンドシェイクが成功して Burp でトラフィックを見ることができる場合、デバイスのトラストストアに対して証明書が検証されているが、ピンニングが実行されていないことを意味します。
3. 前のステップでの指示を実行してもトラフィックが burp 経由でプロキシされない場合、証明書は実際にピン留めされ、すべてのセキュリティ対策が実行されていることを意味します。但し、アプリケーションをテストするには依然としてピンニングをバイパスする必要があります。この詳細については以下の "[証明書ピンニングのバイパス](#bypassing-certificate-pinning "Bypassing Certificate Pinning")" のセクションを参照してください。

#### クライアント証明書の妥当性確認

アプリケーションによっては双方向 SSL ハンドシェイクを使用するものがあります。つまり、アプリケーションがサーバーの証明書を検証し、サーバーがクライアントの証明書を検証します。Burp 'Alerts' タブにクライアントが接続のネゴシエーションに失敗したことを示すエラーがあるかどうかを確認します。

注目すべきことがいくつかあります。

1. クライアント証明書には鍵交換で使用される秘密鍵 (private key) が含まれています。
2. 一般的にこの証明書は使用 (復号) するためにパスワードも必要です。
3. 証明書はバイナリ自体、データディレクトリ、もしくはキーチェーンに格納できます。

双方向ハンドシェイクを行う最も一般的で不適切な方法は、アプリケーションバンドル内にクライアント証明書を格納し、パスワードをハードコードすることです。すべてのクライアントが同じ証明書を共有するため、これはほとんどセキュリティをもたらさないことが明らかです。

証明書 (および場合によってはパスワード) を格納する第二の方法はキーチェーンを使用するものです。最初のログイン時に、アプリケーションは個人証明書をダウンロードし、キーチェーンにセキュアに格納する必要があります。

アプリケーションにはハードコードされ最初のログイン時に使用される一つの証明書を持ち、それから個人証明書がダウンロードされることがあります。この場合、サーバーに接続するために「汎用」証明書を使用できるかどうかを確認します。

(Cycript や Frida を使用して) アプリケーションから証明書を抽出し、Burp のクライアント証明書としてそれを追加すると、トラフィックを傍受することが可能となります。

#### 証明書ピンニングのバイパス

SSL ピンニングをバイパスするにはさまざまな方法があります。以下のセクションでは脱獄済みデバイスと非脱獄済みデバイス向けに説明します。

脱獄済みデバイスを持っているのであれば、自動的に SSL ピンニングを無効にできる以下のツールのいずれかを試してみます。

- "[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2")" は証明書ピンニングを無効にする方法の一つです。[Cydia](0x08-Testing-Tools.md#cydia) ストアからインストールできます。すべての高レベル API コールにフックし、証明書ピンニングをバイパスします。
- [Burp Suite Mobile Assistant](0x08-Testing-Tools.md#burp-suite-mobile-assistant) アプリでも証明書ピンニングをバイパスするために使うことができます。

場合によっては、証明書ピンニングをバイパスすることが難しくなります。ソースコードにアクセスしてアプリを再コンパイルできる場合には、以下を確認します。

- API コール `NSURLSession`, `CFStream`, `AFNetworking`
- "pinning", "X.509", "Certificate" などの単語を含むメソッドや文字列

ソースにアクセスできない場合は、バイナリパッチを試してみます。

- OpenSSL 証明書ピンニングが使用されている場合、[バイナリパッチ](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/january/bypassing-openssl-certificate-pinning-in-ios-apps/ "Bypassing OpenSSL Certificate Pinning in iOS Apps") を試してみます。
- 多くの場合、証明書はアプリケーションバンドル内のファイルです。証明書を Burp の証明書で置き換えることで十分なこともありますが、証明書の SHA sum には注意します。バイナリにハードコードされている場合、それも置き換えなければなりません。

Frida と Objection を使用して、非脱獄済みデバイスで SSL ピンニングをバイパスすることもできます (これは脱獄済みデバイスでも機能します) 。「iOS の基本的なセキュリティテスト」の説明に従って、Objection でアプリケーションを再パッケージ化した後、Objection で以下のコマンドを使用して一般的な SSL ピンニング実装を無効にできます。

```bash
$ ios sslpinning disable
```

[pinning.ts](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts "pinning.ts") を調べてバイパスの仕組みを理解できます。

詳細情報として [iOS の SSL ピンニング無効化に関する Objection の文書](https://github.com/sensepost/objection#ssl-pinning-bypass-running-for-an-ios-application "Disable SSL Pinning in iOS" ) もご覧ください。

ただし、テクノロジとシステムは時間とともに変化するため、このバイパス技法はいずれ機能しなくなる可能性があります。したがって、すべてのツールが OS バージョンに十分迅速に対応できるわけではないため、調査を行うことはテスト担当者の作業の一部です。

たとえば、この執筆時点では Objection バイパスは iOS 10 以降では機能していません。ただし、Frida CodeShare などのリポジトリを調べると、@dki による iOS 10 および 11 で実際に機能する ["ios10-ssl-bypass"](https://codeshare.frida.re/@dki/ios10-ssl-bypass/) など、特定のバージョンをバイパスするスクリプトを見つけることができます。

一部のアプリはカスタム SSL ピンニング手法を実装している可能性があるため、テスト担当者は [Frida](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06b-Basic-Security-Testing.md#frida) と、["iOS リバースエンジニアリング"](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06c-Reverse-Engineering-and-Tampering.md) で説明されている技法を使用して新しいバイパススクリプトを開発することもできます。

ホワイトボックステストと典型的なコードパターンについてもっと知りたい場合には、[#thiel] を参照してください。これには最も一般的な証明書ピンニング技法を説明する記述とコードスニペットが含まれています。

### 参考情報

- [#thiel] - David Thiel. iOS Application Security, No Starch Press, 2015

#### OWASP MASVS

- MSTG-NETWORK-2: "TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨された標準をサポートしていない場合には可能な限り近い状態である。"
- MSTG-NETWORK-3: "セキュアチャネルが確立されたときに、アプリはリモートエンドポイントのX.509証明書を確認している。信頼されたCAにより署名された証明書のみが受け入れられている。"
- MSTG-NETWORK-4: "アプリは自身の証明書ストアを使用するか、エンドポイント証明書もしくは公開鍵をピンニングしている。信頼されたCAにより署名された場合でも、別の証明書や鍵を提供するエンドポイントとの接続を確立していない。"

#### Nscurl

- ATS のガイド - NowSecure によるブログ投稿 - <https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/>
