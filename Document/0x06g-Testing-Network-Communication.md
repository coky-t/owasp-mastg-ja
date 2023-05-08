---
masvs_category: MASVS-NETWORK
platform: ios
---

# iOS のネットワーク通信

## 概要

ほぼすべての iOS アプリは一つ以上のリモートサービスのクライアントとして動作します。このネットワーク通信は一般的に公衆 Wi-Fi などの信頼できないネットワーク上で行われるため、従来のネットワークベースの攻撃が潜在的な問題になります。

最近のモバイルアプリの多くはさまざまな HTTP ベースのウェブサービスを使用しています。これらのプロトコルは十分に文書化されており、サポートされているからです。

### iOS App Transport Security

iOS 9 以降、Apple は [App Transport Security (ATS)](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity) を導入しました。これは [URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) を使用して行われる接続 (通常 `URLSession` 経由) に対して常に HTTPS を使うようにオペレーティングシステムが強制する一連のセキュリティチェックです。アプリは [Apple のベストプラクティス](https://developer.apple.com/news/?id=jxky8h89) に従って、適切に接続を保護すべきです。

> [Apple WWDC 2015 の ATS 紹介ビデオをご覧ください](https://developer.apple.com/videos/play/wwdc2015/711/?time=321) 。

ATS はデフォルトのサーバー信頼性評価を行い、最低限のセキュリティ要件を要求します。

**デフォルトのサーバー信頼性評価:**

アプリがリモートサーバーに接続する際、サーバーは X.509 デジタル証明書を使用してそのアイデンティティを提供します。ATS のデフォルトのサーバー信頼性評価には以下に示す証明書の妥当性確認も含まれています。

- 有効期限が切れていないこと。
- サーバーの DNS 名と一致する名前を持っていること。
- 有効な (改竄されていない) デジタル署名を持ち、[オペレーティングシステムの Trust Store](https://support.apple.com/en-us/HT209143) に含まれる信頼できる認証局 (Certificate Authority, CA) にさかのぼることができるか、ユーザーもしくはシステム管理者がクライアントにインストールしたものであること。

**接続に必要な最低限のセキュリティ要件:**

さらに ATS は以下に示す一連の [最低限のセキュリティ要件](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138464) を満たさない接続をブロックします。

- TLS バージョン 1.2 以上。
- AES-128 または AES-256 でのデータ暗号化。
- 証明書は RSA 鍵 (2048 ビット以上)、ECC 鍵 (256 ビット以上) で署名されていなければならない。
- 証明書のフィンガープリントは SHA-256 以上を使用しなければならない。
- リンクは Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) 鍵交換による Perfect Forward Secrecy (PFS) をサポートしなければならない。

**証明書の有効性チェック:**

[Apple によると](https://support.apple.com/en-gb/guide/security/sec100a75d12/web#sec8b087b1f7) 、「TLS 証明書の信頼ステータスの評価は RFC 5280 で規定されているように確立された業界標準に従って行われ、RFC 6962 (Certificate Transparency) などの新しい標準も取り入れられています。iOS 11 以降では、Apple デバイスは定期的に失効した証明書と制約のある証明書の最新リストで更新されます。このリストは Apple が信頼するビルトインの各ルート認証局およびその下位の CA 発行者が発行する証明書失効リスト (CRL) から集約されています。このリストには Apple の裁量で他の制約が含まれていることもあります。この情報はネットワーク API 関数を使用してセキュア接続を行う際に参照されます。CA から失効した証明書が多すぎて個別にリストアップできない場合、信頼性評価では代わりにオンライン証明書ステータス応答 (Online Certificate Status Response, OCSP) が必要となり、応答が得られない場合には信頼性評価は失敗します。」

#### ATS が適用されないのはどのような場合か？

- **低レベル API を使用する場合:** ATS は [URLSession](https://developer.apple.com/reference/foundation/urlsession) に含まれる [URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) とその上にレイヤー化された API にのみ適用されます。低レベル API (BSD ソケットなど) を使用するアプリには適用されません。その低レベル API 上に TLS を実装しているものも同様です (アーカイブされた Apple Developer ドキュメントの ["Using ATS in Apple Frameworks"](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW55) セクションを参照してください) 。

- **IP アドレス、非修飾ドメイン名、ローカルホストに接続する場合:** ATS はパブリックホスト名に対して行われた接続にのみ適用されます (アーカイブされた Apple Developer ドキュメントの ["Availability of ATS for Remote and Local Connections"](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW54) セクションを参照してください) 。システムは以下に示す接続に対して ATS 保護を提供しません。
    - インターネットプロトコル (Internet Protocol, IP) アドレス
    - 非修飾ホスト名
    - .local トップレベルドメイン (Top-Level Domain, TLD) を使用するローカルホスト

- **ATS 例外を含む場合:** アプリが ATS 互換 API を使用する際、[ATS 例外](#ats-exceptions) を使用して特定のシナリオで ATS を無効にできます。

さらに学ぶために:

- ["ATS and iOS enterprise apps with private networks"](https://developer.apple.com/forums/thread/79662)
- ["ATS and local IP addresses"](https://developer.apple.com/forums/thread/66417)
- ["ATS impact on apps use 3rd party libraries"](https://developer.apple.com/forums/thread/69197)
- ["ATS and SSL pinning / own CA"](https://developer.apple.com/forums/thread/53314)

#### ATS 例外

ATS の制限は `Info.plist` ファイルの `NSAppTransportSecurity` キーに例外を設定することで無効にできます。これらの例外には以下を適用できます。

- セキュアではない接続 (HTTP) の許可
- 最小 TLS バージョンの引き下げ
- Perfect Forward Secrecy (PFS) の無効化
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

出典: [Apple Developer Documentation](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys").

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

**例外の正当性:**

2017年1月1日から Apple App Store レビューでは以下の ATS 例外の一つが定義されている場合に [正当な理由を要求](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) します。

- `NSAllowsArbitraryLoads`
- `NSAllowsArbitraryLoadsForMedia`
- `NSAllowsArbitraryLoadsInWebContent`
- `NSExceptionAllowsInsecureHTTPLoads`
- `NSExceptionMinimumTLSVersion`

これはアプリが意図した目的の一部であるかどうかを判断して、慎重に修正しなければなりません。Apple はアプリのセキュリティを低下させる例外について警告し、ATS の障害に直面した場合には **必要な場合にのみ例外を設定し、サーバーの修正を優先する** ようにアドバイスしています。

**例:**

以下の例では、ATS はグローバルに有効 (グローバルな `NSAllowsArbitraryLoads` は定義されていない) ですが、 `example.com` ドメイン (とそのサブドメイン) に対して例外が **明示的に設定** されています。このドメインをアプリケーション開発者が所有し、適切な正当性があることを考慮すると、他のすべてのドメインに対して ATS のすべての利点を維持しているため、この例外は許容されるでしょう。しかし、上記のようにサーバーを修正することが常に望ましいと思われます。

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

ATS 例外の詳細については [Apple Developer ドキュメント](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138482) の記事 "Preventing Insecure Network Connections" のセクション "Configure Exceptions Only When Needed; Prefer Server Fixes" および [ATS に関するブログ投稿](https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/ "A guide to ATS") を参照してください。

### サーバー信頼性評価

ATS は Transport Layer Security (TLS) プロトコルで規定されたデフォルトのサーバー信頼性評価を補完する拡張セキュリティチェックを課します。ATS 制限を緩めているとアプリのセキュリティが低下します。アプリは ATS 例外を追加する前に、サーバーセキュリティを向上させる別の方法を優先させるべきです。

[Apple Developer ドキュメント](https://developer.apple.com/documentation/security/preventing_insecure_network_connections) ではアプリは `URLSession` を使用してサーバー信頼性評価を自動的に処理できると説明しています。しかし、アプリはそのプロセスをカスタマイズすることもできます。たとえば、以下のことができます。

- 証明書の有効期限をバイパスまたはカスタマイズする。
- 信頼性を緩める/広げる: システムによって拒否されるようなサーバー資格情報を受け入れる。たとえば、アプリに埋め込まれた自己署名証明書を使用して開発サーバーにセキュア接続を行う。
- 信頼性を強める: システムによって受け入れられるサーバー資格証明を拒否します。
- その他

<img src="Images/Chapters/0x06g/manual-server-trust-evaluation.png" width="100%" />

参考情報:

- [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)
- [Performing Manual Server Trust Authentication](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication)
- [Certificate, Key, and Trust Services](https://developer.apple.com/documentation/security/certificate_key_and_trust_services)

### iOS ネットワーク API

iOS 12.0 以降、[Network](https://developer.apple.com/documentation/network) フレームワークと [`URLSession`](https://developer.apple.com/documentation/foundation/urlsession) クラスはネットワークおよび URL リクエストを非同期および同期でロードするメソッドを提供します。古いバージョンの iOS では [Sockets API](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/UsingSocketsandSocketStreams.html) を利用できます。

#### Network フレームワーク

`Network` フレームワークは 2018 年の [Apple Worldwide Developers Conference (WWDC)](https://developer.apple.com/videos/play/wwdc2018/715 "Introducing Network.framework: A modern alternative to Sockets") で紹介された、 Sockets API に代わるものです。この低レベルネットワークフレームワークは動的ネットワーク、セキュリティ、パフォーマンスのサポートが組み込まれたデータ送受信のためのクラスを提供します。

`Network` フレームワークでは引数 `using: .tls` が使用されている場合、デフォルトで TLS 1.3 が有効になっています。これは従来の [Secure Transport](https://developer.apple.com/documentation/security/secure_transport "API Reference Secure Transport") フレームワークよりも優先されるオプションです。

#### URLSession

`URLSession` は `Network` フレームワーク上に構築されており、同じトランスポートサービスを利用します。また、エンドポイントが HTTPS の場合、このクラスはデフォルトで TLS 1.3 を使用します。

**HTTP および HTTPS の接続には `Network` フレームワークを直接利用するのではなく `URLSession` を使用すべきです。** `URLSession` クラスは両方の URL スキームをネイティブにサポートし、そのような接続のために最適化されています。定型コードをあまり必要としないため、エラーの可能性を減らし、デフォルトでセキュアな接続を確保できます。 `Network` フレームワークは低レベルや高度なネットワーク要件がある場合にのみ使用すべきです。

Apple の公式ドキュメントには `Network` フレームワークを使用して [netcat を実装する](https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework "Implementing netcat with Network Framework") 例や、`URLSession` で [ウェブサイトのデータをメモリに取り込む](https://developer.apple.com/documentation/foundation/url_loading_system/fetching_website_data_into_memory "Fetching Website Data into Memory") 例が掲載されています。
