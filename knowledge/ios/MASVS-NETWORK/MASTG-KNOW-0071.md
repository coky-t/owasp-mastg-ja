---
masvs_category: MASVS-NETWORK
platform: ios
title: iOS App Transport Security
---

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

[Apple によると](https://support.apple.com/en-gb/guide/security/sec100a75d12/web#sec8b087b1f7)、「TLS 証明書の信頼ステータスの評価は RFC 5280 で規定されているように確立された業界標準に従って行われ、RFC 6962 (Certificate Transparency) などの新しい標準も取り入れられています。iOS 11 以降では、Apple デバイスは定期的に失効した証明書と制約のある証明書の最新リストで更新されます。このリストは Apple が信頼するビルトインの各ルート認証局およびその下位の CA 発行者が発行する証明書失効リスト (CRL) から集約されています。このリストには Apple の裁量で他の制約が含まれていることもあります。この情報はネットワーク API 関数を使用してセキュア接続を行う際に参照されます。CA から失効した証明書が多すぎて個別にリストアップできない場合、信頼性評価では代わりにオンライン証明書ステータス応答 (Online Certificate Status Response, OCSP) が必要となり、応答が得られない場合には信頼性評価は失敗します。」

## ATS が適用されないのはどのような場合か？

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

## ATS 例外

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

出典: [Apple Developer ドキュメント](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys")

以下の表はグローバル ATS 例外をまとめたものです。これらの例外の詳細については、[公式の Apple Developer ドキュメントの Table 2](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW34 "App Transport Security dictionary primary keys") を参照してください。

| キー | 説明 |
| --------------| ------------|
| `NSAllowsArbitraryLoads` | `NSExceptionDomains` の下に指定された個々のドメインを除いてグローバルに ATS 制限を無効化する (以下のいずれかが設定されている場合、その値に関係なく、このキーは無視されます) |
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

古い例やドキュメントでは `NSTemporaryException...` で始まる例外キーに遭遇することがあります。これらのキーは元々 iOS 9 初期に一時的な ATS 例外ヘルパーとして導入されました。それらは依然として動作しますが、Apple により非推奨となりドキュメント化されていません。開発者は代わりに最新の非一時的な `NSException...` 同等品を使用する必要があります。

**例外の正当性:**

2017年1月1日から Apple App Store レビューでは以下の ATS 例外の一つが定義されている場合に [正当な理由を要求](https://developer.apple.com/documentation/security/preventing-insecure-network-connections#Provide-Justification-for-Exceptions) します。

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
