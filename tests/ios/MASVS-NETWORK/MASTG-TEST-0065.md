---
masvs_v1_id:
- MSTG-NETWORK-1
masvs_v2_id:
- MASVS-NETWORK-1
platform: ios
title: ネットワーク上のデータ暗号化のテスト (Testing Data Encryption on the Network)
masvs_v1_levels:
- L1
- L2
---

## 概要

提示されたすべてのケースは全体として注意深く解析しなければなりません。たとえば、アプリが Info.plist でクリアテキストトラフィックを許可していないとしても、実際にはまだ HTTP トラフィックを送信している可能性があります。これは低レベルの API を使用している (ATS が無視される) 場合や、不適切に設定されたクロスプラットフォームフレームワークを使用している場合に当てはまります。

> 重要: これらのテストはアプリのメインコードだけでなく、アプリ内に組み込まれたアプリの拡張機能、フレームワーク、Watch アプリにも適用すべきです。

詳細については Apple Developer ドキュメントの記事 ["Preventing Insecure Network Connections"](https://developer.apple.com/documentation/security/preventing_insecure_network_connections) および ["Fine-tune your App Transport Security settings"](https://developer.apple.com/news/?id=jxky8h89) を参照してください。

## 静的解析

### セキュアプロトコルでのネットワークリクエストのテスト

まず、ソースコードのすべてのネットワークリクエストを特定し、プレーンな HTTP URL が使用されていないことを確認します。[`URLSession`](https://developer.apple.com/documentation/foundation/urlsession) (標準の [iOS の URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) を使用する) または [`Network`](https://developer.apple.com/documentation/network) (TLS を使用して TCP および UDP にアクセスするソケットレベル通信) を使用して、機密情報がセキュアチャネルで送信されることを確認します。

### 低レベルネットワーク API の使用状況のチェック

アプリが使用するネットワーク API を特定し、低レベルネットワーク API を使用しているかどうかを確認します。

> **Apple の推奨事項: アプリでは高レベルフレームワークを優先すること**: 「ATS はアプリが Network フレームワークや CFNetwork などの低レベルネットワークインタフェースに対して行う呼び出しには適用されません。これらの場合、接続のセキュリティを確保するのはあなたの責任です。この方法でセキュア接続を構築できますが、ミスを犯しやすく、コストもかかります。代わりに Loading System を使用するのが通常はもっとも安全です ([出典](https://developer.apple.com/documentation/security/preventing_insecure_network_connections) を参照) 。」

アプリが [`Network`](https://developer.apple.com/documentation/network) や [`CFNetwork`](https://developer.apple.com/documentation/cfnetwork) などの低レベル API を使用している場合、それらがセキュアに使用されているかどうかを注意深く調査すべきです。クロスプラットフォームフレームワーク (Flutter, Xamarin など) やサードパーティフレームワーク (Alamofire など) を使用するアプリでは、それらがベストプラクティスに沿ってセキュアに設定され使用されているかどうかを解析すべきです。

アプリについて以下を確認します。

- サーバー信頼性評価の実行時にチャレンジタイプとホスト名と資格情報を検証している。
- TLS エラーを無視していない。
- セキュアでない TLS 設定を使用していない (["TLS 設定のテスト"](../../../tests/ios/MASVS-NETWORK/MASTG-TEST-0066.md) を参照)

これらのチェックは方向性を示すものであり、アプリごとに異なるフレームワークを使用している可能性があるため、特定の API を挙げることはできません。コードを調査する際の参考情報としてください。

### クリアテキストトラフィックのテスト

アプリがクリアテキスト HTTP トラフィックを許可していないことを確認します。iOS 9.0 以降、クリアテキスト HTTP トラフィックはデフォルトで (App Transport Security (ATS) により) ブロックされますが、アプリケーションがそれを送信できる方法はいくつかあります。

- アプリの `Info.plist` にある `NSAppTransportSecurity` で `NSAllowsArbitraryLoads` 属性を `true` (または `YES`) にセットしてクリアテキストトラフィックを有効にするよう ATS を設定する。
- [`Info.plist` の取得](../../../Document/0x06b-iOS-Security-Testing.md#the-infoplist-file)
- どのドメインでも `NSAllowsArbitraryLoads` がグローバルに `true` にセットされていないことをチェックする。

- アプリケーションがサードパーティのウェブサイトを WebView で開く際、iOS 10 以降では `NSAllowsArbitraryLoadsInWebContent` を使用して WebView にロードされるコンテンツの ATS 制限を無効にできる。

> **Apple の警告:** ATS を無効にすると、セキュアではない HTTP 接続が許可されます。HTTPS 接続も許可され、依然としてデフォルトのサーバー信頼性評価の対象となります。しかし、最低限の Transport Layer Security (TLS) プロトコルを要求するなどの拡張セキュリティチェックは無効になります。ATS を使用しない場合、 ["Performing Manual Server Trust Authentication"](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication) で説明されているように、デフォルトのサーバー信頼性要件を自由に緩めることもできます。

以下のスニペットは ATS 制限をグローバルに無効化するアプリの **脆弱な例** を示しています。

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

ATS はアプリケーションのコンテキストを考慮して検討すべきです。アプリケーションはその意図する目的を達するために ATS 例外を定義する _必要がある_ かもしれません。たとえば、 [Firefox iOS アプリケーションはグローバルに ATS を無効にしています](https://github.com/mozilla-mobile/firefox-ios/blob/v97.0/Client/Info.plist#L82) 。この例外は受け入れられます。そうしないと、すべての ATS 要件を満たしていない HTTP ウェブサイトに接続できなくなるためです。場合によっては、アプリはグローバルに ATS を無効にするかもしれませんが、例えば、メタデータをセキュアにロードしたり、セキュアログインを可能にするため、特定のドメインでは有効にすることがあります。

ATS にはこれを [正当化する文字列](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) が含まれているべきです (例: 「このアプリはセキュアな接続をサポートしてない別のエンティティで管理されているサーバーに接続しなければなりません」) 。

## 動的解析

テスト対象のアプリの送受信ネットワークトラフィックを傍受して、このトラフィックが暗号化されていることを確認します。以下のいずれかの方法でネットワークトラフィックを傍受できます。

- [OWASP ZAP](../../../Document/0x08a-Testing-Tools.md#owasp-zap) や [Burp Suite](../../../Document/0x08a-Testing-Tools.md#burp-suite) などの傍受プロキシですべての HTTP(S) と Websocket トラフィックをキャプチャして、すべてのリクエストが HTTP ではなく HTTPS 経由で行われることを確認します。
- Burp や OWASP ZAP などの傍受プロキシは HTTP(S) トラフィックのみを表示します。ただし、[Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension") などの Burp プラグインや [mitm-relay](https://github.com/jrmdev/mitm_relay "mitm-relay") というツールを使用して XMPP や他のプトロコルを介した通信をデコードして可視化できます。

> 一部のアプリケーションでは証明書ピン留めが原因で Burp や OWASP ZAP などのプロキシで動作しないことがあります。そのようなシナリオでは ["カスタム証明書ストアおよび証明書ピン留めのテスト"](../../../tests/ios/MASVS-NETWORK/MASTG-TEST-0068.md) を確認してください。

詳細については以下を参照してください。

- ["ネットワーク通信のテスト"](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-traffic-on-the-network-layer) の章の "ネットワーク層でのトラフィックの傍受"
- [iOS のセキュリティテスト入門](../../../Document/0x06b-iOS-Security-Testing.md#setting-up-a-network-testing-environment)  の章の "ネットワークテスト環境のセットアップ"
