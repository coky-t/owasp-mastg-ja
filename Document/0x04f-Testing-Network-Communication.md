# モバイルアプリのネットワーク通信

事実上、ネットワークに接続されたすべてのモバイルアプリは Hypertext Transfer Protocol (HTTP) または HTTP over Transport Layer Security (TLS), HTTPS を使用してリモートエンドポイントとの間でデータを送受信します。その結果、ネットワークベースの攻撃 (パケットスニッフィングや中間者攻撃など) が問題になります。この章ではモバイルアプリとエンドポイント間のネットワーク通信に関する潜在的な脆弱性、テスト技法、ベストプラクティスについて説明します。

## セキュア接続

平文の HTTP を単独で使用することが合理的であった時代は過ぎ去り、HTTPS を使用して HTTP 接続を保護することは一般的にありふれたものとなりました。HTTPS は基本的に Transport Layer Security (TLS) と呼ばれる別のプロトコルの上に HTTP を重ねたものです。そして TLS は公開鍵暗号を使用してハンドシェイクを実行し、セキュア接続を作成します。

HTTPS 接続は以下の三つの性質によってセキュアであると考えられています。

- **機密性 (Confidentiality):** TLS はネットワーク上に送信する前にデータを暗号化するため、仲介者が読み取ることはできません。
- **完全性 (Integrity):** 検出されずにデータを改変することはできません。
- **認証 (Authentication):** クライアントはサーバーの同一性を検証して、正しいサーバーとの接続を確立していることを確認できます。

## サーバーの信頼性評価

認証局 (Certificate Authority, CA) はセキュアなクライアントサーバー通信に不可欠な要素であり、各オペレーティングシステムのトラストストアにあらかじめ定義されています。たとえば、iOS では 200 のルート証明書がインストールされています ([Apple ドキュメント - Available trusted root certificates for Apple operating systems](https://support.apple.com/en-gb/HT204132 "Lists of available trusted root certificates in iOS") を参照ください) 。

CA はユーザーが手動で、エンタープライズデバイスを管理する MDM によって、またはマルウェアを介して、トラストストアに追加できます。問題は「これらの CA をすべて信頼でき、アプリはデフォルトトラストストアに依存すべきか？」ということです。結局のところ、認証局が侵害されたり、騙されて偽物に証明書を発行するケースはよく知られています。CA の侵害や不備の詳細なタイムラインが [sslmate.com](https://sslmate.com/certspotter/failures "Timeline of PKI Security Failures") にあります。

Android と iOS のいずれもユーザーが追加の CA やトラストアンカーをインストールできます。

アプリはプラットフォームのデフォルトではなく、CA のカスタムセットを信頼したいことがあります。これについて最も一般的な理由は以下のとおりです。

- 自己署名された認証局や会社内で発行された認証局など、カスタム認証局 (システムでまだ認識または信頼されていない CA) でホストに接続すること。
- CA のセットを特定の信頼できる CA のリストに限定すること。
- システムに含まれていない追加の CA を信頼すること。

### トラストストアについて

### 信頼の拡張

アプリが自己署名証明書やシステムにとって未知の証明書を持つサーバーに接続すると、セキュア接続は失敗します。これは一般的にたとえば政府、企業、教育機関などの組織が独自に発行するような非公開 CA の場合に当てはまります。

Android と iOS のいずれも信頼を拡張する手段を提供しています。つまり、アプリがシステムにビルトインされているものとカスタムのものを信頼するように、追加の CA を組み込めます。

しかし、デバイスユーザーは常に追加の CA を組み込めることを忘れないでください。したがって、アプリの脅威モデルによってはユーザートラストストアに追加されたすべての証明書を信頼しない、あるいはあらかじめ定義された特定の証明書または証明書セットのみを信頼することが必要な場合があります。

多くのアプリでは、モバイルプラットフォームが提供する「デフォルトの動作」がユースケースに対して十分セキュアです (システムが信頼する CA が侵害されるようなまれなケースでは、アプリが扱うデータは機密とはみなされないか、CA 侵害などに耐性がある他のセキュリティ対策がとられます) 。しかし、金融や医療アプリなどの他のアプリでは、たとえまれなケースであっても CA 侵害のリスクを考慮しなければなりません。

### 信頼の制限: 同一性ピンニング

アプリによっては信頼する CA の数を制限することでセキュリティをさらに高める必要があるかもしれません。一般的には開発者が使用する CA のみを明示的に信頼し、その他はすべて無視します。この信頼の制限は _同一性ピンニング (Identity Pinning)_ と呼ばれ、通常は _証明書ピンニング (Certificate Pinning)_ や _公開鍵ピンニング (Public Key Pinning)_ として実装されます。

> OWASP MASTG ではこの用語を "同一性ピンニング (Identity Pinning)", "証明書ピンニング (Certificate Pinning)", "公開鍵ピンニング (Public Key Pinning)" あるいは単に "ピンニング (Pinning)" と呼びます。

ピンニングとは信頼された CA によって署名された任意の証明書を受け入れる代わりに、X.509 証明書や公開鍵などの特定の同一性とリモートエンドポイントを関連付けるプロセスです。サーバー同一性 (または特定のセット、別名 _pinset_) をピン留めすると、その後モバイルアプリはその同一性が一致した場合にのみそれらのリモートエンドポイントに接続します。不要な ＣＡ から信頼を取り除くことで、アプリの攻撃対象領域が減少します。

#### 一般的なガイドライン

[OWASP Certificate Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html) では以下のような重要なガイダンスを提供しています。

- ピンニングを推奨する場合と例外を適用する可能性がある場合。
- ピン留めする時期: 開発時 (プリロード) または初回遭遇時 (初回使用時の信頼) 。
- ピン留めするもの: 証明書、公開鍵、ハッシュ。

Android と iOS の推奨事項はどちらも以下の「ベストケース」と合致しています。

- 開発者がコントロールできるエンドポイントにのみピン留めする。
- 開発時に (NSC/ATS) 経由で。
- SPKI `subjectPublicKeyInfo` のハッシュをピン留めする。

数年前に導入されて以来、ピンニングには悪い評判が広まっています。少なくともモバイルアプリケーションのセキュリティに有効なポイントをいくつか明らかにしたいと思います。

- 評判が悪いのはセキュリティの欠如ではなく、運用上の理由 (実装やピン管理の複雑さなど) によるものです。
- アプリがピンニングを実装していない場合、これは脆弱性として報告すべきではありません。ただし、MASVS-L2 に対する検証を行わなければならない場合には実装しなければなりません。
- Android と iOS のいずれもピンニングの実装は非常に簡単であり、ベストプラクティスに沿っています。
- ピンニングはデバイスにインストールされている侵害された CA や悪意のある CA から保護します。そのようなケースでは、ピンニングは OS が悪意のあるサーバーとセキュア接続を確立することを防ぎます。しかし、攻撃者がデバイスをコントロールしている場合、簡単にピンニングロジックを無効して、接続を行うことが依然として可能です。結果として、攻撃者がバックエンドにアクセスして、サーバー側の脆弱性を悪用することを防ぐことはできません。
- モバイルアプリのピンニングは HTTP Public Key Pinning (HPKP) と同じではありません。HPKP ヘッダはユーザーがウェブサイトからロックアウトされ、ロックアウトを解除する方法がないことから、ウェブサイトでは推奨されなくなりました。モバイルアプリでは、なんらかの問題があっても帯域外チャネル (つまりアプリストア) を通じて常にアプリを更新できるため、これは問題ではありません。

#### Android 開発者のピンニング推奨事項について

[Android Developers](https://developer.android.com/training/articles/security-ssl#Pinning) サイトには以下の警告が記されています。

> 注意: 証明書ピンニングは別の認証局に変更するなどの将来的なサーバー構成の変更により、クライアントソフトウェアの更新を受けることなくアプリケーションがサーバーに接続できなくなるリスクが高いため、Android アプリケーションには推奨されません。

またこのような [注釈](https://developer.android.com/training/articles/security-config#CertificatePinning) もあります。

> 証明書のピン留めを使用するときは、必ずバックアップの鍵を含めてください。そうすれば、新しい鍵に切り替えたり、CA を変更したりする必要が生じた場合に（CA 証明書またはその CA の中間証明書にピン留めしていても）、アプリの接続が影響を受けることはありません。そうしないと、接続を復元するためにアプリにアップデートをプッシュしなければならなくなります。

最初の文は「証明書ピンニングを推奨しない」と言っているものと誤解される可能性があります。二つ目の文でこれを明らかにしています。実際の推奨事項は、開発者がピンニングを実装したい場合には必要な予防措置を講じなければならない、ということです。

#### Apple 開発者のピンニング推奨事項について

Apple は [長期的に考えること](https://developer.apple.com/news/?id=g9ejcf8y) と [適切なサーバー認証戦略を立てること](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication#2956135) を推奨しています。

#### OWASP MASTG の推奨事項

特に MASVS-L2 アプリで、ピンニングをお勧めします。ただし、開発者は自分の管理下にあるエンドポイントに限定して実装し、バックアップ鍵 (別名、バックアップピン) を含めるようにし、適切なアプリ更新戦略を持つようにしなければなりません。

#### さらに学ぶために

- ["Android Security: SSL Pinning"](https://appmattus.medium.com/android-security-ssl-pinning-1db8acb6621e)
- [OWASP Certificate Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html)

## TLS 設定の検証

コアとなるモバイルアプリの機能のひとつはインターネットなどの信頼できないネットワーク上でデータを送受信することです。データが転送中に正しく保護されない場合、ネットワークインフラストラクチャの任意の部分 (Wi-Fi アクセスポイントなど) にアクセスできる攻撃者は、傍受、読み取り、改変の可能性があります。これが平文のネットワークプロトコルがほとんど推奨されない理由です。

大部分のアプリはバックエンドとの通信に HTTP に依存しています。HTTPS は暗号化された接続で HTTP をラップします (略語の HTTPS はもともと HTTP over Secure Socket Layer (SSL) と呼ばれていました。SSL は TLS の前身で非推奨です) 。TLS はバックエンドサービスの認証を可能にし、ネットワークデータの機密性と完全性を保証します。

### 推奨される TLS 設定

サーバー側で適切な TLS 設定を確保することも重要です。SSL プロトコルは非推奨であり、もはや使用すべきではありません。
また TLS v1.0 および TLS v1.1 には [既知の脆弱性](https://portswigger.net/daily-swig/the-end-is-nigh-browser-makers-ditch-support-for-aging-tls-1-0-1-1-protocols "Browser-makers ditch support for aging TLS 1.0, 1.1 protocols") があり、2020年までにすべての主要なブラウザでその使用が非推奨になりました。
TLS v1.2 および TLS v1.3 はデータのセキュアな送信のためのベストプラクティスとみなされています。Android 10 (API level 29) 以降 TLS v1.3 はより高速でセキュアな通信のためにデフォルトで有効になります。[TLS v1.3 での主な変更点](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3 "TLS 1.3 enabled by default") は暗号スイートのカスタマイズができなくなること、および TLS v1.3 が有効である場合にはそれらすべてが有効になることです。一方、ゼロラウンドトリップ (0-RTT) モードはサポートされません。

クライアントとサーバーの両方が同じ組織により制御され、互いに通信するためだけに使用される場合、[設定を堅牢にすること](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices") によりセキュリティを向上できます。

モバイルアプリケーションが特定のサーバーに接続している場合、そのネットワークスタックを調整して、サーバーの構成に対して可能な限り高いセキュリティレベルを確保できます。基盤となるオペレーティングシステムのサポートがない場合、モバイルアプリケーションがより脆弱な構成を使用するように強制する可能性があります。

### 暗号スイートの用語

暗号スイートの構造は以下の通りです。

```txt
プロトコル_鍵交換アルゴリズム_WITH_ブロック暗号_完全性チェックアルゴリズム
```

この構造は以下のとおりです。

- **プロトコル** は暗号に使用されます
- **鍵交換アルゴリズム** は TLS ハンドシェイク時の認証にサーバーおよびクライアントで使用されます
- **ブロック暗号** はメッセージストリームを暗号化するために使用されます
- **完全性チェックアルゴリズム** はメッセージを認証するために使用されます

例: `TLS_RSA_WITH_3DES_EDE_CBC_SHA`

上記の例では暗号スイートは以下のものを使用します。

- TLS をプロトコルとして
- RSA を認証用の非対称暗号に
- 3DES を EDE_CBC モードで対称暗号用に
- SHA を完全性用のハッシュアルゴリズムに

TLSv1.3 では鍵交換アルゴリズムは暗号スイートの一部ではなく、代わりに TLS ハンドシェイク時に決定されることに注意します。

以下のリストでは、暗号スイートの各部分のさまざまなアルゴリズムについて説明します。

**プロトコル:**

- `SSLv1`
- `SSLv2` - [RFC 6176](https://tools.ietf.org/html/rfc6176 "RFC 6176")
- `SSLv3` - [RFC 6101](https://tools.ietf.org/html/rfc6101 "RFC 6101")
- `TLSv1.0` - [RFC 2246](https://tools.ietf.org/rfc/rfc2246 "RFC 2246")
- `TLSv1.1` - [RFC 4346](https://tools.ietf.org/html/rfc4346 "RFC 4346")
- `TLSv1.2` - [RFC 5246](https://tools.ietf.org/html/rfc5246 "RFC 5246")
- `TLSv1.3` - [RFC 8446](https://tools.ietf.org/html/rfc8446 "RFC 8446")

**鍵交換アルゴリズム:**

- `DSA` - [RFC 6979](https://tools.ietf.org/html/rfc6979 "RFC 6979")
- `ECDSA` - [RFC 6979](https://tools.ietf.org/html/rfc6979 "RFC 6979")
- `RSA` - [RFC 8017](https://tools.ietf.org/html/rfc8017 "RFC 8017")
- `DHE` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE` - [RFC 4492](https://tools.ietf.org/html/rfc4492 "RFC 4492")
- `PSK` - [RFC 4279](https://tools.ietf.org/html/rfc4279 "RFC 4279")
- `DSS` - [FIPS186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf "FIPS186-4")
- `DH_anon` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_RSA` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_DSS` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE_ECDSA` - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")
- `ECDHE_PSK`  - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")  - [RFC 5489](https://tools.ietf.org/html/rfc5489 "RFC 5489")
- `ECDHE_RSA`  - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")

**ブロック暗号:**

- `DES`  - [RFC 4772](https://tools.ietf.org/html/rfc4772 "RFC 4772")
- `DES_CBC`  - [RFC 1829](https://tools.ietf.org/html/rfc1829 "RFC 1829")
- `3DES`  - [RFC 2420](https://tools.ietf.org/html/rfc2420 "RFC 2420")
- `3DES_EDE_CBC` - [RFC 2420](https://tools.ietf.org/html/rfc2420 "RFC 2420")
- `AES_128_CBC` - [RFC 3268](https://tools.ietf.org/html/rfc3268 "RFC 3268")
- `AES_128_GCM`  - [RFC 5288](https://tools.ietf.org/html/rfc5288 "RFC 5288")
- `AES_256_CBC` - [RFC 3268](https://tools.ietf.org/html/rfc3268 "RFC 3268")
- `AES_256_GCM` - [RFC 5288](https://tools.ietf.org/html/rfc5288 "RFC 5288")
- `RC4_40`  - [RFC 7465](https://tools.ietf.org/html/rfc7465 "RFC 7465")
- `RC4_128`  - [RFC 7465](https://tools.ietf.org/html/rfc7465 "RFC 7465")
- `CHACHA20_POLY1305`  - [RFC 7905](https://tools.ietf.org/html/rfc7905 "RFC 7905")  - [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539")

**完全性チェックアルゴリズム:**

- `MD5`  - [RFC 6151](https://tools.ietf.org/html/rfc6151 "RFC 6151")
- `SHA`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")
- `SHA256`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")
- `SHA384`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")

暗号スイートの性能はそのアルゴリズムの性能に依存することに注意します。

以下のリソースには TLS で使用する最新の推奨暗号スイートがあります。

- IANA 推奨暗号スイートは [TLS Cipher Suites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4 "TLS Cipher Suites") にあります。
- OWASP 推奨暗号スイートは [TLS Cipher String Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md "OWASP TLS Cipher String Cheat Sheet") にあります。

一部の Android および iOS バージョンは推奨暗号スイートの一部をサポートしていないため、互換性を保つために [Android](https://developer.android.com/reference/javax/net/ssl/SSLSocket#cipher-suites "Cipher suites") および [iOS](https://developer.apple.com/documentation/security/1550981-ssl_cipher_suite_values?language=objc "SSL Cipher Suite Values") バージョンでサポートされている暗号スイートを確認し、サポートされている上位の暗号スイートを選択します。

サーバーが正しい暗号スイートをサポートしているかどうかを検証したい場合、さまざまなツールを使用できます。

- nscurl - 詳細については [iOS のネットワーク通信](0x06g-Testing-Network-Communication.md) を参照してください。
- [testssl.sh](https://github.com/drwetter/testssl.sh "testssl.sh") は「TLS/SSL 暗号、プロトコルのサポートおよび一部の暗号の欠陥について、任意のポート上のサーバーのサービスをチェックするフリーのコマンドラインツールです。」

最後に、HTTPS 接続が終了するサーバーや終端プロキシがベストプラクティスにしたがって構成されていることを検証します。 [OWASP Transport Layer Protection cheat sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md "Transport Layer Protection Cheat Sheet") および [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices") も参照してください。

## HTTP(S) トラフィックの傍受

多くの場合、HTTP(S) トラフィックがホストコンピュータ上で実行されている _傍受プロキシ_ 経由でリダイレクトされるように、モバイルデバイス上にシステムプロキシを設定することが最も実用的です。モバイルアプリクライアントとバックエンドの間のリクエストを監視することにより、利用可能なサーバーサイド API を簡単にマップし、通信プロトコルの情報を得ることができます。さらに、サーバー側の脆弱性をテストするためにリクエストを再生および操作できます。

フリーおよび商用のプロキシツールがいくつかあります。最も人気のあるものは以下のとおりです。

- [Burp Suite](0x08a-Testing-Tools.md#burp-suite)
- [OWASP ZAP](0x08a-Testing-Tools.md#owasp-zap)

傍受プロキシを使用するには、それをホストコンピュータ上で実行し、HTTP(S) リクエストをプロキシにルーティングするようモバイルアプリを設定する必要があります。ほとんどの場合、モバイルデバイスのネットワーク設定でシステム全体のプロキシを設定するだけで十分です。アプリが標準の HTTP API や `okhttp` などの一般的なライブラリを使用する場合、自動的にシステム設定を使用します。

<img src="Images/Chapters/0x04f/BURP.png" width="100%" />

プロキシを使用すると SSL 証明書の検証が中断され、アプリは通常 TLS 接続を開始できません。この問題を回避するには、プロキシの CA 証明書をデバイスにインストールします。OS ごとの「テスト環境構築」の章でこれを行う方法について説明します。

## 非 HTTP トラフィックの傍受

[Burp](0x08a-Testing-Tools.md#burp-suite) や [OWASP ZAP](0x08a-Testing-Tools.md#owasp-zap) などの傍受プロキシは非 HTTP トラフィックを表示しません。デフォルトでは正しくデコードできないためです。しかしながら、以下のような Burp プラグインを利用できます。

- [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension")
- [Mitm-relay](https://github.com/jrmdev/mitm_relay "Mitm-relay")

これらのプラグインは非 HTTP プロトコルを視覚化することができ、トラフィックを傍受および操作することもできます。

このセットアップは非常に面倒になることがあり、HTTP をテストするほど簡単ではないことに注意します。

## アプリプロセスからのトラフィックの傍受

アプリのテスト時の目的によりますが、ネットワーク層に届く前やアプリでレスポンスを受信する際のトラフィックを監視すれば十分なこともあります。

特定の機密データがネットワークに転送されているかどうかを知りたいだけなら、本格的な MITM 攻撃を展開する必要はありません。この場合、もし実装されていても、ピンニングをバイパスする必要はありません。openssl の `SSL_write` and `SSL_read` などの適切な関数をフックしなければならないだけです。

これは標準 API ライブラリ関数やクラスを使用するアプリではかなりうまく機能しますが、いくつかの欠点があります。

- アプリがカスタムネットワークスタックを実装している可能性がある場合、使用できる API を見つけるためにアプリの解析に時間を費やさなければならないかもしれません ([このブログ投稿](https://hackmag.com/security/ssl-sniffing/) の "Searching for OpenSSL traces with signature analysis" セクションを参照してください ) 。
- (多くのメソッドコールと実行スレッドにまたがる) HTTP レスポンスペアを再アセンブルするための適切なフックスクリプトを作成するのは非常に時間がかかることがあります。 [既製のスクリプト](https://github.com/fanxs-t/Android-SSL_read-write-Hook/blob/master/frida-hook.py) や [代替ネットワークスタック](https://codeshare.frida.re/@owen800q/okhttp3-interceptor/) もありますが、アプリやプラットフォームによってはこれらのスクリプトは多くのメンテナンスが必要かもしれず、 _常に機能する_ とは限りません。

例をいくつかご覧ください。

- ["Universal interception. How to bypass SSL Pinning and monitor traffic of any application"](https://hackmag.com/security/ssl-sniffing/), "Grabbing payload prior to transmission" および "Grabbing payload prior to encryption" のセクション
- ["Frida as an Alternative to Network Tracing"](https://gaiaslastlaugh.medium.com/frida-as-an-alternative-to-network-tracing-5173cfbd7a0b)

> この技法は BLE, NFC など MITM 攻撃の展開に非常にコストがかかったり複雑になる可能性がある他のタイプのトラフィックにも有効です。

## ネットワーク層でのトラフィックの傍受

傍受プロキシを使用することによる動的解析は、標準ライブラリがアプリで使用され、すべての通信が HTTP 経由で行われる場合には簡単です。しかしこれが動作しないいくつかのケースがあります。

- システムプロキシ設定を無視する [Xamarin](https://www.xamarin.com/platform "Xamarin") などのモバイルアプリケーション開発プラットフォームが使用されている場合。
- モバイルアプリケーションがシステムプロキシが使用されているかどうかを確認し、プロキシを介してリクエストを送信することを拒否する場合。
- Android の GCM/FCM などのプッシュ通信を傍受したい場合。
- XMPP や他の非 HTTP プロトコルが使用されている場合。

このような場合は、次に何をすべきかを決めるために、まずネットワークトラフィックを監視および解析する必要があります。幸いにも、ネットワーク通信をリダイレクトおよび傍受するための選択肢がいくつかあります。

- トラフィックをホストコンピュータにルーティングします。ホストコンピュータをネットワークゲートウェイとして設定します。例えば、オペレーティングシステムに内蔵のインターネット共有機能を使用します。それから、[Wireshark](0x08a-Testing-Tools.md#wireshark) を使用して、モバイルデバイスからの任意のトラフィックを傍受できます。
- 場合によっては MITM 攻撃を実行してモバイルデバイスに強制的に会話させる必要があります。このシナリオではモバイルデバイスからホストコンピュータにネットワークトラフィックをリダイレクトするために [bettercap](0x08a-Testing-Tools.md#bettercap) または独自のアクセスポイントを検討する必要があります (下図参照) 。
- ルート化デバイスでは、フックやコードインジェクションを使用して、ネットワーク関連の API コール (HTTP リクエストなど) を傍受したり、これらのコールの引数をダンプしたり操作することも可能です。これにより実際のネットワークデータを検査する必要がなくなります。これらの技法については「リバースエンジニアリングと改竄」の章で詳しく説明します。
- macOS では、iOS デバイスのすべてのトラフィックを傍受するために "Remote Virtual Interface" を作成できます。「iOS アプリのテスト環境構築」の章でこの手法を説明します。

### bettercap による中間者攻撃のシミュレーション

#### ネットワークのセットアップ

中間者のポジションを得るには、モバイルフォンおよびそれと通信するゲートウェイと同じワイヤレスネットワークにホストコンピュータがある必要があります。これが完了するとモバイルフォンの IP アドレスが必要です。モバイルアプリの完全な動的解析には、すべてのネットワークトラフィックを傍受する必要があります。

### MITM 攻撃

まずお好みのネットワーク解析ツールを起動し、次に以下のコマンドで IP アドレス (X.X.X.X) を MITM 攻撃を実行したいターゲットに置き換えて [bettercap](0x08a-Testing-Tools.md#bettercap) を実行します。

```bash
$ sudo bettercap -eval "set arp.spoof.targets X.X.X.X; arp.spoof on; set arp.spoof.internal true; set arp.spoof.fullduplex true;"
bettercap v2.22 (built for darwin amd64 with go1.12.1) [type 'help' for a list of commands]

[19:21:39] [sys.log] [inf] arp.spoof enabling forwarding
[19:21:39] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets.
```

bettercap は自動的にパケットを (ワイヤレス) ネットワークのネットワークゲートウェイに送信します。あなたはそのトラフィックを盗聴できます。2019年の初めに [全二重 ARP スプーフィング](https://github.com/bettercap/bettercap/issues/426 "Full Duplex ARP Spoofing") サポートが bettercap に追加されました。

モバイルフォンでブラウザを起動して `http://example.com` に移動すると、Wireshark を使用している場合には以下のような出力が表示されるはずです。

<img src="Images/Chapters/0x04f/bettercap.png" width="100%" />

それで、モバイルフォンで送受信される完全なネットワークトラフィックを確認できるようになります。これには DNS, DHCP およびその他の形式の通信も含まれるため、非常に「ノイズが多い」かもしれません。したがって、関連するトラフィックだけに集中するために、[Wireshark の DisplayFilter](https://wiki.wireshark.org/DisplayFilters "DisplayFilters") の使い方や [tcpdump でフィルタする方法](https://danielmiessler.com/study/tcpdump/#gs.OVQjKbk "A tcpdump Tutorial and Primer with Examples") を知る必要があります。

> 中間者攻撃は ARP スプーフィングを通じて OSI レイヤ 2 上で攻撃が実行されるため、あらゆるデバイスやオペレーティングシステムに対して機能します。あなたが MITM である場合、通過するデータは TLS を使用して暗号化されている可能性があるため、平文データを見ることができないかもしれません。しかし、それは関与するホスト、使用されるプロトコルおよびアプリが通信しているポートに関する貴重な情報をあなたに提供します。

### アクセスポイントを使用した中間者攻撃のシミュレーション

#### ネットワークのセットアップ

中間者 (MITM) 攻撃をシミュレートする簡単な方法は、スコープ内のデバイスとターゲットネットワーク間のすべてのパケットがホストコンピュータを通過するネットワークを構成することです。モバイルペネトレーションテストでは、モバイルデバイスとホストコンピュータが接続されているアクセスポイントを使用して実現できます。そうしてホストコンピュータがルータおよびアクセスポイントになります。

以下のシナリオが可能です。

- ホストコンピュータの内蔵 WiFi カードをアクセスポイントとして使用し、有線接続を使用してターゲットネットワークに接続します。
- 外部 USB WiFi カードをアクセスポイントとして使用し、ホストコンピュータの内蔵 WiFi を使用してターゲットネットワークに接続します (逆も可能です) 。
- 別のアクセスポイントを使用し、トラフィックをホストコンピュータにリダイレクトします。

外部 WiFi カードを使用するシナリオではカードがアクセスポイントを作成する機能が必要です。さらに、いくつかのツールをインストールするかネットワークを構成して中間者ポジションとなる必要があります (下記参照) 。Kali Linux で `iwconfig` コマンドを使用して、WiFi カードに AP 機能があるかどうかを確認できます。

```bash
iw list | grep AP
```

別のアクセスポイントを使用するシナリオでは AP の構成にアクセスする必要があります。AP が以下のいずれかをサポートしているかどうかを最初に確認する必要があります。

- ポートフォワーディングまたは
- スパンまたはミラーポートを持っている。

どちらの場合もホストコンピュータの IP を指すように AP を構成する必要があります。ホストコンピュータは (有線接続または WiFi を介して) AP に接続する必要があり、ターゲットネットワークに接続する必要があります (AP と同じ接続でもかまいません) 。ターゲットネットワークにトラフィックをルーティングするにはホストコンピュータに追加の構成が必要になる場合があります。

> 別のアクセスポイントがお客様のものである場合、変更を行う前に、すべての変更と構成をエンゲージメントの前に明確にし、バックアップを作成する必要があります。

<img src="Images/Chapters/0x04f/architecture_MITM_AP.png" width="100%" />

#### インストール

以下の手順はアクセスポイントと追加のネットワークインタフェースを使用して中間者ポジションをセットアップしています。

別のアクセスポイント、外部 USB WiFi カード、またはホストコンピュータの内蔵カードのいずれかを使用して WiFi ネットワークを作成します。

これは macOS のビルトインユーティリティを使用して実行できます。[Mac のインターネット接続を他のネットワークユーザーと共有する](https://support.apple.com/en-ke/guide/mac-help/mchlp1540/mac "Share the internet connection on Mac with other network users") を使用できます。

すべての主要な Linux および Unix オペレーティングシステムでは以下のようなツールが必要です。

- hostapd
- dnsmasq
- iptables
- wpa_supplicant
- airmon-ng

Kali Linux ではこれらのツールを `apt-get` でインストールできます。

```bash
apt-get update
apt-get install hostapd dnsmasq aircrack-ng
```

> iptables と wpa_supplicant は Kali Linux にデフォルトでインストールされています。

別のアクセスポイントの場合、トラフィックをホストコンピュータにルーティングします。外部 USB WiFi カードまたは内蔵 WiFi カードの場合、トラフィックはすでにホストコンピュータで利用可能です。

WiFi からの着信トラフィックを、トラフィックがターゲットネットワークに到達できる追加のネットワークインタフェースにルーティングします。追加のネットワークインタフェースは、セットアップに応じて有線接続または他の WiFi カードにできます。

#### 構成

Kali Linux の構成ファイルにフォーカスします。以下の値を定義する必要があります。

- wlan1 - AP ネットワークインタフェースの ID (AP 機能あり)
- wlan0 - ターゲットネットワークインタフェースの ID (これは有線インタフェースまたは他の WiFi カードにできます)
- 10.0.0.0/24 - AP ネットワークの IP アドレスとマスク

以下の構成ファイルを変更し適宜に調整する必要があります。

- hostapd.conf

    ```bash
    # Name of the WiFi interface we use
    interface=wlan1
    # Use the nl80211 driver
    driver=nl80211
    hw_mode=g
    channel=6
    wmm_enabled=1
    macaddr_acl=0
    auth_algs=1
    ignore_broadcast_ssid=0
    wpa=2
    wpa_key_mgmt=WPA-PSK
    rsn_pairwise=CCMP
    # Name of the AP network
    ssid=STM-AP
    # Password of the AP network
    wpa_passphrase=password
    ```

- wpa_supplicant.conf

    ```bash
    network={
        ssid="NAME_OF_THE_TARGET_NETWORK"
        psk="PASSWORD_OF_THE_TARGET_NETWORK"
    }
    ```

- dnsmasq.conf

    ```bash
    interface=wlan1
    dhcp-range=10.0.0.10,10.0.0.250,12h
    dhcp-option=3,10.0.0.1
    dhcp-option=6,10.0.0.1
    server=8.8.8.8
    log-queries
    log-dhcp
    listen-address=127.0.0.1
    ```

#### MITM 攻撃

中間者ポジションを取得できるためには上記の構成を実行する必要があります。これは Kali Linux 上で以下のコマンドを使用して実行できます。

```bash
# check if other process is not using WiFi interfaces
$ airmon-ng check kill
# configure IP address of the AP network interface
$ ifconfig wlan1 10.0.0.1 up
# start access point
$ hostapd hostapd.conf
# connect the target network interface
$ wpa_supplicant -B -i wlan0 -c wpa_supplicant.conf
# run DNS server
$ dnsmasq -C dnsmasq.conf -d
# enable routing
$ echo 1 > /proc/sys/net/ipv4/ip_forward
# iptables will NAT connections from AP network interface to the target network interface
$ iptables --flush
$ iptables --table nat --append POSTROUTING --out-interface wlan0 -j MASQUERADE
$ iptables --append FORWARD --in-interface wlan1 -j ACCEPT
$ iptables -t nat -A POSTROUTING -j MASQUERADE
```

これでモバイルデバイスをアクセスポイントに接続できます。

### ネットワーク解析ツール

ホストコンピュータにリダイレクトされるネットワークトラフィックを監視および解析できるツールをインストールします。もっとも一般的な二つのネットワーク監視 (またはキャプチャ) ツールは以下の通りです。

- [Wireshark](https://www.wireshark.org "Wireshark") (CLI pendant: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html "TShark"))
- [tcpdump](https://www.tcpdump.org/tcpdump_man.html "tcpdump")

Wireshark には GUI があり、コマンドラインに慣れていないのであれば簡単です。コマンドラインツールを探しているのであれば TShark または tcpdump を使用する必要があります。これらのツールはいずれも、すべての主要な Linux および Unix オペレーティングシステムで利用可能であり、それぞれのパッケージインストールメカニズムの一部です。

### 実行時計装によるプロキシの設定

ルート化または脱獄済みデバイスでは、ランタイムフックを使用して、新しいプロキシを設定したりネットワークトラフィックをリダイレクトすることが可能です。これは [Inspeckage](https://github.com/ac-pm/Inspeckage "Inspeckage") などのフックツールや [Frida](https://www.frida.re "Frida") および [cycript](http://www.cycript.org "cycript") などのコードインジェクションフレームワークで実現できます。実行時計装についての詳細はこのガイドの「リバースエンジニアリングと改竄」の章で参照できます。

### 例 - Xamarin の扱い

例として、すべてのリクエストを Xamarin アプリから傍受プロキシにリダイレクトしてみます。

Xamarin は Visual Studio と C# をプログラミング言語として使用して [ネイティブ Android](https://docs.microsoft.com/en-us/xamarin/android/get-started/ "Getting Started with Android") および [iOS アプリ](https://docs.microsoft.com/en-us/xamarin/ios/get-started/ "Getting Started with iOS") を作成できるモバイルアプリケーション開発プラットフォームです。

Xamarin アプリをテストするときに Wi-Fi 設定でシステムプロキシを設定しようとすると、傍受プロキシで HTTP リクエストを見ることができなくなります。Xamarin により作成されたアプリはスマホのローカルプロキシ設定を使用しないためです。これを解決する方法は三つあります。

- 第一の方法: [アプリにデフォルトプロキシ](https://developer.xamarin.com/api/type/System.Net.WebProxy/ "System.Net.WebProxy Class") を追加します。`OnCreate` または `Main` に以下のコードを追加してアプリを再作成します。

    ```cs
    WebRequest.DefaultWebProxy = new WebProxy("192.168.11.1", 8080);
    ```

- 第二の方法: bettercap を使用して中間者ポジション (MITM) を取得します。MITM 攻撃のセットアップ方法については上記のセクションを参照してください。MITM であれば、ポート 443 を localhost 上で動作する傍受プロキシにリダイレクトするだけです。これは macOS で `rdr` コマンドを使うことにより行えます。

    ```bash
    $ echo "
    rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
    " | sudo pfctl -ef -
    ```

    Linux システムでは `iptables` を使用できます。

    ```bash
    sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8080
    ```

    最後のステップとして、 [Burp Suite](0x08a-Testing-Tools.md#burp-suite) の listener settings で 'Support invisible proxy' をセットする必要があります。

- 第三の方法: bettercap の代わりのものでモバイルフォンの `/etc/hosts` を調整します。 `/etc/hosts` にターゲットドメインのエントリを追加し、傍受プロキシの IP アドレスをポイントします。これにより bettercap と同様に MITM となる状況を生成します。傍受プロキシで使用されるポートにポート 443 をリダイレクトする必要があります。リダイレクトは上述のように適用できます。さらに、トラフィックを傍受プロキシから元のロケーションとポートにリダイレクトする必要があります。

> トラフィックをリダイレクトする際、ノイズとスコープ外のトラフィックを最小限に抑えるために、スコープ内のドメインと IP を狭めるルールを作成する必要があります。

傍受プロキシは上記のポートフォワーディングルールで指定されたポート 8080 をリッスンする必要があります。

Xamarin アプリがプロキシを使用 (例えば `WebRequest.DefaultWebProxy` を使用) するように設定されている場合、トラフィックを傍受プロキシにリダイレクトした後、次にトラフィックを送信すべき場所を指定する必要があります。そのトラフィックを元のロケーションにリダイレクトする必要があります。以下の手順は [Burp](0x08a-Testing-Tools.md#burp-suite) で元のロケーションへのリダイレクトを設定しています。

1. **Proxy** タブに移動し、**Options** をクリックします。
2. proxy listeners のリストからリスナーを選択して編集します。
3. **Request handling** タブに移動して以下をセットします。

    - Redirect to host: 元のトラフィックロケーションを指定します。
    - Redirect to port: 元のポートロケーションを指定します。
    - 'Force use of SSL' をセット (HTTPS 使用時) および 'Support invisible proxy' をセットします。

<img src="Images/Chapters/0x04f/burp_xamarin.png" width="100%" />

#### CA 証明書

まだ行われていなければ、HTTPS リクエストの傍受を許可するモバイルデバイスに CA 証明書をインストールします。

- [Android フォンに傍受プロキシの CA 証明書をインストールする](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp\'s CA Certificate in an Android Device")
    > Android 7.0 (API level 24) 以降、アプリで指定されていない限り、OS はもはやユーザー指定の CA 証明書を信頼しないことに注意します。このセキュリティ対策の回避については、「セキュリティテスト入門」の章で説明します。
- [iOS フォンに傍受プロキシの CA 証明書をインストールする](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp")

#### トラフィックの傍受

アプリの使用を開始し、その機能を動かします。傍受プロキシに HTTP メッセージが表示されるはずです。

> bettercap を使用する場合は、Proxy タブ / Options / Edit Interface で "Support invisible proxying" を有効にする必要があります

## 参考情報

### OWASP MASVS

- MSTG-NETWORK-1: "データはネットワーク上でTLSを使用して暗号化されている。セキュアチャネルがアプリ全体を通して一貫して使用されている。"
- MSTG-NETWORK-2: "TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨される標準規格をサポートしていない場合には可能な限り近い状態である。"
