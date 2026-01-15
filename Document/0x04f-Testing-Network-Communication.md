---
masvs_category: MASVS-NETWORK
platform: all
---

# モバイルアプリのネットワーク通信

ネットワークに接続されたほとんどすべてのモバイルアプリは、リモートエンドポイントとデータを交換するために、Hypertext Transfer Protocol (HTTP) またはその安全なバージョンである HTTPS (Transport Layer Security, TLS を使用) に依存しています。安全に実装されていない場合、この通信はパケットスニッフィングや中間マシン (Machine-in-the-Middle, MITM) 攻撃などのネットワークベースの攻撃に対して脆弱になる可能性があります。この章では、潜在的な脆弱性、テスト技法、モバイルアプリのネットワーク通信を保護するためのベストプラクティスについて説明します。

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
- アプリがピンニングを実装していない場合、これは脆弱性として報告すべきではありません。ただし、MAS-L2 に対する検証を行わなければならない場合には実装しなければなりません。
- Android と iOS のいずれもピンニングの実装は非常に簡単であり、ベストプラクティスに沿っています。
- ピンニングはデバイスにインストールされている侵害された CA や悪意のある CA から保護します。そのようなケースでは、ピンニングは OS が悪意のあるサーバーとセキュア接続を確立することを防ぎます。しかし、攻撃者がデバイスをコントロールしている場合、簡単にピンニングロジックを無効して、接続を行うことが依然として可能です。結果として、攻撃者がバックエンドにアクセスして、サーバー側の脆弱性を悪用することを防ぐことはできません。
- モバイルアプリのピンニングは HTTP Public Key Pinning (HPKP) と同じではありません。HPKP ヘッダはユーザーがウェブサイトからロックアウトされ、ロックアウトを解除する方法がないことから、ウェブサイトでは推奨されなくなりました。モバイルアプリでは、なんらかの問題があっても帯域外チャネル (つまりアプリストア) を通じて常にアプリを更新できるため、これは問題ではありません。

#### Android 開発者のピンニング推奨事項について

[Android Developers](https://developer.android.com/training/articles/security-ssl#Pinning) サイトには以下の警告が記されています。

> 注意: 証明書ピンニングは別の認証局に変更するなどの将来的なサーバー構成の変更により、クライアントソフトウェアの更新を受けることなくアプリケーションがサーバーに接続できなくなるリスクが高いため、Android アプリケーションには推奨されません。

またこのような [注釈](https://developer.android.com/training/articles/security-config#CertificatePinning) もあります。

> [!NOTE]
> 証明書のピン留めを使用するときは、必ずバックアップの鍵を含めてください。そうすれば、新しい鍵に切り替えたり、CA を変更したりする必要が生じた場合に（CA 証明書またはその CA の中間証明書にピン留めしていても）、アプリの接続が影響を受けることはありません。そうしないと、接続を復元するためにアプリにアップデートをプッシュしなければならなくなります。

最初の文は「証明書ピンニングを推奨しない」と言っているものと誤解される可能性があります。二つ目の文でこれを明らかにしています。実際の推奨事項は、開発者がピンニングを実装したい場合には必要な予防措置を講じなければならない、ということです。

#### Apple 開発者のピンニング推奨事項について

Apple は [長期的に考えること](https://developer.apple.com/news/?id=g9ejcf8y) と [適切なサーバー認証戦略を立てること](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication#2956135) を推奨しています。

#### OWASP MASTG の推奨事項

特に MAS-L2 アプリで、ピンニングをお勧めします。ただし、開発者は自分の管理下にあるエンドポイントに限定して実装し、バックアップ鍵 (別名、バックアップピン) を含めるようにし、適切なアプリ更新戦略を持つようにしなければなりません。

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

クライアントとサーバーの両方が同じ組織により制御され、互いに通信するためだけに使用される場合、[設定を堅牢にすること](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices "Qualys SSL/TLS Deployment Best Practices") によりセキュリティを向上できます。

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
- `DHE` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631") - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE` - [RFC 4492](https://tools.ietf.org/html/rfc4492 "RFC 4492")
- `PSK` - [RFC 4279](https://tools.ietf.org/html/rfc4279 "RFC 4279")
- `DSS` - [FIPS186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf "FIPS186-4")
- `DH_anon` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631") - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_RSA` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631") - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_DSS` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631") - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE_ECDSA` - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")
- `ECDHE_PSK`  - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422") - [RFC 5489](https://tools.ietf.org/html/rfc5489 "RFC 5489")
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
- `CHACHA20_POLY1305`  - [RFC 7905](https://tools.ietf.org/html/rfc7905 "RFC 7905") - [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539")

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

最後に、HTTPS 接続が終了するサーバーや終端プロキシがベストプラクティスにしたがって構成されていることを検証します。 [OWASP Transport Layer Protection cheat sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md "Transport Layer Protection Cheat Sheet") および [Qualys SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices "Qualys SSL/TLS Deployment Best Practices") も参照してください。

## MITM によるネットワークトラフィックの傍受

モバイルアプリのトラフィックを傍受することはセキュリティテストの側面であり、テスト担当者、アナリスト、ペネトレーションテスト担当者がネットワーク通信を解析および操作して脆弱性を特定できるようにします。このプロセスで重要な技法は **中間マシン (Machine-in-the-Middle, MITM)** 攻撃 (["中間者 (Man-in-the-Middle)"](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) (従来)、"中間敵対者 (Adversary-in-the-Middle)" ([MITRE](https://attack.mitre.org/techniques/T1638/) や [CAPEC](https://capec.mitre.org/data/definitions/94.html) などによる) とも呼ばれます) です。_攻撃者_ は自分のマシンを二つの通信エンティティ、通常はモバイルアプリ (クライアント) とそれが通信するサーバー、の間に配置します。そうすることで、攻撃者のマシンはさまざまな当事者間で送信されるデータを傍受して監視します。

この技法には二つの側面があります。

- 通常、どちらの当事者 (アプリまたはサーバー) に気付かれることなく通信を傍受、監視、潜在的に改変するために **悪意のある攻撃者によって使用されます**。これは、盗聴、悪意のあるコンテンツの注入、交換されるデータの操作などの悪意のあるアクティビティを可能にします。
- しかし、**OWASP MASTG** とモバイルアプリセキュリティテスト **のコンテキストでは**、アプリテスト担当者がトラフィックをレビュー、解析、変更するための技法の一部として使用し、暗号化されていない通信や弱いセキュリティコントロールなどの脆弱性を特定できます。

使用される具体的な傍受方法はアプリのセキュリティメカニズムと送信されるデータの性質によって異なります。各アプローチは、暗号化や、妨害に対する耐性などの要素に応じて、複雑さや有効性が異なります。

さまざまなネットワーク層での傍受技法の概要は以下のとおりです。

| **傍受技法** | **ツール例** | **備考** |
|--------------|--------------|----------|
| API フック (`HttpUrlConnection`, `NSURLSession`, `WebRequest`) | Frida | アプリがネットワークリクエストを処理する方法を変更します。 |
| TLS 関数のフック (`SSL_read`, `SSL_write`) | Frida, SSL Kill Switch | 暗号化データがアプリに到達する前に傍受します。 |
| プロキシ傍受 | Burp Suite, ZAP, mitmproxy | アプリがプロキシ設定を尊重する必要があります。 |
| パケットスニッフィング | `tcpdump`, Wireshark | **すべての** TCP/UDP をキャプチャしますが HTTPS を復号 **しません**。 |
| ARP スプーフィングによる MITM | bettercap | ネットワークが攻撃者によって制御されていない場合でも、デバイスを騙して攻撃者のマシン経由でトラフィックを送信します。 |
| 不正な Wi-Fi AP | `hostapd`, `dnsmasq`, `iptables`, `wpa_supplicant`, `airmon-ng` | 攻撃者によって完全に制御されているアクセスポイントを使用します。 |

これらの技法の詳細については、それぞれの技法のページにあります。

- [アプリケーション層でネットワーク API をフックして HTTP トラフィックを傍受する (Intercepting HTTP Traffic by Hooking Network APIs at the Application Layer)](../techniques/generic/MASTG-TECH-0119.md)
- [傍受プロキシを使用して HTTP トラフィックを傍受する (Intercepting HTTP Traffic Using an Interception Proxy)](../techniques/generic/MASTG-TECH-0120.md)
- [傍受プロキシを使用して非 HTTP トラフィックを傍受する (Intercepting Non-HTTP Traffic Using an Interception Proxy)](../techniques/generic/MASTG-TECH-0121.md)
- [受動的な盗聴 (Passive Eavesdropping)](../techniques/generic/MASTG-TECH-0122.md)
- [ARP スプーフィングによる MITM ポジションを獲得する (Achieving a MITM Position via ARP Spoofing)](../techniques/generic/MASTG-TECH-0123.md)
- [不正アクセスポイントを使用して MITM ポジションを獲得する (Achieving a MITM Position Using a Rogue Access Point)](../techniques/generic/MASTG-TECH-0124.md)

**証明書ピン留めに関する注意:** アプリが証明書ピン留めを使用している場合、トラフィックの傍受を開始すると上記の技法は失敗するように見えるかもしれませんが、別の手法を使用してバイパスできます。詳細については以下の技法を参照してください。

- Android: [証明書ピン留めのバイパス (Bypassing Certificate Pinning)](../techniques/android/MASTG-TECH-0012.md)
- iOS: [証明書ピン留めのバイパス (Bypassing Certificate Pinning)](../techniques/ios/MASTG-TECH-0064.md)
