## ネットワーク通信のテスト (iOS アプリ)

Almost every every iOS app acts as a client to one or more remote services. As this network communcation usually takes place of the public Internet, and often over unstrusted networks such as public Wifi, classical, network based-attacks become a potential issue.

Most modern mobile apps use variants of http-based (web-)services, as these protocols are well-documented and supported. On iOS, the The <code>NSURLConnection</code> class provides convenience class methods to load URL requests asynchronously and synchronously.

### App Transport Security のテスト

#### 概要

App Transport Security (ATS) <sup>[1]</sup> は NSURLConnection <sup>[2]</sup>, NSURLSession <sup>[3]</sup>, CFURL <sup>[4]</sup> でパブリックホスト名に接続する際にオペレーティングシステムが強制する一連のセキュリティチェックです。iOS SDK 9 および以降のアプリケーションビルドでは ATS がデフォルトで有効になっています。

ATS はパブリックホスト名に接続する際にのみ強制されます。したがって、IP アドレス、不完全なドメイン名、.local の TLD への接続は ATS で保護されません。

以下は App Transport Security Requirements <sup>[1]</sup> の要約リストです。

- HTTP 接続は許可されない
- X.509 証明書には SHA256 フィンガープリントがあり、少なくとも 2048 ビットの RSA 鍵または 256 ビットの楕円曲線暗号 (ECC) 鍵で署名する必要がある。
- Transport Layer Security (TLS) バージョンは 1.2 もしくは以降が必要であり、Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) 鍵交換による Perfect Forward Secrecy (PFS) および AES-128 もしくは AES-256 対称暗号をサポートする必要がある。

暗号スイートは以下のいずれかが必要である。

* `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
* `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
* `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`
* `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`
* `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`
* `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`
* `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
* `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
* `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`
* `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`
* `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`

##### ATS 例外

ATS の制限は Info.plist ファイルの `NSAppTransportSecurity` キーに例外を設定することで無効にできます。これらの例外には以下があります。
* 安全でない接続の許可 (HTTP)
* 最小 TLS バージョンの引き下げ
* PFS の無効化
* ローカルドメインへの接続の許可

ATS exceptions can be applied globally or per domain basis. The application can globally disable ATS, but opt in for individual domains. The following listing from Apple Developer documentation shows the structure of the `NSAppTransportSecurity` dictionary<sup>[1]</sup>.

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
Source: Apple Developer Documentation<sup>[1]</sup>.

The following table summarises the global ATS exceptions. For more information about these exceptions, please refer to Table 2 in reference [1].

|  Key | Description |
| -----| ------------|
| `NSAllowsArbitraryLoads` | Disable ATS restrictions globally excepts for individual domains specified under `NSExceptionDomains` |
| `NSAllowsArbitraryLoadsInWebContent` | Disable ATS restrictions for all the connections made from web views |
| `NSAllowsLocalNetworking` | Allow connection to unqualified domain names and .local domains |
| `NSAllowsArbitraryLoadsForMedia` | Disable all ATS restrictions for media loaded through the AV Foundations framework |


The following table summarises the per-domain ATS exceptions. For more information about these exceptions, please refer to Table 3 in reference [1].

|  Key | Description |
| -----| ------------|
| `NSIncludesSubdomains` | Indicates whether ATS exceptions should apply to subdomains of the named domain |
| `NSExceptionAllowsInsecureHTTPLoads` | Allows HTTP connections to the named domain, but does not affect TLS requirements |
| `NSExceptionMinimumTLSVersion` | Allows connections to servers with TLS versions less than 1.2 |
| `NSExceptionRequiresForwardSecrecy` | Disable perfect forward secrecy (PFS) |


Starting from January 1 2017, Apple App Store review and requires justification if one of the following ATS exceptions are defined. However this decline is extended later by Apple stating “To give you additional time to prepare, this deadline has been extended and we will provide another update when a new deadline is confirmed”<sup>[5]</sup>

* `NSAllowsArbitraryLoads`
* `NSAllowsArbitraryLoadsForMedia`
* `NSAllowsArbitraryLoadsInWebContent`
* `NSExceptionAllowsInsecureHTTPLoads`
* `NSExceptionMinimumTLSVersion`

#### 静的解析

If the source code is available, open then `Info.plist` file in the application bundle directory using a text editor and look for any exceptions that the application developer has configured. This file should be examined taking the applications context into consideration. 

The following listing is an example of an exception configured to disable ATS restrictions globally. 

```
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
	</dict>
```

If the source code is not available, then the `Info.plist` file should be either can be obtained from a jailbroken device or by extracting the application IPA file.

Since IPA files are ZIP archives, they can be extracted using any zip utility.

```
$ unzip app-name.ipa
```

`Info.plist` file can be found in the `Payload/BundleName.app/` directory of the extract. It’s a binary encoded file and has to be converted to a human readable format for the analysis. 

`plutil`<sup>[6]</sup> is a tool that’s designed for this purpose. It comes natively with Mac OS 10.2 and above versions.

The following command shows how to convert the Info.plist file into XML format.
```
$ plutil -convert xml1 Info.plist
```

Once the file is converted to a human readable format, the exceptions can analysed. The application may have ATS exceptions defined to allow it’s normal functionality. For an example, the Firefox iOS application has ATS disabled globally. This exception is acceptable because otherwise the application would not be able to connect to any HTTP web sites or website that do not have the ATS requirements.


#### 動的解析

--TODO

#### 改善方法
* ATS should always be activated and only be deactivated under certain circumstances.
* If the application connects to a defined number of domains that the application owner controls, then configure the servers to support the ATS requirements and opt-in for the ATS requirements within the app. In the following example, `example.com` is owned by the applicaiton owner and ATS is enabled for that domain.
```
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

* If connections to 3rd party domains are made (that are not under control of the app owner) it should be evaluated what ATS settings are not supported by the 3rd party domain and deactivated.
* If the application opens third party web sites in web views, then from iOS 10 onwards NSAllowsArbitraryLoadsInWebContent can be used to disable ATS restrictions for the content loaded in web views 

#### 参考情報

— TODO —

##### OWASP Mobile Top 10 2016

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

* V5.1: "データはネットワーク上でTLSを使用して暗号化されている。セキュアチャネルがアプリ全体を通して一貫して使用されている。"
* V5.2: "TLS 設定は現在のベストプラクティスと一致している。モバイルオペレーティングシステムが推奨された標準をサポートしていない場合には可能な限り近い状態である。"

##### CWE

— TODO —

##### その他

* [1] Information Property List Key Reference: Cocoa Keys - https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html
* [2] API Reference NSURLConnection - https://developer.apple.com/reference/foundation/nsurlconnection
* [3] API Reference NSURLSession - https://developer.apple.com/reference/foundation/urlsession
* [4] API Reference CFURL - https://developer.apple.com/reference/corefoundation/cfurl-rd7
* [5] Apple Developer Portal Announcement - Supporting App Transport Security - https://developer.apple.com/news/?id=12212016b
* [6] OS X Man Pages - Plutil - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/plutil.1.html

##### ツール

— TODO —

### エンドポイント同一性検証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Endpoint Identity Verification".]

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Add content on "Testing Endpoint Identity Verification" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Endpoint Identity Verification" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Endpoint Identity Verification".] --

#### 参考情報

#### OWASP Mobile Top 10 2016

* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS

* V5.3: "セキュアチャネルが確立されたときに、アプリはリモートエンドポイントのX.509証明書を確認している。有効なCAにより署名された証明書のみが受け入れられている。"

##### CWE

* CWE-296 - Improper Following of a Certificate's Chain of Trust - https://cwe.mitre.org/data/definitions/296.html
* CWE-297 - Improper Validation of Certificate with Host Mismatch - https://cwe.mitre.org/data/definitions/297.html
* CWE-298 - Improper Validation of Certificate Expiration - https://cwe.mitre.org/data/definitions/298.html

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing Endpoint Identity Verification"] --


### カスタム証明書ストアおよび SSL ピンニングのテスト

#### 概要

証明書ピンニングはサーバーで使用されていることが分かっている証明書をクライアントにハードコードします。この技法は不正な CA や CA の侵害の脅威を軽減するために使用されます。サーバーの証明書をピンニングするとそれらの CA はゲーム終了となります。証明書ピンニングを実装するモバイルアプリケーションでは限られた数のサーバーにのみ接続します。そのため、信頼できる CA やサーバー証明書の小さなリストをアプリケーションにハードコードします。

#### 静的解析

以下に示すコードはサーバーによって提供された証明書がアプリケーションにハードコードされた証明書を反映しているかどうかを確認する方法を示しています。以下のメソッドは接続認証を実装して、接続が認証チャレンジの要求を送信することをデリゲートに通知します。

デリゲートは connection:canAuthenticateAgainstProtectionSpace: と connection: forAuthenticationChallenge を実装する必要があります。connection: forAuthenticationChallenge では、デリゲートは SecTrustEvaluate をコールして一般的な X509 チェックを実行する必要があります。以下は証明書のチェックを実装するスニペットです。

```Objective-C
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

#### 動的解析

##### サーバー証明書の検証

セキュアな接続を確立する中でアプリケーションの動作をテストすることで解析を開始します。テストアプローチは SSL ハンドシェイクネゴシエーションのセキュリティを少しずつ緩めて、どのセキュリティメカニズムが有効であるかを確認することです。

1. Wi-Fi 設定でプロキシとして設定された burp を使用する場合、トラストストア (設定 -> 一般 -> プロファイル) に証明書が追加されていること、および SSL キルスイッチなどのツールが無効であることを確認します。アプリケーションを起動して、Burp にトラフィックが表示されるかどうかを確認します。問題がある場合は 'Alerts' タブに報告されます。トラフィックが表示される場合、証明書検証がまったく実行されていないことを意味します。これは事実上アクティブな攻撃者があなたのアプリケーションに対して静かに MiTM を実行できることを意味します。そうではなければ、トラフィックは表示されておらず SSL ハンドシェイク失敗に関する情報があります。次の点に従います。
2. 次に、[セキュリティテスト入門 セクション](./0x06b-Basic-Security-Testing.md) で説明されているように、Burp 証明書をインストールします。ハンドシェイクが成功して Burp にトラフィックが表示されている場合、デバイスのトラストストアに対して証明書が検証されているが、ピンニングが実行されていないことを意味します。[セキュリティテスト入門 セクション](./0x06b-Basic-Security-Testing.md) で説明されているように、この時点での2つの主な攻撃シナリオは不正な CA とフィッシング攻撃であるため、リスクは以前のシナリオほどではありません。
3. 前のステップでの指示を実行してもトラフィックが burp 経由でプロキシされない場合、証明書は実際にピンされ、すべてのセキュリティ対策が実行されていることを意味します。但し、アプリケーションをテストするには依然としてピンニングをバイパスする必要があります。詳細については、[セキュリティテスト入門 セクション](./0x06b-Basic-Security-Testing.md) を参照ください。

##### クライアント証明書の検証

アプリケーションによっては双方向 SSL ハンドシェイクを使用するものがあります。つまり、アプリケーションがサーバーの証明書を検証し、サーバーがクライアントの証明書を検証します。Burp 'Alerts' タブにクライアントが接続のネゴシエーションに失敗したことを示すエラーがあるかどうかを確認します。

注目すべきことがいくつかあります。

1. クライアント証明書には鍵交換で使用される秘密鍵が含まれています
2. 一般的に証明書には使用(復号)するためにパスワードも必要です
3. 証明書自体はバイナリ自体、データディレクトリ、もしくはキーチェーンに格納されます

双方向ハンドシェイクを行う最も一般的で不適切な方法は、アプリケーションバンドル内にクライアント証明書を格納し、パスワードをハードコードすることです。すべてのクライアントが同じ証明書を共有するため、これはほとんどセキュリティをもたらさないことが明らかです。

証明書(および場合によってはパスワード)を格納する第2の方法はキーチェーンを使用するものです。最初のログイン時に、アプリケーションは個人証明書をダウンロードし、キーチェーンにセキュアに格納します。

アプリケーションはハードコードされ最初のログイン時に使用される1つの証明書を持ち、それから個人証明書がダウンロードされることがあります。この場合、サーバーに接続するために「汎用」証明書を使用できるかどうかを確認します。

(CycriptやFridaを使用して)アプリケーションから証明書を抽出し、Burp のクライアント証明書としてそれを追加すると、トラフィックを傍受することが可能となります。

#### 改善方法

ベストプラクティスとしては、証明書をピンすべきです。これにはいくつかの方法がありますが、最も一般的な方法は以下のとおりです。

1. アプリケーションバンドルにサーバーの証明書を含め、各接続で検証を実行します。これはサーバーの証明書が更新されるたびに更新メカニズムが必要となります。
2. 証明書の発行者を1つのエンティティなどに制限し、ルート CA の公開鍵をアプリケーションにバンドルします。このようにして攻撃対象領域を制限して有効な証明書を取得します。
3. 独自の PKI を所有および管理します。アプリケーションにはルート CA の公開鍵が含まれます。これは期限切れなどによるサーバーの証明書を変更するたびにアプリケーションを更新することを回避します。独自の CA を使用すると証明書が自己署名されることに注意します。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS

* V5.4 "アプリは独自の証明書ストアを使用するか、エンドポイント証明書もしくは公開鍵を固定化しており、信頼できるCAにより署名された場合でも、別の証明書や鍵を提供するエンドポイントとの接続を確立していない。"

##### CWE

* CWE-295 - Improper Certificate Validation

##### その他

* [1] Setting Burp Suite as a proxy for iOS Devices : https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp
* [2] OWASP - Certificate Pinning for iOS : https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#iOS
