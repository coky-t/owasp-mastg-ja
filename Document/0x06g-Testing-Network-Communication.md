## ネットワーク通信のテスト (iOS アプリ)

### エンドポイント同一性検証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Endpoint Identity Verification".]

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on "Testing Endpoint Identity Verification" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Endpoint Identity Verification" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app窶冱 behavior to code injection, debugging, instrumentation, etc.] --

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
* Enjarify - https://github.com/google/enjarify


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

セキュアな接続を確立する中でアプリケーションの動作をテストすることで解析を開始します。
テストアプローチは SSL ハンドシェイクネゴシエーションのセキュリティを少しずつ緩めて、どのセキュリティメカニズムが有効であるかを確認することです。

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
