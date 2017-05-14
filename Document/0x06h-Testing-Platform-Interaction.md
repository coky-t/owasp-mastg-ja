## プラットフォームインタラクションのテスト

### アプリ権限のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing App permissions".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on Static analysis of "Testing App permissions" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing App permissions" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app's behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing App permissions".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage

##### OWASP MASVS
* V6.1: "アプリは必要となる最低限の権限のみを要求している。"

##### CWE
* CWE-250 - Execution with Unnecessary Privileges

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール
-- TODO [Add tools for "Testing App permissions"] --



### 入力の妥当性確認とサニタイズ化のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Input Validation and Sanitization".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content for static analysis of "Testing Input Validation and Sanitization" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app's behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Input Validation and Sanitization".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V6.2: "外部ソースおよびユーザーからの入力がすべて検証されており、必要に応じてサニタイズされている。これにはUI、インテントやカスタムURLなどのIPCメカニズム、ネットワークソースを介して受信したデータを含んでいる。"

##### CWE
* CWE-20 - Improper Input Validation

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール
-- TODO [Add relevant tools for "Testing Input Validation and Sanitization"] --



### カスタムURLスキームのテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Custom URL Schemes".]

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on static analysis for "Testing Custom URL Schemes" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Custom URL Schemes" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Custom URL Schemes".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage

##### OWASP MASVS
* V6.3: "アプリはメカニズムが適切に保護されていない限り、カスタムURLスキームを介して機密な機能をエクスポートしていない。"

##### CWE
-- TODO [Add relevant CWE for "Testing Custom URL Schemes"] --

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### ツール
-- TODO [Add relevant tools for "Testing Custom URL Schemes"] --



### IPC経由での機密性のある機能の開示に関するテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing for Sensitive Functionality Exposed Through IPC".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on static analysis of "Testing for Sensitive Functionality Exposed Through IPC" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing for Sensitive Functionality Exposed Through IPC" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Sensitive Functionality Exposed Through IPC".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage

##### OWASP MASVS
- V6.4: "アプリはメカニズムが適切に保護されていない限り、IPC機構を通じて機密な機能をエクスポートしていない。"

##### CWE
-- TODO [Add relevant CWE for "Testing for Sensitive Functionality Exposed Through IPC"] --

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール
-- TODO [Add relevant tools for "Testing for Sensitive Functionality Exposed Through IPC"] --



### WebViewでのJavaScript実行のテスト

#### 概要

WebViewオブジェクトは iOS アプリケーションに Web ブラウザを埋め込むために使用されます。ネイティブモバイルブラウザとのやりとりなしにアプリケーションに Web ページを表示するための便利な方法です。WebView ではロードしたページの JavaScript コードと対話することもできます。しかしながらこの素晴らしい状況はセキュリティコントロールが適用されていなければ、アプリケーションに大きなリスクをもたらす可能性があります。そのような大きなリスクの一つとして WebView オブジェクトを介してアプリケーションに悪質な JavaScript コードを実行する可能性があります。

#### 静的解析

iOS バージョンに応じて、WebView オブジェクトは UIWebView (iOS バージョン 7.1.2 および以前) <sup>[1]</sup> もしくは WKWebView (iOS バージョン 8.0 および以降) <sup>[2]</sup> を使用して実装できます。WKWebView の使用をお勧めします。

WKWebView オブジェクトはデフォルトで JavaScript の実行を許可します。WebView オブジェクトを介してユーザーのデバイス上で任意のコードを実行する深刻なリスクを引き起こす可能性があります。静的な Web ページを表示するだけであり WebView が JavaScript を実行する必要がなければ、明示的に無効にすべきです。オブジェクト WKPreferences <sup>[3]</sup> の設定を使用します。以下に例を示します。

```
#import "ViewController.h"
#import <WebKit/WebKit.h>
@interface ViewController ()<WKNavigationDelegate,WKUIDelegate>
@property(strong,nonatomic) WKWebView *webView;
@end

@implementation ViewController

- (void)viewDidLoad {
    
    NSURL *url = [NSURL URLWithString:@"http://www.example.com/"];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    WKPreferences *pref = [[WKPreferences alloc] init];
    
    //Disable javascript execution:
    [pref setJavaScriptEnabled:NO];
    [pref setJavaScriptCanOpenWindowsAutomatically:NO];
    
    WKWebViewConfiguration *conf = [[WKWebViewConfiguration alloc] init];
    [conf setPreferences:pref];
    _webView = [[WKWebView alloc]initWithFrame:CGRectMake(self.view.frame.origin.x,85, self.view.frame.size.width, self.view.frame.size.height-85) configuration:conf] ;
    [_webView loadRequest:request];
    [self.view addSubview:_webView];
    
}

```

WKPreferences オブジェクトを介して JavaScript の実行を明示的に無効にしていない場合、それが有効であることを意味します。


#### 動的解析

アプリケーションの WebView に JavaScript を挿入するさまざまな可能性があるため、動的解析はさまざまな周囲の条件に依存します。

* エンドポイントでの蓄積型クロスサイトスクリプティング (XSS) 脆弱性。脆弱な機能に遷移する際、モバイルアプリの WebView にエクスプロイトが送られる。
* 中間者 (MITM) ポジション。 攻撃者は JavaScript を注入してレスポンスを改竄する可能性がある。

#### 改善方法

UIWebView を避け、代わりに WKWebView を使用します。JavaScript は WKWebView ではデフォルトで有効になっており、必要がなければ無効にすべきです。これによりアプリケーションに対する攻撃の可能性と潜在的な脅威が軽減されます。

これらの攻撃ベクトルに対処するには、以下のチェックの結果を検証する必要があります。

* エンドポイントにより提供されるすべての機能に XSS 脆弱性 <sup>[4]</sup> がないこと。

* MITM 攻撃を回避するためにベストプラクティスに従って HTTPS 通信を実装していること (「ネットワーク通信のテスト」を参照ください) 。


#### 参考情報

##### OWASP Mobile Top 10 2016

* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.5: "明示的に必要でない限りWebViewでJavaScriptが無効にされている。"

##### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html

##### その他

- [1] UIWebView reference documentation - https://developer.apple.com/reference/uikit/uiwebview
- [2] WKWebView reference documentation - https://developer.apple.com/reference/webkit/wkwebview
- [3] WKPreferences - https://developer.apple.com/reference/webkit/wkpreferences#//apple_ref/occ/instp/WKPreferences/javaScriptEnabled
- [4] XSS (Cross Site Scripting) Prevention Cheat Sheet - https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet


### WebViewプロトコルハンドラのテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing WebView Protocol Handlers".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on static analysis of "Testing WebView Protocol Handlers" with source code) --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing WebView Protocol Handlers" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing WebView Protocol Handlers".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V6.6: "WebViewは最低限必要なプロトコルハンドラのセットのみを許可するよう構成されている（理想的には、httpsのみがサポートされている）。file, tel, app-id などの潜在的に危険なハンドラは無効にされている。"

##### CWE
-- TODO [Add relevant CWE for "Testing WebView Protocol Handlers"] --

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール
-- TODO [Add relevant tools for "Testing WebView Protocol Handlers"] --



### WebViewでのローカルファイルインクルージョンに関するテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing for Local File Inclusion in WebViews".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on static analysis of "Testing for Local File Inclusion in WebViews" with source code] --


#### 動的解析

-- TODO [Describe how to test for this issue "Testing for Local File Inclusion in WebViews" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Local File Inclusion in WebViews".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V6.7: "アプリはWebViewにユーザー提供のローカルリソースをロードしていない。"

##### CWE
-- TODO [Add relevant CWE for "Testing for Local File Inclusion in WebViews"] --

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール
-- TODO [Add relevant tools for "Testing for Local File Inclusion in WebViews"] --



### WevView経由でJavaオブジェクトが開示されるかのテスト

このコントロールは Android プラットフォームでのみ適用可能であることを明確にすることが重要です。Android の「WebView 経由で Java オブジェクトが開示されるかのテスト」をご覧ください。



### オブジェクトシリアライズ化のテスト

#### 概要

-- TODO [Add overview for "Testing Object Serialization"] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on static analysis of "Testing Object Serialization" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Object Serialization" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Object Serialization".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V6.9: "オブジェクトシリアライズ化は安全なシリアライズ化APIを使用して実装されている。"

##### CWE
-- TODO [Add relevant CWE for "Testing Object Serialization"] --

##### その他
- [1] Update Security Provider - https://developer.android.com/training/articles/security-gms-provider.html

##### ツール
-- TODO [Add relevant tools for "Testing Object Serialization"] --



### 脱獄検出のテスト

#### 概要

iOS はそれぞれのアプリが自身のサンドボックスに限定されるようにコンテナ化を実装しています。通常のアプリは専用のデータディレクトリ以外のファイルにはアクセスできず、システム API へのアクセスはアプリの権限では制限されています。結果として、アプリの機密データは OS の完全性と同様に通常の条件下では保証されます。但し、攻撃者がモバイルオペレーティングシステムへのルートアクセスを取得した場合、デフォルト保護は完全にバイパスされます。

デフォルトの完全性チェックが無効になっているため、悪意のあるコードがルートとして実行されるリスクは脱獄されたデバイスの方が高くなります。したがって、機密性の高いデータを扱うアプリの開発者は、これらの条件下でアプリが実行されないようにするか、少なくともリスクの増加をユーザーに警告するチェックを実行することを検討する必要があります。

#### 静的解析

コード内で isJailBroken などの名前の関数を探します。利用されていない場合、以下のコードチェックを探します。
1. ファイルの有無(名前に cydia や substrate があるものなど(`/private/var/lib/cydia や /Library/MobileSubstrate/MobileSubstrate.dylib` など)、`/var/lib/apt, /bin/bash, /usr/sbin/sshd, sftp` など)。swift では `FileManager.default.fileExists(atPath: filePath)` 関数で行われ、objective-c は `[NSFileManager defaultManager] fileExistsAtPath:filePath` を使用しているので、fileExists の grep により適切なリストが表示されます。
2. ディレクトリパーミッションの変更(アプリが所有するディレクトリ外のファイルに書き込みできるようにするなど - 一般的な例として `/, /private, /lib, /etc, /System, /bin, /sbin, /cores, /etc` があります)。/private や / がテストのために最も一般的に使用されるようです。

	2.1 現在のパーミッションを確認する：Swift は `NSFilePosixPermissions` を使い、objective-c は `directoryAttributes` を使うので、これらを grep します。
	
	2.2 ファイルを書くことができるか確認する：Swift と objective-c のいずれもファイルとディレクトリの書き込みと作成にキーワード `write` と `create` を使います。そのため、これを grep し、`/private` などの grep に pipe して参照を取得します。
3. `/etc/fstab` のサイズを確認する - 多くのツールがこのファイルを改変しますが、apple のアップデートがこのチェックを破る可能性があるので、この方法は一般的ではありません。
4. 脱獄のためのシンボリックリンクの作成はシステムパーティション上のスペースを占有します。コード内で `/Library/Ringtones,/Library/Wallpaper,/usr/arm-apple-darwin9,/usr/include,/usr/libexec,/usr/share,/Applications` への参照を探します。


#### 動的解析

まず脱獄済みデバイスで実行を試みて、何が起こるかをみます。脱獄検出が実装されている場合は Cycript <sup>[3]</sup> を使用して任意の明白な脱獄タイプ名(`isJailBroken` など)のメソッドを調べます。これには Cycript がインストールされ(ssh 経由で)シェルアクセスされる脱獄済み iOS デバイスが必要です。また、執筆時点では、Cycrpt はネイティブの Swift コードを操作することはできません(但し、コールされる Objective-C ライブラリを探すことはできます)。アプリが Swift で書かれているかどうかを知るには nm <sub>[4]</sub> ツールを使用します。

```
nm <appname> | grep swift
```
Objective-C のみのアプリの場合には出力はありません。しかし、アプリは Swift と Objective-C が混在している可能性があります。

```
cycript -p <AppName>
cy#[ObjectiveC.classes allKeys]
```

これをファイルにパイプし、jailbreak, startup, system, initial, load などのクラス名としてありそうなものを検索することをお勧めします。メソッドの候補リストを取得したら

```
cy#printMethods(<classname>)
```

再び、ファイルにパイプして、(タイトルに jail や root があるなどの)ありそうなメソッドを探します。

#### 改善方法

iOS の脱獄では、特定のハッカー(やテスター)が Cycript の method swizzling を使用して、この関数を常に true を戻すように改変することができます。もちろんより複雑な実装もありますが、ほぼすべてが破壊される可能性があります。アイデアとしてはもっと困難にすることです。したがって以下が推奨されます。
1. 上記の方法のうち2つ以上を使用してデバイスが脱獄されているかどうかを確認します。
2. すぐには分からない(がよくコメントされている)クラスやメソッドをコールします。
3. Objective-C の代わりに Swift を使用します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M8 - コード改竄 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M8-Code_Tampering
* M9 - リバースエンジニアリング - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS
* V6.10: "アプリはルート化デバイスや脱獄デバイスで実行されているかどうかを検出している。ビジネス要件に応じて、デバイスがルート化もしくは脱獄されている場合に、ユーザーに警告している、もしくはアプリが終了している。"

##### CWE
適用されません。

##### その他
[4] - nm tool (part of XCode) - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/nm.1.html

##### ツール

[3] cycript - http://www.cycript.org/
