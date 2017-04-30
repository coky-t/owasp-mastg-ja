## プラットフォームインタラクションのテスト

### アプリ権限のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing App permissions".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on Static analysis of "Testing App permissions" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing App permissions" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app窶冱 behavior to code injection, debugging, instrumentation, etc.] --

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

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app窶冱 behavior to code injection, debugging, instrumentation, etc.] --

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

-- TODO [Provide a general description of the issue "Testing JavaScript Execution in WebViews".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content on static analysis of "Testing JavaScript Execution in WebViews" with source code] --


#### 動的解析

-- TODO [Describe how to test for this issue "Testing JavaScript Execution in WebViews" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing JavaScript Execution in WebViews".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V6.5: "明示的に必要でない限りWebViewでJavaScriptが無効にされている。"

##### CWE
- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール
-- TODO [Add relevant tools for "Testing JavaScript Execution in WebViews"] --


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

It is important to clarify that this control is only applicable on the Android Platform. Please look at "Testing Whether Java Objects Are Exposed Through WebViews" in Android for a detailed explanation of this test case.



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

First try running on a jailbroken device and see what happens. If a jailbreak detection is implemented use Cycript<sup>[3]</sup> to examine the methods for any obvious anti-Jailbreak type name (e.g. `isJailBroken`). Note this requires a jailbroken iOS device with Cycript installed and shell access (via ssh). Also, at time of writing, Cycript cannot manipulate native Swift code (but can still look at any Objective-C libraries that are called). To tell if the app is written in Swift use the nm<sub>[4]</sub> tool:

```
nm <appname> | grep swift
```
For an Objective-C only app there will be no output. However, it is still possible the app is mixed Swift and Objective-C.

```
cycript -p <AppName>
cy#[ObjectiveC.classes allKeys]
```

It is recommended you pipe this to a file, then search for something that sounds like a promising classname like jailbreak, startup, system, initial, load, etc. Once you have a candidate list the methods:

```
cy#printMethods(<classname>)
```

Again, you may want to pipe to a file and go through it for a promising sounding method (e.g. has jail or root in the title).

#### 改善方法

For iOS jailbreaking, it is worth noting that a determined hacker (or tester!) could use Cycript's method swizzling to modify this function to always return true. Of course there are more complex implementations, but nearly all can be subverted - the idea is just to make it harder. As such the following is recommended:
1. Use more than 1 of the above methods to check if a device is jailbroken.
2. Call the class and method something that is not immediately obvious (but it well commented).
3. Use Swift instead of Objective-C.

#### 参考情報

##### OWASP Mobile Top 10 2016
* M8 - コード改竄 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M8-Code_Tampering
* M9 - リバースエンジニアリング - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS
* V6.10: "アプリはルート化デバイスや脱獄デバイスで実行されているかどうかを検出している。ビジネス要件に応じて、デバイスがルート化もしくは脱獄されている場合に、ユーザーに警告している、もしくはアプリが終了している。"

##### CWE
Not covered.

##### その他
[4] - nm tool (part of XCode) - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/nm.1.html

##### ツール

[3] cycript - http://www.cycript.org/
