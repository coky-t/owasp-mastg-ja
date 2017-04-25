## プラットフォームインタラクションのテスト

### アプリ権限のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing App permissions".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### ソースコードあり

-- TODO [Add content on Static analysis of "Testing App permissions" with source code] --

##### ソースコードなし

-- TODO [Add content on Static analysis of "Testing App permissions" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing App permissions" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app窶冱 behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing App permissions".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing App permissions"] --

##### OWASP MASVS

- V6.1: "アプリは必要となる最低限の権限のみを要求している。"

##### CWE

-- TODO [Add relevant CWE for "Testing App permissions"] --

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

##### ソースコードあり

-- TODO [Add content for static analysis of "Testing Input Validation and Sanitization" with source code] --

##### ソースコードなし

-- TODO [Add content for static analysis of "Testing Input Validation and Sanitization" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app窶冱 behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Input Validation and Sanitization".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing Input Validation and Sanitization"] --

##### OWASP MASVS

- V6.2: "外部ソースおよびユーザーからの入力がすべて検証されており、必要に応じてサニタイズされている。これにはUI、インテントやカスタムURLなどのIPCメカニズム、ネットワークソースを介して受信したデータを含んでいる。"

##### CWE

-- TODO [Add relevant CWE for "Testing Input Validation and Sanitization"] --

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

##### ソースコードあり

-- TODO [Add content on static analysis for "Testing Custom URL Schemes" with source code] --

##### ソースコードなし

-- TODO [Add content on static analysis for "Testing Custom URL Schemes" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Custom URL Schemes" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Custom URL Schemes".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing Custom URL Schemes"] --

##### OWASP MASVS

- V6.3: "アプリはメカニズムが適切に保護されていない限り、カスタムURLスキームを介して機密な機能をエクスポートしていない。"

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

##### ソースコードあり

-- TODO [Add content on static analysis of "Testing for Sensitive Functionality Exposed Through IPC" with source code] --

##### ソースコードなし

-- TODO [Add content on static analysis of "Testing for Sensitive Functionality Exposed Through IPC" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing for Sensitive Functionality Exposed Through IPC" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Sensitive Functionality Exposed Through IPC".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing for Sensitive Functionality Exposed Through IPC"] --

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

##### ソースコードあり

-- TODO [Add content on static analysis of "Testing JavaScript Execution in WebViews" with source code] --

##### ソースコードなし

-- TODO [Add content on static analysis of "Testing JavaScript Execution in WebViews" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing JavaScript Execution in WebViews" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing JavaScript Execution in WebViews".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing JavaScript Execution in WebViews"] --

##### OWASP MASVS

- V6.5: "明示的に必要でない限りWebViewでJavaScriptが無効にされている。"

##### CWE

-- TODO [Add relevant CWE for "Testing JavaScript Execution in WebViews"] --

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

##### ソースコードあり

-- TODO [Add content on static analysis of "Testing WebView Protocol Handlers" with source code) --

##### ソースコードなし

-- TODO [Add content on static analysis of "Testing WebView Protocol Handlers" without source code) --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing WebView Protocol Handlers" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing WebView Protocol Handlers".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing WebView Protocol Handlers"] --

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

##### ソースコードあり

-- TODO [Add content on static analysis of "Testing for Local File Inclusion in WebViews" with source code] --

##### ソースコードなし

-- TODO [Add content on static analysis of "Testing for Local File Inclusion in WebViews" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing for Local File Inclusion in WebViews" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Local File Inclusion in WebViews".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014] --

##### OWASP MASVS

- V6.7: "アプリはWebViewにユーザー提供のローカルリソースをロードしていない。"

##### CWE

-- TODO [Add relevant CWE for "Testing for Local File Inclusion in WebViews"] --

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### ツール

-- TODO [Add relevant tools for "Testing for Local File Inclusion in WebViews"] --


### WevView経由でJavaオブジェクトが開示されるかのテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Whether Java Objects Are Exposed Through WebViews".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### ソースコードあり

-- TODO [Add content for static analysis of "Testing Whether Java Objects Are Exposed Through WebViews" with source code] --

##### ソースコードなし

-- TODO [Add content for static analysis of "Testing Whether Java Objects Are Exposed Through WebViews" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Whether Java Objects Are Exposed Through WebViews" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Whether Java Objects Are Exposed Through WebViews".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014 for "Testing Whether Java Objects Are Exposed Through WebViews"] --

##### OWASP MASVS

- V6.8: "WeｂViewでJavaオブジェクトが扱われる場合は、WebViewはアプリパッケージに含まれるJavaScriptのみ表示している。"

##### CWE

-- TODO [Add relevant CWE for "Testing Whether Java Objects Are Exposed Through WebViews"] --

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### ツール

-- TODO [Add relevant tools for "Testing Whether Java Objects Are Exposed Through WebViews"] --


### オブジェクトシリアライズ化のテスト

#### 概要

-- TODO [Add overview for "Testing Object Serialization"] --


#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### ソースコードあり

-- TODO [Add content on static analysis of "Testing Object Serialization" with source code] --

##### ソースコードなし

-- TODO [Add content on static analysis of "Testing Object Serialization" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Object Serialization" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Object Serialization".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add reference to OWASP Mobile Top 10 2014] --

##### OWASP MASVS

- V6.9: "オブジェクトシリアライズ化は安全なシリアライズ化APIを使用して実装されている。"

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



##### ソースコードあり

Look for a function with a name like isJailBroken in the code. If none of these are available, look for code checking for the following:
1. Existence of files (such as anything with cydia or substrate in the name (such as `/private/var/lib/cydia or /Library/MobileSubstrate/MobileSubstrate.dylib`), `/var/lib/apt, /bin/bash, /usr/sbin/sshd, sftp`, etc). In swift this is done with the `FileManager.default.fileExists(atPath: filePath)` function and objective-c uses `[NSFileManager defaultManager] fileExistsAtPath:filePath`, so grepping for fileExists should show you a good list.
2. Changes of directory permissions (ie being able to write to a file outside the the apps own directory - common examples are `/, /private, /lib, /etc, /System, /bin, /sbin, /cores, /etc`). /private and / seem to be the most commonly used for testing.

	2.1 Check actual permissions themselves: Swift uses `NSFilePosixPermissions` and objective-c uses `directoryAttributes`, so grep for these. 
	
	2.2 Check if you can write a file: Swift and objective-c both use the key words `write` and `create` for file and directory writing and creation. So grep for this and pipe to a grep for `/private` (or others) to get a reference.
3. Checking size of `/etc/fstab` - a lot of tools modify this file, but this method is uncommon as an update from apple may break this check.
4. Creation of symlinks due to the jailbreak taking up space on the system partition. Look for references to `/Library/Ringtones,/Library/Wallpaper,/usr/arm-apple-darwin9,/usr/include,/usr/libexec,/usr/share,/Applications` in the code.

##### ソースコードなし

Use Cycript<sup>[3]</sup> to examine the methods for any obvious anti-Jailbreaky type name (eg `isJailBroken`). Note this requires a jailbroken iOS device with cycript installed and shell access (via ssh). Also, at time of writing, Cycript cannot manipulate native switft code (but can still look at any objective-c libraries that are called). To tell if the app is written in swift, then used the nm<sub>[4]</sub> tool:
```
nm <appname> | grep swift
```
For an Objective-C only app there will be no output. However, it is still possible the app is mixed swift and objective-c.

```
cycript -p <AppName>
cy#[ObjectiveC.classes allKeys]
```
It is recommended you pipe this to a file, then search for something that sounds like a promising classname(jailbreak, startup, system, initial, load, etc). Once you have a candidate, then list the methods:
```
cy#printMethods(<classname>)
```
Again, you may want to pipe to a file and go through it for a promising sounding method (eg has jail or root in the title).

#### 動的解析

Try running on a jailbroken device and see what happens.

#### 改善方法

For iOS jailbreaking, it is worth noting that a determined hacker (or tester!) could use Cycript's method swizzling to modify this function to always return true. Of course there are more complex implementations, but nearly all can be subverted - the idea is just to make it harder. As such the following is recommended:
1. Use more than 1 of the above methods to check if a device is jailbroken.
2. Call the class and method something that is not immediately obvious (but it well commented).
3. Use swift instead of objective-c.

#### 参考情報

##### OWASP Mobile Top 10 2016

[1] - 2016-M8-Code Tampering - https://www.owasp.org/index.php/Mobile_Top_10_2016-M8-Code_Tampering

[2] - 2016-M9-Reverse Engineering - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

- V6.10: "アプリはルート化デバイスや脱獄デバイスで実行されているかどうかを検出している。ビジネス要件に応じて、デバイスがルート化もしくは脱獄されている場合に、ユーザーに警告している、もしくはアプリが終了している。"

##### CWE

Not covered.

##### その他

[4] - nm tool (part of XCode) - https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/nm.1.html

##### ツール

[3] cycript - http://www.cycript.org/
