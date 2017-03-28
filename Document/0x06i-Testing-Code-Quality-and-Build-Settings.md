## コード品質とビルド設定のテスト

### アプリが正しく署名されていることの検証

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### ホワイトボックステスト

-- TODO [Add content on white-box testing of "Verifying that the App is Properly Signed"] --

#### ブラックボックステスト

-- TODO [Add content on black-box testing of "Verifying that the App is Properly Signed"] --

#### 改善方法

-- TODO [Add remediation for "Verifying that the App is Properly Signed"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Verifying that the App is Properly Signed"] --

##### OWASP MASVS

- V7.1: "アプリは有効な証明書で署名およびプロビジョニングされている。"

##### CWE

-- TODO [Add relevant CWE for "Verifying that the App is Properly Signed"] --

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール

-- TODO [Add tools for "Verifying that the App is Properly Signed"] --

### アプリがデバッグ可能であるかのテスト

#### 概要

-- TODO [Give an overview about the functionality "Testing Whether the App is Debuggable" and it's potential weaknesses] --

#### ホワイトボックステスト

1. Xcode エディタにソースコードをインポートします。
1. プロジェクトのビルド設定の 'DEBUG' パラメータを確認します。"Apple LVM – Preprocessing" -> "Preprocessor Macros" の下にあります。
1. ソースコードの NSAsserts メソッドや類似のものを確認します。

#### ブラックボックステスト

このテストケースはホワイトボックステストで実行する必要があります。

-- TODO [Develop content on black-box testing of "Testing Whether the App is Debuggable"] --

#### 改善方法

App Store 経由もしくは Ad Hoc や エンタープライズビルドのいずれかで iOS アプリケーションをデプロイすると、Xcode のデバッガをそのアプリケーションにアタッチすることはできなくなります。問題をデバッグするには、デバイス自体からのクラッシュログやコンソール出力を解析する必要があります。コンソールからデバッグリークを防ぐには NSLog 呼び出しを削除してください。

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing Whether the App is Debuggable"] --

##### OWASP MASVS

- V7.1: ""

##### CWE

-- TODO [Add relevant CWE for "Testing Whether the App is Debuggable"] --

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール

-- TODO [Add tools for "Testing Whether the App is Debuggable"] --


### デバッグシンボルが削除されていることの検証

#### 概要

一般的な経験則として、コンパイルされたコードとともに説明的な情報を提供する必要はありません。デバッグ情報、行番号、記述的な関数名やメソッド名などのメタデータはリバースエンジニアにとってバイナリやバイトコードを理解しやすくしますが、リリースビルドでは実際には必要ではないため、アプリの機能に影響することなく安全に除外できます。

これらのシンボルは "Stabs" 形式か DWARF 形式で保存できます。Stabs 形式を使用する場合、他のシンボルと同様にデバッグシンボルが通常のシンボルテーブルに格納されます。DWARF 形式では、デバッグシンボルはバイナリ内の特別な "\_\_DWARF" セグメントに格納されます。DWARF デバッグシンボルは別のデバッグ情報ファイルとして保存することもできます。このテストケースでは、デバッグシンボルがリリースバイナリ自体(シンボルテーブル内、もしくは \_\_DWARF セグメント)に含まれていないことを確認します。

#### 静的解析

gobjdump を使用して、メインバイナリとインクルードされた dylib の Stabs および DWARF シンボルを検査します。

~~~~
$ gobjdump --stabs --dwarf TargetApp
In archive MyTargetApp:

armv5te:     file format mach-o-arm


aarch64:     file format mach-o-arm64
~~~~

gobjdump は binutils [1] の一部であり、Homebrew 経由でインストールできます。

#### 動的解析

適用できません。

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying that Debugging Symbols Have Been Removed"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Verifying that Debugging Symbols Have Been Removed"] --

##### OWASP MASVS

-- TODO [Add reference to OWASP MASVS for "Verifying that Debugging Symbols Have Been Removed"] --
- V7.1: ""

##### CWE

-- TODO [Add relevant CWE for "Verifying that Debugging Symbols Have Been Removed"] --

##### その他

- [1] https://www.gnu.org/s/binutils/

##### ツール

-- TODO [Add tools for "Verifying that Debugging Symbols Have Been Removed"] --


### デバッグコードや詳細エラーログに関するテスト

#### 概要

-- TODO [Give an overview about the functionality "Testing for Debugging Code and Verbose Error Logging" and it's potential weaknesses] --

#### ホワイトボックステスト

-- TODO [Add content for white-box testing of "Testing for Debugging Code and Verbose Error Logging"] --

#### ブラックボックステスト

-- TODO [Add content for black-box testing of "Testing for Debugging Code and Verbose Error Logging"] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Debugging Code and Verbose Error Logging"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing for Debugging Code and Verbose Error Logging"] --

##### OWASP MASVS

-- TODO [Add reference to OWASP MASVS for "Testing for Debugging Code and Verbose Error Logging"] --
- V7.1: ""

##### CWE

-- TODO [Add relevant CWE for "Testing for Debugging Code and Verbose Error Logging"] --

##### その他

- [1] https://www.gnu.org/s/binutils/

##### ツール

-- TODO [Add tools for "Testing for Debugging Code and Verbose Error Logging"] --

### 例外処理のテスト

#### 概要

-- TODO [Give an overview about the functionality "Testing Exception Handling" and it's potential weaknesses] --

#### ホワイトボックステスト

ソースコードをレビューして、アプリケーションがさまざまなタイプのエラー(IPC通信、リモートサービス呼び出しなど)を処理する人を理解/識別します。この段階で実行されるチェックの例を以下に示します。

* アプリケーションが[適切に設計された](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047) (統一された) スキームを使用して例外を処理することを確認する。
* アプリケーションが例外を処理するときに機密情報を公開していないが、ユーザーには十分詳細に問題を説明していることを確認する。
* C3

#### ブラックボックステスト

-- TODO [Describe how to test for this issue "Testing Exception Handling" using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Exception Handling"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing Exception Handling"] --

##### OWASP MASVS

-- TODO [Add reference to OWASP MASVS for "Testing Exception Handling"] --
- V7.1: ""

##### CWE

-- TODO [Add relevant CWE for "Testing Exception Handling"] --

##### Info

- [1] https://www.gnu.org/s/binutils/

##### Tools

-- TODO [Add tools for "Testing Exception Handling"] --


### アプリが安全に失敗することの検証

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### ホワイトボックステスト

-- TODO [Add content on white-box testing for "Verifying that the App Fails Securely"] --

#### ブラックボックステスト

-- TODO [Describe how to test for this issue "Verifying that the App Fails Securely" using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying that the App Fails Securely"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Verifying that the App Fails Securely"] --

##### OWASP MASVS

-- TODO [Add reference to OWASP MASVS for "Verifying that the App Fails Securely"] --
- V7.1: ""

##### CWE

-- TODO [Add relevant CWE for "Verifying that the App Fails Securely"] --

##### その他

- [1] https://www.gnu.org/s/binutils/

##### ツール

-- TODO [Add tools for "Verifying that the App Fails Securely"] --

### コンパイラ設定のテスト

XCode ではデフォルトですべてのバイナリセキュリティが設定されていますが、古いアプリケーションやコンパイルオプションの設定ミスのチェックには関係するかもしれません。以下の機能が適用されます。
* **ARC** - Automatic Reference Counting - メモリ管理機能
  * 必要に応じてメッセージを保持および解放します
* **Stack Canary** - バッファオーバーフロー攻撃の防止に役立ちます
* **PIE** - Position Independent Executable - バイナリに対し完全な ASLR を有効にします

#### 概要

-- TODO [Give an overview about the functionality "Testing Compiler Settings" and it's potential weaknesses] --

#### ホワイトボックステスト

-- TODO [Describe how to assess this with access to the source code and build configuration] --

#### ブラックボックステスト

-- TODO [Add content on black-box testing for "Testing Compiler Settings"] --

##### otool を使用

以下はこれらの機能をチェックする方法の例です。これらの例ではすべてが有効になっています。
* PIE:
~~~
$ unzip DamnVulnerableiOSApp.ipa
$ cd Payload/DamnVulnerableIOSApp.app
$ otool -hv DamnVulnerableIOSApp
DamnVulnerableIOSApp (architecture armv7):
Mach header
magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
MH_MAGIC ARM V7 0x00 EXECUTE 38 4292 NOUNDEFS DYLDLINK TWOLEVEL
WEAK_DEFINES BINDS_TO_WEAK PIE
DamnVulnerableIOSApp (architecture arm64):
Mach header
magic cputype cpusubtype caps filetype ncmds sizeofcmds flags
MH_MAGIC_64 ARM64 ALL 0x00 EXECUTE 38 4856 NOUNDEFS DYLDLINK TWOLEVEL
WEAK_DEFINES BINDS_TO_WEAK PIE
~~~

* Stack Canary:
~~~
$ otool -Iv DamnVulnerableIOSApp | grep stack
0x0046040c 83177 ___stack_chk_fail
0x0046100c 83521 _sigaltstack
0x004fc010 83178 ___stack_chk_guard
0x004fe5c8 83177 ___stack_chk_fail
0x004fe8c8 83521 _sigaltstack
0x00000001004b3fd8 83077 ___stack_chk_fail
0x00000001004b4890 83414 _sigaltstack
0x0000000100590cf0 83078 ___stack_chk_guard
0x00000001005937f8 83077 ___stack_chk_fail
0x0000000100593dc8 83414 _sigaltstack
~~~ 

* Automatic Reference Counting:
~~~
$ otool -Iv DamnVulnerableIOSApp | grep release
0x0045b7dc 83156 ___cxa_guard_release
0x0045fd5c 83414 _objc_autorelease
0x0045fd6c 83415 _objc_autoreleasePoolPop
0x0045fd7c 83416 _objc_autoreleasePoolPush
0x0045fd8c 83417 _objc_autoreleaseReturnValue
0x0045ff0c 83441 _objc_release
[SNIP]
~~~

##### idb を使用

IDB は Stack Canary と PIE サポートの両方をチェックするプロセスを自動化します。IDB gui でターゲットバイナリを選択し、"Analyze Binary..." ボタンをクリックします。

![alt tag](Images/Chapters/0x06i/idb.png)

#### 改善方法

* スタックスマッシュ保護

iOS アプリケーション内でスタックスマッシュ保護を有効にする手順：

1. Xcodeで、"Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックして設定を表示します。
1. "Other C Flags" セクションで "–fstack-protector-all" オプションが選択されていることを確認します。

* PIE サポート

iOS アプリケーションを PIE としてビルドする手順：

1. Xcodeで、"Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックして設定を表示します。
1. iOS アプリの場合、iOS Deployment Target を iOS 4.3 もしくはそれ以降に設定します。Mac アプリの場合、OS X Deployment Target を OS X 10.7 もしくはそれ以降に設定します。
1. "Generate Position-Dependent Code" がデフォルト値の NO に設定されていることを確認します。
1. "Create Position Independent Executables" がデフォルト値の NO に設定されていないことを確認します。

* ARC 保護

iOS アプリケーションで ACR 保護を有効にする手順：

1. Xcodeで、"Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックして設定を表示します。
1. "Objective-C Automatic Reference Counting" がデフォルト値の YES に設定されていることを確認します。

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing Compiler Settings"] --

##### OWASP MASVS

-- TODO [Add reference to OWASP MASVS for "Testing Compiler Settings"] --
- V7.1: ""

##### CWE

-- TODO [Add relevant CWE for "Testing Compiler Settings"] --

##### その他

* Technical Q&A QA1788 Building a Position Independent Executable : https://developer.apple.com/library/mac/qa/qa1788/_index.html
* idb : https://github.com/dmayer/idb

##### ツール

-- TODO [Add tools for "Testing Compiler Settings"] --


### メモリ管理バグに関するテスト

#### 概要

-- TODO [Give an overview about the functionality "Testing for Memory Management Bugs" and it's potential weaknesses] --

#### ホワイトボックステスト

-- TODO [Add content for white-box testing of "Testing for Memory Management Bugs"] --

#### ブラックボックステスト

-- TODO [Add content for black-box testing of "Testing for Memory Management Bugs"] --

#### 改善方法

#### 参考情報

##### OWASP Mobile Top 10 2014

-- TODO [Add link to OWASP Mobile Top 10 2014 for "Testing for Memory Management Bugs"] --

##### OWASP MASVS

- V7.7: "アンマネージドコードでは、メモリは安全に割り当て、解放、使用されている。"

##### CWE

-- TODO [Add relevant CWE for "Testing for Memory Management Bugs"] --

##### その他

-- TODO [Add info sor "Testing for Memory Management Bugs"] --

##### ツール

-- TODO [Add tools for "Testing for Memory Management Bugs"] --

### JavaバイトコードがMinifyされていることの検証

iOS では適用できません。
