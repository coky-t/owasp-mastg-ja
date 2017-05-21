## コード品質とビルド設定のテスト

### アプリが正しく署名されていることの検証

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### 静的解析

-- TODO [Add content on white-box testing of "Verifying that the App is Properly Signed"] --

#### 動的解析

-- TODO [Add content on black-box testing of "Verifying that the App is Properly Signed"] --

#### 改善方法

-- TODO [Add remediation for "Verifying that the App is Properly Signed"] --

#### 参考情報

##### OWASP Mobile Top 10 2016
- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

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

#### 静的解析

- Xcode エディタにソースコードをインポートします。
- プロジェクトのビルド設定の 'DEBUG' パラメータを確認します。"Apple LVM – Preprocessing" -> "Preprocessor Macros" の下にあります。
- ソースコードの NSAsserts メソッドや類似のものを確認します。

#### 動的解析

このテストケースは静的解析で実行する必要があります。
-- TODO [Develop content on black-box testing of "Testing Whether the App is Debuggable"] --

#### 改善方法

App Store 経由もしくは Ad Hoc や エンタープライズビルドのいずれかで iOS アプリケーションをデプロイすると、Xcode のデバッガをそのアプリケーションにアタッチすることはできなくなります。問題をデバッグするには、デバイス自体からのクラッシュログやコンソール出力を解析する必要があります。コンソールからデバッグリークを防ぐには NSLog 呼び出しを削除してください。

#### 参考情報

##### OWASP Mobile Top 10 2016
- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V7.2: "アプリはリリースモードでビルドされている。リリースビルドに適した設定である。（非デバッグなど）"

##### CWE
-- TODO [Add relevant CWE for "Testing Whether the App is Debuggable"] --

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx

##### ツール
-- TODO [Add tools for "Testing Whether the App is Debuggable"] --


### デバッグシンボルの検証

#### 概要

一般的な経験則として、コンパイルされたコードとともに説明的な情報を提供する必要はありません。デバッグ情報、行番号、記述的な関数名やメソッド名などのメタデータはリバースエンジニアにとってバイナリやバイトコードを理解しやすくしますが、リリースビルドでは実際には必要ではないため、アプリの機能に影響することなく安全に除外できます。

これらのシンボルは "Stabs" 形式か DWARF 形式で保存できます。Stabs 形式を使用する場合、他のシンボルと同様にデバッグシンボルが通常のシンボルテーブルに格納されます。DWARF 形式では、デバッグシンボルはバイナリ内の特別な "\_\_DWARF" セグメントに格納されます。DWARF デバッグシンボルは別のデバッグ情報ファイルとして保存することもできます。このテストケースでは、デバッグシンボルがリリースバイナリ自体(シンボルテーブル内、もしくは \_\_DWARF セグメント)に含まれていないことを確認します。

#### 静的解析

gobjdump を使用して、メインバイナリとインクルードされた dylib の Stabs および DWARF シンボルを検査します。

```
$ gobjdump --stabs --dwarf TargetApp
In archive MyTargetApp:

armv5te:     file format mach-o-arm


aarch64:     file format mach-o-arm64
```

gobjdump は binutils <sup>[1]</sup> の一部であり、Homebrew 経由でインストールできます。

#### 動的解析

適用できません。

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying that Debugging Symbols Have Been Removed"] --

#### 参考情報

##### OWASP Mobile Top 10 2016
- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V7.3: "デバッグシンボルはネイティブバイナリから削除されている。"

##### CWE
-- TODO [Add relevant CWE for "Verifying that Debugging Symbols Have Been Removed"] --

##### その他
- [1] Binutils - https://www.gnu.org/s/binutils/



### デバッグコードや詳細エラーログに関するテスト

#### 概要
開発者は検証をスピードアップしエラーの理解を深めるために API からのレスポンスやアプリケーションの状況や状態について (`NSLog`, `println`, `print`, `dump`, `debugPrint` を使用して) 詳細なログ出力文などのデバッグコードをしばしば埋め込みます。
さらに、API からの疑似応答などアプリケーションの状態を設定するために開発者が使用する「管理機能」と呼ばれるデバッグコードが存在する可能性があります。
この情報はリバースエンジニアがアプリケーションで起こっていることを追跡するために簡単に使用できます。したがって、デバッグコードはリリースバージョンのアプリケーションから削除する必要があります。

#### 静的解析
静的解析では、ログ出力文に関して以下のアプローチをとることができます。
1. Xcode にアプリケーションのコードをインポートする。
2. 次の出力関数でコードを検索する:`NSLog`, `println`, `print`, `dump`, `debugPrint`.
3. いずれか一つを見つけたら、ログ出力のマークアップとしてログ出力関数の周りにラップ関数を使用しているか確認し、その関数を検索に追加する。
4. 手順2と3で見つけたすべてのものについて、マクロやデバッグ状態に関連するガードがログ出力なしに設定されているかどうかを確認する。Objective-C がプリプロセッサマクロをどのように使用して変更するかに注意する。
```objc
#ifdef DEBUG
    // Debug-only code
#endif
```
Swift ではこれとは異なります。スキームに環境変数を設定するか、ターゲットのビルド設定にカスタムフラグを設定する必要があります。アプリが Swift 2.1 のリリース構成でビルドされているかどうかを確認できる次の関数が推奨されていることに注意します (Xcode 8 および Swift3 ではサポートされません): `_isDebugAssertConfiguration()`, `_isReleaseAssertConfiguration()`, `_isFastAssertConfiguration()`.

アプリケーションの設定により、より多くのログ出力関数があることに注意します。例えば、CocoaLumberjack (https://github.com/CocoaLumberjack/CocoaLumberjack) が使用された場合などでは、静的解析は多少異なったものになります。

組み込みの「デバッグ管理」コードにて、ストーリーボードを調査して、アプリケーションによりサポートされるものとは異なる機能を提供するフローやビューコントローラがあるかどうかを調べます。
--TODO: reviewer: should we go in depth on different patterns one can find on this subject? --

#### 動的解析
動的解析はシミュレータとデバイスの両方で実行すべきです。開発者はデバッグコードの実行有無のために (リリース/デバッグモードベースの関数の代わりに) ターゲットベースの関数を使用することが時折あります。
1. シミュレータ上でアプリケーションを実行して、アプリの実行中にコンソールに出力を見つけることができるか確認する。
2. デバイスを Mac に接続して、Xcode 経由でデバイス上のアプリケーションを実行し、アプリの実行中にコンソールに出力を見つけることができるか確認する。

他の「マネージャベース」のデバッグコードでは、シミュレータとデバイスの両方でアプリケーションをクリックして、いくつかの機能を見つけることができるか確認します。アプリの事前設定プロファイルを許可する機能、実サーバーを選択する機能、API からの可能なレスポンスを選択する機能など。

#### 改善方法
As a developer, it should not be a problem to incorporate debug statements in your debug version of the application as long as you realize that the statements made for debugging should never:
- have impact on the actual computational results in such a way that the code should be present in the release version of the application;
- end up in the release-configuration of the application.

In Objective-C, developers can use pre-processor macro's to filter out debug code:
```objc
#ifdef DEBUG
    // Debug-only code
#endif
```
In Swift 2, using xCode 7, one has to set custom compiler flags for every target, where the compiler flag has to start with -D. So, when the debug flag -DMSTG-DEBUG is set, you can use the following annotations:

```swift
#if MSTG-DEBUG
    // Debug-only code
#endif
```

In swift 3, using xCode 8, one can set Active Compilation Conditions setting in Build settings / Swift compiler - Custom flags. Swift3 does not use a pre-processor, but instead makes use of conditional compilation blocks based on the conditions defined:

```swift3
#if DEBUG_LOGGING
    // Debug-only code
#endif
```

#### 参考情報

##### OWASP Mobile Top 10 2016
- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V7.4: "デバッグコードは削除されており、アプリは詳細なエラーやデバッグメッセージを記録していない。"

##### CWE
-- TODO [Add relevant CWE for "Testing for Debugging Code and Verbose Error Logging"] --

##### その他
- [1] CocoaLumberjack - [https://github.com/CocoaLumberjack/CocoaLumberjack]
- [2] Swift conditional compilation blocks - [https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/InteractingWithCAPIs.html#//apple_ref/doc/uid/TP40014216-CH8-ID34]

##### ツール
- XCode & simulator
- A standard iPhone/iPad



### 例外処理のテスト

#### 概要

-- TODO [Give an overview about the functionality "Testing Exception Handling" and it's potential weaknesses] --

#### 静的解析

ソースコードをレビューして、アプリケーションがさまざまなタイプのエラー(IPC通信、リモートサービス呼び出しなど)を処理する人を理解/識別します。この段階で実行されるチェックの例を以下に示します。

- アプリケーションが[適切に設計された](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047) (および統一された) スキームを使用して例外を処理することを確認する。
- アプリケーションが例外を処理するときに機密情報を公開していないが、ユーザーには十分詳細に問題を説明していることを確認する。

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Exception Handling" using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Exception Handling"] --

#### 参考情報

##### OWASP Mobile Top 10 2016
- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V7.5: "アプリは可能性のある例外をキャッチし処理している。"
- V7.6: "セキュリティコントロールのエラー処理ロジックはデフォルトでアクセスを拒否している。"

##### CWE
-- TODO [Add relevant CWE for "Testing Exception Handling"] --

##### Info
- [1] https://www.gnu.org/s/binutils/

##### Tools
-- TODO [Add tools for "Testing Exception Handling"] --



### アンマネージドコードでのメモリバグのテスト

#### 概要

-- TODO [Give an overview about the functionality "Testing for Memory Management Bugs" and it's potential weaknesses] --

#### 静的解析

-- TODO [Add content for white-box testing of "Testing for Memory Management Bugs"] --

#### 動的解析

-- TODO [Add content for black-box testing of "Testing for Memory Management Bugs"] --

#### 改善方法

-- TODO

#### 参考情報

##### OWASP Mobile Top 10 2016
- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V7.7: "アンマネージドコードでは、メモリは安全に割り当て、解放、使用されている。"

##### CWE
-- TODO [Add relevant CWE for "Testing for Memory Management Bugs"] --

##### その他
-- TODO [Add info sor "Testing for Memory Management Bugs"] --

##### ツール
-- TODO [Add tools for "Testing for Memory Management Bugs"] --


### フリーなセキュリティ機能が有効であることの検証

#### 概要

XCode ではデフォルトですべてのバイナリセキュリティが設定されていますが、古いアプリケーションやコンパイルオプションの設定ミスのチェックには関係するかもしれません。以下の機能が適用されます。

- **ARC** - Automatic Reference Counting - メモリ管理機能
  * 必要に応じてメッセージを保持および解放します
- **Stack Canary** - バッファオーバーフロー攻撃の防止に役立ちます
- **PIE** - Position Independent Executable - バイナリに対し完全な ASLR を有効にします

#### 静的解析

-- TODO

#### 動的解析

##### otool を使用

以下はこれらの機能をチェックする方法の例です。これらの例ではすべてが有効になっています。

- PIE:
```
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
```

- Stack Canary:
```
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
```

- Automatic Reference Counting:
```
$ otool -Iv DamnVulnerableIOSApp | grep release
0x0045b7dc 83156 ___cxa_guard_release
0x0045fd5c 83414 _objc_autorelease
0x0045fd6c 83415 _objc_autoreleasePoolPop
0x0045fd7c 83416 _objc_autoreleasePoolPush
0x0045fd8c 83417 _objc_autoreleaseReturnValue
0x0045ff0c 83441 _objc_release
[SNIP]
```

##### idb を使用

IDB <sup>[2]</sup> は Stack Canary と PIE サポートの両方をチェックするプロセスを自動化します。IDB GUI でターゲットバイナリを選択し、"Analyze Binary..." ボタンをクリックします。

![alt tag](Images/Chapters/0x06i/idb.png)

#### 改善方法

- スタックスマッシュ保護

iOS アプリケーション内でスタックスマッシュ保護を有効にする手順：

1. Xcodeで、"Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックして設定を表示します。
1. "Other C Flags" セクションで "–fstack-protector-all" オプションが選択されていることを確認します。

- PIE サポート

iOS アプリケーションを PIE としてビルドする手順：

1. Xcodeで、"Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックして設定を表示します。
1. iOS アプリの場合、iOS Deployment Target を iOS 4.3 もしくはそれ以降に設定します。
1. "Generate Position-Dependent Code" がデフォルト値の NO に設定されていることを確認します。
1. "Create Position Independent Executables" がデフォルト値の NO に設定されていないことを確認します。

- ARC 保護

iOS アプリケーションで ACR 保護を有効にする手順：

1. Xcodeで、"Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックして設定を表示します。
1. "Objective-C Automatic Reference Counting" がデフォルト値の YES に設定されていることを確認します。

#### 参考情報

##### OWASP Mobile Top 10 2016
- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V7.8: "バイトコードの軽量化、スタック保護、PIEサポート、自動参照カウントなどツールチェーンにより提供されるフリーのセキュリティ機能が有効化されている。"

##### CWE

-- TODO [Add relevant CWE for "Testing Compiler Settings"] --

##### その他

- [1] Technical Q&A QA1788 Building a Position Independent Executable - https://developer.apple.com/library/mac/qa/qa1788/_index.html
- [2] idb - https://github.com/dmayer/idb

##### ツール
-- TODO [Add tools for "Testing Compiler Settings"] --
