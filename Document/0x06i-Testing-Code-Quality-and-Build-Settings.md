## コード品質とビルド設定のテスト (iOS アプリ)


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

このテストケースは静的解析で実行する必要があります。-- TODO [Develop content on black-box testing of "Testing Whether the App is Debuggable"] --

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

開発者は検証をスピードアップしエラーの理解を深めるために API からのレスポンスやアプリケーションの状況や状態について (`NSLog`, `println`, `print`, `dump`, `debugPrint` を使用して) 詳細なログ出力文などのデバッグコードをしばしば埋め込みます。さらに、API からの疑似応答などアプリケーションの状態を設定するために開発者が使用する「管理機能」と呼ばれるデバッグコードが存在する可能性があります。この情報はリバースエンジニアがアプリケーションで起こっていることを追跡するために簡単に使用できます。したがって、デバッグコードはリリースバージョンのアプリケーションから削除する必要があります。

#### 静的解析

静的解析では、ログ出力文に関して以下のアプローチをとることができます。1. Xcode にアプリケーションのコードをインポートする。2. 次の出力関数でコードを検索する:`NSLog`, `println`, `print`, `dump`, `debugPrint`.3. いずれか一つを見つけたら、ログ出力のマークアップとしてログ出力関数の周りにラップ関数を使用しているか確認し、その関数を検索に追加する。4. 手順2と3で見つけたすべてのものについて、マクロやデバッグ状態に関連するガードがログ出力なしに設定されているかどうかを確認する。Objective-C がプリプロセッサマクロをどのように使用して変更するかに注意する。

```objc
#ifdef DEBUG
    // Debug-only code
#endif
```

Swift ではこれとは異なります。スキームに環境変数を設定するか、ターゲットのビルド設定にカスタムフラグを設定する必要があります。アプリが Swift 2.1 のリリース構成でビルドされているかどうかを確認できる次の関数が推奨されていることに注意します (Xcode 8 および Swift3 ではサポートされません): `_isDebugAssertConfiguration()`, `_isReleaseAssertConfiguration()`, `_isFastAssertConfiguration()`.

アプリケーションの設定により、より多くのログ出力関数があることに注意します。例えば、CocoaLumberjack (https://github.com/CocoaLumberjack/CocoaLumberjack) が使用された場合などでは、静的解析は多少異なったものになります。

組み込みの「デバッグ管理」コードにて、ストーリーボードを調査して、アプリケーションによりサポートされるものとは異なる機能を提供するフローやビューコントローラがあるかどうかを調べます。これはいろいろあります。デバッグビューから、エラーメッセージ出力まで。カスタムスタブレスポンス構成からアプリケーション上のファイルやリモートサーバーへのログ出力まで。

#### 動的解析

動的解析はシミュレータとデバイスの両方で実行すべきです。開発者はデバッグコードの実行有無のために (リリース/デバッグモードベースの関数の代わりに) ターゲットベースの関数を使用することが時折あります。1. シミュレータ上でアプリケーションを実行して、アプリの実行中にコンソールに出力を見つけることができるか確認する。2. デバイスを Mac に接続して、Xcode 経由でデバイス上のアプリケーションを実行し、アプリの実行中にコンソールに出力を見つけることができるか確認する。

他の「マネージャベース」のデバッグコードでは、シミュレータとデバイスの両方でアプリケーションをクリックして、いくつかの機能を見つけることができるか確認します。アプリの事前設定プロファイルを許可する機能、実サーバーを選択する機能、API からの可能なレスポンスを選択する機能など。

#### 改善方法

デバッグ用に作成した文が以下でないことが分かっている限りにおいては、開発者がデバッグバージョンのアプリケーションにデバッグ文を組み込むことは問題ではありません。- コードがリリースバージョンのアプリケーションに存在して実際の計算結果に影響を与える。- 最終的にアプリケーションのリリース構成にもある。

Objective-C では、開発者はプリプロセッサマクロを使用してデバッグコードを除外できます。

```objc
#ifdef DEBUG
    // Debug-only code
#endif
```

Swift 2 では、Xcode 7 を使用して、すべてのターゲットにカスタムコンパイラフラグを設定する必要があります。コンパイラフラグは -D で始まる必要があります。したがって、デバッグフラグ -DMSTG-DEBUG を設定されている場合、以下のアノテーションが使用できます。

```swift
#if MSTG-DEBUG
    // Debug-only code
#endif
```

Swift 3 では、Xcode 8 を使用して、Build settings / Swift compiler - Custom flags の Active Compilation Conditions setting を設定できます。Swift3 はプリプロセッサを使用せず、代わりに定義された条件に基づく条件付きコンパイルブロックを使用します。

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

- XCode およびシミュレータ
- 標準的な iPhone/iPad


### 例外処理のテスト

#### 概要
例外はアプリケーションが正常ではない状態やエラーのある状態になった場合によく発生します。
例外処理のテストとは、アプリケーションで使用される UI とロギングメカニズムの両方で機密情報を開示することなく、アプリケーションが例外を処理して安全な状態になることを再確認することです。

但し、Objective-C の例外処理は Swift とはまったく異なることに注意します。従来の Objective-C コードと Swift コードの両方を持つアプリケーションで二つの概念を相互に橋渡しすることは問題になる可能性があります。

##### 例外処理 (Objective-C)
Objective-C には二種類のエラーがあります。

**NSException**
`NSException` はプログラミングエラーや低レベルエラー (0 による除算、配列の境界外アクセスなど) を処理するために使用されます。
`NSException` は `raise()` によるレイズ、または `@throw` でスローされます。catch されない場合、unhandled 例外ハンドラが呼び出され、ステートメントをログ出力してプログラムを停止します。`@try`-`@catch` ブロックを使用している場合、`@catch` はそれから回復できます。
```obj-c
 @try {
 	//do work here
 }

@catch (NSException *e) {
	//recover from exception
}

@finally {
 	//cleanup
```

NSException の使用にはメモリ管理に関する落とし穴があることに気をつけます。finally ブロック内で try ブロックでの割り当てをクリーンアップする必要があります <sup>[1], [2]</sup> 。`@catch` ブロックで `NSError` をインスタンス化することにより `NSException` オブジェクトを `NSError` に変換できることに注意します。

**NSError**
`NSError` は他のすべてのタイプのエラーに使用されます <sup>[3]</sup> 。Cocoa フレームワークの一部の API では何かが間違っている場合の失敗時コールバックのオブジェクトしてそれらを提供します。もしくは、`NSError` オブジェクトへのポインタが参照渡しされます。`NSError` オブジェクトへのポインタをとり、もともと (成功か失敗かを示す) 戻りタイプの戻り値を持たないメソッドに、`BOOL` の戻り値型を提供することはよい習慣です。戻り値の型がある場合、エラーの場合に nil を戻すことを確認します。したがって NO または nil の場合には、エラーや失敗の理由を調べることができます。
 
##### 例外処理 (Swift)
Swift (2～4) の例外処理はまったく異なります。try-catch ブロックがあるにもかかわらず、NSException を処理することはできません。代わりに、`Error` (Swift3 の場合、Swift2 では `ErrorType`) プロトコルに準拠するエラーを処理するために使用されます。同じアプリケーションで Objective-C と Swift コードを組み合わせる場合、これは困難になることがあります。したがって、両方の言語が関係するプログラムでは `NSException` を使用するよりも `NSError`を使用することを推奨します。さらに、Objective-C のエラー処理はオプトインですが、Swift では明示的に `throws` を処理する必要があります。エラーを throw する際の変換には、Apple のドキュメント <sup>[4]</sup> を参照ください。
エラーを throw するメソッドは `throws` キーワードを使用します。Swift でエラーを処理する方法は四つあります <sup>[5]</sup> 。

- 関数からその関数を呼び出すコードにエラーを伝えることができます。この場合、do-catch はありません。単に実際のエラーを throw する `throw` があるか、throw するメソッドを実行する `try` があります。`try` を含むメソッドには `throws` キーワードも必要です。

```swift
func dosomething(argumentx:TypeX) throws {
	try functionThatThrows(argumentx: argumentx)
}
```
- do-catch 文を使用してエラーを処理します。ここでは以下のパターンを使用できます。

```swift
do {
    try functionThatThrows()
    defer {
    	//use this as your finally block as with Objective-c
    }
    statements
} catch pattern 1 {
    statements
} catch pattern 2 where condition {
    statements
}
```

- エラーを optional 値として処理します。

```
	let x = try? functionThatThrows()
	//In this case the value of x is nil in case of an error.

```
- エラーが発生しないことを assert します。`try!` 式を使用します。



#### 静的解析
ソースコードをレビューして、アプリケーションがさまざまなタイプのエラー (IPC 通信、リモートサービス呼び出しなど) をどのように処理するか理解および特定します。言語ごとにこのステージで実行されるチェックの例をいくつか示します。

##### 静的解析 (Objective-C)
ここでは以下を検証します。

* アプリケーションは例外やエラーを処理するために十分に設計および統合されたスキームを使用している。
* Cocoa フレームワークの例外を正しく処理している。
* `@try` ブロックで割り当てたメモリは `@finally` ブロックで解放している。
* すべての `@throw` に対して、呼び出し側のメソッドは適切な `@catch` を呼び出し側のメソッドレベルか `NSApplication` / `UIApplication` オブジェクトのレベルで持ち、機密情報をクリーンアップし、あるいは問題から回復しようと試みる。
* UI またはログステートメントでエラーを処理する際に、アプリケーションは機密情報を開示することはないが、ユーザーに問題を十分詳細に説明している。
* リスクの高いアプリケーションの場合には、鍵マテリアルや認証情報などの機密情報は `@finally` ブロックで常に消去される。
* これ以上の警告なしでプログラムの終了が必要がある場合のまれな状況でのみ `raise()` が使用される。
* `NSError` オブジェクトには機密情報が漏洩する可能性のある情報を含まない。

##### 静的解析 (Swift)
ここでは以下を検証します。

* アプリケーションはエラーを処理するために十分に設計および統合されたスキームを使用している。
* UI またはログステートメントでエラーを処理する際に、アプリケーションは機密情報を開示することはないが、ユーザーに問題を十分詳細に説明している。
* リスクの高いアプリケーションの場合には、鍵マテリアルや認証情報などの機密情報は `defer` ブロックで常に消去される。
* `try!` は前面を適切にガードすることにのみ使用される。`try!` を使用して呼び出されるメソッドによりエラーはスローされないことがプログラムで検証されている。

#### 動的解析

動的解析にはさまざまな方法があります。

- iOS アプリケーションの UI フィールドに予期しない値を入力する。
- 予期しない値や例外を発生させる可能性のある値を指定して、カスタム URL スキーム、ペーストボード、その他アプリ間通信制御をテストする。
- ネットワーク通信やアプリケーションにより格納されたファイルを改竄する。
- Objective-C の場合には、Cycript を使用してメソッドにフックし、呼出先に例外をスローする可能性のある引数を入力する。

In most cases, the application should not crash, but instead, it should:

- Recover from the error or get into a state in which it can inform the user that it is not able to continue.
- If necessary, inform the user in an informative message to make him/her take appropriate action. The message itself should not leak sensitive information.
- Not provide any information in logging mechanims used by the application.

#### 改善方法
There are a few things a developer can do:
- Ensure that the application use a well-designed and unified scheme to handle errors.
- Make sure that all logging is removed or guarded as described in ["Testing for Debugging Code and Verbose Error Logging" for iOS]{TODO: whatlinkshouldbehere?}.
- For Objective-C, in case of a high-risk application: create your own exception handler which cleans out any secret that should not be easily retrieved. The handler that can be set through `NSSetUncaughtExceptionHandler`.
- When using Swift, make sure that you do not use `try!` unless you have made sure that there really cannot be any error in the method the throwing method that is being called.
- When using Swift, make sure that the error does not propagate too far off through intermediate methods.

#### 参考情報

##### OWASP Mobile Top 10 2016

- M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V7.5: "アプリは可能性のある例外をキャッチし処理している。"
- V7.6: "セキュリティコントロールのエラー処理ロジックはデフォルトでアクセスを拒否している。"

##### CWE

-- TODO [Add relevant CWE for "Testing Exception Handling"] --

##### Info

-  [1] Raising exceptions - https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/RaisingExceptions.html#//apple_ref/doc/uid/20000058-BBCCFIBF
-  [2] Handling Exceptions - https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/HandlingExceptions.html
-  [3] Dealing with Errors - https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/ErrorHandling/ErrorHandling.html
-  [4] Adopting Cocoa Design Patterns - https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/AdoptingCocoaDesignPatterns.html
-  [5] Error Handling - https://developer.apple.com/library/content/documentation/Swift/Conceptual/Swift_Programming_Language/ErrorHandling.html


##### Tools

-- CyCript

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
  - 必要に応じてメッセージを保持および解放します
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
2. "Other C Flags" セクションで "–fstack-protector-all" オプションが選択されていることを確認します。

- PIE サポート

iOS アプリケーションを PIE としてビルドする手順：

1. Xcodeで、"Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックして設定を表示します。
2. iOS アプリの場合、iOS Deployment Target を iOS 4.3 もしくはそれ以降に設定します。
3. "Generate Position-Dependent Code" がデフォルト値の NO に設定されていることを確認します。
4. "Create Position Independent Executables" がデフォルト値の NO に設定されていないことを確認します。

- ARC 保護

iOS アプリケーションで ACR 保護を有効にする手順：

1. Xcodeで、"Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックして設定を表示します。
2. "Objective-C Automatic Reference Counting" がデフォルト値の YES に設定されていることを確認します。

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
