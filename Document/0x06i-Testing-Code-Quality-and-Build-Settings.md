# iOS のコード品質とビルド設定

## アプリが正しく署名されていることの確認 (MSTG-CODE-1)

### 概要

アプリを [コード署名](0x06a-Platform-Overview.md#code-signing) することで、アプリが既知のソースを持ち、最後に署名されてから改変されていないことをユーザーに保証します。アプリは、アプリサービスを統合する前、脱獄していないデバイスにインストールされるか、App Store に提出する前に、Apple により発行された証明書で署名される必要があります。証明書をリクエストしてアプリにコード署名する方法の詳細については、[アプリ配布ガイド](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/Introduction/Introduction.html "App Distribution Guide") をご覧ください。

### 静的解析

アプリが [最新のコード署名形式を使用している](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format) ことを確認する必要があります。[codesign](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html "Code Signing Tasks") でアプリの .app ファイルから署名証明書情報を取得できます。codesign はコード署名の作成、確認、表示、およびシステム内の署名済みコードの動的ステータスの照会に使用されます。

アプリケーションの IPA ファイルを取得した後、ZIP ファイルとして再度保存し、ZIP ファイルを展開します。アプリケーションの .app ファイルがある Payload ディレクトリに移動します。

以下の `codesign` コマンドを実行して、署名情報を表示します。

```bash
$ codesign -dvvv YOURAPP.app
Executable=/Users/Documents/YOURAPP/Payload/YOURAPP.app/YOURNAME
Identifier=com.example.example
Format=app bundle with Mach-O universal (armv7 arm64)
CodeDirectory v=20200 size=154808 flags=0x0(none) hashes=4830+5 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha1=455758418a5f6a878bb8fdb709ccfca52c0b5b9e
CandidateCDHash sha256=fd44efd7d03fb03563b90037f92b6ffff3270c46
Hash choices=sha1,sha256
CDHash=fd44efd7d03fb03563b90037f92b6ffff3270c46
Signature size=4678
Authority=iPhone Distribution: Example Ltd
Authority=Apple Worldwide Developer Relations Certification Authority
Authority=Apple Root CA
Signed Time=4 Aug 2017, 12:42:52
Info.plist entries=66
TeamIdentifier=8LAMR92KJ8
Sealed Resources version=2 rules=12 files=1410
Internal requirements count=1 size=176
```

[Apple ドキュメント](https://developer.apple.com/business/distribute/ "Apple Business") で説明されているように、アプリを配布するにはいくつかの方法があります。App Store を使用する方法や、カスタムディストリビューションや組織内ディストリビューション向けに Apple Business Manager を使用する方法があります。組織内ディストリビューションスキームの場合、ディストリビューション用にアプリに署名する際にアドホック証明書が使用されていないことを確認します。

## アプリがデバッグ可能かどうかの判断 (MSTG-CODE-2)

### 概要

iOS アプリケーションのデバッグは lldb と呼ばれる強力なデバッガを組み込んだ Xcode を使用して行うことができます。lldb は Xcode5 以降のデフォルトデバッガであり、gdb などの GNU ツールを置き換え、開発環境に完全に統合されています。デバッグはアプリを開発する際には便利な機能ですが、App Store やエンタープライズプログラムにリリースする前にオフにする必要があります。

ビルドモードまたはリリースモードでのアプリケーションの生成は Xcode のビルド設定に依存します。アプリがデバッグモードで生成されると、DEBUG フラグが生成されたファイルに挿入されます。

### 静的解析

まず環境内のフラグをチェックするために、アプリを生成するモードを決定する必要があります。

- プロジェクトのビルド設定を選択します。
- 'Apple LVM - Preprocessing' と 'Preprocessor Macros' で、'DEBUG' または 'DEBUG_MODE' が選択されていないことを確認します (Objective-C) 。
- "Debug executable" オプションが選択されていないことを確認します。
- もしくは 'Swift Compiler - Custom Flags' セクションの 'Other Swift Flags' で、'-D DEBUG' エントリが存在しないことを確認します。

### 動的解析

Xcode を使用して、直接デバッガをアタッチできるかどうかを確認します。次に、脱獄済みデバイスで Clutch を行った後にアプリをデバッグできるかどうかを確認します。これは Cydia の BigBoss リポジトリにある debug-server を使用して行われます。

注意: アプリケーションにアンチリバースエンジニアリングコントロールが装備されている場合、デバッガを検出して停止することがあります。

## デバッグシンボルの検索 (MSTG-CODE-3)

### 概要

良い習慣として、コンパイルされたバイナリで提供される説明情報はできる限り少なくするべきです。デバッグシンボルなどの付加的なメタデータの存在はコードに関する貴重な情報を提供する可能性があります。例えば、関数名は関数が何をするかについての情報を漏洩します。このメタデータはバイナリの実行には必要ありませんので、リリースビルド時に破棄しても問題ありません。これは適切なコンパイラ設定を使用して実行できます。テスト担当者としてはアプリで配布されるすべてのバイナリを検査し、デバッグシンボルが存在しないことを確認するべきです (少なくともデバッグシンボルはコードに関する貴重な情報を漏洩します) 。

iOS アプリケーションがコンパイルされると、コンパイラはアプリ内の各バイナリファイル (メインアプリ実行可能ファイル、フレームワーク、アプリ拡張機能) のデバッグシンボルのリストを生成します。これらのシンボルにはクラス名、グローバル変数、メソッド名や関数名が含まれ、それらが定義されている特定のファイルと行番号にマップされます。アプリのデバッグビルドはデフォルトでコンパイル済みバイナリにデバッグシンボルを配置しますが、アプリのリリースビルドは配布するアプリのサイズを縮小するためにコンパニオン _Debug Symbol ファイル_ (dSYM) に配置します。

### 静的解析

デバッグシンボルの存在を検証するには [binutils](https://www.gnu.org/s/binutils/ "Binutils") の objdump または [llvm-objdump](https://llvm.org/docs/CommandGuide/llvm-objdump.html "llvm-objdump") を使用してすべてのアプリバイナリを検査できます。

以下のスニペットでは `TargetApp` (iOS メインアプリ実行可能ファイル) に対して objdump を実行して `d` (debug) フラグでマークされたデバッグシンボルを含むバイナリの典型的な出力を示しています。その他のさまざまなシンボルフラグ文字については [objdump man page](https://www.unix.com/man-page/osx/1/objdump/ "objdump man page") を確認してください。

```bash
$ objdump --syms TargetApp

0000000100007dc8 l    d  *UND* -[ViewController handleSubmitButton:]
000000010000809c l    d  *UND* -[ViewController touchesBegan:withEvent:]
0000000100008158 l    d  *UND* -[ViewController viewDidLoad]
...
000000010000916c l    d  *UND* _disable_gdb
00000001000091d8 l    d  *UND* _detect_injected_dylds
00000001000092a4 l    d  *UND* _isDebugged
...
```

デバッグシンボルが含まれないようにするには、 XCode プロジェクトのビルド設定で `Strip Debug Symbols During Copy` を `YES` に設定します。デバッグシンボルを削除するとバイナリサイズが小さくなるだけでなく、リバースエンジニアリングの難易度が上がります。

### 動的解析

動的解析はデバッグシンボルの検索には適用できません。

## デバッグコードと詳細エラーログの検索 (MSTG-CODE-4)

### 概要

検証をスピードアップしエラーの理解を深めるために、開発者は API からのレスポンスやアプリケーションの状況や状態について (`NSLog`, `println`, `print`, `dump`, `debugPrint` を使用して) 詳細なログ出力文などのデバッグコードをしばしば埋め込みます。さらに、アプリケーションの状態や API からの疑似応答を設定するために開発者が使用する「管理機能」と呼ばれるデバッグコードが存在する可能性があります。リバースエンジニアはこの情報を使用してアプリケーションで起こっていることを簡単に追跡できます。したがって、デバッグコードはアプリケーションのリリースバージョンから削除する必要があります。

### 静的解析

ログ出力文について以下の静的解析アプローチをとることができます。

1. Xcode にアプリケーションのコードをインポートします。
2. 次の出力関数についてコードを検索します: `NSLog`, `println`, `print`, `dump`, `debugPrint`.
3. いずれか一つを見つけたら、ログ出力されるステートメントのより良いマークアップのために開発者がログ出力関数を囲うラップ関数を使用しているかどうかを判断します。そうであれば、その関数を検索に追加します。
4. 手順 2 と 3 のすべてのものについて、マクロやデバッグ状態に関連するガードがリリースビルドでログ出力なしにするように設定されているかどうかを判断します。Objective-C がプリプロセッサマクロを使用する方法の変更点に注意します。

```objectivec
#ifdef DEBUG
    // Debug-only code
#endif
```

Swift ではこの動作を有効にする手続きが変更されています。スキームで環境変数を設定するか、ターゲットのビルド設定でカスタムフラグとして設定する必要があります。Xcode 8 および Swift3 ではサポートされていないため、(アプリが Swift 2.1 のリリース構成でビルドされているかどうかを判断できる) 次の関数は推奨されていないことに注意します。

- `_isDebugAssertConfiguration`
- `_isReleaseAssertConfiguration`
- `_isFastAssertConfiguration`.

アプリケーションの設定に応じて、より多くのログ出力関数が存在する可能性があります。例えば、[CocoaLumberjack](https://github.com/CocoaLumberjack/CocoaLumberjack "CocoaLumberjack") を使用する場合、静的解析は多少異なります。

(ビルトインの) 「デバッグ管理」コードについて、ストーリーボードを調査して、アプリケーションがサポートすべき機能とは異なる機能を提供するフローやビューコントローラがあるかどうかを確認します。この機能には、デバッグビューからエラーメッセージ出力まで、カスタムスタブレスポンス構成からアプリケーション上のファイルシステムやリモートサーバーへのログ出力まで、いろいろあります。

一人の開発者として、アプリケーションのデバッグバージョンにデバッグステートメントを組み込むことは、デバッグステートメントがアプリケーションのリリースバージョンに存在しないことを確認していれば問題ありません。

Objective-C では、開発者はプリプロセッサマクロを使用してデバッグコードを除外できます。

```objectivec
#ifdef DEBUG
    // Debug-only code
#endif
```

Swift 2 では (Xcode 7 を使用して) 、すべてのターゲットにカスタムコンパイラフラグを設定する必要があります。コンパイラフラグは "-D" で始まる必要があります。したがって、デバッグフラグ `MSTG-DEBUG` を設定されている場合、以下のアノテーションが使用できます。

```default
#if MSTG-DEBUG
    // Debug-only code
#endif
```

Swift 3 では (Xcode 8 を使用して) 、Build settings/Swift compiler - Custom flags の Active Compilation Conditions を設定できます。プリプロセッサを使用する代わりに、Swift3 は定義済みの条件に基づく [条件付きコンパイルブロック](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/InteractingWithCAPIs.html#//apple_ref/doc/uid/TP40014216-CH8-ID34 "Swift conditional compilation blocks") を使用します。

```default
#if DEBUG_LOGGING
    // Debug-only code
#endif
```

### 動的解析

動的解析はシミュレータとデバイスの両方で実行すべきです。開発者はデバッグコードを実行するために (リリース/デバッグモードベースの関数の代わりに) ターゲットベースの関数を使用することが時折あるためです。

1. シミュレータ上でアプリケーションを実行して、アプリの実行中にコンソールで出力を確認します。
2. デバイスを Mac に接続して、Xcode 経由でデバイス上のアプリケーションを実行し、アプリの実行中にコンソールで出力を確認します。

他の「マネージャベース」のデバッグコードでは、シミュレータとデバイスの両方でアプリケーションをクリックして、アプリのプロファイルをプリセットできる機能、実サーバーを選択する機能、API からのレスポンスを選択する機能があるかどうかを確認します。

## サードパーティライブラリの脆弱性のチェック (MSTG-CODE-5)

### 概要

iOS アプリケーションではサードパーティライブラリを使用することがよくあります。これらのサードパーティライブラリは開発者が問題を解決するためのコード記述を少なくし、開発を加速します。しかし、サードパーティライブラリには脆弱性、互換性のないライセンス、または悪意のあるコンテンツが含まれている可能性があります。さらに、ライブラリリリースの監視や利用可能なセキュリティパッチの適用など、組織や開発者はアプリケーションの依存関係を管理することが困難となります。

広く使用されているパッケージ管理ツールには [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org"), [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub"), [CocoaPods](https://cocoapods.org "CocoaPods.org") の三つがあります。

- Swift Package Manager はオープンソースであり、 Swift 言語に含まれ、 Xcode に統合 (Xcode 11 以降) され、 [Swift, Objective-C, Objective-C++, C, および C++](https://developer.apple.com/documentation/swift_packages "Swift Packages Documentation") パッケージをサポートします。 Swift で記述され、分散化されており、 Package.swift ファイルを使用してプロジェクト依存関係を文書化および管理します。
- Carthage はオープンソースであり、 Swift および Objective-C パッケージに使用できます。Swift で記述され、分散化されており、 Cartfile ファイルを使用してプロジェクトの依存関係を文書化および管理します。
- CocoaPods はオープンソースであり、 Swift および Objective-C パッケージに使用できます。 Ruby で記述され、パブリックおよびプライベートパッケージの集中パッケージレジストリを利用し、 Podfile ファイルを使用してプロジェクトの依存関係を文書化および管理します。

ライブラリには二つのカテゴリがあります。

- 実際の製品アプリケーションにはパックされない (またはすべきではない) ライブラリ、テストに使用される `OHHTTPStubs` など。
- 実際の製品アプリケーションにパックされるライブラリ、`Alamofire` など。

これらのライブラリは望ましくない副作用を引き起こす可能性があります。

- ライブラリには脆弱性が存在する可能性があり、アプリケーションを脆弱にする可能性があります。よい例は `AFNetworking` バージョン 2.5.1 で、証明書検証を無効にしたバグがありました。この脆弱性により攻撃者は API に接続するためにライブラリを使用しているアプリに対して中間者攻撃を実行できます。
- ライブラリはもはや保守されていないかほとんど使用できない可能性があります。脆弱性が報告されず修正されないためです。これによりライブラリを介してアプリケーションに不正なコードや脆弱なコードが含まれる可能性があります。
- ライブラリは LGPL2.1 などのライセンスを使用できます。そのライセンスでは、アプリケーションを使用しソースの内容を要求する人に対して、アプリケーション作成者はソースコードへのアクセスを提供する必要があります。実際にはアプリケーションはそのソースコードを改変して再配布することを許可される必要があります。これはアプリケーションの知的財産 (IP) を危険にさらす可能性があります。

この問題は複数のレベルで発生する可能性があることに注意します。WebView を使用し、WebView で JavaScript を実行する場合、JavaScript ライブラリにもこれらの問題があります。同じことが Cordova, React-native, Xamarin アプリのプラグインやライブラリにも当てはまります。

### 静的解析

#### サードパーティライブラリの脆弱性の検出

アプリにより使用されるライブラリに脆弱性がないようにするためには、CocoaPods や Carthage によりインストールされた依存関係を確認することがベストです。

##### Swift Package Manager

サードパーティ依存関係の管理に [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org") を使用する場合、以下の手順を実行してサードパーティライブラリを解析し、脆弱性がないか確認できます。

最初に、 Package.swift ファイルが置かれているプロジェクトのルートで、以下のように入力します。

```bash
$ swift build
```

次に、 Package.resolved ファイルで実際に使用されているバージョンを確認し、特定のライブラリに既知の脆弱性がないか検査します。

[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/ "OWASP Dependency-Check") の実験的な [Swift Package Manager Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/swift.html "dependency-check - SWIFT Package Manager Analyzer") を利用して、すべての依存関係の [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") 命名スキームと対応する [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/ "CVE") エントリを識別することができます。以下のコマンドでアプリケーションの Package.swift ファイルをスキャンし、既知の脆弱なライブラリのレポートを生成します。

```bash
$ dependency-check  --enableExperimental --out . --scan Package.swift
```

##### CocoaPods

サードパーティ依存関係の管理に [CocoaPods](https://cocoapods.org "CocoaPods.org") を使用する場合、以下の手順を実行してサードパーティライブラリを解析し、脆弱性がないか確認できます。

最初に、 Podfile があるプロジェクトのルートで、以下のコマンドを実行します。

```bash
$ sudo gem install cocoapods
$ pod install
```

次に、依存関係ツリーが構築されたので、以下のコマンドを実行して依存関係とそのバージョンの概要を作成します。

```bash
$ sudo gem install cocoapods-dependencies
$ pod dependencies
```

上記の手順の結果を、既知の脆弱性に対するさまざまな脆弱性フィードを検索するための入力として使用できます。

> 注釈:
>
> 1. 開発者が .podspec ファイルを使用して自身のサポートライブラリに関してすべての依存関係をパックする場合、この .podspec ファイルを実験的な CocoaPods podspec checker で確認できます。
> 2. プロジェクトで CocoaPods を Objective-C と組み合わせて使用する場合、SourceClear を使用できます。
> 3. HTTPS ではなく HTTP ベースのリンクを持つ CocoaPods を使用すると、依存関係のダウンロード時に中間者攻撃を許す可能性があり、攻撃者はライブラリ (の一部) を他のコンテンツと置き換える可能性があります。したがって、常に HTTPS を使用します。

[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/ "OWASP Dependency-Check") の実験的な [CocoaPods Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/cocoapods.html "dependency-check - CocoaPods Analyzer") を利用して、
すべての依存関係の [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") 命名スキームと対応する [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/ "CVE") エントリを識別することができます。以下のコマンドでアプリケーションの \*.podspec や Podfile.lock ファイルをスキャンし、既知の脆弱なライブラリのレポートを生成します。

```bash
$ dependency-check  --enableExperimental --out . --scan Podfile.lock
```

##### Carthage

サードパーティ依存関係の管理に [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub") を使用する場合、以下の手順を実行してサードパーティライブラリを解析し、脆弱性がないか確認できます。

最初に、 Cartfile があるプロジェクトのルートで、以下を入力します。

```bash
$ brew install carthage
$ carthage update --platform iOS
```

次に、 Cartfile を確認します。使用されている実際のバージョンを解決し、既知の脆弱性についてライブラリを調査します。

> 注釈、この章の執筆時点では、執筆者に知られている Carthage ベースの依存関係解析の自動サポートはありません。少なくとも、この機能は OWASP DependencyCheck ツールですでにリクエストされていますがまだ実装されていません ([GitHub issue](https://github.com/jeremylong/DependencyCheck/issues/962 "Add Carthage Analyze for Swift") を参照) 。

##### 発見されたライブラリ脆弱性

ライブラリに脆弱性が含まれていることが判明した場合、以下の推論を適用します。

- ライブラリがアプリケーションにパッケージされている場合、それからライブラリに脆弱性がパッチされているバージョンがあるか確認します。ない場合、脆弱性が実際にアプリケーションに影響を及ぼすかどうかを確認します。それが当てはまる場合、または将来そうなる可能性がある場合、同様の機能を提供する、脆弱性のない代替手段を探します。
- ライブラリはアプリケーションにはパッケージされていない場合、脆弱性が修正されているパッチされたバージョンがあるかどうかを確認します。これがない場合、ビルドプロセスに対する脆弱性の影響を調べます。脆弱性がビルドを邪魔したり、ビルドパイプラインのセキュリティを弱めたりする場合、脆弱性が修正される代替案を探してみます。

リンクされるライブラリとしてフレームワークを手動で追加する場合。

1. xcodeproj ファイルを開き、プロジェクトのプロパティを確認します。
2. **Build Phases** タブに移動して、いずれかのライブラリの **Link Binary With Libraries** のエントリを確認します。[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF "MobSF") を使用して同様の情報を取得する方法については、これまでのセクションを参照してください。

コピー＆ペーストされたソースの場合、(Objective-C を使用する場合) ヘッダファイルを検索し、あるいは既存のライブラリの既存のメソッド名の Swift ファイルを検索します。

次に、ハイブリッドアプリケーションでは、JavaScript の依存関係を [RetireJS](https://retirejs.github.io/retire.js/ "RetireJS") で確認する必要があることに注意します。同様に Xamarin では、C# の依存関係を確認する必要があります。

最後に、アプリケーションがリスクの高いアプリケーションである場合、ライブラリを手動で検査することになります。その場合、ネイティブコードには特定の要件があります。これはアプリケーション全体に対して MASVS により確立された要件に似ています。その次に、ソフトウェアエンジニアリングのすべてのベストプラクティスが適用されているかどうかを吟味することをお勧めします。

#### アプリケーションのライブラリで使用されるライセンスの検出

著作権法が侵害されないようにするには、Swift Packager Manager, CocoaPods または Carthage によりインストールされた依存関係を確認することがベストです。

##### Swift Package Manager

アプリケーションソースが利用可能で Swift Package Manager が使用されている場合、 Package.swift ファイルが置かれているプロジェクトのルートディレクトリで以下のコードを実行します。

```bash
$ swift build
```

これで各依存関係のソースがプロジェクトの `/.build/checkouts/` フォルダにダウンロードされました。ここで各ライブラリのライセンスをそれぞれのフォルダに見つけることができます。

##### CocoaPods

アプリケーションソースが利用可能であり、CocoaPods が使用されている場合、以下の手順を実行してそれぞれのライセンスを取得します。
最初に、 Podfile があるプロジェクトのルートで、以下を実行します。

```bash
$ sudo gem install CocoaPods
$ pod install
```

これにより、すべてのライブラリがインストールされている Pods フォルダが作成されます。ライブラリは各自のフォルダにあります。各フォルダのライセンスファイルを調べることで、各ライブラリのライセンスを確認できます。

##### Carthage

アプリケーションソースが利用可能であり、Carthage が使用されている場合、 Cartfile があるプロジェクトのルートディレクトリで、以下のコードを実行します。

```bash
$ brew install carthage
$ carthage update --platform iOS
```

各依存関係のソースはプロジェクトの `Carthage/Checkouts` フォルダにダウンロードされます。ここで各ライブラリのそれぞれのフォルダにライセンスを見つけることができます。

##### ライブラリライセンスの問題

ライブラリがアプリの知的財産をオープンソース化する必要があるライセンスを含む場合、同様の機能を提供するために使用できるライブラリの代替があるかどうかを確認します。

注釈：ハイブリッドアプリの場合、使用のビルドツールを確認してください。それらの多くは使用されているライセンスを見つけるためのライセンス列挙プラグインを持っています。

### 動的解析

このセクションの動的解析は二つのパートで構成されています。実際のライセンスの検証と、ソースが見つからない場合にどのライブラリが関与しているかの確認です。

ライセンスの著作権が守られているかどうかを検証する必要があります。これは通常、サードパーティライブラリのライセンスにより要求されるものとして、著作権表示が記されている `about` や `EULA` セクションをアプリケーションが持つべきであることを意味しています。

#### アプリケーションライブラリの一覧表示

アプリ解析を実行する際には、アプリの (通常はライブラリまたはいわゆる iOS フレームワークの形式での) 依存関係も解析し、脆弱性が含まれていないことを確認することが重要です。ソースコードがない場合でも、 [objection](https://github.com/sensepost/objection), [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), otool などのツールを使用して、アプリの依存関係の一部を特定できます。 objection は最も正確な結果が得られ、使いやすいため、推奨のツールです。これには iOS バンドルと連携するモジュールが含まれており、 `list_bundles` と `list_frameworks` という二つのコマンドを提供します。

`list_bundles` コマンドはフレームワークに関係しないアプリケーションのすべてのバンドルを一覧表示します。出力には実行可能ファイル名、バンドル ID 、ライブラリのバージョン、ライブラリのパスが含まれます。

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_bundles
Executable    Bundle                                       Version  Path
------------  -----------------------------------------  ---------  -------------------------------------------
DVIA-v2       com.highaltitudehacks.DVIAswiftv2.develop          2  ...-1F0C-4DB1-8C39-04ACBFFEE7C8/DVIA-v2.app
CoreGlyphs    com.apple.CoreGlyphs                               1  ...m/Library/CoreServices/CoreGlyphs.bundle
```

`list_frameworks` コマンドはフレームワークを表すアプリケーションのすべてのバンドルを一覧表示します。

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_frameworks
Executable      Bundle                                     Version    Path
--------------  -----------------------------------------  ---------  -------------------------------------------
Bolts           org.cocoapods.Bolts                        1.9.0      ...8/DVIA-v2.app/Frameworks/Bolts.framework
RealmSwift      org.cocoapods.RealmSwift                   4.1.1      ...A-v2.app/Frameworks/RealmSwift.framework
                                                                      ...ystem/Library/Frameworks/IOKit.framework
...
```

## 例外処理のテスト (MSTG-CODE-6)

### 概要

例外はアプリケーションが正常ではない状態やエラーのある状態になった場合によく発生します。
例外処理のテストとは、ログ出力メカニズムや UI を介して機密情報を開示することなく、アプリケーションが例外を処理して安全な状態になることを確認することです。

但し、Objective-C の例外処理は Swift とはまったく異なることに注意します。従来の Objective-C コードと Swift コードの両方で書かれたアプリケーションで二つの概念を橋渡しすることは問題になる可能性があります。

#### Objective-C の例外処理

Objective-C には二種類のエラーがあります。

**NSException**
`NSException` はプログラミングエラーや低レベルエラー (0 による除算、配列の境界外アクセスなど) を処理するために使用されます。
`NSException` は `raise` によりレイズされるか、または `@throw` でスローされます。catch されない場合、この例外は unhandled 例外ハンドラを呼び出し、ステートメントをログ出力します (ログ出力はプログラムを停止します) 。`@try`-`@catch` ブロックを使用している場合、`@catch` はその例外から回復できます。

```objectivec
 @try {
    //do work here
 }

@catch (NSException *e) {
    //recover from exception
}

@finally {
    //cleanup
```

`NSException` の使用にはメモリ管理の落とし穴があることに気をつけます。[finally ブロック](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/HandlingExceptions.html "Handling Exceptions") 内で try ブロックでの [割り当てをクリーンアップする](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/RaisingExceptions.html#//apple_ref/doc/uid/20000058-BBCCFIBF "Raising exceptions") 必要があります。`@catch` ブロックで `NSError` をインスタンス化することにより `NSException` オブジェクトを `NSError` に変換できることに注意します。

**NSError**
`NSError` は他のすべてのタイプの [エラー](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/ErrorHandling/ErrorHandling.html "Dealing with Errors") に使用されます。Cocoa フレームワークの一部の API では何らかの問題が発生した場合に失敗時コールバックのオブジェクトしてエラーを提供します。それらを提供しないものは `NSError` オブジェクトへのポインタを参照渡しします。成功または失敗を示す `NSError` オブジェクトへのポインタを取るメソッドに、`BOOL` の戻り値型を提供することはよい習慣です。戻り値の型がある場合、エラーの場合に `nil` を戻すことを確認します。`NO` または `nil` が戻される場合には、エラーや失敗の理由を調べることができます。

#### Swift の例外処理

Swift (2～5) の例外処理はまったく異なります。try-catch ブロックは `NSException` を処理するためのものではありません。そのブロックは `Error` (Swift3) または `ErrorType` (Swift2) プロトコルに準拠するエラーを処理するために使用されます。一つのアプリケーション内で Objective-C と Swift コードを組み合わせる場合、これは困難になることがあります。したがって、両方の言語で書かれたプログラムでは `NSException` よりも `NSError` が好まれます。さらに、Objective-C ではエラー処理はオプトインですが、Swift では明示的に `throws` を処理する必要があります。エラーを throw する際の変換には、[Apple のドキュメント](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/AdoptingCocoaDesignPatterns.html "Adopting Cocoa Design Patterns") をご覧ください。
エラーを throw するメソッドは `throws` キーワードを使用します。`Result` タイプは成功または失敗を表します。[Result](https://developer.apple.com/documentation/swift/result), [Swift 5 での Result の使用方法](https://www.hackingwithswift.com/articles/161/how-to-use-result-in-swift), [Swift での Result タイプの威力](https://www.swiftbysundell.com/posts/the-power-of-result-types-in-swift) を参照してください。。[Swift でエラーを処理する](https://developer.apple.com/library/content/documentation/Swift/Conceptual/Swift_Programming_Language/ErrorHandling.html "Error Handling in Swift") 方法は四つあります。

- 関数からその関数を呼び出すコードにエラーを伝えることができます。この場合、`do-catch` はありません。単に実際のエラーを throw する `throw` があるか、throw するメソッドを実行する `try` があります。`try` を含むメソッドには `throws` キーワードも必要です。

```default
func dosomething(argumentx:TypeX) throws {
    try functionThatThrows(argumentx: argumentx)
}
```

- `do-catch` 文を使用してエラーを処理します。ここでは以下のパターンを使用できます。

  ```default
  func doTryExample() {
      do {
          try functionThatThrows(number: 203)
      } catch NumberError.lessThanZero {
          // Handle number is less than zero
      } catch let NumberError.tooLarge(delta) {
          // Handle number is too large (with delta value)
      } catch {
          // Handle any other errors
      }
  }

  enum NumberError: Error {
      case lessThanZero
      case tooLarge(Int)
      case tooSmall(Int)
  }

  func functionThatThrows(number: Int) throws -> Bool {
      if number < 0 {
          throw NumberError.lessThanZero
      } else if number < 10 {
          throw NumberError.tooSmall(10 - number)
      } else if number > 100 {
          throw NumberError.tooLarge(100 - number)
      } else {
          return true
      }
  }
  ```

- エラーを optional 値として処理します。

  ```default
      let x = try? functionThatThrows()
      // In this case the value of x is nil in case of an error.
  ```

- `try!` 式を使用して、エラーが発生しないことを assert します。
- 一般的なエラーを `Result` 戻り値として処理します。

```default
enum ErrorType: Error {
    case typeOne
    case typeTwo
}

func functionWithResult(param: String?) -> Result<String, ErrorType> {
    guard let value = param else {
        return .failure(.typeOne)
    }
    return .success(value)
}

func callResultFunction() {
    let result = functionWithResult(param: "OWASP")

    switch result {
    case let .success(value):
        // Handle success
    case let .failure(error):
        // Handle failure (with error)
    }
}
```

- ネットワークおよび JSON デコーディングエラーを `Result` タイプで処理します。

```default
struct MSTG: Codable {
    var root: String
    var plugins: [String]
    var structure: MSTGStructure
    var title: String
    var language: String
    var description: String
}

struct MSTGStructure: Codable {
    var readme: String
}

enum RequestError: Error {
    case requestError(Error)
    case noData
    case jsonError
}

func getMSTGInfo() {
    guard let url = URL(string: "https://raw.githubusercontent.com/OWASP/owasp-mstg/master/book.json") else {
        return
    }

    request(url: url) { result in
        switch result {
        case let .success(data):
            // Handle success with MSTG data
            let mstgTitle = data.title
            let mstgDescription = data.description
        case let .failure(error):
            // Handle failure
            switch error {
            case let .requestError(error):
                // Handle request error (with error)
            case .noData:
                // Handle no data received in response
            case .jsonError:
                // Handle error parsing JSON
            }
        }
    }
}

func request(url: URL, completion: @escaping (Result<MSTG, RequestError>) -> Void) {
    let task = URLSession.shared.dataTask(with: url) { data, _, error in
        if let error = error {
            return completion(.failure(.requestError(error)))
        } else {
            if let data = data {
                let decoder = JSONDecoder()
                guard let response = try? decoder.decode(MSTG.self, from: data) else {
                    return completion(.failure(.jsonError))
                }
                return completion(.success(response))
            }
        }
    }
    task.resume()
}
```

### 静的解析

ソースコードをレビューして、アプリケーションがさまざまなタイプのエラー (IPC 通信、リモートサービス呼び出しなど) をどのように処理するか理解します。以下のセクションでは言語ごとにこのステージでチェックするものの例を示します。

#### Objective-C の静的解析

以下を確認します。

- アプリケーションは例外やエラーを処理するために十分に設計および統合されたスキームを使用しています。
- Cocoa フレームワークの例外を正しく処理しています。
- `@try` ブロックで割り当てられたメモリは `@finally` ブロックで解放されています。
- すべての `@throw` に対して、呼び出し側のメソッドは適切な `@catch` を呼び出し側のメソッドレベルか `NSApplication`/`UIApplication` オブジェクトのレベルで持ち、機密情報をクリーンアップし、可能であれば回復します。
- UI またはログステートメントでエラーを処理する際に、アプリケーションは機密情報を開示せず、そのステートメントはユーザーに問題を十分詳細に説明しています。
- リスクの高いアプリケーションの、鍵マテリアルや認証情報などの機密情報は `@finally` ブロックの実行で常に消去されます。
- `raise` はまれな状況でのみ使用されます (これ以上の警告なしでプログラムの終了が必要がある場合にそれが使用されます) 。
- `NSError` オブジェクトには機密情報が漏洩する可能性のある情報を含みません。

#### Swift の静的解析

以下を確認します。

- アプリケーションはエラーを処理するために十分に設計および統合されたスキームを使用しています。
- UI またはログステートメントでエラーを処理する際に、アプリケーションは機密情報を開示せず、そのステートメントはユーザーに問題を十分詳細に説明しています。
- リスクの高いアプリケーションの、鍵マテリアルや認証情報などの機密情報は `defer` ブロックの実行で常に消去されます。
- `try!` は前面を適切にガードすることにのみ使用されます (`try!` を使用して呼び出されるメソッドはエラーをスローしないことがプログラムで検証されています) 。

#### 適切なエラー処理

開発者はいくつかの方法で適切なエラー処理を実装できます。

- アプリケーションがエラーを処理するために十分に設計および統合されたスキームを使用していることを確認します。
- テストケース「デバッグコードと詳細エラーログのテスト」で説明されているように、すべてのログ出力が削除されている、もしくはガードされていることを確認します。
- Objective-C で書かれたリスクの高いアプリケーションの場合、容易に取得されてはいけない秘密を消去する例外ハンドラを作成します。ハンドラは `NSSetUncaughtExceptionHandler` で設定可能です。
- 呼び出されているスローメソッドにメソッドにエラーがないことを確認しない限り、Swift では `try!` を使用してはいけません。
- Swift エラーが多数の中間メソッドに伝播しないことを確認します。

### 動的テスト

動的解析にはいくつかの方法があります。

- iOS アプリケーションの UI フィールドに予期しない値を入力します。
- 予期しない値や例外を発生させる値を指定して、カスタム URL スキーム、ペーストボード、その他アプリ間通信制御をテストします。
- ネットワーク通信やアプリケーションにより格納されたファイルを改竄します。
- Objective-C の場合には、Cycript を使用してメソッドにフックし、呼出先に例外をスローする可能性のある引数を入力します。

ほとんどの場合には、アプリケーションはクラッシュしてはいけません。代わりに、以下のようにすべきです。

- エラーから回復するか、継続できないことをユーザーに通知できる状態にします。
- ユーザーに適切な措置を取らせるためのメッセージを通知します (メッセージは機密情報を漏洩してはいけません) 。
- アプリケーションにより使用されるログ出力機構には何も情報を提供しません。

## メモリ破損バグ (MSTG-CODE-8)

iOS アプリケーションはさまざまな状況でメモリ破損バグに遭遇します。まず、一般的なメモリ破損バグのセクションで言及されているネイティブコードの問題があります。次に、Objective-C と Swift のいずれにも問題を引き起こす可能性のあるネイティブコードを実際にラップするさまざまな危険な操作があります。最後に、Swift と Objective-C の実装はいずれも使用されなくなったオブジェクトを保持するためにメモリリークが発生する可能性があります。

### 静的解析

ネイティブコードの部分はありますか。もしそうなら、一般的なメモリ破損のセクションで与えられた問題を確認します。ネイティブコードはコンパイル時に見つけることは少々困難です。ソースがある場合は C ファイルでは .c ソースファイルと .h ヘッダファイルを使用し、C++ では .cpp ファイルと .h ファイルを使用します。これは Swift および Objective-C の .swift および .m ソースファイルとは少し異なります。これらのファイルはソースの一部、またはサードパーティライブラリの一部であり、フレームワークとして登録され、Carthage, Swift Package Manager, Cocoapods などのさまざまなツールを介してインポートされます。

プロジェクト内のマネージコード (Objective-C / Swift) については、以下の項目を確認します。

- 二重解放の問題: `free` が与えられた領域に対して一度ではなく二度呼ばれるとき。
- 循環保持: メモリにマテリアルを保持するコンポーネント間の強い相互参照による循環依存関係を探します。
- `UnsafePointer` のインスタンスを使用することは間違って管理される可能性があり、さまざまなメモリ破損問題を可能にします。
- 手動で `Unmanaged` によるオブジェクトへの参照カウントを管理しようと、カウンタ番号の間違いや解放の遅すぎや早すぎにつながります。

[Realm アカデミーでこの話題について素晴らしい講演が行われました](https://academy.realm.io/posts/russ-bishop-unsafe-swift/ "Russh Bishop on Unsafe Swift") 。また、この話題について Ray Wenderlich は [実際に何が起こっているかを見るための素敵なチュートリアル](https://www.raywenderlich.com/780-unsafe-swift-using-pointers-and-interacting-with-c "Unsafe Swift: Using Pointers And Interacting With C") を提供しています。

> Swift 5 ではフルブロックの割り当て解除のみ可能であることに注意します。これはプレイグラウンドが少し変更されたことを意味しています。

### 動的解析

Xcode 8 で導入された Debug Memory Graph や Xcode の Allocations and Leaks instrument など、Xcode 内でメモリバグを特定するのに役立つさまざまなツールがあります。

次に、アプリケーションのテスト時に Xcode で `NSAutoreleaseFreedObjectCheckEnabled`, `NSZombieEnabled`, `NSDebugEnabled` を有効にすることで、メモリの解放が早すぎるか遅すぎるかを確認できます。

メモリ管理の面倒を見る手助けとなるさまざまなうまくまとめられた解説があります。これらは本章の参考情報リストにあります。

## フリーなセキュリティ機能が有効であることの確認 (MSTG-CODE-9)

### 概要

Xcode ではデフォルトですべてのバイナリセキュリティが有効ですが、古いアプリケーションでの検証やコンパイルオプションの設定ミスのチェックには関係するかもしれません。以下の機能が適用可能です。

- **ARC** - Automatic Reference Counting - メモリ管理機能 - 必要に応じてメッセージ保持および解放します
- **Stack Canary** - スタックスマッシュ保護 - リターンポインタの前に小さな整数を持つことでバッファオーバーフロー攻撃の防止に役立ちます。バッファオーバーフロー攻撃はリターンポインタを上書きしてプロセスコントロールを引き継ぐために、メモリ領域を上書きすることがよくあります。その場合、カナリアも上書きされます。したがって、ルーチンがスタック上のリターンポインタを使用する前に、カナリアの値を常にチェックして変更されていないことを確認します。
- **PIE** - Position Independent Executable - 実行可能バイナリに対し完全な ASLR を有効にします (ライブラリには適用されません) 。

これらの保護メカニズムの存在を検出するためのテストは、アプリケーション開発に使用される言語に大きく依存します。例えば、スタックカナリアの存在を検出するための既存の技法は純粋な Swift アプリでは機能しません。詳細については、オンライン記事 "[On iOS Binary Protections](https://sensepost.com/blog/2021/on-ios-binary-protections/ "On iOS Binary Protection")" を確認してください。

### 静的解析

#### Xcode プロジェクト設定

##### Stack Canary 保護

iOS アプリケーションで Stack Canary 保護を有効にする手順。

1. Xcode の "Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックしてターゲットの設定を表示します。
2. "Other C Flags" セクションで "-fstack-protector-all" オプションが選択されていることを確認します。
3. Position Independent Executables (PIE) support が有効になっていることを確認します。

##### PIE 保護

iOS アプリケーションを PIE としてビルドする手順。

1. Xcode の "Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックしてターゲットの設定を表示します。
2. iOS Deployment Target を iOS 4.3 以降に設定します。
3. "Generate Position-Dependent Code" ("Apple Clang - Code Generation" セクション) がデフォルト値 ("NO") に設定されていることを確認します。
4. "Generate Position-Dependent Executable" ("Linking" セクション) がデフォルト値 ("NO") に設定されていることを確認します。

##### ARC 保護

Swift アプリでは `swiftc` コンパイラによって ARC が自動的に有効になります。一方 Objective-C アプリでは以下の手順で有効になっていることを確認します。

1. Xcode の "Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックしてターゲットの設定を表示します。
2. "Objective-C Automatic Reference Counting" がデフォルト値 ("YES") に設定されていることを確認します。

[Technical Q&A QA1788 Building a Position Independent Executable](https://developer.apple.com/library/mac/qa/qa1788/_index.html "Technical Q&A QA1788 Building a Position Independent Executable") を参照してください。

#### otool を使用

以下は上記のバイナリセキュリティ機能をチェックする手順です。これらの例ではすべての機能が有効になっています。

- PIE:

    ```bash
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

    この出力結果は `PIE` の Mach-O フラグが設定されていることを示しています。このチェックは Objective-C, Swift, ハイブリッドアプリのすべてに適用されますが、メインの実行可能ファイルにのみ適用されます。

- Stack canary:

    ```bash
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

    上記の出力結果で `__stack_chk_fail` の存在はスタックカナリアが使用されていることを示しています。このチェックは純粋な Objective-C アプリとハイブリッドアプリに適用できますが、純粋な Swift アプリには適用できません (つまり Swift は設計上、メモリセーフであるため無効と表示されていても問題ありません) 。

- ARC:

    ```bash
    $ otool -Iv DamnVulnerableIOSApp | grep release
    0x0045b7dc 83156 ___cxa_guard_release
    0x0045fd5c 83414 _objc_autorelease
    0x0045fd6c 83415 _objc_autoreleasePoolPop
    0x0045fd7c 83416 _objc_autoreleasePoolPush
    0x0045fd8c 83417 _objc_autoreleaseReturnValue
    0x0045ff0c 83441 _objc_release
    [SNIP]
    ```

    このチェックは自動的に有効になる純粋な Swift アプリを含むすべてのケースに適用できます。

### 動的解析

これらのチェックは [objection](0x08-Testing-Tools.md#objection) を使用して動的に実行できます。以下はその一例です。

```bash
com.yourcompany.PPClient on (iPhone: 13.2.3) [usb] # ios info binary
Name                  Type     Encrypted    PIE    ARC    Canary    Stack Exec    RootSafe
--------------------  -------  -----------  -----  -----  --------  ------------  ----------
PayPal                execute  True         True   True   True      False         False
CardinalMobile        dylib    False        False  True   True      False         False
FraudForce            dylib    False        False  True   True      False         False
...
```

## 参考情報

- Codesign - <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html>
- Building Your App to Include Debugging Information - <https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information>

### メモリ管理 - 動的解析事例

- <https://developer.ibm.com/tutorials/mo-ios-memory/>
- <https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/MemoryMgmt.html>
- <https://medium.com/zendesk-engineering/ios-identifying-memory-leaks-using-the-xcode-memory-graph-debugger-e84f097b9d15>

### OWASP MASVS

- MSTG-CODE-1: "アプリは有効な証明書で署名およびプロビジョニングされている。その秘密鍵は適切に保護されている。"
- MSTG-CODE-2: "アプリはリリースモードでビルドされている。リリースビルドに適した設定である（デバッグ不可など）。"
- MSTG-CODE-3: "デバッグシンボルはネイティブバイナリから削除されている。"
- MSTG-CODE-4: "デバッグコードおよび開発者支援コード (テストコード、バックドア、隠し設定など) は削除されている。アプリは詳細なエラーやデバッグメッセージをログ出力していない。"
- MSTG-CODE-5: "モバイルアプリで使用されるライブラリ、フレームワークなどのすべてのサードパーティコンポーネントを把握し、既知の脆弱性を確認している。"
- MSTG-CODE-6: "アプリは可能性のある例外をキャッチし処理している。"
- MSTG-CODE-8: "アンマネージドコードでは、メモリはセキュアに割り当て、解放、使用されている。"
- MSTG-CODE-9: "バイトコードの軽量化、スタック保護、PIEサポート、自動参照カウントなどツールチェーンにより提供されるフリーのセキュリティ機能が有効化されている。"
