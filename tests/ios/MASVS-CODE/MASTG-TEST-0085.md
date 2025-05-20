---
masvs_v1_id:
- MSTG-CODE-5
masvs_v2_id:
- MASVS-CODE-3
platform: ios
title: サードパーティライブラリの脆弱性のチェック (Checking for Weaknesses in Third Party Libraries)
masvs_v1_levels:
- L1
- L2
status: deprecated
covered_by: [MASTG-TEST-0273, MASTG-TEST-0275]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

### サードパーティライブラリの脆弱性の検出

アプリにより使用されるライブラリに脆弱性がないようにするためには、CocoaPods や Carthage によりインストールされた依存関係を確認することがベストです。

#### Swift Package Manager

サードパーティ依存関係の管理に [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org") を使用する場合、以下の手順を実行してサードパーティライブラリを解析し、脆弱性がないか確認できます。

最初に、 Package.swift ファイルが置かれているプロジェクトのルートで、以下のように入力します。

```bash
swift build
```

次に、 Package.resolved ファイルで実際に使用されているバージョンを確認し、特定のライブラリに既知の脆弱性がないか検査します。

[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/ "OWASP Dependency-Check") の実験的な [Swift Package Manager Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/swift.html "dependency-check - SWIFT Package Manager Analyzer") を利用して、すべての依存関係の [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") 命名スキームと対応する [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/ "CVE") エントリを識別することができます。以下のコマンドでアプリケーションの Package.swift ファイルをスキャンし、既知の脆弱なライブラリのレポートを生成します。

```bash
dependency-check  --enableExperimental --out . --scan Package.swift
```

#### CocoaPods

サードパーティ依存関係の管理に [CocoaPods](https://cocoapods.org "CocoaPods.org") を使用する場合、以下の手順を実行してサードパーティライブラリを解析し、脆弱性がないか確認できます。

最初に、 Podfile があるプロジェクトのルートで、以下のコマンドを実行します。

```bash
sudo gem install cocoapods
pod install
```

次に、依存関係ツリーが構築されたので、以下のコマンドを実行して依存関係とそのバージョンの概要を作成します。

```bash
sudo gem install cocoapods-dependencies
pod dependencies
```

上記の手順の結果を、既知の脆弱性に対するさまざまな脆弱性フィードを検索するための入力として使用できます。

> 注釈:
>
> 1. 開発者が .podspec ファイルを使用して自身のサポートライブラリに関してすべての依存関係をパックする場合、この .podspec ファイルを実験的な CocoaPods podspec checker で確認できます。
> 2. プロジェクトで CocoaPods を Objective-C と組み合わせて使用する場合、SourceClear を使用できます。
> 3. HTTPS ではなく HTTP ベースのリンクを持つ CocoaPods を使用すると、依存関係のダウンロード時に [中間マシン (Machine-in-the-Middle, MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃を許す可能性があり、攻撃者はライブラリ (の一部) を他のコンテンツと置き換える可能性があります。したがって、常に HTTPS を使用します。

[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/ "OWASP Dependency-Check") の実験的な [CocoaPods Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/cocoapods.html "dependency-check - CocoaPods Analyzer") を利用して、
すべての依存関係の [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") 命名スキームと対応する [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/ "CVE") エントリを識別することができます。以下のコマンドでアプリケーションの \*.podspec や Podfile.lock ファイルをスキャンし、既知の脆弱なライブラリのレポートを生成します。

```bash
dependency-check  --enableExperimental --out . --scan Podfile.lock
```

#### Carthage

サードパーティ依存関係の管理に [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub") を使用する場合、以下の手順を実行してサードパーティライブラリを解析し、脆弱性がないか確認できます。

最初に、 Cartfile があるプロジェクトのルートで、以下を入力します。

```bash
brew install carthage
carthage update --platform iOS
```

次に、 Cartfile を確認します。使用されている実際のバージョンを解決し、既知の脆弱性についてライブラリを調査します。

> 注釈、この章の執筆時点では、執筆者に知られている Carthage ベースの依存関係解析の自動サポートはありません。少なくとも、この機能は OWASP DependencyCheck ツールですでにリクエストされていますがまだ実装されていません ([GitHub issue](https://github.com/jeremylong/DependencyCheck/issues/962 "Add Carthage Analyze for Swift") を参照) 。

### 発見されたライブラリ脆弱性

ライブラリに脆弱性が含まれていることが判明した場合、以下の推論を適用します。

- ライブラリがアプリケーションにパッケージされている場合、それからライブラリに脆弱性がパッチされているバージョンがあるか確認します。ない場合、脆弱性が実際にアプリケーションに影響を及ぼすかどうかを確認します。それが当てはまる場合、または将来そうなる可能性がある場合、同様の機能を提供する、脆弱性のない代替手段を探します。
- ライブラリはアプリケーションにはパッケージされていない場合、脆弱性が修正されているパッチされたバージョンがあるかどうかを確認します。これがない場合、ビルドプロセスに対する脆弱性の影響を調べます。脆弱性がビルドを邪魔したり、ビルドパイプラインのセキュリティを弱めたりする場合、脆弱性が修正される代替案を探してみます。

リンクされるライブラリとしてフレームワークを手動で追加する場合。

1. xcodeproj ファイルを開き、プロジェクトのプロパティを確認します。
2. **Build Phases** タブに移動して、いずれかのライブラリの **Link Binary With Libraries** のエントリを確認します。[MobSF](../../../tools/generic/MASTG-TOOL-0035.md) を使用して同様の情報を取得する方法については、これまでのセクションを参照してください。

コピー＆ペーストされたソースの場合、(Objective-C を使用する場合) ヘッダファイルを検索し、あるいは既存のライブラリの既存のメソッド名の Swift ファイルを検索します。

次に、ハイブリッドアプリケーションでは、JavaScript の依存関係を [RetireJS](https://retirejs.github.io/retire.js/ "RetireJS") で確認する必要があることに注意します。同様に Xamarin では、C# の依存関係を確認する必要があります。

最後に、アプリケーションがリスクの高いアプリケーションである場合、ライブラリを手動で検査することになります。その場合、ネイティブコードには特定の要件があります。これはアプリケーション全体に対して MASVS により確立された要件に似ています。その次に、ソフトウェアエンジニアリングのすべてのベストプラクティスが適用されているかどうかを吟味することをお勧めします。

## 動的解析

このセクションの動的解析は二つのパートで構成されています。実際のライセンスの検証と、ソースが見つからない場合にどのライブラリが関与しているかの確認です。

ライセンスの著作権が守られているかどうかを検証する必要があります。これは通常、サードパーティライブラリのライセンスにより要求されるものとして、著作権表示が記されている `about` や `EULA` セクションをアプリケーションが持つべきであることを意味しています。

### アプリケーションライブラリの一覧表示

アプリ解析を実行する際には、アプリの (通常はライブラリまたはいわゆる iOS フレームワークの形式での) 依存関係も解析し、脆弱性が含まれていないことを確認することが重要です。ソースコードがない場合でも、 [objection](../../../tools/generic/MASTG-TOOL-0038.md), [MobSF](../../../tools/generic/MASTG-TOOL-0035.md) などのツールや `otool -L` コマンドを使用して、アプリの依存関係の一部を特定できます。 objection は最も正確な結果が得られ、使いやすいため、推奨のツールです。これには iOS バンドルと連携するモジュールが含まれており、 `list_bundles` と `list_frameworks` という二つのコマンドを提供します。

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
