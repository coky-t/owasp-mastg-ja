---
masvs_category: MASVS-CODE
platform: ios
title: サードパーティライブラリ (Third-Party Libraries)
---

iOS アプリケーションではサードパーティライブラリを使用することがよくあります。これらのサードパーティライブラリは開発者が問題を解決するためのコード記述を少なくし、開発を加速します。しかし、サードパーティライブラリには脆弱性、互換性のないライセンス、または悪意のあるコンテンツが含まれている可能性があります。さらに、ライブラリリリースの監視や利用可能なセキュリティパッチの適用など、組織や開発者はアプリケーションの依存関係を管理することが困難となります。

広く使用されているパッケージ管理ツールには [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org"), [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub"), [CocoaPods](https://cocoapods.org "CocoaPods.org") の三つがあります。

- Swift Package Manager はオープンソースであり、 Swift 言語に含まれ、 Xcode に統合 (Xcode 11 以降) され、 [Swift, Objective-C, Objective-C++, C, および C++](https://developer.apple.com/documentation/xcode/swift-packages "Swift Packages Documentation") パッケージをサポートします。Swift で記述され、分散化されており、 Package.swift ファイルを使用してプロジェクト依存関係を文書化および管理します。
- Carthage はオープンソースであり、Swift および Objective-C パッケージに使用できます。Swift で記述され、分散化されており、 Cartfile ファイルを使用してプロジェクトの依存関係を文書化および管理します。
- CocoaPods はオープンソースであり、Swift および Objective-C パッケージに使用できます。Ruby で記述され、パブリックおよびプライベートパッケージの集中パッケージレジストリを利用し、Podfile ファイルを使用してプロジェクトの依存関係を文書化および管理します。

ライブラリには二つのカテゴリがあります。

- 実際の製品アプリケーションにはパックされない (またはすべきではない) ライブラリ、テストに使用される `OHHTTPStubs` など。
- 実際の製品アプリケーションにパックされるライブラリ、`Alamofire` など。

これらのライブラリは望ましくない副作用を引き起こす可能性があります。

- ライブラリには脆弱性が存在する可能性があり、アプリケーションを脆弱にする可能性があります。よい例は `AFNetworking` バージョン 2.5.1 で、証明書検証を無効にしたバグがありました。この脆弱性により攻撃者は API に接続するためにライブラリを使用しているアプリに対して [中間マシン (Machine-in-the-Middle, MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃を実行できます。
- ライブラリはもはや保守されていないかほとんど使用できない可能性があります。脆弱性が報告されず修正されないためです。これによりライブラリを介してアプリケーションに不正なコードや脆弱なコードが含まれる可能性があります。
- ライブラリは LGPL2.1 などのライセンスを使用できます。そのライセンスでは、アプリケーションを使用しソースの内容を要求する人に対して、アプリケーション作成者はソースコードへのアクセスを提供する必要があります。実際にはアプリケーションはそのソースコードを改変して再配布することを許可される必要があります。これはアプリケーションの知的財産 (IP) を危険にさらす可能性があります。

この問題は複数のレベルで発生する可能性があることに注意します。WebView を使用し、WebView で JavaScript を実行する場合、JavaScript ライブラリにもこれらの問題があります。同じことが Cordova, React-native, Xamarin アプリのプラグインやライブラリにも当てはまります。
