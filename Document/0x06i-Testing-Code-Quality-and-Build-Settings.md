---
masvs_category: MASVS-CODE
platform: ios
---

# iOS のコード品質とビルド設定

## 概要

### アプリ署名

アプリを [コード署名](0x06a-Platform-Overview.md#code-signing) することで、アプリが既知のソースを持ち、最後に署名されてから改変されていないことをユーザーに保証します。アプリは、アプリサービスを統合する前、脱獄していないデバイスにインストールされるか、App Store に提出する前に、Apple により発行された証明書で署名される必要があります。証明書をリクエストしてアプリにコード署名する方法の詳細については、[アプリ配布ガイド](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/Introduction/Introduction.html "App Distribution Guide") をご覧ください。

### サードパーティライブラリ

iOS アプリケーションではサードパーティライブラリを使用することがよくあります。これらのサードパーティライブラリは開発者が問題を解決するためのコード記述を少なくし、開発を加速します。しかし、サードパーティライブラリには脆弱性、互換性のないライセンス、または悪意のあるコンテンツが含まれている可能性があります。さらに、ライブラリリリースの監視や利用可能なセキュリティパッチの適用など、組織や開発者はアプリケーションの依存関係を管理することが困難となります。

広く使用されているパッケージ管理ツールには [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org"), [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub"), [CocoaPods](https://cocoapods.org "CocoaPods.org") の三つがあります。

- Swift Package Manager はオープンソースであり、 Swift 言語に含まれ、 Xcode に統合 (Xcode 11 以降) され、 [Swift, Objective-C, Objective-C++, C, および C++](https://developer.apple.com/documentation/xcode/swift-packages "Swift Packages Documentation") パッケージをサポートします。 Swift で記述され、分散化されており、 Package.swift ファイルを使用してプロジェクト依存関係を文書化および管理します。
- Carthage はオープンソースであり、 Swift および Objective-C パッケージに使用できます。Swift で記述され、分散化されており、 Cartfile ファイルを使用してプロジェクトの依存関係を文書化および管理します。
- CocoaPods はオープンソースであり、 Swift および Objective-C パッケージに使用できます。 Ruby で記述され、パブリックおよびプライベートパッケージの集中パッケージレジストリを利用し、 Podfile ファイルを使用してプロジェクトの依存関係を文書化および管理します。

ライブラリには二つのカテゴリがあります。

- 実際の製品アプリケーションにはパックされない (またはすべきではない) ライブラリ、テストに使用される `OHHTTPStubs` など。
- 実際の製品アプリケーションにパックされるライブラリ、`Alamofire` など。

これらのライブラリは望ましくない副作用を引き起こす可能性があります。

- ライブラリには脆弱性が存在する可能性があり、アプリケーションを脆弱にする可能性があります。よい例は `AFNetworking` バージョン 2.5.1 で、証明書検証を無効にしたバグがありました。この脆弱性により攻撃者は API に接続するためにライブラリを使用しているアプリに対して [中間マシン (Machine-in-the-Middle, MITM)](0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) 攻撃を実行できます。
- ライブラリはもはや保守されていないかほとんど使用できない可能性があります。脆弱性が報告されず修正されないためです。これによりライブラリを介してアプリケーションに不正なコードや脆弱なコードが含まれる可能性があります。
- ライブラリは LGPL2.1 などのライセンスを使用できます。そのライセンスでは、アプリケーションを使用しソースの内容を要求する人に対して、アプリケーション作成者はソースコードへのアクセスを提供する必要があります。実際にはアプリケーションはそのソースコードを改変して再配布することを許可される必要があります。これはアプリケーションの知的財産 (IP) を危険にさらす可能性があります。

この問題は複数のレベルで発生する可能性があることに注意します。WebView を使用し、WebView で JavaScript を実行する場合、JavaScript ライブラリにもこれらの問題があります。同じことが Cordova, React-native, Xamarin アプリのプラグインやライブラリにも当てはまります。

### メモリ破損バグ

iOS アプリケーションはさまざまな状況で [メモリ破損バグ](0x04h-Testing-Code-Quality.md#memory-corruption-bugs) に遭遇します。まず、一般的なメモリ破損バグのセクションで言及されているネイティブコードの問題があります。次に、Objective-C と Swift のいずれにも問題を引き起こす可能性のあるネイティブコードを実際にラップするさまざまな危険な操作があります。最後に、Swift と Objective-C の実装はいずれも使用されなくなったオブジェクトを保持するためにメモリリークが発生する可能性があります。

詳しくはこちら。

- <https://developer.ibm.com/tutorials/mo-ios-memory/>
- <https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/MemoryMgmt.html>
- <https://medium.com/zendesk-engineering/ios-identifying-memory-leaks-using-the-xcode-memory-graph-debugger-e84f097b9d15>

### バイナリ保護メカニズム

[バイナリ保護メカニズム](0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) の存在を検出するためにはアプリケーションの開発に使用された言語に大きく依存します。

Xcode はデフォルトですべてのバイナリセキュリティ機能を有効にしますが、古いアプリケーションに対してこれを検証したり、コンパイラフラグの設定ミスをチェックすることが適切な場合があります。以下の機能が適用可能です。

- [**PIE (Position Independent Executable)**](0x04h-Testing-Code-Quality.md#position-independent-code):
    - PIE は実行形式バイナリ (Mach-O タイプ `MH_EXECUTE`) に適用されます。 [情報源](https://web.archive.org/web/20230328221404/https://opensource.apple.com/source/cctools/cctools-921/include/mach-o/loader.h.auto.html)
    - ただし、ライブラリ (Mach-O タイプ `MH_DYLIB`) には適用されません。
- [**メモリ管理**](0x04h-Testing-Code-Quality.md#memory-management):
    - 純粋な Objective-C、Swift、ハイブリッドバイナリのいずれも ARC (Automatic Reference Counting) を有効にすべきです。
    - C/C++ ライブラリでは、開発者は適切な [手動メモリ管理](0x04h-Testing-Code-Quality.md#manual-memory-management) を行う責任があります。 ["メモリ破損バグ"](0x04h-Testing-Code-Quality.md#memory-corruption-bugs) を参照してください。
- [**スタックスマッシュ保護**](0x04h-Testing-Code-Quality.md#stack-smashing-protection): 純粋な Objective-C バイナリでは、これは常に有効にすべきです。Swift はメモリセーフに設計されているので、ライブラリが純粋に Swift で書かれていれば、スタックカナリアが有効にされていなくても、リスクは最小限に抑えられます。

詳しくはこちら。

- [OS X ABI Mach-O File Format Reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
- [On iOS Binary Protections](https://sensepost.com/blog/2021/on-ios-binary-protections/)
- [Security of runtime process in iOS and iPadOS](https://support.apple.com/en-gb/guide/security/sec15bfe098e/web)
- [Mach-O Programming Topics - Position-Independent Code](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/dynamic_code.html)

これらの保護メカニズムの存在を検出するためのテストはアプリケーションの開発に使用される言語に大きく依存します。たとえば、スタックカナリアの存在を検出するための既存の技法は純粋な Swift アプリでは機能しません。

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

### デバッグ可能アプリ

アプリがデバッグ可能 ([デバッグ (Debugging)](../techniques/ios/MASTG-TECH-0084.md)) であるかどうかをテストするには、アプリのエンタイトルメントを調べて [`get-task-allow`](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues "Resolving common notarization issues") キーの値が `true` に設定されているかを確認します。

デバッグはアプリを開発する際に便利な機能ですが、App Store やエンタープライズプログラム内にアプリをリリースする前にオフにしなければなりません。そのためにはアプリを生成するモードを決定して、環境内のフラグを確認する必要があります。

- プロジェクトのビルド設定を選択します。
- 'Apple LVM - Preprocessing' と 'Preprocessor Macros' で、'DEBUG' または 'DEBUG_MODE' が選択されていないことを確認します (Objective-C) 。
- "Debug executable" オプションが選択されていないことを確認します。
- もしくは 'Swift Compiler - Custom Flags' セクションの 'Other Swift Flags' で、'-D DEBUG' エントリが存在しないことを確認します。

### デバッグシンボル

良い習慣として、コンパイルされたバイナリで提供される説明情報はできる限り少なくするべきです。デバッグシンボルなどの付加的なメタデータの存在はコードに関する貴重な情報を提供する可能性があります。例えば、関数名は関数が何をするかについての情報を漏洩します。このメタデータはバイナリの実行には必要ありませんので、リリースビルド時に破棄しても問題ありません。これは適切なコンパイラ設定を使用して実行できます。テスト担当者としてはアプリで配布されるすべてのバイナリを検査し、デバッグシンボルが存在しないことを確認するべきです (少なくともデバッグシンボルはコードに関する貴重な情報を漏洩します) 。

iOS アプリケーションがコンパイルされると、コンパイラはアプリ内の各バイナリファイル (メインアプリ実行可能ファイル、フレームワーク、アプリ拡張機能) のデバッグシンボルのリストを生成します。これらのシンボルにはクラス名、グローバル変数、メソッド名や関数名が含まれ、それらが定義されている特定のファイルと行番号にマップされます。アプリの [デバッグビルド](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information "Building Your App to Include Debugging Information") はデフォルトでコンパイル済みバイナリにデバッグシンボルを配置しますが、アプリのリリースビルドは配布するアプリのサイズを縮小するためにコンパニオン _Debug Symbol ファイル_ (dSYM) に配置します。

### デバッグコードとエラーログ

検証をスピードアップしエラーの理解を深めるために、開発者は API からのレスポンスやアプリケーションの状況や状態について (`NSLog`, `println`, `print`, `dump`, `debugPrint` を使用して) 詳細なログ出力文などのデバッグコードをしばしば埋め込みます。 さらに、アプリケーションの状態や API からの疑似応答を設定するために開発者が使用する「管理機能」と呼ばれるデバッグコードが存在する可能性があります。リバースエンジニアはこの情報を使用してアプリケーションで起こっていることを簡単に追跡できます。したがって、デバッグコードはアプリケーションのリリースバージョンから削除する必要があります。

### 例外処理

例外はアプリケーションが正常ではない状態やエラーのある状態になった場合によく発生します。
例外処理のテストとは、ログ出力メカニズムや UI を介して機密情報を開示することなく、アプリケーションが例外を処理して安全な状態になることを確認することです。

但し、Objective-C の例外処理は Swift とはまったく異なることに注意します。従来の Objective-C コードと Swift コードの両方で書かれたアプリケーションで二つの概念を橋渡しすることは問題になる可能性があります。

#### Objective-C の例外処理

Objective-C には二種類のエラーがあります。

**NSException:**

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

**NSError:**

`NSError` は他のすべてのタイプの [エラー](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/ErrorHandling/ErrorHandling.html "Dealing with Errors") に使用されます。Cocoa フレームワークの一部の API では何らかの問題が発生した場合に失敗時コールバックのオブジェクトしてエラーを提供します。それらを提供しないものは `NSError` オブジェクトへのポインタを参照渡しします。成功または失敗を示す `NSError` オブジェクトへのポインタを取るメソッドに、`BOOL` の戻り値型を提供することはよい習慣です。戻り値の型がある場合、エラーの場合に `nil` を戻すことを確認します。`NO` または `nil` が戻される場合には、エラーや失敗の理由を調べることができます。

#### Swift の例外処理

Swift (2～5) の例外処理はまったく異なります。try-catch ブロックは `NSException` を処理するためのものではありません。そのブロックは `Error` (Swift3) または `ErrorType` (Swift2) プロトコルに準拠するエラーを処理するために使用されます。一つのアプリケーション内で Objective-C と Swift コードを組み合わせる場合、これは困難になることがあります。したがって、両方の言語で書かれたプログラムでは `NSException` よりも `NSError` が好まれます。さらに、Objective-C ではエラー処理はオプトインですが、Swift では明示的に `throws` を処理する必要があります。エラーを throw する際の変換には、[Apple のドキュメント](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/AdoptingCocoaDesignPatterns.html "Adopting Cocoa Design Patterns") をご覧ください。
エラーを throw するメソッドは `throws` キーワードを使用します。`Result` タイプは成功または失敗を表します。[Result](https://developer.apple.com/documentation/swift/result), [Swift 5 での Result の使用方法](https://www.hackingwithswift.com/articles/161/how-to-use-result-in-swift), [Swift での Result タイプの威力](https://www.swiftbysundell.com/posts/the-power-of-result-types-in-swift) を参照してください。[Swift でエラーを処理する](https://developer.apple.com/library/content/documentation/Swift/Conceptual/Swift_Programming_Language/ErrorHandling.html "Error Handling in Swift") 方法は四つあります。

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
    guard let url = URL(string: "https://raw.githubusercontent.com/OWASP/owasp-mastg/master/book.json") else {
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
