---
masvs_category: MASVS-CODE
platform: ios
title: 例外処理 (Exception Handling)
---

例外はアプリケーションが正常ではない状態やエラーのある状態になった場合によく発生します。
例外処理のテストとは、ログ出力メカニズムや UI を介して機密情報を開示することなく、アプリケーションが例外を処理して安全な状態になることを確認することです。

但し、Objective-C の例外処理は Swift とはまったく異なることに注意します。従来の Objective-C コードと Swift コードの両方で書かれたアプリケーションで二つの概念を橋渡しすることは問題になる可能性があります。

## Objective-C の例外処理

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

## Swift の例外処理

Swift (2～5) の例外処理はまったく異なります。try-catch ブロックは `NSException` を処理するためのものではありません。そのブロックは `Error` (Swift 3) または `ErrorType` (Swift 2) プロトコルに準拠するエラーを処理するために使用されます。一つのアプリケーション内で Objective-C と Swift コードを組み合わせる場合、これは困難になることがあります。したがって、両方の言語で書かれたプログラムでは `NSException` よりも `NSError` が好まれます。さらに、Objective-C ではエラー処理はオプトインですが、Swift では明示的に `throws` を処理する必要があります。エラーを throw する際の変換には、[Apple のドキュメント](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/AdoptingCocoaDesignPatterns.html "Adopting Cocoa Design Patterns") をご覧ください。
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
    guard let url = URL(string: "https://raw.githubusercontent.com/OWASP/mastg/master/book.json") else {
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
