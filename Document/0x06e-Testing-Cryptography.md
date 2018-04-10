## iOS の暗号化 API

「モバイルアプリの暗号化のテスト」の章では、一般的な暗号化のベストプラクティスを紹介し、モバイルアプリで暗号化が正しく使用されない場合に起こりうる典型的な欠陥について説明しました。この章では、iOS で利用可能な暗号化 API について詳しく説明します。ソースコードでそれらの API の使用方法を特定する方法とその設定を判断する方法を示します。コードをレビューする際は、使用されている暗号化パラメータとこのガイドからリンクされている現行のベストプラクティスを必ず確認してください。

### iOS の暗号化 API

Apple は最も一般的に使用される暗号化アルゴリズムの実装でのライブラリを提供しています。[Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide") が参考になります。標準ライブラリを使用して暗号化プリミティブを初期化および使用する方法に関する広範囲なドキュメントがあり、ソースコード解析を実行する際にも役立ちます。

iOS のコードは通常 `CommonCryptor.h` で定義された既定の定数を参照します (例えば、`kCCAlgorithmDES`) 。ソースコードを検索してこれらの定数が使用されているかどうかを検出できます。iOS 上の定数は数値であることに注意し、`CCCrypt` 関数に送られるアルゴリズム定数値が既知のセキュアではないまたは推奨されていないアルゴリズムであるかどうかを必ず確認してください。

アプリが Apple により提供されている標準暗号化実装を使用している場合、最も簡単な方法は `CCCrypt`, `CCCryptorCreate` などの `CommonCryptor` から関数への呼び出しをチェックすることです。[ソースコード](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h "CommonCryptor.h") にすべての関数のシグネチャがあります。例えば、`CCCryptorCreate` は以下のシグネチャを持っています。

```
CCCryptorStatus CCCryptorCreate(
	CCOperation op,             /* kCCEncrypt, etc. */
	CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
	CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
	const void *key,            /* raw key material */
	size_t keyLength,
	const void *iv,             /* optional initialization vector */
	CCCryptorRef *cryptorRef);  /* RETURNED */
```

すべての `enum` 型を比較することで、どのアルゴリズム、パディング、鍵マテリアルが使用されているか理解できます。鍵マテリアルに注意します。パスワードから直接来ていますか (それはいけません)、それとも鍵導出関数 (PBKDF2 など) から来ていますか。明らかに、アプリケーションが使用している可能性のある他の非標準ライブラリ (例えば `openssl`) があれば、それらもチェックします。

iOS のコードは通常 `CommonCryptor.h` で定義された既定の定数を参照します (例えば、`kCCAlgorithmDES`) 。ソースコードを検索してこれらの定数が使用されているかどうかを検出できます。iOS 上の定数は数値であることに注意します。`CCCrypt` 関数に送られるアルゴリズム定数値が既知のセキュアではないまたは推奨されていないアルゴリズムであるかどうかを必ず確認してください。iOS での暗号化の使用は [モバイルアプリの暗号化](0x04g-Testing-Cryptography.md) の章で説明されているのと同じベストプラクティスに従う必要があります。

### iOS での乱数生成

Apple は暗号論的にセキュアな乱数を生成する [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") アプリケーションプログラミングインタフェース (API) を開発者に提供しています。

Randomization Services API は `SecRandomCopyBytes` 関数を使用して数値生成を実行します。これは `/dev/random` デバイスファイルのラッパー関数であり、0 から 255 までの暗号論的にセキュアな擬似乱数値を提供し、連結を実行します。

すべての乱数値がこの API を使用して生成されていることを確認します。開発者が別のものを使用すべき理由はありません。

Swift では [`SecRandomCopyBytes` API](https://developer.apple.com/reference/security/1399291-secrandomcopybytes "SecRandomCopyBytes (Swift)") が以下のように定義されています。
```
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

[Objective-C version](https://developer.apple.com/reference/security/1399291-secrandomcopybytes?language=objc "SecRandomCopyBytes (Objective-C)") は以下のとおりです。
```
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

以下はその使用例です。
```
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

### 参考情報

#### OWASP Mobile Top 10 2016
- M5 - 不十分な暗号化 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography (日本語訳) - https://coky-t.github.io/owasp-mobile-top10-2016-ja/Mobile_Top_10_2016-M5-Insufficient_Cryptography.html

#### OWASP MASVS
- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"
- V3.6: "すべての乱数値は、十分に安全な乱数生成器を用いて生成している。"

#### CWE
- CWE-337 - Predictable Seed in PRNG
- CWE-338 - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
