# iOS の暗号化 API

「モバイルアプリの暗号化」の章では、一般的な暗号化のベストプラクティスを紹介し、暗号化が正しく使用されない場合に起こりうる典型的な問題について説明しました。この章では、iOS で利用可能な暗号化 API について詳しく説明します。ソースコードでそれらの API の使用方法を特定する方法とその暗号設定を判断する方法を示します。コードをレビューする際は、使用されている暗号化パラメータとこのガイドにリンクされている現行のベストプラクティスを比較します。

## 暗号化標準アルゴリズムの構成の検証 (MSTG-CRYPTO-2 and MSTG-CRYPTO-3)

### 概要

Apple は最も一般的な暗号化アルゴリズムの実装を含むライブラリを提供しています。[Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide") は素晴らしいリファレンスです。標準ライブラリを使用して暗号化プリミティブを初期化および使用する方法に関する汎用的なドキュメントがあり、この情報はソースコード解析に役立ちます。

#### CryptoKit

Apple CryptoKit は iOS 13 でリリースされ、Apple のネイティブ暗号化ライブラリ `corecrypto` の上に構築されています。Swift フレームワークは厳密に型付けされた API インタフェースを提供し、効果的なメモリ管理を行い、比較可能 (eauatable) に適応し、ジェネリックをサポートします。CryptoKit にはハッシュ、対称鍵暗号化、公開鍵暗号化のためのセキュアなアルゴリズムが含まれています。このフレームワークでは Secure Enclave のハードウェアベースの鍵マネージャも利用できます。

Apple CryptoKit には以下のアルゴリズムが含まれています。

*ハッシュ*
    - MD5 (Insecure Module)
        - SHA1 (Insecure Module)
        - SHA-2 256-bit digest
        - SHA-2 384-bit digest
        - SHA-2 512-bit digest

*対称鍵*
    - Message Authentication Codes (HMAC)
    - Authenticated Encryption
        - AES-GCM
        - ChaCha20-Poly1305

*公開鍵*
    - Key Agreement
        - Curve25519
        - NIST P-256
        - NIST P-384
        - NIST P-512

例:

対称鍵の生成と解放:

```default
let encryptionKey = SymmetricKey(size: .bits256)
```

SHA-2 512-bit digest の計算:

```default
let rawString = "OWASP MTSG"
let rawData = Data(rawString.utf8)
let hash = SHA512.hash(data: rawData) // Compute the digest
let textHash = String(describing: hash)
print(textHash) // Print hash text
```

Apple CryptoKit の詳細については、以下のリソースを参照してください。

- [Apple CryptoKit | Apple Developer Documentation](https://developer.apple.com/documentation/cryptokit "Apple CryptoKit from Apple Developer Documentation")
- [Performing Common Cryptographic Operations | Apple Developer Documentation](https://developer.apple.com/documentation/cryptokit/performing_common_cryptographic_operations "Performing Common Cryptographic Operations from Apple Developer Documentation")
- [WWDC 2019 session 709 | Cryptography and Your Apps](https://developer.apple.com/videos/play/wwdc19/709/ "Cryptography and Your Apps from WWDC 2019 session 709")
- [How to calculate the SHA hash of a String or Data instance | Hacking with Swift](https://www.hackingwithswift.com/example-code/cryptokit/how-to-calculate-the-sha-hash-of-a-string-or-data-instance "How to calculate the SHA hash of a String or Data instance from Hacking with Swift")

#### CommonCrypto, SecKeyEncrypt および Wrapper ライブラリ

暗号化操作で最も一般的に使用されるクラスは iOS ランタイムに同梱されている CommonCrypto です。CommonCrypto オブジェクトにより提供される機能は [ヘッダーファイルのソースコード](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html "CommonCrypto.h") を参照することが分析に最適です。

- `Commoncryptor.h` は対称暗号化操作のパラメータを提供します。
- `CommonDigest.h` はハッシュアルゴリズムのパラメータを提供します。
- `CommonHMAC.h` はサポートされている HMAC 操作のパラメータを提供します。
- `CommonKeyDerivation.h` はサポートされている KDF 関数のパラメータを提供します。
- `CommonSymmetricKeywrap.h` は対称鍵を鍵暗号化鍵でラップするために使用される関数を提供します。

残念ながら、CommonCryptor のパブリック API には次のようないくつかのタイプの操作がありません。GCM モードはプライベート API でのみ利用可能です。[そのソースコード](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h "GCM in CC") を参照してください。これには追加のバインディングヘッダーが必要です。または他のラッパーライブラリを使用できます。

次に、非対称操作のために、Apple は [SecKey](https://opensource.apple.com/source/Security/Security-57740.51.3/keychain/SecKey.h.auto.html "SecKey") を提供します。Apple は [開発者ドキュメント](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption "Using keys for encryption") でこれを使用する方法に関する素晴らしいガイドを提供しています。

前述のように、利便性を提供するために両方に対するラッパーライブラリがいくつか存在します。使用される典型的なライブラリには例えば以下のものがあります。

- [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto "IDZSwiftCommonCrypto")
- [Heimdall](https://github.com/henrinormak/Heimdall "Heimdall")
- [SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA "SwiftyRSA")
- [RNCryptor](https://github.com/RNCryptor/RNCryptor "RNCryptor")
- [Arcane](https://github.com/onmyway133/Arcane "Arcane")

#### サードパーティーライブラリ

以下のようなさまざまなサードパーティーライブラリが利用可能です。

- **CJOSE**: JWE の台頭と AES GCM のパブリックサポートの不足により、[CJOSE](https://github.com/cisco/cjose "cjose") などの他のライブラリが進出しています。CJOSE は C/C++ 実装のみを提供するため、依然として高レベルのラッピングが必要です。
- **CryptoSwift**: Swift のライブラリで、[GitHub](https://github.com/krzyzanowskim/CryptoSwift "CryptoSwift") にあります。このライブラリはさまざまなハッシュ関数、MAC 関数、CRC 関数、対称暗号、およびパスワードベースの鍵導出関数をサポートしています。これはラッパーではなく、それぞれの暗号を完全に自己実装したバージョンです。関数の効果的な実装を検証することが重要です。
- **OpenSSL**: [OpenSSL](https://www.openssl.org/ "OpenSSL") は TLS で使用されるツールキットライブラリで、C で記述されています。その暗号化機能のほとんどは (H)MAC 、署名、対称および非対称暗号、ハッシュを作成するなど、必要となるさまざまな暗号化アクションを実行するために使用できます。[OpenSSL](https://github.com/ZewoGraveyard/OpenSSL "OpenSSL") や [MIHCrypto](https://github.com/hohl/MIHCrypto "MIHCrypto") などのさまざまなラッパーがあります。
- **LibSodium**: Sodium は暗号化、復号化、署名、パスワードハッシュなどのための最新の使いやすいソフトウェアライブラリです。これは互換性のある API と使いやすさをさらに向上させる拡張 API を備え、ポータブルで、クロスコンパイル、インストール、パッケージ化が可能な NaCl のフォークです。詳細については [LibSodium ドキュメント](https://download.libsodium.org/doc/installation "LibSodium docs") を参照してください。[Swift-sodium](https://github.com/jedisct1/swift-sodium "Swift-sodium"), [NAChloride](https://github.com/gabriel/NAChloride "NAChloride"), [libsodium-ios](https://github.com/mochtu/libsodium-ios "libsodium ios") などのラッパーライブラリがいくつかあります。
- **Tink**: Google による新しい暗号化ライブラリです。Google は [セキュリティブログで](https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html "Introducing Tink") でこのライブラリの背景にある理由を説明しています。ソースは [Tink GitHub リポジトリ](https://github.com/google/tink "Tink at GitHub") にあります。
- **Themis**: Swift, Obj-C, Android/Java, C++, JS, Python, Ruby, PHP, Go 向けのストレージおよびメッセージング用暗号化ライブラリです。[Themis](https://github.com/cossacklabs/themis "Themis") は LibreSSL/OpenSSL エンジン libcrypto を依存関係として使用します。鍵生成、セキュアメッセージング (ペイロード暗号化および署名など) 、セキュアストレージ、およびセキュアセッションのセットアップのために Objective-C および Swift をサポートしています。詳細については [Wiki](https://github.com/cossacklabs/themis/wiki/Objective-C-Howto "Themis wiki") を参照してください。
- **その他**: [CocoaSecurity](https://github.com/kelp404/CocoaSecurity "CocoaSecurity"), [Objective-C-RSA](https://github.com/ideawu/Objective-C-RSA "Objective-C-RSA"), [aerogear-ios-crypto](https://github.com/aerogear/aerogear-ios-crypto "Aerogera-ios-crypto") など、他にも多くのライブラリがあります。これらの一部はもはや保守されておらず、セキュリティレビューが行われていない可能性があります。いつものように、サポートおよび保守されているライブラリを探すことをお勧めします。
- **DIY**: まずます多くの開発者が暗号または暗号化機能の独自実装を作成しています。このプラクティスは _まったく_ 推奨されておらず、もし使用するのであれば暗号化の専門家により非常に綿密な精査を行うべきです。

### 静的解析

非推奨のアルゴリズムおよび暗号化設定について「モバイルアプリの暗号化」セクションで多くのことが言及されています。いうまでもなく、この章で言及されている各ライブラリについてそれらを検証すべきです。
鍵を保持するデータ構造の削除方法とプレーンテキストデータ構造が定義されていることに注意します。キーワード `let` が使用されている場合、メモリから消去するのが難しい不変 (immutable) 構造を作成します。メモリから簡単に削除できる  (たとえば、一時的に存在する `struct` などの) 親構造の一部であることを確認します。

#### CommonCryptor

アプリが Apple により提供されている標準暗号化実装を使用する場合、関連するアルゴリズムのステータスを判断する最も簡単な方法は `CCCrypt` や `CCCryptorCreate` など、`CommonCryptor` からの関数呼び出しをチェックすることです。[ソースコードe](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h "CommonCryptor.h") には CommonCryptor.h のすべての関数のシグネチャが含まれています。例えば、`CCCryptorCreate` は以下のシグネチャを持ちます。

```c
CCCryptorStatus CCCryptorCreate(
    CCOperation op,             /* kCCEncrypt, etc. */
    CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
    CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
    const void *key,            /* raw key material */
    size_t keyLength,
    const void *iv,             /* optional initialization vector */
    CCCryptorRef *cryptorRef);  /* RETURNED */
```

それからすべての `enum` タイプを比較して、使用されているアルゴリズム、パディング、鍵マテリアルを確定します。鍵マテリアルに注意します。鍵は鍵導出関数または乱数生成関数を使用してセキュアに生成されるべきです。
「モバイルアプリの暗号化」の章で非推奨として記載されている機能は、依然としてプログラムでサポートされていることに注意します。それらを使用すべきではありません。

#### サードパーティーライブラリ

すべてのサードパーティーライブラリの継続的な進化を考えると、これは静的解析の観点から各ライブラリを評価する適切な機会ではありません。まだ注意点がいくつかあります。

- **利用されているライブラリを見つける**: これは以下の手法を使用して実行できます。
  - [cartfile](https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile "cartfile") をチェックします (Carthage が使用されている場合) 。
  - [podfile](https://guides.cocoapods.org/syntax/podfile.html "podfile") をチェックします (Cocoapods が使用されている場合) 。
  - リンクされたライブラリをチェックします。codeproj ファイルを開き、プロジェクトのプロパティをチェックします。**Build Phases** タブに移動し、いずれかのライブラリの **Link Binary With Libraries** のエントリをチェックします。[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF "MobSF") を使用して同様の情報を取得する方法については以前のセクションを参照してください。
  - ソースをコピー＆ペーストした場合、既知のライブラリの既知のメソッド名でヘッダファイル (Objective-C を使用している場合) およびその他の Swift ファイルを検索します。
- **使用しているバージョンを確定する**: 使用しているライブラリのバージョンを常にチェックし、考えられる脆弱性または不具合が修正された新しいバージョンが利用可能かどうかをチェックします。ライブラリの新しいバージョンがない場合でも、暗号化機能はまだレビューされていない場合があります。そのため、妥当性確認されたライブラリを使用することを常にお勧めします。もしくはあなた自身に妥当性確認を行う能力、知識、経験があることを確認します。
- **手製か？**: 独自の暗号を動かしたり、既存の暗号化機能を自分自身で実装したりしないことをお勧めします。

## 鍵管理のテスト (MSTG-CRYPTO-1 および MSTG-CRYPTO-5)

### 概要

デバイス上に鍵を保存する方法にはさまざまな手法があります。鍵を全く保存しなければ、鍵マテリアルがダンプできなくなることを確実にします。これは PKBDF-2 などのパスワード鍵導出関数を使用して実現できます。以下の例を参照してください。

```default
func pbkdf2SHA1(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2SHA256(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2SHA512(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    return pbkdf2(hash: CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}

func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
    let passwordData = password.data(using: String.Encoding.utf8)!
    var derivedKeyData = Data(repeating: 0, count: keyByteCount)
    let derivedKeyDataLength = derivedKeyData.count
    let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
        salt.withUnsafeBytes { saltBytes in

            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password, passwordData.count,
                saltBytes, salt.count,
                hash,
                UInt32(rounds),
                derivedKeyBytes, derivedKeyDataLength
            )
        }
    }
    if derivationStatus != 0 {
        // Error
        return nil
    }

    return derivedKeyData
}

func testKeyDerivation() {
    let password = "password"
    let salt = Data([0x73, 0x61, 0x6C, 0x74, 0x44, 0x61, 0x74, 0x61])
    let keyByteCount = 16
    let rounds = 100_000

    let derivedKey = pbkdf2SHA1(password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
}
```

 *出典: [https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios](https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios "PBKDF2 using CommonCrypto on iOS
"), `Arcane` ライブラリのテストスイートでテスト済み*

鍵を保存する必要がある場合、選択した保護クラスが `kSecAttrAccessibleAlways` でない限り、キーチェーンを使用することをお勧めします。`NSUserDefaults`、プロパティリストファイル、または Core Data や Realm からの他のシンクなど、他の場所に鍵を保存することは一般的にキーチェーンを使用するよりセキュアではなくなります。
Core Data や Realm からのシンクが `NSFileProtectionComplete` データ保護クラスを使用して保護されている場合でも、キーチェーンを使用することをお勧めします。詳細については "[iOS のデータストレージ](0x06d-Testing-Data-Storage.md)" の章を参照してください。

キーチェーンは二種類のストレージメカニズムをサポートします。鍵がセキュアエンクレーブに格納されている暗号化鍵により保護されるか、鍵自体がセキュアエンクレーブ内にあります。後者は ECDH 署名鍵を使用する場合にのみ有効です。実装の詳細については [Apple ドキュメント](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave "Secure Enclave") を参照してください。

最後の三つのオプションはソースコードにハードコードされた暗号化鍵を使用すること、固定された属性に基づく予測可能な鍵導出関数を持つこと、生成された鍵を他のアプリケーションと共有する場所に保存することで構成されます。ハードコードされた暗号化鍵を使用することは明らかに進むべき道ではありません。これはアプリケーションのすべてのインスタンスが同じ暗号化鍵を使用することを意味するためです。攻撃者はソースコードから鍵を抽出するために (ネイティブに保存されているか Objective-C/Swift に保存されているかにかかわらず) 一度だけ作業を行う必要があります。その結果、攻撃者はアプリケーションにより暗号化された他のデータを復号できます。
次に、他のアプリケーションからアクセス可能な識別子に基づいた予測可能な鍵導出関数がある場合、攻撃者はその鍵導出関数を見つけてデバイスに適用するだけで鍵を見つけることができます。最後に、対称暗号化鍵をパブリックに保存することもあまりお勧めできません。

暗号化に関して忘れてはならない二つの概念があります。

1. 常に公開鍵で暗号化や検証を行い、常に秘密鍵 (private key) で復号化や署名をします。
2. 鍵(ペア)を別の目的に再利用してはいけません。これによりその鍵に関する情報が漏洩する可能性があります。署名用に別の鍵ペアと暗号化用に別の鍵(ペア)が必要です。

### 静的解析

探すべきさまざまなキーワードがあります。鍵がどのように格納されているかを最もよく確認できるキーワードについては「暗号化標準アルゴリズムの構成の検証」セクションの概要と静的解析で言及されているライブラリをチェックします。

常に以下のことを確認します。

- 鍵がデバイス上で同期されていないこと (リスクの高いデータを保護するために使用される場合) 。
- 鍵が追加の保護なしで保存されていないこと。
- 鍵がハードコードされていないこと。
- 鍵がデバイスの固定機能から導出されたものではないこと。
- 鍵が低レベル言語 (C/C++ など) の使用により隠されていないこと。
- 鍵が安全でない場所からインポートされていないこと。

静的解析に関する推奨事項のほとんどは「iOS のデータストレージのテスト」の章にすでに記載されています。次に、以下のページで読むことができます。

- [Apple 開発者ドキュメント: 証明書と鍵](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys "Certificates and keys")
- [Apple 開発者ドキュメント: 新しい鍵の生成](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys "Generating new keys")
- [Apple 開発者ドキュメント: 鍵生成属性](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes "Key Generation attributes")

### 動的解析

暗号化メソッドをフックし、使用されている鍵を解析します。暗号化操作が実行される際にファイルシステムへのアクセスを監視し、鍵マテリアルが書き込みまたは読み取りされる場所を評価します。

## 乱数生成のテスト (MSTG-CRYPTO-6)

### 概要

Apple は [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") API を提供しており、暗号論的にセキュアな乱数を生成します。

Randomization Services API は `SecRandomCopyBytes` 関数を使用して数値を生成します。これは `/dev/random` デバイスファイルのラッパー関数であり、0 から 255 までの暗号論的にセキュアな擬似乱数値を提供します。すべての乱数がこの API で生成されることを確認します。開発者が別のものを使用する理由はありません。

### 静的解析

Swift では、 [`SecRandomCopyBytes` API](https://developer.apple.com/reference/security/1399291-secrandomcopybytes "SecRandomCopyBytes (Swift)") は以下のように定義されています。

```default
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

[Objective-C バージョン](https://developer.apple.com/reference/security/1399291-secrandomcopybytes?language=objc "SecRandomCopyBytes (Objective-C)") は以下の通りです。

```objectivec
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

以下はこの API の使用例です。

```objectivec
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

注意: コード内の乱数に他のメカニズムが使用されている場合には、これらが上述の API のラッパーであることを検証するか、セキュアランダム性をレビューします。多くの場合これは非常に困難であり、上記の実装を守ることが最適であることを意味します。

### 動的解析

ランダム性をテストしたい場合には、多数の数値セットをキャプチャし、[Burp の sequencer プラグイン](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Sequencer") を使用してランダム性の品質をチェックします。

## 参考情報

### OWASP MASVS

- MSTG-CRYPTO-1: "アプリは暗号化の唯一の方法としてハードコードされた鍵による対称暗号化に依存していない。"
- MSTG-CRYPTO-2: "アプリは実績のある暗号化プリミティブの実装を使用している。"
- MSTG-CRYPTO-3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- MSTG-CRYPTO-5: "アプリは複数の目的のために同じ暗号化鍵を再利用していない。"
- MSTG-CRYPTO-6: "すべての乱数値は十分にセキュアな乱数生成器を用いて生成されている。"

### 一般的なセキュリティドキュメント

- Apple Developer Documentation on Security - <https://developer.apple.com/documentation/security>
- Apple Security Guide - <https://www.apple.com/business/site/docs/iOS_Security_Guide.pdf>

### 暗号化アルゴリズムの構成

- Apple's Cryptographic Services Guide - <https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html>
- Apple Developer Documentation on randomization SecKey - <https://opensource.apple.com/source/Security/Security-57740.51.3/keychain/SecKey.h.auto.html>
- Apple Documentation on Secure Enclave - <https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave?language=objc>
- Source code of the header file - <https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html>
- GCM in CommonCrypto - <https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h>
- Apple Developer Documentation on SecKey - <https://opensource.apple.com/source/Security/Security-57740.51.3/keychain/SecKey.h.auto.html>
- IDZSwiftCommonCrypto - <https://github.com/iosdevzone/IDZSwiftCommonCrypto>
- Heimdall - <https://github.com/henrinormak/Heimdall>
- SwiftyRSA - <https://github.com/TakeScoop/SwiftyRSA>
- RNCryptor - <https://github.com/RNCryptor/RNCryptor>
- Arcane - <https://github.com/onmyway133/Arcane>
- CJOSE - <https://github.com/cisco/cjose>
- CryptoSwift - <https://github.com/krzyzanowskim/CryptoSwift>
- OpenSSL - <https://www.openssl.org/>
- LibSodiums documentation - <https://download.libsodium.org/doc/installation>
- Google on Tink - <https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html>
- Themis - <https://github.com/cossacklabs/themis>
- cartfile - <https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile>
- Podfile - <https://guides.cocoapods.org/syntax/podfile.html>

### 乱数ドキュメント

- Apple Developer Documentation on randomization - <https://developer.apple.com/documentation/security/randomization_services>
- Apple Developer Documentation on secrandomcopybytes - <https://developer.apple.com/reference/security/1399291-secrandomcopybytes>
- Burp Suite Sequencer - <https://portswigger.net/burp/documentation/desktop/tools/sequencer>

### 鍵管理

- Apple Developer Documentation: Certificates and keys - <https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys>
- Apple Developer Documentation: Generating new keys - <https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys>
- Apple Developer Documentation: Key generation attributes -
<https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes>
