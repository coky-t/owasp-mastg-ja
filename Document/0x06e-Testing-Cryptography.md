---
masvs_category: MASVS-CRYPTO
platform: ios
---

# iOS の暗号化 API

## 概要

["モバイルアプリの暗号化"](0x04g-Testing-Cryptography.md) の章では、一般的な暗号化のベストプラクティスを紹介し、暗号化が正しく使用されない場合に起こりうる典型的な問題について説明しました。この章では、iOS の暗号化 API についてさらに詳しく説明します。ソースコードでそれらの API の使用を特定する方法とその暗号設定を判断する方法を示します。コードをレビューする際には、使用されている暗号パラメータをこのガイドからリンクされている現行のベストプラクティスと比較するようにしてください。

Apple は最も一般的な暗号化アルゴリズムの実装を含むライブラリを提供しています。[Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide") は素晴らしいリファレンスです。標準ライブラリを使用して暗号化プリミティブを初期化および使用する方法に関する汎用的なドキュメントがあり、この情報はソースコード解析に役立ちます。

### CryptoKit

Apple CryptoKit は iOS 13 でリリースされ、[FIPS 140-2 認証](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3856) の Apple のネイティブ暗号化ライブラリ corecrypto の上に構築されています。Swift フレームワークは厳密に型付けされた API インタフェースを提供し、効果的なメモリ管理を行い、比較可能 (eauatable) に適応し、ジェネリックをサポートします。CryptoKit にはハッシュ、対称鍵暗号化、公開鍵暗号化のためのセキュアなアルゴリズムが含まれています。このフレームワークでは Secure Enclave のハードウェアベースの鍵マネージャも利用できます。

Apple CryptoKit には以下のアルゴリズムが含まれています。

**ハッシュ:**

- MD5 (Insecure Module)
- SHA1 (Insecure Module)
- SHA-2 256-bit digest
- SHA-2 384-bit digest
- SHA-2 512-bit digest

**対称鍵:**

- Message Authentication Codes (HMAC)
- Authenticated Encryption
    - AES-GCM
    - ChaCha20-Poly1305

**公開鍵:**

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

### CommonCrypto, SecKey および Wrapper ライブラリ

暗号化操作で最も一般的に使用されるクラスは iOS ランタイムに同梱されている CommonCrypto です。CommonCrypto オブジェクトにより提供される機能は [ヘッダーファイルのソースコード](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html "CommonCrypto.h") を参照することが分析に最適です。

- `Commoncryptor.h` は対称暗号化操作のパラメータを提供します。
- `CommonDigest.h` はハッシュアルゴリズムのパラメータを提供します。
- `CommonHMAC.h` はサポートされている HMAC 操作のパラメータを提供します。
- `CommonKeyDerivation.h` はサポートされている KDF 関数のパラメータを提供します。
- `CommonSymmetricKeywrap.h` は対称鍵を鍵暗号化鍵でラップするために使用される関数を提供します。

残念ながら、CommonCryptor のパブリック API には次のようないくつかのタイプの操作がありません。GCM モードはプライベート API でのみ利用可能です。[そのソースコード](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h "GCM in CC") を参照してください。これには追加のバインディングヘッダーが必要です。または他のラッパーライブラリを使用できます。

次に、非対称操作のために、Apple は [SecKey](https://developer.apple.com/documentation/security/seckey "SecKey") を提供します。Apple は [開発者ドキュメント](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption "Using keys for encryption") でこれを使用する方法に関する素晴らしいガイドを提供しています。

前述のように、利便性を提供するために両方に対するラッパーライブラリがいくつか存在します。使用される典型的なライブラリには例えば以下のものがあります。

- [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto "IDZSwiftCommonCrypto")
- [Heimdall](https://github.com/henrinormak/Heimdall "Heimdall")
- [SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA "SwiftyRSA")
- [RNCryptor](https://github.com/RNCryptor/RNCryptor "RNCryptor")
- [Arcane](https://github.com/onmyway133/Arcane "Arcane")

### サードパーティーライブラリ

以下のようなさまざまなサードパーティーライブラリが利用可能です。

- **CJOSE**: JWE の台頭と AES GCM のパブリックサポートの不足により、[CJOSE](https://github.com/cisco/cjose "cjose") などの他のライブラリが進出しています。CJOSE は C/C++ 実装のみを提供するため、依然として高レベルのラッピングが必要です。
- **CryptoSwift**: Swift のライブラリで、[GitHub](https://github.com/krzyzanowskim/CryptoSwift "CryptoSwift") にあります。このライブラリはさまざまなハッシュ関数、MAC 関数、CRC 関数、対称暗号、およびパスワードベースの鍵導出関数をサポートしています。これはラッパーではなく、それぞれの暗号を完全に自己実装したバージョンです。関数の効果的な実装を検証することが重要です。
- **OpenSSL**: [OpenSSL](https://www.openssl.org/ "OpenSSL") は TLS で使用されるツールキットライブラリで、C で記述されています。その暗号化機能のほとんどは (H)MAC 、署名、対称および非対称暗号、ハッシュを作成するなど、必要となるさまざまな暗号化アクションを実行するために使用できます。[OpenSSL](https://github.com/ZewoGraveyard/OpenSSL "OpenSSL") や [MIHCrypto](https://github.com/hohl/MIHCrypto "MIHCrypto") などのさまざまなラッパーがあります。
- **LibSodium**: Sodium は暗号化、復号化、署名、パスワードハッシュなどのための最新の使いやすいソフトウェアライブラリです。これは互換性のある API と使いやすさをさらに向上させる拡張 API を備え、ポータブルで、クロスコンパイル、インストール、パッケージ化が可能な NaCl のフォークです。詳細については [LibSodium ドキュメント](https://download.libsodium.org/doc/installation "LibSodium docs") を参照してください。[Swift-sodium](https://github.com/jedisct1/swift-sodium "Swift-sodium"), [NAChloride](https://github.com/gabriel/NAChloride "NAChloride"), [libsodium-ios](https://github.com/mochtu/libsodium-ios "libsodium ios") などのラッパーライブラリがいくつかあります。
- **Tink**: Google による新しい暗号化ライブラリです。Google は [セキュリティブログで](https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html "Introducing Tink") でこのライブラリの背景にある理由を説明しています。ソースは [Tink GitHub リポジトリ](https://github.com/google/tink "Tink at GitHub") にあります。
- **Themis**: Swift, Obj-C, Android/Java, C++, JS, Python, Ruby, PHP, Go 向けのストレージおよびメッセージング用暗号化ライブラリです。[Themis](https://github.com/cossacklabs/themis "Themis") は LibreSSL/OpenSSL エンジン libcrypto を依存関係として使用します。鍵生成、セキュアメッセージング (ペイロード暗号化および署名など) 、セキュアストレージ、およびセキュアセッションのセットアップのために Objective-C および Swift をサポートしています。詳細については [Wiki](https://github.com/cossacklabs/themis/wiki/Objective-C-Howto "Themis wiki") を参照してください。
- **その他**: [CocoaSecurity](https://github.com/kelp404/CocoaSecurity "CocoaSecurity"), [Objective-C-RSA](https://github.com/ideawu/Objective-C-RSA "Objective-C-RSA"), [aerogear-ios-crypto](https://github.com/aerogear/aerogear-ios-crypto "Aerogera-ios-crypto") など、他にも多くのライブラリがあります。これらの一部はもはや保守されておらず、セキュリティレビューが行われていない可能性があります。いつものように、サポートおよび保守されているライブラリを探すことをお勧めします。
- **DIY**: まずます多くの開発者が暗号または暗号化機能の独自実装を作成しています。このプラクティスは _まったく_ 推奨されておらず、もし使用するのであれば暗号化の専門家により非常に綿密な精査を行うべきです。

### 鍵管理

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

- _出典: [https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios](https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios "PBKDF2 using CommonCrypto on iOS"), `Arcane` ライブラリのテストスイートでテスト済み_

鍵を保存する必要がある場合、選択した保護クラスが `kSecAttrAccessibleAlways` でない限り、キーチェーンを使用することをお勧めします。`NSUserDefaults`、プロパティリストファイル、または Core Data や Realm からの他のシンクなど、他の場所に鍵を保存することは一般的にキーチェーンを使用するよりセキュアではなくなります。
Core Data や Realm からのシンクが `NSFileProtectionComplete` データ保護クラスを使用して保護されている場合でも、キーチェーンを使用することをお勧めします。詳細については ["iOS のデータストレージ"](0x06d-Testing-Data-Storage.md) の章を参照してください。

キーチェーンは二種類のストレージメカニズムをサポートします。鍵がセキュアエンクレーブに格納されている暗号化鍵により保護されるか、鍵自体がセキュアエンクレーブ内にあります。後者は ECDH 署名鍵を使用する場合にのみ有効です。実装の詳細については [Apple ドキュメント](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave "Secure Enclave") を参照してください。

最後の三つのオプションはソースコードにハードコードされた暗号化鍵を使用すること、固定された属性に基づく予測可能な鍵導出関数を持つこと、生成された鍵を他のアプリケーションと共有する場所に保存することで構成されます。ハードコードされた暗号化鍵を使用することは明らかに進むべき道ではありません。これはアプリケーションのすべてのインスタンスが同じ暗号化鍵を使用することを意味するためです。攻撃者はソースコードから鍵を抽出するために (ネイティブに保存されているか Objective-C/Swift に保存されているかにかかわらず) 一度だけ作業を行う必要があります。その結果、攻撃者はアプリケーションにより暗号化された他のデータを復号できます。
次に、他のアプリケーションからアクセス可能な識別子に基づいた予測可能な鍵導出関数がある場合、攻撃者はその鍵導出関数を見つけてデバイスに適用するだけで鍵を見つけることができます。最後に、対称暗号化鍵をパブリックに保存することもあまりお勧めできません。

暗号化に関して忘れてはならない二つの概念があります。

1. 常に公開鍵で暗号化や検証を行い、常に秘密鍵 (private key) で復号化や署名をします。
2. 鍵(ペア)を別の目的に再利用してはいけません。これによりその鍵に関する情報が漏洩する可能性があります。署名用に別の鍵ペアと暗号化用に別の鍵(ペア)が必要です。

### 乱数生成

Apple は [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") API を提供しており、暗号論的にセキュアな乱数を生成します。

Randomization Services API は `SecRandomCopyBytes` 関数を使用して数値を生成します。これは `/dev/random` デバイスファイルのラッパー関数であり、0 から 255 までの暗号論的にセキュアな擬似乱数値を提供します。すべての乱数がこの API で生成されることを確認します。開発者が別のものを使用する理由はありません。
