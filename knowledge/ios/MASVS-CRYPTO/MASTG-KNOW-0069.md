---
masvs_category: MASVS-CRYPTO
platform: ios
title: 鍵管理 (Key Management)
---

デバイス上に鍵を保存する方法にはさまざまな手法があります。鍵を全く保存しなければ、鍵マテリアルがダンプできなくなることを確実にします。これは PKBDF-2 などのパスワード鍵導出関数を使用して実現できます。以下の例を参照してください。

```swift
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

- 出典: [https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios](https://stackoverflow.com/questions/8569555/pbkdf2-using-commoncrypto-on-ios "PBKDF2 using CommonCrypto on iOS"), `Arcane` ライブラリのテストスイートでテスト済み_

鍵を保存する必要がある場合、選択した保護クラスが `kSecAttrAccessibleAlways` でない限り、キーチェーンを使用することをお勧めします。`NSUserDefaults`、プロパティリストファイル、または Core Data や Realm からの他のシンクなど、他の場所に鍵を保存することは一般的にキーチェーンを使用するよりセキュアではなくなります。
Core Data や Realm からのシンクが `NSFileProtectionComplete` データ保護クラスを使用して保護されている場合でも、キーチェーンを使用することをお勧めします。詳細については ["iOS のデータストレージ"](../../../Document/0x06d-Testing-Data-Storage.md) の章を参照してください。

キーチェーンは二種類のストレージメカニズムをサポートします。鍵がセキュアエンクレーブに格納されている暗号化鍵により保護されるか、鍵自体がセキュアエンクレーブ内にあります。後者は ECDH 署名鍵を使用する場合にのみ有効です。実装の詳細については [Apple ドキュメント](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave "Secure Enclave") を参照してください。

最後の三つのオプションはソースコードにハードコードされた暗号化鍵を使用すること、固定された属性に基づく予測可能な鍵導出関数を持つこと、生成された鍵を他のアプリケーションと共有する場所に保存することで構成されます。ハードコードされた暗号化鍵を使用することは明らかに進むべき道ではありません。これはアプリケーションのすべてのインスタンスが同じ暗号化鍵を使用することを意味するためです。攻撃者はソースコードから鍵を抽出するために (ネイティブに保存されているか Objective-C/Swift に保存されているかにかかわらず) 一度だけ作業を行う必要があります。その結果、攻撃者はアプリケーションにより暗号化された他のデータを復号できます。
次に、他のアプリケーションからアクセス可能な識別子に基づいた予測可能な鍵導出関数がある場合、攻撃者はその鍵導出関数を見つけてデバイスに適用するだけで鍵を見つけることができます。最後に、対称暗号化鍵をパブリックに保存することもあまりお勧めできません。

暗号化に関して忘れてはならない二つの概念があります。

1. 常に公開鍵で暗号化や検証を行い、常に秘密鍵 (private key) で復号化や署名をします。
2. 鍵(ペア)を別の目的に再利用してはいけません。これによりその鍵に関する情報が漏洩する可能性があります。署名用に別の鍵ペアと暗号化用に別の鍵(ペア)が必要です。
