---
masvs_category: MASVS-CRYPTO
platform: ios
title: CryptoKit
---

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
