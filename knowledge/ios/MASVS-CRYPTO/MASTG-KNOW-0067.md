---
masvs_category: MASVS-CRYPTO
platform: ios
title: CommonCrypto, SecKey および Wrapper ライブラリ (CommonCrypto, SecKey and Wrapper libraries)
---

暗号化操作で最も一般的に使用されるクラスは iOS ランタイムに同梱されている CommonCrypto です。CommonCrypto オブジェクトにより提供される機能は [ヘッダーファイルのソースコード](https://web.archive.org/web/20240606000307/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h.auto.html "CommonCrypto.h") を参照することが分析に最適です。

- `Commoncryptor.h` は対称暗号化操作のパラメータを提供します。
- `CommonDigest.h` はハッシュアルゴリズムのパラメータを提供します。
- `CommonHMAC.h` はサポートされている HMAC 操作のパラメータを提供します。
- `CommonKeyDerivation.h` はサポートされている KDF 関数のパラメータを提供します。
- `CommonSymmetricKeywrap.h` は対称鍵を鍵暗号化鍵でラップするために使用される関数を提供します。

残念ながら、CommonCryptor のパブリック API には次のようないくつかのタイプの操作がありません。GCM モードはプライベート API でのみ利用可能です。[そのソースコード](https://web.archive.org/web/20240703215805/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h "GCM in CC") を参照してください。これには追加のバインディングヘッダーが必要です。または他のラッパーライブラリを使用できます。

次に、非対称操作のために、Apple は [SecKey](https://developer.apple.com/documentation/security/seckey "SecKey") を提供します。Apple は [開発者ドキュメント](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption "Using keys for encryption") でこれを使用する方法に関する素晴らしいガイドを提供しています。

前述のように、利便性を提供するために両方に対するラッパーライブラリがいくつか存在します。使用される典型的なライブラリには例えば以下のものがあります。

- [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto "IDZSwiftCommonCrypto")
- [Heimdall](https://github.com/henrinormak/Heimdall "Heimdall")
- [SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA "SwiftyRSA")
- [RNCryptor](https://github.com/RNCryptor/RNCryptor "RNCryptor")
- [Arcane](https://github.com/onmyway133/Arcane "Arcane")
