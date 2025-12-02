---
title: 安全な乱数生成器 API を使用する (Use Secure Random Number Generator APIs)
alias: ios-use-secure-random
id: MASTG-BEST-0025
platform: ios
---

オペレーティングシステムの _暗号論的に安全な擬似乱数生成器 (CSPRNG)_ を基盤とする安全な乱数生成器 API を使用します。独自の _擬似乱数生成器 (PRNG)_ を構築してはいけません。

## Swift / Objective-C

- **Security フレームワーク (推奨)**: Security フレームワークの [`SecRandomCopyBytes`](https://developer.apple.com/documentation/security/secrandomcopybytes(_:_:_:)) API を使用します。これはシステム CSPRNG を基盤とする暗号論的に安全なランダムバイトを生成します。
- **CommonCrypto**: `CCRandomCopyBytes` や `CCRandomGenerateBytes` (Apple Developers ウェブサイトには記載されていません) を使用 _できます_。これらもシステム CSPRNG を基盤としています。但し、これらの関数のラッパーである `SecRandomCopyBytes` をお勧めします。
- **Swift 標準ライブラリ**: `SystemRandomNumberGenerator` を基盤とする Swift 標準ライブラリの `.random` API を使用できます。但し、それらの乱数生成器はカスタマイズ可能であるため、デフォルトの `SystemRandomNumberGenerator` (カスタム生成器を指定していないなど) や安全な代替手段 (暗号論的に安全であることを確保している) を使用するように、注意します。
- **CryptoKit**: CryptoKit は直接ランダムバイト生成器を公開していませんが、システム CSPRNG を基盤とする暗号演算を通じて、安全なランダムノンスと鍵を提供します。たとえば、鍵には `SymmetricKey`、ノンスには `AES.GCM.Nonce` を使用でき、生のランダムバイトを直接管理する必要はありません。

これらの API のコード例については [乱数生成 (Random Number Generator)](../knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0070.md) を参照してください。

## その他の言語

標準ライブラリやフレームワークを参照して、オペレーティングシステム CSPRNG を公開する API を見つけてください。ライブラリ自体に既知の脆弱性がない限り、これは通常最も安全な方法です。

iOS 上のクロスプラットフォームアプリやハイブリッドアプリでは、基盤となるシステム CSPRNG への呼び出しを転送するフレームワークを頼ります。以下に例を示します。

- Flutter や Dart では [`Random.secure()`](https://api.flutter.dev/flutter/dart-math/Random/Random.secure.html) を使用します。これは暗号論的に安全であると記述されています。[プラットフォーム統合レイヤ](https://github.com/dart-lang/sdk/blob/47e77939fce74ffda0b7252f33ba1ced2ea09c52/runtime/bin/crypto_macos.cc#L16) を通じて `SecRandomCopyBytes` に到達します。セキュリティレビューについては [この記事](https://www.zellic.io/blog/proton-dart-flutter-csprng-prng/) をご覧ください。
- React Native では、iOS 上で内部的に `SecRandomCopyBytes` を呼び出す、[`react-native-secure-random`](https://github.com/robhogan/react-native-securerandom) や [`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values) などのライブラリを使用します。
