---
masvs_category: MASVS-CRYPTO
platform: ios
title: 暗号サードパーティーライブラリ (Cryptographic Third-Party libraries)
---

以下のようなさまざまなサードパーティーライブラリが利用可能です。

- **CJOSE**: JWE の台頭と AES GCM のパブリックサポートの不足により、[CJOSE](https://github.com/cisco/cjose "cjose") などの他のライブラリが進出しています。CJOSE は C/C++ 実装のみを提供するため、依然として高レベルのラッピングが必要です。
- **CryptoSwift**: Swift のライブラリで、[GitHub](https://github.com/krzyzanowskim/CryptoSwift "CryptoSwift") にあります。このライブラリはさまざまなハッシュ関数、MAC 関数、CRC 関数、対称暗号、およびパスワードベースの鍵導出関数をサポートしています。これはラッパーではなく、それぞれの暗号を完全に自己実装したバージョンです。関数の効果的な実装を検証することが重要です。
- **OpenSSL**: [OpenSSL](https://www.openssl.org/ "OpenSSL") は TLS で使用されるツールキットライブラリで、C で記述されています。その暗号化機能のほとんどは (H)MAC 、署名、対称および非対称暗号、ハッシュを作成するなど、必要となるさまざまな暗号化アクションを実行するために使用できます。[OpenSSL](https://github.com/ZewoGraveyard/OpenSSL "OpenSSL") や [MIHCrypto](https://github.com/hohl/MIHCrypto "MIHCrypto") などのさまざまなラッパーがあります。
- **LibSodium**: Sodium は暗号化、復号化、署名、パスワードハッシュなどのための最新の使いやすいソフトウェアライブラリです。これは互換性のある API と使いやすさをさらに向上させる拡張 API を備え、ポータブルで、クロスコンパイル、インストール、パッケージ化が可能な NaCl のフォークです。詳細については [LibSodium ドキュメント](https://download.libsodium.org/doc/installation "LibSodium docs") を参照してください。[Swift-sodium](https://github.com/jedisct1/swift-sodium "Swift-sodium"), [NAChloride](https://github.com/gabriel/NAChloride "NAChloride"), [libsodium-ios](https://github.com/mochtu/libsodium-ios "libsodium ios") などのラッパーライブラリがいくつかあります。
- **Tink**: Google による新しい暗号化ライブラリです。Google は [セキュリティブログで](https://security.googleblog.com/2018/08/introducing-tink-cryptographic-software.html "Introducing Tink") このライブラリの背景にある理由を説明しています。ソースは [Tink GitHub リポジトリ](https://github.com/google/tink "Tink at GitHub") にあります。
- **Themis**: Swift, Obj-C, Android/Java, C++, JS, Python, Ruby, PHP, Go 向けのストレージおよびメッセージング用暗号化ライブラリです。[Themis](https://github.com/cossacklabs/themis "Themis") は LibreSSL/OpenSSL エンジン libcrypto を依存関係として使用します。鍵生成、セキュアメッセージング (ペイロード暗号化および署名など)、セキュアストレージ、およびセキュアセッションのセットアップのために Objective-C および Swift をサポートしています。詳細については [Wiki](https://github.com/cossacklabs/themis/wiki/Objective-C-Howto "Themis wiki") を参照してください。
- **その他**: [CocoaSecurity](https://github.com/kelp404/CocoaSecurity "CocoaSecurity"), [Objective-C-RSA](https://github.com/ideawu/Objective-C-RSA "Objective-C-RSA"), [aerogear-ios-crypto](https://github.com/aerogear/aerogear-ios-crypto "Aerogera-ios-crypto") など、他にも多くのライブラリがあります。これらの一部はもはや保守されておらず、セキュリティレビューが行われていない可能性があります。いつものように、サポートおよび保守されているライブラリを探すことをお勧めします。
- **DIY**: まずます多くの開発者が暗号または暗号化機能の独自実装を作成しています。このプラクティスは _まったく_ 推奨されておらず、もし使用するのであれば暗号化の専門家により非常に綿密な精査を行うべきです。
