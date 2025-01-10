---
title: 安全な乱数生成 API を使用する (Use Secure Random Number Generator APIs)
alias: android-use-secure-random
id: MASTG-BEST-0001
platform: android
---

使用しているプラットフォームやプログラミング言語によって提供される、暗号論的に安全な擬似乱数生成器を使用します。

## Java/Kotlin

[`java.security.SecureRandom`](https://developer.android.com/reference/java/security/SecureRandom) を使用します。これは [FIPS 140-2, Security Requirements for Cryptographic Modules, section 4.9.1](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-2.pdf) で指定されている統計的乱数生成器テストに準拠しており、[RFC 4086: Randomness Requirements for Security](http://tools.ietf.org/html/rfc4086) で記されている暗号強度要件を満たしています。これは非決定論的な出力を生成し、システムエントロピーを使用してオブジェクトの初期化時に自動的にシードを行うため、手動でのシード処理は一般的に不要であり、適切に行われないとランダム性を弱める可能性があります。

`SecureRandom` のデフォルト (引数なし) コンストラクタが推奨されます。高いエントロピーを確保するためにシステムが提供する適切な長さのシードを使用するためです。コンストラクタにシード (ハードコードされているかどうかに関係なく) を提供することは [Android ドキュメントでは推奨していません](https://developer.android.com/privacy-and-security/risks/weak-prng?source=studio#weak-prng-java-security-securerandom)。決定論的な出力を作成し、セキュリティを損なうリスクがあるためです。

[ドキュメント](https://developer.android.com/reference/java/security/SecureRandom?hl=en#setSeed(byte[])) では、提供されたシードは通常は既存のシードを補完すると言われていますが、[古いセキュリティプロバイダ](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html) が使用されている場合はこの動作が異なる可能性があります。このような落とし穴を避けるには、アプリが最新のプロバイダを備えた最新の Android バージョンをターゲットにしているか、AndroidOpenSSL (または新しいリリースでは Conscrypt) などの安全なプロバイダを明示的に構成していることを確保します。

## その他の言語

標準ライブラリやフレームワークのドキュメントを参照して、オペレーティングシステムの暗号論的に安全な擬似乱数生成器を公開している API を見つけます。そのライブラリの乱数生成に既知の脆弱性がない限り、通常はこれが最も安全なアプローチです。たとえば、[Flutter/Dart issue](https://www.zellic.io/blog/proton-dart-flutter-csprng-prng/) を参照してください。フレームワークによっては PRNG 実装に既知の弱点があるかもしれないことに注意してください。
