---
masvs_category: MASVS-CRYPTO
platform: android
title: 乱数生成 (Random Number Generation)
---

暗号には安全な擬似乱数生成 (PRNG) が必要です。`java.util.Random` のような標準の Java クラスは十分なランダム性を提供しないため、実際に攻撃者が生成される次の値を推測し、この推測を使用して別のユーザーになりすましたり機密情報にアクセスしたりするおそれがあります。

一般的に、`SecureRandom` を使用すべきです。しかし、Android 4.4 (API レベル 19) 以前の Android バージョンをサポートする場合には、 [PRNG を適切に初期化できない](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html "Some SecureRandom Thoughts") Android 4.1-4.3 (API レベル 16-18) バージョンのバグを回避するために更なる注意が必要です。

ほとんどの開発者は引数なしでデフォルトコンストラクタを介して `SecureRandom` をインスタンス化する必要があります。他のコンストラクタはより高度な用途のためにあり、誤って使用されると、ランダム性やセキュリティが低下するおそれがあります。`SecureRandom` を支援する PRNG プロバイダは `AndroidOpenSSL` (Conscrypt) プロバイダから `SHA1PRNG` を使用します。

詳細については [Android ドキュメント](https://developer.android.com/privacy-and-security/risks/weak-prng) を確認してください。
