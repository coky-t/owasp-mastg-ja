---
title: 安全な乱数生成 API を使用する (Use Secure Random Number Generator APIs)
alias: android-use-secure-random
id: MASTG-BEST-0001
platform: android
---

[`java.security.SecureRandom`](https://developer.android.com/reference/java/security/SecureRandom) はデフォルトで SHA1PRNG を使用して、`dev/urandom` から取得したシステムスレッドタイミングに基づくシードから非決定論的な結果を生成します。このシードはオブジェクトの構築時や取得時に自動的に発生するため、PRNG の明示的なシードは必要ありません。

安全な乱数値を生成するには、通常はデフォルトコンストラクタで十分です。しかし、高度なユースケースでは他のコンストラクタも利用できますが、それらを不適切に使用すると出力のランダム性が低下する可能性があります。したがって、デフォルト以外のコンストラクタは注意して使用すべきです。
