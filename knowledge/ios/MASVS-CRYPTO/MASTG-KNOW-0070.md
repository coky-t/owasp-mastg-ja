---
masvs_category: MASVS-CRYPTO
platform: ios
title: 乱数生成 (Random Number Generator)
---

Apple は [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") API を提供しており、暗号論的に安全な乱数を生成します。

Randomization Services API は `SecRandomCopyBytes` 関数を使用して数値を生成します。これは `/dev/random` デバイスファイルのラッパー関数であり、0 から 255 までの暗号論的に安全な擬似乱数値を提供します。すべての乱数がこの API で生成されることを確認します。開発者が別のものを使用する理由はありません。
