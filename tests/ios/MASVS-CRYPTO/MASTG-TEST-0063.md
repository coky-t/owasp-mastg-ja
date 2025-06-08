---
masvs_v1_id:
- MSTG-CRYPTO-6
masvs_v2_id:
- MASVS-CRYPTO-1
platform: ios
title: 乱数生成のテスト (Testing Random Number Generation)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

## 静的解析

Swift では、 [`SecRandomCopyBytes` API](https://developer.apple.com/reference/security/1399291-secrandomcopybytes "SecRandomCopyBytes (Swift)") は以下のように定義されています。

```default
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

[Objective-C バージョン](https://developer.apple.com/reference/security/1399291-secrandomcopybytes?language=objc "SecRandomCopyBytes (Objective-C)") は以下の通りです。

```objectivec
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

以下はこの API の使用例です。

```objectivec
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

注意: コード内の乱数に他のメカニズムが使用されている場合には、これらが上述の API のラッパーであることを検証するか、セキュアランダム性をレビューします。多くの場合これは非常に困難であり、上記の実装を守ることが最適であることを意味します。

## 動的解析

ランダム性をテストしたい場合には、多数の数値セットをキャプチャし、[Burp の sequencer プラグイン](https://portswigger.net/burp/documentation/desktop/tools/sequencer "Sequencer") を使用してランダム性の品質をチェックします。
