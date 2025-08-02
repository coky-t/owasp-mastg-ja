---
masvs_category: MASVS-CRYPTO
platform: ios
---

# iOS の暗号化 API

## 概要

["モバイルアプリの暗号化"](0x04g-Testing-Cryptography.md) の章では、一般的な暗号化のベストプラクティスを紹介し、暗号化が正しく使用されない場合に起こりうる典型的な問題について説明しました。この章では、iOS の暗号化 API についてさらに詳しく説明します。ソースコードでそれらの API の使用を特定する方法とその暗号設定を判断する方法を示します。コードをレビューする際には、使用されている暗号パラメータをこのガイドからリンクされている現行のベストプラクティスと比較するようにしてください。

Apple は最も一般的な暗号化アルゴリズムの実装を含むライブラリを提供しています。[Apple の Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide") は素晴らしいリファレンスです。標準ライブラリを使用して暗号化プリミティブを初期化および使用する方法に関する汎用的なドキュメントがあり、この情報はソースコード解析に役立ちます。
