---
title: 情報収集 - API 使用 (Information Gathering - API Usage)
platform: ios
---

iOS プラットフォームは、暗号化、Bluetooth、NFC、ネットワーク、位置情報サービスといった、一般的なアプリケーション機能のために多くの組み込みライブラリを提供しています。アプリケーションにこれらのライブラリが存在するかどうかを判断することで、その基盤となるロジックに関する貴重な洞察を得ることができます。

たとえば、アプリケーションが `CC_SHA256` 関数をインポートする場合、アプリケーションは SHA256 ハッシュを実行することを示しています。iOS の暗号化 API の解析についての詳細は "[iOS の暗号化 API](../../Document/0x06e-Testing-Cryptography.md "iOS Cryptographic APIs")" のセクションで説明されています。

同様に、上記のアプローチはアプリケーションが Bluetooth をどこでどのように使用するかを判断するために使用できます。たとえば、Bluetooth チャネルで通信するアプリケーションは `CBCentralManager` や `connect` などの Core Bluetooth フレームワークの関数を使用する必要があります。[iOS Bluetooth ドキュメント](https://developer.apple.com/documentation/corebluetooth "iOS Bluetooth documentation") を使用することで、重要な関数を特定し、それらのインポート依存関係から解析を開始できます。
