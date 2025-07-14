---
title: 情報収集 - API 使用 (Information Gathering - API Usage)
platform: ios
---

iOS プラットフォームは、暗号化、Bluetooth、NFC、ネットワーク、位置情報ライブラリといった、アプリケーションで頻繁に使用される機能のために多くの組み込みライブラリを提供しています。アプリケーションにこれらのライブラリが存在するかどうかを判断することで、その基盤となる動作に関する貴重な情報を得ることができます。

たとえば、アプリケーションが `CC_SHA256` 関数をインポートしている場合、アプリケーションは SHA256 アルゴリズムを使用して何らかのハッシュ演算を実行することを示しています。iOS の暗号化 API を解析する方法についての詳細は "[iOS の暗号化 API](../../Document/0x06e-Testing-Cryptography.md "iOS Cryptographic APIs")" のセクションで説明されています。

同様に、上記のアプローチはアプリケーションが Bluetooth をどこでどのように使用しているかを判断するために使用できます。たとえば、Bluetooth チャネルを使用して通信を行うアプリケーションは `CBCentralManager` や `connect` などの Core Bluetooth フレームワークの関数を使用する必要があります。[iOS Bluetooth ドキュメント](https://developer.apple.com/documentation/corebluetooth "iOS Bluetooth documentation") を使用することで、重要な関数を判断し、それらの関数のインポートに関する解析を開始できます。
