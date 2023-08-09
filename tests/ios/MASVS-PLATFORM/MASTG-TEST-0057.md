---
masvs_v1_id:
- MSTG-STORAGE-7
masvs_v2_id:
- MASVS-PLATFORM-3
platform: ios
title: 機密データがユーザーインタフェースを通じて開示されているかどうかのチェック (Checking for Sensitive Data Disclosed Through the User Interface)
masvs_v1_levels:
- L1
- L2
---

## 概要

## 静的解析

入力をマスクする入力フィールドは二つの方法で設定できます。

**ストーリーボード**
iOS プロジェクトのストーリーボードで、機密データを取得するテキストフィールドの設定オプションに移動します。"Secure Text Entry" オプションが選択されていることを確認します。このオプションが有効になっていると、テキスト入力の代わりにテキストフィールドにドットが表示されます。

**ソースコード**
テキストフィールドがソースコードで定義されている場合は、[`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/1624427-issecuretextentry "isSecureTextEntry in Text Field") オプションが "true" に設定されていることを確認します。このオプションはドットを表示してテキスト入力を見えなくします。

```swift
sensitiveTextField.isSecureTextEntry = true
```

## 動的解析

アプリケーションが機密情報をユーザーインタフェースに漏洩するかどうかを判断するには、アプリケーションを実行し、そのような情報を表示したり、入力として受け取るコンポーネントを特定します。

情報がたとえばアルタリスクやドットでマスクされている場合、そのアプリはユーザーインタフェースにデータを漏洩していません。
