---
platform: ios
title: テキスト入力フィールドの機密データを隠す API の実行時使用 (Runtime Use of APIs Hiding Sensitive Data in Text Input Fields)
id: MASTG-TEST-0347
type: [dynamic]
weakness: MASWE-0053
profiles: [L2]
best-practices: [MASTG-BEST-0044]
knowledge: [MASTG-KNOW-0121]
---

## 概要

このテストは [テキスト入力フィールドの機密データを隠す API への参照 (References to APIs Hiding Sensitive Data in Text Input Fields)](MASTG-TEST-0346.md) を補完するものです。アプリの実行時にテキスト入力フィールドを監視し、ユーザーが機密データを入力した際にアプリがテキスト入力をマスクしているかどうかをチェックします。

アプリが機密データを含むテキスト入力フィールドをマスクしない場合、そのようなデータは傍観者 (ショルダーサーフィン) に見えたり、スクリーンショットやスクリーンレコーディングでキャプチャされる可能性があります。

アプリを徹底的に動かし、特定された各テキスト入力フィールドに現実的な機密データ (ユーザー名、パスワード、電子メールアドレス、クレジットカード番号、リカバリコードなど) を入力します。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](../../../techniques/ios/MASTG-TECH-0095.md) を使用して、関連する API をフックします。

## 結果

出力には各テキスト入力と対応する入力フィールドおよびその保護状態を関連付けることを可能にする証跡を含む可能性があります。少なくとも以下を含む可能性があります。

- `UITextField`, `SecureField`, `TextField` などの入力フィールドクラス。
- `isSecureTextEntry` などの可視性に関連する入力特定。
- 機密データと関連付けるための入力された値。

## 評価

アプリがテキストをマスクすることを許可しない UI 要素を使用している場合、または機密データを含むテキスト入力フィールドがマスクされていないことを見つけた場合、そのテストケースは不合格です。たとえば、以下のような場合です。

- パスワード、PIN、OTP に使用されている `UITextField` が `true` に設定した [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry) を持っていない。
- パスワード、PIN、OTP フィールドに [`SecureField`](https://developer.apple.com/documentation/swiftui/securefield) の代わりに SwiftUI `TextField` が使用されている。

> [!NOTE]
> 機密性の低いテキスト入力フィールド (ユーザー名や電子メールアドレスなど) がマスクされていないとしても、それは不具合ではありません。テキスト入力フィールドが機密データに使用されているかどうかを検証するには、アプリの UI とビジネスロジックをレビューし、そのフィールドが使用されるコンテキストを特定する必要があるかもしれません。

> [!NOTE]
> アプリが `UITextField` や `SecureField` などの標準クラスに依存しないカスタムテキスト入力コントロールを使用している場合 (たとえば、カスタム UI フレームワークやゲームエンジン内、またはテキスト入力が静止時の入力特性を確実に観測できない非標準の抽象化によって処理される場合)、このテストは検出漏れとなる可能性があります。
