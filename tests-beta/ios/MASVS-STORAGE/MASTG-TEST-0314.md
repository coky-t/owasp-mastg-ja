---
platform: ios
title: キーボードキャッシュの対象となるテキストフィールドの実行時監視 (Runtime Monitoring of Text Fields Eligible for Keyboard Caching)
id: MASTG-TEST-0314
type: [dynamic]
weakness: MASWE-0053
profiles: [L2]
prerequisites:
- identify-sensitive-data
best-practices: [MASTG-BEST-0026]
knowledge: [MASTG-KNOW-0100]
---

## 概要

このテストは [テキストフィールドのキーボードキャッシュを防止するための API への参照 (References to APIs for Preventing Keyboard Caching of Text Fields)](MASTG-TEST-0313.md) を補完するものです。実行時に、[`UITextField`](https://developer.apple.com/documentation/uikit/uitextfield), [`UITextView`](https://developer.apple.com/documentation/uikit/uitextview), [`UISearchBar`](https://developer.apple.com/documentation/uikit/uisearchbar) など、アプリのテキスト入力を監視し、ユーザーが機密情報を入力した際にキーボードキャッシュの対象となるかどうかをチェックします。

## 手順

1. [アプリのインストール (Installing Apps)](../../../techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. [iOS での動的解析 (Dynamic Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0067.md) を使用して、アプリの UI のテキスト入力フィールドを探し、関連する属性を使用しているものを特定します。
3. 特定された各入力フィールドに現実的な機密情報 (ユーザー名、パスワード、電子メールアドレス、クレジットカード番号、リカバリコードなど) を入力し、アプリを徹底的に実行します。

## 結果

出力には、テスト担当者が各テキスト入力を対応する入力フィールドとその保護状態に関連付けるようにする必要があります。少なくとも以下を含む必要があります。

- 入力ウィジェットの詳細。利用可能な場合、クラスとアクセシビリティ識別子を含む。
- キーボードキャッシュに関連する入力特性。例: `isSecureTextEntry`, `autocorrectionType`, `spellCheckingType`, その他キーボード予測やキャッシュに影響を与える特定やフラグ。
- 入力値。機密情報との関連付けが可能であるため。

## 評価

機密性の高い値 (ユーザー名、パスワード、電子メールアドレス、クレジットカード番号、リカバリコードなど) を扱う可能性のある UI 入力がキーボードキャッシュの対象となる場合、このテストは不合格です。これは以下の場合に発生します。

- `isSecureTextEntry` が有効になっていない場合、または
- `autocorrectionType` が `default` または `yes` に設定されている場合、または
- `spellCheckingType` が `default` または `yes` に設定されている場合。

セキュリティ上機密のすべての入力がキーボードキャッシュから保護されている場合、そのテストは合格です。

**注:** アプリが `UITextField` や `UITextView` のような標準 UIKit クラスに依存しないカスタムテキスト入力コントロール (カスタム UI フレームワークやゲームエンジンなど) を使用している場合、またはテキスト入力が、実行時の入力特性を確実に監視できない、非標準の抽象化によって処理されている場合、このテストは偽陰性を生み出す可能性があります。
