---
platform: ios
title: テキストフィールドのキーボードキャッシュを防止するための API への参照 (References to APIs for Preventing Keyboard Caching of Text Fields)
id: MASTG-TEST-0313
type: [static]
weakness: MASWE-0053
profiles: [L2]
best-practices: [MASTG-BEST-0026]
---

## 概要

このテストは、ターゲットアプリがテキストフィールドに入力された機密情報をシステムキーボードによってキャッシュ [キーボードキャッシュ (Keyboard Cache)](../../../knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0100.md) されることから防止しているかどうかを検証します。iOS では、デバイス上の任意のアプリの入力時に、キーボードが以前に入力されたテキストを提案することがあります。

このテストは、`UITextField`, `UITextView`, `UISearchBar` などの UI 要素が、以下のいずれかまたは複数の属性を使用してキーボードのキャッシュを防止しているかどうかをチェックします。

- [`UITextAutocorrectionType`](https://developer.apple.com/documentation/uikit/uitextautocorrectiontype) の設定
- [`isSecureTextEntry`](https://developer.apple.com/documentation/uikit/uitextinputtraits/issecuretextentry) の有効化
- [`spellCheckingType`](https://developer.apple.com/documentation/uikit/uitextinputtraits/spellcheckingtype) の設定

**注:** デフォルトでは、テキスト入力はキーボードキャッシュの対象となり、アプリはテキストフィールドを作成する際に `UITextAutocorrectionType` を明示的に設定する必要はありません。さらに、UI は Storyboard で構成される可能性があります。結果として、このテストは多くの真陽性を見逃す可能性があります。完全なカバレッジには、[キーボードキャッシュの対象となるテキストフィールドの実行時監視 (Runtime Monitoring of Text Fields Eligible for Keyboard Caching)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0314.md) を使用することをお勧めします。

**注:** アプリが、カスタム UI フレームワークやゲームエンジンなど、`UITextField` や `UITextView` のような標準 UIKit クラスに依存しないカスタムテキスト入力コントロールを使用している場合、またはテキスト入力が、保存時の入力特性を確実に監視できない、非標準の抽象化によって処理されている場合、このテストは偽陰性を生み出す可能性があります。

## 手順

1. [iOS アプリのリバースエンジニアリング (Reverse Engineering iOS Apps)](../../../techniques/ios/MASTG-TECH-0065.md) を使用して、アプリをリバースエンジニアします。
2. [相互参照の取得 (Retrieving Cross References)](../../../techniques/ios/MASTG-TECH-0072.md) を使用して、関連する入力属性を設定する API への参照を探します。
3. [逆アセンブルされた Objective-C と Swift のコードをレビューする (Reviewing Disassembled Objective-C and Swift Code)](../../../techniques/ios/MASTG-TECH-0076.md) を使用して、関連するコードパスを解析し、これらの属性に割り当てられた値を特定します。

## 結果

出力にはアプリが以下を行う場所のリストを含む可能性があります。

- `UITextField`, `UITextView`, `UISearchBar` などのテキスト入力フィールドを作成する。
- セキュリティ上の機密テキストフィールドのキーボードキャッシュを防止する入力属性を明示的に設定する。

## 評価

ユーザー名、パスワード、電子メールアドレス、クレジットカード番号、リカバリコードなど、機密性の高い値を扱う可能性のある UI 入力がキーボードキャッシュの対象となる場合、そのテストは不合格です。これは以下の場合に発生します。

- `isSecureTextEntry` が有効になっていない場合、または
- `autocorrectionType` が `default` または `yes` に設定されている場合、または
- `spellCheckingType` が `default` または `yes` に設定されている場合。

セキュリティ上機密のすべての入力がキーボードキャッシュから保護されている場合、そのテストは合格です。

**注:** アプリの脅威モデルによっては、一部のテキストフィールドでスペルチェックを無効にする必要がないことがあります。但し、`isSecureTextEntry` を有効にするとオートコレクトとスペルチェックの両方が暗黙的に無効になり、明示的な保証も限られるため、機密情報を扱う可能性のあるテキストフィールドでは一般的に三つの属性すべてを無効にすることをお勧めします。
