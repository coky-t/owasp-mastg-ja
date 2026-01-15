---
platform: android
title: テキスト入力フィールドにユーザー認証データを露出するアプリ (App Exposing User Authentication Data in Text Input Fields)
id: MASTG-TEST-0316
type: [static, manual]
weakness: MASWE-0053
profiles: [L2]
---

## 概要

このテストは、アプリがユーザー入力を正しく処理することを検証し、アクセスコード (パスワードまたは PIN) と検証コード (OTP) がテキスト入力フィールド内にプレーンテキストで露出されていないことを確認します。

ユーザーのプライバシーを保護するには、これらのコードの適切なマスク (入力文字の代わりのドットなど) が不可欠です。これは、ユーザーが入力した文字を隠す適切な入力タイプを使用することで実現できます。Jetpack Compose では、`SecureTextField` は `TextObfuscationMode` を使用します。これは [デフォルトでは `TextObfuscationMode.RevealLastTyped`](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:compose/material/material/src/commonMain/kotlin/androidx/compose/material/SecureTextField.kt;l=115?q=SecureTextField) であるため、開発者は別の動作が必要な場合を除き、明示的に `textObfuscationMode` を設定することなく、単に `SecureTextField` を使用するだけです。

XML ビュー:

```xml
<EditText
    android:inputType="textPassword"
    ...
/>
```

Jetpack Compose:

```kotlin
SecureTextField(
    // textObfuscationMode defaults to TextObfuscationMode.RevealLastTyped
    textObfuscationMode = TextObfuscationMode.RevealLastTyped, // or TextObfuscationMode.Hidden
    ...
)
```

> [!NOTE]
> `SecureTextField` がデフォルトの `TextObfuscationMode.RevealLastTyped` を使用している場合や、明示的に `RevealLastTyped` または `Hidden` を設定している場合でも、後でプログラムによって `Visible` に変更できます。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、テキストフィールドクラスとテキスト難読化 API への参照を探します。
3. アクセスコードまたは検証コードの使用のためのフィールドを手動で評価して絞り込みます。

## 結果

出力にはアクセスコードまたは検証コードのテキスト入力フィールドが使用される場所のリストを含む可能性があります。

## 評価

アクセスコードまたは検証コードに使用されるテキスト入力フィールドがマスクされていないことが判明した場合、このテストケースは不合格です。たとえば、以下の理由が考えられます。

- `TextField` が使用されている
- `SecureTextField` が使用されているが、`TextObfuscationMode.Visible` が設定されている

> [!NOTE]
> アプリが `TextField` や `SecureTextField` のような標準クラスに依存しないカスタムテキスト入力コントロールを使用している場合 (カスタム UI フレームワークやゲームエンジンなど)、このテストは偽陰性を生み出す可能性があります。
