---
platform: android
title: UI 要素のキーボードキャッシュ属性への参照 (References to Keyboard Caching Attributes in UI Elements)
id: MASTG-TEST-0258
type: [static, code]
weakness: MASWE-0053
best-practices: [MASTG-BEST-0019]
profiles: [L2]
knowledge: [MASTG-KNOW-0055]
---

## 概要

このテストは、アプリがテキスト入力フィールドを適切に設定して、パスワードや個人データなどの機密情報をキーボードがキャッシュしないことを検証します。

Android アプリはテキスト入力フィールドの動作を以下を用いて構成できます。

- `res/layout` ディレクトリ内のレイアウトファイルから:
    - `android:inputType` XML 属性を使用する。
- コード内でプログラム的に:
    - 入力フィールドの `setInputType` を呼び出し、適切な入力タイプ値を渡す。
    - Jetpack Compose では、[`KeyboardOptions` constructors](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/KeyboardOptions#public-constructors_1) を使用して、`keyboardType` と `autoCorrect` パラメータを設定する。

機密情報のキーボードキャッシュを防止する入力タイプの詳細について [キーボードキャッシュ (Keyboard Cache)](../../../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055.md) の「非キャッシュ入力タイプ」セクションを参照してください。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、関連する API を探します。
3. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/android/MASTG-TECH-0007.md) を使用して、アプリパッケージからレイアウトファイルを抽出します。

## 結果

出力には以下を含む可能性があります。

- UI に XML を使用している場合、すべての `android:inputType` XML 属性。
- `setInputType` メソッドへのすべてのコールと、それに渡される入力タイプ値。

## 評価

アプリが非キャッシュ入力タイプ ([キーボードキャッシュ (Keyboard Cache)](../../../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055.md) の「非キャッシュ入力タイプ」セクションを参照) を使用していない機密データを処理するフィールドがある場合、そのテストケースは不合格です。
