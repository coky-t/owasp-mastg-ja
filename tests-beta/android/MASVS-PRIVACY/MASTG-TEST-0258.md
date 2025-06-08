---
platform: android
title: UI 要素のキーボードキャッシュ属性への参照 (References to Keyboard Caching Attributes in UI Elements)
id: MASTG-TEST-0258
type: [static]
weakness: MASWE-0053
profiles: [L2]
---

## 概要

このテストは、アプリがテキスト入力フィールドを適切に設定して、パスワードや個人データなどの機密情報を [キーボードがキャッシュ](../../../Document/0x05d-Testing-Data-Storage.md#keyboard-cache) しないことを検証します。

Android アプリはレイアウトファイル内の XML 属性を使用するか、コード内でプログラム的にテキスト入力フィールドの動作を設定できます。アプリが機密データに対して [非キャッシュ入力タイプ](../../../Document/0x05d-Testing-Data-Storage.md#non-caching-input-types) を使用しない場合、キーボードは機密情報をキャッシュする可能性があります。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. `res/layout` ディレクトリ内のレイアウトファイルに対して上記の XML 属性を検索します。
3. `setInputType` メソッドコールとそれに渡される入力タイプ値を検索します ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md))。
4. アプリが Jetpack Compose を使用している場合、リバースしたコードに対して [`KeyboardOptions` コンストラクタ](https://developer.android.com/reference/kotlin/androidx/compose/foundation/text/KeyboardOptions#public-constructors_1) へのコールとそのパラメータを検索します ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md))。特に `keyboardType` と `autoCorrect` です。

## 結果

出力には以下を含む可能性があります。

- UI に XML を使用している場合、すべての `android:inputType` XML 属性。
- `setInputType` メソッドへのすべてのコールと、それに渡される入力タイプ値。

## 評価

アプリが [非キャッシュ入力タイプ](../../../Document/0x05d-Testing-Data-Storage.md#keyboard-cache) を使用していない機密データを処理するフィールドがある場合、そのテストケースは不合格です。
