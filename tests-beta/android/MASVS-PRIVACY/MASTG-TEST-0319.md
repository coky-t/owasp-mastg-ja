---
platform: android
title: 機密ユーザーデータを扱うことが知られている SDK API の実行時使用 (Runtime Use of SDK APIs Known to Handle Sensitive User Data)
id: MASTG-TEST-0319
type: [dynamic]
weakness: MASWE-0112
prerequisites:
  - identify-sensitive-data
profiles: [P]
---

## 概要

このテストは [機密ユーザーデータを扱うことが知られている SDK API への参照 (References to SDK APIs Known to Handle Sensitive User Data)](MASTG-TEST-0318.md) と対をなす動的テストです。

## 手順

1. [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) を使用して、機密ユーザーデータを扱うことが知られている SDK メソッドをフックします。

## 結果

出力には、SDK メソッドが呼び出される場所、そのスタックトレース (その呼び出しに至る呼び出し階層)、実行時に SDK メソッドに渡される引数 (値) をリストする可能性があります。

## 評価

アプリコードでこれらの SDK メソッドに渡されている機密ユーザーデータを見つけることができた場合、そのテストケースは不合格です。これはアプリがサードパーティ SDK と機密ユーザーデータを共有していることを示します。そのようなデータ共有が見つからない場合、そのテストケースは合格です。
