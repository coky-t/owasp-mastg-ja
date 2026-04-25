---
title: コンテンツプロバイダでの SQL インジェクションを防止する (Prevent SQL Injection in ContentProviders)
alias: prevent-sqli-contentprovider
id: MASTG-BEST-0039
platform: android
knowledge: [MASTG-KNOW-0117]
---

`ContentProvider` は Android アプリケーションが他のアプリケーションやシステムコンポーネントとデータを共有できるようにします。`ContentProvider` が、バリデーションやパラメータ化なしで URI、IPC 呼び出し、インテントからの信頼できない入力を使用して SQL クエリを構築すると、SQL インジェクションに対して脆弱になります。攻撃者はこの脆弱性を悪用して、アクセス制御をバイパスし、機密データを抽出できます。`ContentProvider` クエリでの URI パスセグメント、クエリパラメータ、`selection` 引数の不適切な処理は任意の SQL 実行につながる可能性があります。

- **パラメータ化されたクエリを使用する**: 文字列連結を使用して SQL を構築する代わりに、`selection` および `selectionArgs` パラメータを使用します。

例:

```kotlin
  val idSegment = uri.getPathSegments()[1]
  val selection = "id = ?"
  val selectionArgs = arrayOf(idSegment)
  val cursor = qb.query(db, projection, selection, selectionArgs, null, null, sortOrder)
```

- **プリペアドステートメントを使用する**: 挿入、更新、削除操作を実行する際は、動的に構築された SQL ではなく、SQLite のプリペアドステートメント (引数バインディングをサポートする `SQLiteStatement` メソッドや `SQLiteDatabase` メソッドなど) を使用します。プリペアドステートメントは、信頼できない入力がパラメータとしてバインドされ、SQL クエリの構造を改変できず、入力が URI や IPC 呼び出しから発生した場合でも、SQL インジェクションを効果的に防止します。

詳細については ["悪意のある入力から保護する"](https://developer.android.com/guide/topics/providers/content-provider-basics#Injection) を参照してください。
