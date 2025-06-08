---
masvs_v1_id:
- MSTG-PLATFORM-2
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: インジェクション欠陥のテスト (Testing for Injection Flaws)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

[インジェクション欠陥](../../../Document/0x04h-Testing-Code-Quality.md#injection-flaws "Injection Flaws") をテストするには、まず、他のテストに依存し、露出している可能性のある機能をチェックする必要があります。

- [ディープリンクのテスト (Testing Deep Links)](../MASVS-PLATFORM/MASTG-TEST-0028.md)
- [IPC を介した機密機能露出のテスト (Testing for Sensitive Functionality Exposure Through IPC)](../MASVS-PLATFORM/MASTG-TEST-0029.md)
- [オーバーレイ攻撃のテスト (Testing for Overlay Attacks)](../MASVS-PLATFORM/MASTG-TEST-0035.md)

## 静的解析

脆弱な IPC メカニズムの例を以下に示します。

_ContentProviders_ を使用してデータベース情報にアクセスしたり、サービスを調べてデータを返すかどうかを確認できます。データが適切に検証されていない場合、他のアプリがコンテンツプロバイダとやり取りする際、コンテンツプロバイダは SQL インジェクションを受ける可能性があります。以下の _ContentProvider_ の脆弱な実装を参照してください。

```xml
<provider
    android:name=".OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation"
    android:authorities="sg.vp.owasp_mobile.provider.College">
</provider>
```

上記の `AndroidManifest.xml` はエクスポートされるコンテンツプロバイダを定義しているため、他のすべてのアプリで利用できます。 `OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.java` クラスの `query` 関数を検査する必要があります。

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection,String[] selectionArgs, String sortOrder) {
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables(STUDENTS_TABLE_NAME);

    switch (uriMatcher.match(uri)) {
        case STUDENTS:
            qb.setProjectionMap(STUDENTS_PROJECTION_MAP);
            break;

        case STUDENT_ID:
            // SQL Injection when providing an ID
            qb.appendWhere( _ID + "=" + uri.getPathSegments().get(1));
            Log.e("appendWhere",uri.getPathSegments().get(1).toString());
            break;

        default:
            throw new IllegalArgumentException("Unknown URI " + uri);
    }

    if (sortOrder == null || sortOrder == ""){
        /**
         * By default sort on student names
         */
        sortOrder = NAME;
    }
    Cursor c = qb.query(db, projection, selection, selectionArgs,null, null, sortOrder);

    /**
     * register to watch a content URI for changes
     */
    c.setNotificationUri(getContext().getContentResolver(), uri);
    return c;
}
```

ユーザーが `content://sg.vp.owasp_mobile.provider.College/students` に STUDENT_ID を提供する際、クエリ文は SQL インジェクションを受けるかもしれません。SQL インジェクションを避けるには、[プリペアドステートメント](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html "OWASP SQL Injection Prevention Cheat Sheet") を使用しなければならないのは明らかですが、アプリが記載する入力のみが処理されるように [入力バリデーション](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html "OWASP Input Validation Cheat Sheet") も適用すべきです。

UI を介して入ってくるデータを処理するすべてのアプリの関数は入力バリデーションを実装すべきです。

- ユーザーインタフェースの入力には、[Android Saripaar v2](https://github.com/ragunathjawahar/android-saripaar "Android Saripaar v2") を使用できます。
- IPC または URL スキームからの入力には、バリデーション関数を作成すべきです。たとえば、 [文字列が英数字である](https://stackoverflow.com/questions/11241690/regex-for-checking-if-a-string-is-strictly-alphanumeric "Input Validation") かどうかを判定するのは以下のようになります。

```java
public boolean isAlphaNumeric(String s){
    String pattern= "^[a-zA-Z0-9]*$";
    return s.matches(pattern);
}
```

バリデーション関数の代わりとして、たとえば、整数のみが期待される場合は `Integer.parseInt` での型変換があります。[OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html "OWASP Input Validation Cheat Sheet") にはこのトピックに関する詳細情報があります。

## 動的解析

たとえば、ローカル SQL インジェクション脆弱性が特定されるかどうかなど、テスト担当者は入力フィールドを `OR 1=1--` などの文字列で手作業でテストする必要があります。

ルート化されたデバイス上では、コマンドコンテンツを使用してコンテンツプロバイダからデータをクエリできます。以下のコマンドは上述の脆弱な機能をクエリします。

```bash
# content query --uri content://sg.vp.owasp_mobile.provider.College/students
```

SQL インジェクションは以下のコマンドで悪用できます。Bob だけのレコードを取得する代わりに、ユーザーはすべてのデータを取得できます。

```bash
# content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='Bob') OR 1=1--''"
```
