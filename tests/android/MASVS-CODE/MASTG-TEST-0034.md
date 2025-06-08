---
masvs_v1_id:
- MSTG-PLATFORM-8
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: オブジェクト永続化のテスト (Testing Object Persistence)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

デバイス上の機密情報の保存に使用されている [オブジェクト永続化](../../../Document/0x05h-Testing-Platform-Interaction.md#object-persistence "Object Persistence") をテストするには、まずオブジェクトシリアル化のすべてのインスタンスを特定し、それらが機密データを保持しているかどうかをチェックします。もしそうであれば、盗聴や認可されていない変更に対して適切に保護されているかどうかをチェックします。

いつでも実行できる一般的な改善手順がいくつかあります。

1. 機密データが暗号化され、シリアル化や永続化の後に HMAC 化や署名されていることを確認します。データを使用する前に、署名や HMAC を評価します。詳細については "[Android の暗号化 API](../../../Document/0x05e-Testing-Cryptography.md)" の章を参照してください。
2. ステップ 1 で使用した鍵が簡単に抽出できないことを確認します。ユーザーやアプリケーションインスタンスが鍵を取得するために適切に認証や認可されている必要があります。詳細については "[Android のデータストレージ](../../../Document/0x05d-Testing-Data-Storage.md)" の章を参照してください。
3. 逆シリアル化されたオブジェクト内のデータは実際に使用する前に注意深く検証していることを確認します (ビジネスロジックやアプリケーションロジックを悪用していないなど) 。

可用性を重視するリスクの高いアプリケーションでは、シリアル化されたクラスが stable である場合にのみ `Serializable` を使用することを推奨します。次に、リフレクションベースの永続化を使用しないことを推奨します。理由は以下の通りです。

- 攻撃者は文字列ベースの引数を介してメソッドのシグネチャを見つける可能性があります。
- 攻撃者はリフレクションベースのステップを操作してビジネスロジックを実行できる可能性があります。

## 静的解析

### オブジェクトのシリアル化

以下のキーワードでソースコードを検索します。

- `import java.io.Serializable`
- `implements Serializable`

### JSON

メモリダンプ対策の必要がある場合、非常に機密性の高い情報が JSON 形式で保存されていないことを確認します。標準ライブラリではメモリダンプ対策技法の防止を保証できません。対応するライブラリで以下のキーワードをチェックできます。

**`JSONObject`** 以下のキーワードでソースコードを検索します。

- `import org.json.JSONObject;`
- `import org.json.JSONArray;`

**`GSON`** 以下のキーワードでソースコードを検索します。

- `import com.google.gson`
- `import com.google.gson.annotations`
- `import com.google.gson.reflect`
- `import com.google.gson.stream`
- `new Gson();`
- `@Expose`, `@JsonAdapter`, `@SerializedName`,`@Since`, `@Until` などのアノテーション

**`Jackson`** 以下のキーワードでソースコードを検索します。

- `import com.fasterxml.jackson.core`
- `import org.codehaus.jackson` (古いバージョン向け)

### ORM

ORM ライブラリを使用する場合は、データが暗号化されたデータベースに保存され、クラス表現が保存前に個別に暗号化されていることを確認します。詳細については "[Android のデータストレージ](../../../Document/0x05d-Testing-Data-Storage.md)" および "[Android の暗号化 API](../../../Document/0x05e-Testing-Cryptography.md)" の章を参照してください。対応するライブラリで以下のキーワードをチェックできます。

**`OrmLite`** 以下のキーワードでソースコードを検索します。

- `import com.j256.*`
- `import com.j256.dao`
- `import com.j256.db`
- `import com.j256.stmt`
- `import com.j256.table\`

ログ記録が無効になっていることを確認してください。

**`SugarORM`** 以下のキーワードでソースコードを検索します。

- `import com.github.satyan`
- `extends SugarRecord<Type>`
- AndroidManifest には、`DATABASE`, `VERSION`, `QUERY_LOG`, `DOMAIN_PACKAGE_NAME` などの値を持つ `meta-data` エントリがあるかもしれません。

`QUERY_LOG` が false に設定されていることを確認します。

**`GreenDAO`** 以下のキーワードでソースコードを検索します。

- `import org.greenrobot.greendao.annotation.Convert`
- `import org.greenrobot.greendao.annotation.Entity`
- `import org.greenrobot.greendao.annotation.Generated`
- `import org.greenrobot.greendao.annotation.Id`
- `import org.greenrobot.greendao.annotation.Index`
- `import org.greenrobot.greendao.annotation.NotNull`
- `import org.greenrobot.greendao.annotation.*`
- `import org.greenrobot.greendao.database.Database`
- `import org.greenrobot.greendao.query.Query`

**`ActiveAndroid`** 以下のキーワードでソースコードを検索します。

- `ActiveAndroid.initialize(<contextReference>);`
- `import com.activeandroid.Configuration`
- `import com.activeandroid.query.*`

**`Realm`** 以下のキーワードでソースコードを検索します。

- `import io.realm.RealmObject;`
- `import io.realm.annotations.PrimaryKey;`

### Parcelable

機密情報が Parcelable を含む Bundle を介して Intent に格納されている場合は、適切なセキュリティ対策が講じられていることを確認します。アプリケーションレベルの IPC を使用する場合は、明示的な Intent を使用し、適切な追加のセキュリティコントロール (署名検証、インテントパーミッション、暗号化など) を検証します。

## 動的解析

動的解析を実施するにはいくつかの方法があります。

1. 実際の永続化には: データストレージの章で説明されている技法を使用します。
2. リフレクションベースのアプローチでは: [Frida for Android](../../../tools/android/MASTG-TOOL-0001.md) を使用して、逆シリアル化メソッドをフックするか、シリアライズされたオブジェクトに処理不可能な情報を追加して、オブジェクトがどのように処理されるか (アプリケーションがクラッシュするかどうか、オブジェクトをエンリッチすることで追加の情報を抽出できるかどうかなど) を確認します。
