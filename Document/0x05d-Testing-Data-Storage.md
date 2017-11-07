## データストレージのテスト (Android)

ユーザー資格情報やプライバシー情報などの機密データを保護することはモバイルセキュリティの重要な焦点です。この章では、Android がローカルデータストレージ用に提供する API と、それらの API を使用するためのベストプラクティスについて学びます。

「機密データ」はそれぞれ特定のアプリのコンテキストで識別する必要があることに注意します。データの分類については「テストプロセスと技法」の章で詳しく説明しています。

### 機密データのテスト (ローカルストレージ)

#### 概要

通念として、永続的なローカルストレージには可能な限り機密データを保存しないことを推奨しています。しかし、ほとんどの実際のシナリオでは、少なくともいくつかのタイプのユーザー関連データを格納する必要があります。例えば、アプリを起動するごとに非常に複雑なパスワードを入力するようにユーザーに依頼することは、ユーザビリティの観点からよい考えとはいえません。その結果、ほとんどのアプリではある種のセッショントークンをローカルにキャッシュする必要があります。個人識別情報などの他の種類の機密データも、特定のシナリオで必要とされる場合には保存されることもあります。

機密データがアプリにより適切に保護されていない場合に永続的にそれを格納すると脆弱性が発生します。デバイスのローカルや外部 SD カードなどのさまざまな場所にアプリは機密データを格納する可能性があります。この種の問題を悪用しようとする場合には、さまざまな場所に処理および格納された多くの情報がある可能性を考慮します。重要なのは、どのような種類の情報がそのモバイルアプリケーションにより処理されユーザーにより入力されるか、また、何が攻撃者にとって興味深く価値のあるものであるか (パスワード、クレジットカード情報、PII など) を最初から特定することです。

機密情報を開示することによる結果はさまざまです。例えば暗号鍵の開示は攻撃者により使用され情報を解読されます。より一般的に言えば、攻撃者はこの情報を特定して、他の攻撃の基礎として使用できます。例えば、ソーシャルエンジニアリング (PII が開示されている場合) 、セッションハイジャック (セッション情報やトークンが開示されている場合) があります。また、支払オプションを持つアプリから情報を収集して、それを攻撃および悪用することもあります。

データの格納 <sup>[1]</sup> は多くのモバイルアプリケーションで不可欠です。例えば、ユーザー設定やユーザーが入力したデータを記録するために、ローカルやオフラインで保存する必要があります。データはさまざまな方法で永続的に格納されます。以下のリストは Android プラットフォームで利用可能なこれらのメカニズムを示しています。

* Shared Preferences
* 内部ストレージ
* 外部ストレージ
* SQLite データベース

以下のコードスニペットは機密情報を開示するバッドプラクティスを示していますが、Android のさまざまなストレージメカニズムも詳細に示しています。

##### Shared Preferences

SharedPreferences <sup>[2]</sup> は XML 構造を使用してキー/値のペアをファイルシステムに永続的に格納する一般的なアプローチです。アクティビティ内では、以下のコードを使用してユーザー名やパスワードなどの機密情報を格納できます。

```java
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

アクティビティが呼ばれると、ファイル key.xml が提供されたデータで作成されます。このコードはいくつかのベストプラクティスに違反しています。

* ユーザー名とパスワードが平文で `/data/data/<PackageName>/shared_prefs/key.xml` に格納されています

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
```

* `MODE_WORLD_READABLE` はすべてのアプリケーションが `key.xml` のコンテンツにアクセスおよび読むことを許可します

```bash
root@hermes:/data/data/sg.vp.owasp_mobile.myfirstapp/shared_prefs # ls -la
-rw-rw-r-- u0_a118 u0_a118    170 2016-04-23 16:51 key.xml
```

> `MODE_WORLD_READABLE` および `MODE_WORLD_WRITEABLE` は API 17 で廃止されたことに注意してください。これは新しいデバイスには影響しませんが、Android 4.2 (`JELLY_BEAN_MR1`) より前の OS で動作する場合、android:targetSdkVersion が 17 より前の設定でコンパイルされたアプリケーションは依然として影響を受ける可能性があります。


##### SQLite データベース (暗号化なし)

SQLite は `.db` ファイルにデータを格納する SQL データベースです。Android SDK には SQLite データベースのサポートが組み込まれています。データベースを管理する主なパッケージは `android.database.sqlite` です。
アクティビティ内では、以下のコードを使用してユーザー名やパスワードなどの機密情報を格納できます。

```java
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure",MODE_PRIVATE,null);
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

アクティビティが呼び出されると、データベースファイル `privateNotSoSecure` が提供されたデータで作成され、`/data/data/<PackageName>/databases/privateNotSoSecure` に平文で格納されます。

databases ディレクトリには SQLite データベースのほかにいくつかのファイルがある可能性があります。

* ジャーナルファイル: これらは SQLite のアトミックコミットとロールバック機能を実装するために使用される一時ファイルです <sup>[3]</sup> 。
* ロックファイル: ロックファイルは SQLite の同時並行性を向上させ、writer starvation 問題を低減するために設計されたロックとジャーナルのメカニズムの一部です <sup>[4]</sup> 。

暗号化なしの SQLite データベースを機密情報の格納に使用すべきではありません。

##### SQLite データベース (暗号化あり)

ライブラリ SQLCipher <sup>[5]</sup> を使用すると、パスワードを提供することで SQLite データベースが暗号化できます。

```java
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
secureDB.close();

```

暗号化ありの SQLite データベースを使用する場合、パスワードがソースにハードコードされているかどうか、shared preferences に格納されているか、コードやファイルシステムのどこかに隠されているかどうかを確認します。
キーを取得するセキュアなアプローチは、ローカルに格納するのではなく、次のいずれかになります。

* アプリを開く際、毎回ユーザーに PIN やパスワードを問い合わせ、データベースを復号します (弱いパスワードや PIN はブルートフォース攻撃を受けやすくなります)
* サーバーにキーを格納し、Web サービス経由でアクセス可能にします (アプリはデバイスがオンラインの場合のみ使用できます)

##### 内部ストレージ

ファイルはデバイスの内部ストレージ <sup>[6]</sup> に直接保存できます。デフォルトでは、内部ストレージに保存されたファイルはアプリケーション専用であり、他のアプリケーションはアクセスできません。ユーザーがアプリケーションをアンインストールすると、これらのファイルは削除されます。
アクティビティ内で、以下のコードを使用して、変数 test の機密情報を内部ストレージに永続的に格納できます。

```java
FileOutputStream fos = null;
try {
   fos = openFileOutput(FILENAME, Context.MODE_PRIVATE);
   fos.write(test.getBytes());
   fos.close();
} catch (FileNotFoundException e) {
   e.printStackTrace();
} catch (IOException e) {
   e.printStackTrace();
}
```

ファイルモードをチェックする必要があります。`MODE_PRIVATE` を使用して、そのアプリ自身のみがファイルにアクセスできることを確認します。`MODE_WORLD_READABLE` (非推奨) や  `MODE_WORLD_WRITEABLE` (非推奨) などの他のモードはとても緩く、セキュリティリスクを引き起こす可能性があります。

クラス `FileInputStream` を検索して、どのファイルがアプリ内で読み込まれているかもチェックすべきです。内部ストレージメカニズムの一部にはキャッシュストレージもあります。一時的にデータをキャッシュするために、`getCacheDir()` などの関数を使用する可能性があります。

##### 外部ストレージ

すべての Android 互換デバイスは共有外部ストレージ <sup>[7]</sup> をサポートしており、ファイルを保存するために使用できます。これはリムーバブルストレージメディア (SD カードなど) や内部 (非リムーバブル) ストレージがあります。
外部ストレージに保存されたファイルは world-readable であり、ユーザーが変更できます。USB マスストレージを有効にすると、コンピュータ上にファイルを転送できます。
アクティビティ内では、以下のコードを使用して、ファイル `password.txt` の機密情報を外部ストレージに永続的に格納できます。

```java
File file = new File (Environment.getExternalFilesDir(), "password.txt");
String password = "SecretPassword";
FileOutputStream fos;
    fos = new FileOutputStream(file);
    fos.write(password.getBytes());
    fos.close();
```

アクティビティが呼び出されると、提供されたデータでファイルが作成され、データは平文で外部ストレージに格納されます。

アプリケーションフォルダ (`data/data/<packagename>/`) の外に格納されたファイルは、ユーザーがアプリケーションをアンインストールしたときに削除されないことも知っておく価値があります。

##### KeyChain

KeyChain クラス <sup>[10]</sup> は *システムワイドの* 秘密鍵とそれに関連する証明書 (チェーン) を格納および取得するために使用されます。ユーザーは、初めて KeyChain に何かがインポートされた際に、ロック画面の PIN やパスワードが設定されていない場合、資格情報ストレージを保護するためにそれらを設定するように求められます。キーチェーンはシステムワイドであることに注意します。つまり、すべてのアプリケーションが KeyChain に格納されているマテリアルにアクセスできます。

##### KeyStore (AndroidKeyStore)

Android KeyStore <sup>[8]</sup> は (多かれ少なかれ) セキュアな資格情報ストレージの手段を提供します。Android 4.3 以降では、アプリの秘密鍵を格納及び使用するためにパブリック API を提供しています。アプリは秘密鍵・公開鍵のペアを作成して、公開鍵を使用してアプリケーションの秘密を暗号化し、秘密鍵を使用してそれを復号できます。

Android KeyStore に格納された鍵は保護され、ユーザーがアクセスするためには認証が必要とすることが可能です。ユーザーのロック画面の資格情報 (パターン、PIN、パスワード、指紋) が認証に使用されます。

格納された鍵は次の二つのモードのいずれかで動作するように設定できます。

1. ユーザー認証は一定期間の鍵の使用を許可します。このモードのすべての鍵は、ユーザーがデバイスのロックを解除するとすぐに、使用を許可されます。許可が有効である期間は各鍵ごとにカスタマイズできます。このオプションはセキュアロック画面が有効である場合にのみ使用できます。ユーザーがセキュアロック画面を無効にすると、格納されている鍵は完全に無効になります。

2. ユーザー認証はひとつの鍵に関連付けられた特定の暗号化操作を許可します。このモードでは、そのような鍵を含む操作はユーザーにより個別に許可される必要があります。現在、そのような許可の唯一の手段は指紋認証です。

Android KeyStore により提供されるセキュリティのレベルはその実装に依存し、デバイス間で異なります。最新のデバイスのほとんどはハードウェア支援のキーストア実装を提供します。その場合、鍵は Trusted Execution Environment または Secure Element で生成および使用され、オペレーティングシステムは直接アクセスできません。これは暗号鍵自体がルート化デバイスからでも容易には取得できないことを意味します。鍵の `KeyInfo` の一部である `isInsideSecureHardware()` に基づいて、鍵がセキュアなハードウェア内にあるかどうかを確認できます。秘密鍵は通常セキュアなハードウェア内に正しく格納されていますが、共通鍵、hmac 鍵は KeyInfo に従ってセキュアに格納されないデバイスがかなりあります。

ソフトウェアのみの実装では、鍵はユーザーごとの暗号マスターキー <sup>[16]</sup> で暗号化されます。その場合、攻撃者はルート化デバイスのフォルダ <code>/data/misc/keystore/</code> のすべての鍵にアクセスできます。マスターキーはユーザー自身のロック画面 PIN やパスワードを使用して生成されるため、Android KeyStore はデバイスがロックされているときには利用できません <sup>[9]</sup> 。

##### 古い Java-KeyStore
古い Android バージョンには KeyStore はありませんが、JCA (Java Cryptography Architecture) の KeyStore インタフェースを備えています。このインタフェースを実装するさまざまな KeyStore を使用して、キーストア実装に格納される鍵の機密性と完全性の保護を提供できます。その実装はすべてファイルシステムに格納されたファイルであるという事実に依存するため、パスワードによりその内容を保護しています。このため、BounceyCastle KeyStore (BKS) の使用をお勧めします。
`KeyStore.getInstance("BKS", "BC");` を使用してそれを作成できます。"BKS" はキーストア名 (BounceycastleKeyStore) であり、"BC" はプロバイダ (BounceyCastle) です。代わりに SpongeyCastle をラッパーとして使用し、キーストアを初期化することもできます: `KeyStore.getInstance("BKS", "SC");` 。

すべての KeyStore がキーストアファイルに格納された鍵の適切な保護を提供するわけではないことに気をつけます。



#### 静的解析

##### ローカルストレージ

既に示したように、Android 内に情報を格納するにはいくつかの方法があります。従って、いくつかのチェックをソースコードに適用して、Android アプリ内で使用されるストレージメカニズムを特定し、機密データが非セキュアにしょりされていないかどうかを確認します。

* 外部ストレージの読み書きのためのパーミッションについて `AndroidManifest.xml` をチェックする。`uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"` など。
* データの格納に使用される関数および API 呼び出しについてソースコードをチェックする。
  * 任意の IDE やテキストエディタで Java ファイルを開くか、コマンドラインで grep を使用して検索する。
    * ファイルパーミッション
      * `MODE_WORLD_READABLE` や `MODE_WORLD_WRITABLE` 。IPC ファイルはアプリのプライベートデータディレクトリに格納されていても、任意のアプリがそのファイルを読み書きする必要がなければ、`MODE_WORLD_READABLE` や `MODE_WORLD_WRITABLE` のパーミッションで作成するべきではありません。
    * クラスおよび関数
      * `SharedPreferences` クラス (キーバリューペアのストレージ)
      * `FileOutPutStream` クラス (内部または外部ストレージの使用)
      * `getExternal*` 関数 (外部ストレージの使用)
      * `getWritableDatabase` 関数 (書き込み用の SQLiteDatabase を戻す)
      * `getReadableDatabase` 関数 (読み取り用の SQLiteDatabase を戻す)
      * `getCacheDir` および `getExternalCacheDirs` 関数 (キャッシュファイルの使用)

暗号化操作は SDK により提供される実証済み機能に依存すべきです。以下では、ソースコードでチェックする必要があるさまざまな「バッドプラクティス」について説明します。

* 単純なビット操作が使用されているかどうかを確認します。XOR やビットフリップなどでローカルに格納される資格情報や秘密鍵などの機密情報を「暗号化」します。これはデータを容易に復元できるため避けるべきです。
* Android KeyStore <sup>[8]</sup> などの Android オンボード機能を利用せずに鍵を生成または使用されているかどうかを確認します。
* 鍵が開示されているかどうかを確認します。

###### よくある間違い: ハードコードされた暗号鍵

ハードコードされた暗号鍵や誰にでも読み取り可能な暗号鍵を使用すると、暗号化されたデータを復元される可能性が大幅に高まります。攻撃者がそれを取得すると、機密データを復号する作業は簡単になり、機密性を保護するという当初の考えは失敗します。

対称暗号を使用する場合、鍵はデバイス内に格納する必要があり、攻撃者がそれを特定するのは時間と労力だけの問題です。

次のシナリオを考えます。あるアプリケーションは暗号化されたデータベースを読み書きしますが、復号化はハードコードされた鍵に基づいて行われます。

```Java
this.db = localUserSecretStore.getWritableDatabase("SuperPassword123");
```

鍵はすべてのアプリインストールで同じであるため、取得することは簡単です。機密データを暗号化する利点は無くなり、このような方法で暗号化を使用することで得られるものは実際にはありません。同様に、ハードコードされた API 鍵や秘密鍵およびその他の価値のある部品を探します。エンコードや暗号化された鍵はさらなる試みであり、王冠の宝石を手に入れることは困難ですが不可能ではありません。

このコードを考えて見ましょう。

```Java
//A more complicated effort to store the XOR'ed halves of a key (instead of the key itself)
private static final String[] myCompositeKey = new String[]{
  "oNQavjbaNNSgEqoCkT9Em4imeQQ=","3o8eFOX4ri/F8fgHgiy/BS47"
};
```

このケースでの元の鍵を解読するためのアルゴリズムは以下のようになります <sup>[1]</sup> 。

```Java
public void useXorStringHiding(String myHiddenMessage) {
  byte[] xorParts0 = Base64.decode(myCompositeKey[0],0);
  byte[] xorParts1 = Base64.decode(myCompositeKey[1],0);

  byte[] xorKey = new byte[xorParts0.length];
  for(int i = 0; i < xorParts1.length; i++){
    xorKey[i] = (byte) (xorParts0[i] ^ xorParts1[i]);
  }
  HidingUtil.doHiding(myHiddenMessage.getBytes(), xorKey, false);
}
```

秘密が通常隠されている一般的な場所を確認します。
* resources (通常は res/values/strings.xml にあります)

例:
```xml
<resources>
    <string name="app_name">SuperApp</string>
    <string name="hello_world">Hello world!</string>
    <string name="action_settings">Settings</string>
    <string name="secret_key">My_S3cr3t_K3Y</string>
  </resources>
```

* build configs, local.properties や gradle.properties などにあります

例:
```
buildTypes {
  debug {
    minifyEnabled true
    buildConfigField "String", "hiddenPassword", "\"${hiddenPassword}\""
  }
}
```

* shared preferences, 通常は /data/data/package_name/shared_prefs にあります

##### KeyChain および Android KeyStore

ソースコードを調べる際は、Android により提供されるネイティブメカニズムが識別された機密情報に適用されているかどうかを解析する必要があります。機密情報は平文で格納してはいけません。暗号化する必要があります。機密情報をデバイス自体に格納する必要がある場合には、いくつかの API 呼び出しを利用できます。**KeyChain <sup>[10]</sup>** や **Android Keystore <sup>[8]</sup>** を使用して Android デバイス上のデータを保護します。従って、以下のコントロールを使用する必要があります。

* クラス `KeyPairGenerator` を探して、アプリ内で鍵ペアが作成されているかどうかを確認します。
* アプリケーションが Android KeyStore や Cipher メカニズムを使用して、暗号化された情報をデバイス上にセキュアに格納していることを確認します。パターン `import java.security.KeyStore`, `import javax.crypto.Cipher`, `import java.security.SecureRandom` および対応する使用法を探します。
* `store(OutputStream stream, char[] password)` 関数を使用して、指定されたパスワードでディスクに KeyStore を格納できます。提供されるパスワードはハードコードされておらず、ユーザー入力により定義され、ユーザーだけが知っているものであることを確認します。パターン `.store(` を探します。

#### 動的解析

アプリをインストールして、それが意図したとおりに使用します。すべての機能を少なくとも一回は実行します。データが生成されるのは、ユーザーが入力したとき、エンドポイントにより送信されたとき、またはインストール時にアプリ内にすでに同梱されています。それから以下の項目を確認します。

* `/data/data/<package_name>/` にインストールされたモバイルアプリケーションに同梱されているファイルを確認し、製品リリースにはないはずの開発、バックアップ、または単に古いファイルを特定します。
* SQLite データベースが利用可能であるかどうか、およびそれらに機密情報 (ユーザー名、パスワード、鍵など) が含まれているかどうかを確認します。SQLite データベースは `/data/data/<package_name>/databases` に格納されます。
* 機密情報について、アプリの shared_prefs ディレクトリに XML ファイルとして格納されている Shared Preferences を確認します。`/data/data/<package_nam>/shared_prefs` にあります。
* `/data/data/<package_name>` にあるファイルのファイルシステム権限を確認します。アプリをインストールした際に作成されるユーザーおよびグループ (u0_a82 など) のみがユーザー権限の読み取り、書き込み、実行 (rwx) を持つ必要があります。他の人はファイルへの権限を持たないはずですが、ディレクトリに対して実行可能フラグを持つ可能性があります。

#### 改善方法

データを保存する際の約束事は次のように非常に簡単に要約できます。パブリックデータは誰でも利用可能とすべきですが、機密およびプライベートのデータは保護する必要がありますし、そもそもデバイスに格納しないほうがさらに良いです。

機密情報 (資格情報、鍵、PII など) はデバイス上でローカルに必要である場合、セキュアにデータを格納するために使用されるベストプラクティスは Android により提供されます。そうでなければ、車輪を再発明するか、デバイスに暗号化されていないデータをが残ります。

以下は、証明書、鍵、機密データのセキュアストレージに一般的に使用されるベストプラクティスのリストです。

* 自己実装された暗号化または復号化機能は避ける必要があります。代わりに Cipher <sup>[11]</sup>, SecureRandom <sup>[12]</sup>, KeyGenerator <sup>[13]</sup> などの Android 実装を使用します。
* ユーザー名とパスワードはデバイスに格納すべきではありません。代わりに、ユーザーが入力したユーザー名とパスワードを使用して初期認証を行い、短期間でサービス固有の認証トークン (セッショントークン) を使用します。可能であれば、AccountManager <sup>[14]</sup> クラスを使用してクラウドベースサービスを呼び出し、デバイスにパスワードを格納しません。
* ファイルに対して `MODE_WORLD_WRITEABLE` または `MODE_WORLD_READABLE` の使用は通常避けるべきです。他のアプリケーションとデータを共有する必要がある場合には、コンテンツプロバイダを検討すべきです。コンテンツプロバイダは他のアプリに読み取りおよび書き込みパーミッションを提供し、ケースバイケースベースで動的にパーミッションを割り当てることができます。
* データを保護できない Shared Preferences またはその他のメカニズムの使用は機密情報を格納するには避けるべきです。SharedPreferences はセキュアではなく、デフォルトで暗号化されません。Secure-preferences <sup>[15]</sup> は Shared Preferences 内に格納される値を暗号化するために使用できますが、セキュアにデータを格納するための最初の選択肢は Android Keystore です。
* 機密データ用に外部ストレージを使用してはいけません。デフォルトでは、内部ストレージに保存されるファイルはあなたのアプリケーションのプライベートであり、他のアプリケーションはそれらにアクセスできません (そのユーザーもアクセスできません) 。ユーザーがアプリケーションをアンインストールすると、これらのファイルも削除されます。
* 機密データを更に保護するために、アプリケーションが直接アクセスできない鍵を使用してローカルファイルを暗号化することを選択できます。例えば、鍵を KeyStore に配置し、デバイスに格納されていないユーザーパスワードで保護できます。これはユーザーがパスワードを入力することを監視するルートの侵害からデータを保護するものではありませんが、ファイルシステムの暗号化なしに紛失したデバイスの保護を提供できます。
* 機密情報を使用し終えた変数に null を設定します。
* 機密データに immutable オブジェクトを使用することで、変更できなくなります。
* セキュリティの多層対策として、コードの難読化もアプリに適用し、攻撃者のリバースエンジニアリングを困難にします。


#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage
* M2 - 安全でないデータストレージ - https://www.owasp.org/index.php/Mobile_Top_10_2016-M2-Insecure_Data_Storage

##### OWASP MASVS

* V2.1: "ユーザー資格情報や暗号化鍵などの機密データを格納するために、システムの資格情報保存機能が適切に使用されている。"

##### CWE
* CWE-311 - Missing Encryption of Sensitive Data
* CWE-312 - Cleartext Storage of Sensitive Information
* CWE-522 - Insufficiently Protected Credentials
* CWE-922 - Insecure Storage of Sensitive Information

##### その他

[1] Security Tips for Storing Data - http://developer.android.com/training/articles/security-tips.html#StoringData
[2] SharedPreferences - http://developer.android.com/reference/android/content/SharedPreferences.html
[3] SQLite Journal files - https://www.sqlite.org/tempfiles.html
[4] SQLite Lock Files - https://www.sqlite.org/lockingv3.html
[5] SQLCipher - https://www.zetetic.net/sqlcipher/sqlcipher-for-android/
[6] Using Internal Storage -  http://developer.android.com/guide/topics/data/data-storage.html#filesInternal
[7] Using External Storage - https://developer.android.com/guide/topics/data/data-storage.html#filesExternal
[8] Android KeyStore System -  http://developer.android.com/training/articles/keystore.html
[9] Use Android Keystore - http://www.androidauthority.com/use-android-keystore-store-passwords-sensitive-information-623779/
[10] Android KeyChain -  http://developer.android.com/reference/android/security/KeyChain.html
[11] Cipher - https://developer.android.com/reference/javax/crypto/Cipher.html
[12] SecureRandom - https://developer.android.com/reference/java/security/SecureRandom.html
[13]KeyGenerator - https://developer.android.com/reference/javax/crypto/KeyGenerator.html
[14] AccountManager -  https://developer.android.com/reference/android/accounts/AccountManager.html
[15] Secure Preferences - https://github.com/scottyab/secure-preferences
[16] Nikolay Elenvok - Credential storage enhancements in Android 4.3 - https://nelenkov.blogspot.sg/2013/08/credential-storage-enhancements-android-43.html


##### ツール

* Enjarify - https://github.com/google/enjarify
* JADX - https://github.com/skylot/jadx
* Dex2jar - https://github.com/pxb1988/dex2jar
* Lint - http://developer.android.com/tools/help/lint.html
* Sqlite3 - http://www.sqlite.org/cli.html



### 機密データのテスト (ログ)

#### 概要

モバイルデバイス上にログファイルを作成する正当な理由は数多くあります。例えば、クラッシュやエラーを追跡したり、単に使用統計を記録したりするなどです。ログファイルはオフライン時にはローカルに格納され、再びオンラインになるとエンドポイントに送信されます。しかし、ユーザー名やセッション ID などの機密情報をログ出力すると、攻撃者や悪意のあるアプリケーションにデータを公開され、データの機密性を失う可能性があります。
ログファイルはさまざまな方法で作成できます。以下のリストは Android で利用可能なメカニズムを示しています。

* Log クラス <sup>[1]</sup>
* Logger クラス
* System.out/System.err.print

#### 静的解析

ソースコードにいくつかのチェックを適用して、Android アプリ内で使用されているログ出力メカニズムを特定する必要があります。これは機密データが非セキュアに処理されているかどうかを特定します。
ソースコードはAndroid アプリ内で使用されているログ出力メカニズムをチェックする必要があります。以下のものを検索します。

1. 関数及びクラス
  * `android.util.Log`
  * `Log.d` | `Log.e` | `Log.i` | `Log.v` | `Log.w` | `Log.wtf`
  * `Logger`
  * `System.out.print` | `System.err.print`

2. 非標準のログメカニズムを特定するためのキーワードとシステム出力
  * logfile
  * logging
  * logs

#### 動的解析

モバイルアプリを広範囲に使用し、すべての機能が少なくとも一度は起動されるようにします。その後、アプリケーションのデータディレクトリを特定し、ログファイルを探します (`/data/data/package_name`) 。アプリケーションログを確認してログデータが生成されているかどうかをチェックします。一部のモバイルアプリケーションはデータディレクトリに独自のログを作成および格納します。

多くのアプリケーション開発者は適切なログ出力クラスの代わりに `System.out.println()` や `printStackTrace()` をいまだに使用しています。したがって、テストアプローチではアプリケーションの起動、実行、終了時にアプリケーションにより生成されるすべての出力をカバーする必要もあります。`System.out.println()` や `printStackTrace()` を使用して直接出力されるデータを確認するために、ツール `LogCat` <sup>[2]</sup> を使用してアプリの出力をチェックできます。LogCat を実行するには二つの異なるアプローチが利用可能です。
  * LogCat はすでに _Dalvik Debug Monitor Server_ (DDMS) の一部であり、Android Studio に組み込まれています。アプリがデバッグモードで実行されている場合、ログ出力は Android Monitor の LogCat タブに表示されます。LogCat にパターンを定義して、アプリのログ出力をフィルタできます。

![Log output in Android Studio](Images/Chapters/0x05d/log_output_Android_Studio.png)

  * adb を使用して LogCat を実行して、ログ出力を永続的に格納できます。

```bash
$ adb logcat > logcat.log
```

#### 改善方法

一元的なログ出力クラスとメカニズムが使用され、プロダクションリリースからログ出力ステートメントが削除されていることを確認します。ログは他のアプリケーションにより傍受や読み取りが可能です。Android Studio に既に含まれている `ProGuard` などのツールを使用して、プロダクションリリースを準備する際にコード内のログ出力部分を取り除くことができます。例えば、クラス `android.util.Log` で実行されたログ出力呼び出しを削除するには、ProGuard の _proguard-project.txt_ 設定ファイルに以下のオプションを追加するだけです。

```java
-assumenosideeffects class android.util.Log
{
public static boolean isLoggable(java.lang.String, int);
public static int v(...);
public static int i(...);
public static int w(...);
public static int d(...);
public static int e(...);
public static int wtf(...);
}
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage
* M2 - 安全でないデータストレージ - https://www.owasp.org/index.php/Mobile_Top_10_2016-M2-Insecure_Data_Storage

##### OWASP MASVS
* V2.2: "機密データがアプリケーションログに書き込まれていない。"

##### CWE
* CWE-117: Improper Output Neutralization for Logs
* CWE-532: Information Exposure Through Log Files
* CWE-534: Information Exposure Through Debug Log Files

##### その他
* [1] Overview of Class Log - http://developer.android.com/reference/android/util/Log.html
* [2] Debugging Logs with LogCat - http://developer.android.com/tools/debugging/debugging-log.html

##### ツール
* ProGuard - http://proguard.sourceforge.net/
* LogCat - http://developer.android.com/tools/help/logcat.html


### 機密データが第三者に送信されているかどうかのテスト

#### 概要

アプリに組み込むことでさまざまな機能を実装できるさまざまなサードパーティサービスが利用できます。これらの機能はトラッカーサービスやアプリ内のユーザー行動の監視、販売バナー広告、より良いユーザーエクスペリエンスの作成などさまざまです。これらのサービスとのやり取りは、機能の独自実装や車輪の再発明といった複雑さと必要性を抽象化します。

欠点は、サードパーティライブラリを介してどのようなコードが実行されているかを開発者が詳細に把握せず、したがって可視性をあきらめることです。そのため、必要以上の情報がサービスに送信されていないこと、および機密情報が開示されていないことを確認する必要があります。

サードパーティサービスは主に二つの方法で実装されます。
* スタンドアローンのライブラリを使用する。Android プロジェクトの Jar など。APK に組み込まれる。
* フル SDK を使用する。

#### 静的解析

一部のサードパーティライブラリは IDE 内のウィザードを使用してアプリに自動的に統合できます。IDE ウィザードを使用してライブラリをインストールする場合には、`AndroidManifest.xml` に設定されたパーミッションを確認する必要があります。特に、SMS (`READ_SMS`), 連絡先 (`READ_CONTACTS`), 位置情報 (`ACCESS_FINE_LOCATION`) にアクセスするためのパーミッションは、ライブラリが真に最小限で機能するために本当に必要であるかどうか、説明を求めるべきです。「アプリパーミッションのテスト」も参照します。開発者と話す際には、IDE を使用してライブラリをインストールする前と後でプロジェクトソースコードの相違点を確認し、コードベースにどのような変更が加えられたかを確認する必要があります。

ライブラリまたは SDK を手動で追加する場合にも同じことが適用されます。サードパーティライブラリや SDK により提供される API 呼び出しや関数についてソースコードをチェックする必要があります。適用されるコード変更をレビューし、ライブラリや SDK の利用可能なセキュリティベストプラクティスが適用および使用されているかどうかをチェックする必要があります。

プロジェクトにロードされたライブラリをレビューし、開発者と共にそれらが必要であるかと確認します。また、古くなり既知の脆弱性を含むかどうかも確認します。

#### 動的解析

外部サービスに対するすべてのリクエストについて、機密情報が埋め込まれているかどうかを解析する必要があります。動的解析は中間者 (MITM) 攻撃を開始することにより実行できます。_Burp Proxy_ <sup>[1]</sup> や _OWASP ZAP_ を使用し、クライアントとサーバーとの間で交換されるトラフィックを傍受します。傍受プロキシにトラフィックをルーティングできるようになると、アプリからサーバーへおよびその反対のトラフィックを盗聴することができます。アプリを使用する場合には、メイン機能がホストされているサーバーに直接接続されていないすべてのリクエストについて、機密情報がサードパーティに送信されているかどうかを確認する必要があります。これには例えば、トラッカーや広告サービスでの PII (個人識別情報) があります。

#### 改善方法

サードパーティサービスに送信されるすべてのデータは匿名化されるべきです。そのため PII データは利用できません。また、ユーザーアカウントやセッションにマップできるアプリケーションの ID などの他のすべてのデータをサードパーティに送信すべきではありません。
`AndroidManifest.xml` には正しく動作するために必要なパーミッションだけを含む必要があります。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage
* M2 - 安全でないデータストレージ - https://www.owasp.org/index.php/Mobile_Top_10_2016-M2-Insecure_Data_Storage

##### OWASP MASVS
- V2.3: "機密データはアーキテクチャに必要な部分でない限りサードパーティと共有されていない。"

##### CWE
- CWE-359 - Exposure of Private Information ('Privacy Violation')

##### その他
[1] Configure Burp with Android - https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
[2] Bulletproof Android, Godfrey Nolan - Chapter 7, Third-Party Library Integration

##### ツール
* Burp Suite Professional - https://portswigger.net/burp/
* OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project


### テキスト入力フィールドでキーボードキャッシュが無効かどうかのテスト

#### 概要

入力フィールドにデータを入力すると、ソフトウェアキーボードはユーザーがキー入力したいデータを自動的に提示します。この機能はメッセージングアプリで非常に役に立ち、テキストメッセージを非常に効率的に書くことができます。クレジットカードデータなどの機密情報を要求する入力フィールドでは、その入力フィールドが選択された際にキーボードキャッシュが既存の機密情報を開示する可能性があります。したがって、機密情報を要求する入力フィールドではこの機能を無効にする必要があります。

#### 静的解析

アクティビティのレイアウト定義では、XML 属性を持つ TextView を定義できます。XML 属性 `android:inputType` に定数 `textNoSuggestions` を設定すると、その入力フィールドを選択した際にキーボードキャッシュは表示されません。キーボードだけが表示され、ユーザーは手動ですべてを入力する必要があり、何も提示されません。

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions"/>
```


#### 動的解析

アプリを起動し、機密データを要求する入力フィールドをクリックします。文字列が提示される場合、この入力フィールドでキーボードキャッシュは無効ではありません。

#### 改善方法

機密情報を要求するすべての入力フィールドでは、以下の XML 属性を実装し、キーボードの提示を無効にする必要があります <sup>[1]</sup> 。

```xml
android:inputType="textNoSuggestions"
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage
* M2 - 安全でないデータストレージ - https://www.owasp.org/index.php/Mobile_Top_10_2016-M2-Insecure_Data_Storage

##### OWASP MASVS
- V2.4: "機密データを処理するテキスト入力では、キーボードキャッシュが無効にされている。"

##### CWE
- CWE-524 - Information Exposure Through Caching

##### その他
[1] No suggestions for text - https://developer.android.com/reference/android/text/InputType.html#TYPE_TEXT_FLAG_NO_SUGGESTIONS


### 機密データのテスト (クリップボード)

#### 概要

入力フィールドにデータを入力する際に、clipboard <sup>[1]</sup> を使用してデータをコピーできます。クリップボードはシステム全体でアクセスできるため、アプリ間で共有されます。この機能を悪用して、悪意のあるアプリが機密データを取得できる可能性があります。


#### 静的解析

機密情報を要求する入力フィールドを特定し、クリップボードの表示を抑制するための対策が適切にされているかどうかを調査する必要があります。適用可能なコードスニペットについては改善方法のセクションを参照ください。

#### 動的解析

アプリを起動し、機密データを要求する入力フィールドをクリックします。データをコピー、ペーストするためのメニューを取得可能である場合、この入力フィールドに対して機能は無効ではありません。

クリップボードに格納されたデータを抽出するには、Drozer モジュール `post.capture.clipboard` を使用できます。

```
dz> run post.capture.clipboard
[*] Clipboard value: ClipData.Item { T:Secretmessage }
```

#### 改善方法

一般的なベストプラクティスは入力フィールドのさまざまな機能を上書きして、クリップボードを明確に無効にすることです。

```Java
EditText  etxt = (EditText) findViewById(R.id.editText1);
etxt.setCustomSelectionActionModeCallback(new Callback() {

            public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                return false;
            }
0
            public void onDestroyActionMode(ActionMode mode) {                  
            }

            public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                return false;
            }

            public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                return false;
            }
        });
```

また、入力フィールドに対して `longclickable` を無効にする必要があります。

```xml
android:longClickable="false"
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.5: "機密データを含む可能性があるテキストフィールドでは、クリップボードが無効化されている。"

##### CWE
* CWE-200 - Information Exposure

##### その他
[1] Copy and Paste in Android - https://developer.android.com/guide/topics/text/copy-paste.html

##### ツール
* Drozer - https://labs.mwrinfosecurity.com/tools/drozer/



### 機密データがIPCメカニズムを介して開示されているかどうかのテスト

#### 概要

モバイルアプリケーションの開発では、共有ファイルやネットワークソケットの使用など IPC に関する従来の技術が適用される可能性があります。モバイルアプリケーションプラットフォームは IPC について独自のシステム機能を実装しているため、旧来の技術よりもはるかに成熟しているこれらのメカニズムを適用すべきです。セキュリティを考慮せずに IPC メカニズムを使用すると、アプリケーションは機密データの漏洩や開示を引き起こす可能性があります。

以下は機密データを開示する可能性のある Android IPC メカニズムのリストです。
* Binders <sup>[1]</sup>
* Services <sup>[2]</sup>
  * Bound Services <sup>[9]</sup>
  * AIDL <sup>[10]</sup>
* Intents <sup>[3]</sup>
* Content Providers <sup>[4]</sup>

#### 静的解析

最初のステップは `AndroidManifest.xml` を調べて、アプリにより開示されている IPC メカニズムを検出及び特定することです。以下のような要素を特定したいと思うでしょう。

* `<intent-filter>`<sup>[5]</sup>
* `<service>`<sup>[6]</sup>
* `<provider>`<sup>[7]</sup>
* `<receiver>`<sup>[8]</sup>

`<intent-filter>` 要素を除いて、前述の要素に以下の属性が含まれているかどうか確認します。
* `android:exported`
* `android:permission`

IPC メカニズムの一覧を特定したら、ソースコードをレビューして、使用時に機密データが漏洩しているかどうかを検出します。例えば、_ContentProviders_ を使用してデータベース情報にアクセスできます。サービスがプローブされてデータを返すかどうかを調べます。また、BroadcastReceiver と Broadcast インテントはプローブや盗聴された場合に機密情報を漏洩する可能性があります。

**脆弱な ContentProvider**

脆弱な _ContentProvider_ の例:
(and SQL injection **-- TODO [Refer to any input validation test in the project] --**

```xml
<provider android:name=".CredentialProvider"
          android:authorities="com.owaspomtg.vulnapp.provider.CredentialProvider"
          android:exported="true">
</provider>
```

上述の `AndroidManifest.xml` にあるように、アプリケーションはコンテンツプロバイダをエクスポートしています。
`CredentialProvider.java` ファイルでは `query` 関数を検査して、機密情報を漏洩しているかどうかを検出する必要があります。

```java
public Cursor query(Uri uri, String[] projection, String selection,
			String[] selectionArgs, String sortOrder) {
		 SQLiteQueryBuilder queryBuilder = new SQLiteQueryBuilder();
		 // the TABLE_NAME to query on
		 queryBuilder.setTables(TABLE_NAME);
	      switch (uriMatcher.match(uri)) {
	      // maps all database column names
	      case CREDENTIALS:
	    	  queryBuilder.setProjectionMap(CredMap);
	         break;
	      case CREDENTIALS_ID:
	    	  queryBuilder.appendWhere( ID + "=" + uri.getLastPathSegment());
	         break;
	      default:
	         throw new IllegalArgumentException("Unknown URI " + uri);
	      }
	      if (sortOrder == null || sortOrder == ""){
	         sortOrder = USERNAME;
	      }
	     Cursor cursor = queryBuilder.query(database, projection, selection,
	    		  selectionArgs, null, null, sortOrder);
	      cursor.setNotificationUri(getContext().getContentResolver(), uri);
	      return cursor;
	}
```

`content://com.owaspomtg.vulnapp.provider.CredentialProvider/CREDENTIALS` にアクセスすると、query ステートメントはすべての資格情報を返します。


* 脆弱な Broadcast
`sendBroadcast`, `sendOrderedBroadcast`, `sendStickyBroadcast` などの文字列でソースコードを検索し、アプリケーションが機密データを送信していない確認します。

脆弱なブロードキャストの例は以下のとおりです。

```java
private void vulnerableBroadcastFunction() {
    // ...
    Intent VulnIntent = new Intent();
    VulnIntent.setAction("com.owasp.omtg.receiveInfo");
    VulnIntent.putExtra("ApplicationSession", "SESSIONID=A4EBFB8366004B3369044EE985617DF9");
    VulnIntent.putExtra("Username", "litnsarf_omtg");
    VulnIntent.putExtra("Group", "admin");
  }
  this.sendBroadcast(VulnIntent);
```

#### 動的解析

##### コンテンツプロバイダのテスト

アプリケーションのコンテンツプロバイダの動的解析を開始するには、まずアタックサーフェイスを列挙する必要があります。これを実現するためには Drozer モジュール `app.provider.info` を使用します。

```
dz> run app.provider.info -a com.mwr.example.sieve
  Package: com.mwr.example.sieve
  Authority: com.mwr.example.sieve.DBContentProvider
  Read Permission: null
  Write Permission: null
  Content Provider: com.mwr.example.sieve.DBContentProvider
  Multiprocess Allowed: True
  Grant Uri Permissions: False
  Path Permissions:
  Path: /Keys
  Type: PATTERN_LITERAL
  Read Permission: com.mwr.example.sieve.READ_KEYS
  Write Permission: com.mwr.example.sieve.WRITE_KEYS
  Authority: com.mwr.example.sieve.FileBackupProvider
  Read Permission: null
  Write Permission: null
  Content Provider: com.mwr.example.sieve.FileBackupProvider
  Multiprocess Allowed: True
  Grant Uri Permissions: False
```

この例では、二つのコンテンツプロバイダがエクスポートされ、`DBContentProvider` の `/Keys` を除いて、それらとやり取りするためのパーミッションを必要としません。この情報を使用すると、コンテンツ URI の一部を再構築して `DBContentProvider` にアクセスできます。`content://` ではじめる必要があることが知られているためです。しかし、完全なコンテンツプロバイダ URI は現在知られていません。

アプリケーション内のコンテンツプロバイダ URI を特定するには、Drozer の `scanner.provider.finduris` モジュールを使用する必要があります。これはさまざまな技法を利用してパスを推測し、アクセス可能なコンテンツ URI の一覧を決定します。

```
dz> run scanner.provider.finduris -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Unable to Query content://com.mwr.
example.sieve.DBContentProvider/
...
Unable to Query content://com.mwr.example.sieve.DBContentProvider/Keys
Accessible content URIs:
content://com.mwr.example.sieve.DBContentProvider/Keys/
content://com.mwr.example.sieve.DBContentProvider/Passwords
content://com.mwr.example.sieve.DBContentProvider/Passwords/
```

アクセス可能なコンテンツプロバイダの一覧を入手しました。次のステップはそれぞれのプロバイダからデータの抽出を試みることです。実現には `app.provider.query` モジュールを使用します。

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --vertical
_id: 1
service: Email
username: incognitoguy50
password: PSFjqXIMVa5NJFudgDuuLVgJYFD+8w== (Base64
-
encoded)
email: incognitoguy50@gmail.com
```

データのクエリに加えて、Drozer では脆弱なコンテンツプロバイダからレコードの更新、挿入、削除にも使用できます。

* レコードの挿入

```
dz> run app.provider.insert content://com.vulnerable.im/messages
                --string date 1331763850325
                --string type 0
                --integer _id 7
```

* レコードの更新

```
dz> run app.provider.update content://settings/secure
                --selection "name=?"
                --selection-args assisted_gps_enabled
                --integer value 0
```

* レコードの削除

```
dz> run app.provider.delete content://settings/secure
                --selection "name=?"
                --selection-args my_setting
```

##### コンテンツプロバイダでのSQLインジェクション

Android プラットフォームはユーザーデータの格納に SQLite データベースの使用を勧めます。これらのデータベースは SQL を使用するため、SQL インジェクションに脆弱となる可能性があります。Drozer モジュール `app.provider.query` を使用して、SQL インジェクションのテストできます。コンテンツプロバイダに渡される projection と selection フィールドを操作します。

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "'"
unrecognized token: "' FROM Passwords" (code 1): , while compiling: SELECT ' FROM Passwords

dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --selection "'"
unrecognized token: "')" (code 1): , while compiling: SELECT * FROM Passwords WHERE (')
```

SQL インジェクションの脆弱性がある場合、アプリケーションは詳細なエラーメッセージを返します。Android の SQL インジェクションを悪用して、脆弱なコンテンツプロバイダのデータを変更または照会できます。以下の例では、Drozer モジュール `app.provider.query` を使用して、データベースのすべてのテーブルをリストします。

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "*
FROM SQLITE_MASTER WHERE type='table';--"
| type  | name             | tbl_name         | rootpage | sql              |
| table | android_metadata | android_metadata | 3        | CREATE TABLE ... |
| table | Passwords        | Passwords        | 4        | CREATE TABLE ... |
| table | Key              | Key              | 5        | CREATE TABLE ... |
```

SQL インジェクションを悪用して、保護されていないテーブルからデータを取得することもできます。

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM Key;--"
| Password | pin |
| thisismypassword | 9876 |
```

これらのステップを自動化するには `scanner.provider.injection` モジュールを使用できます。アプリ内の脆弱なコンテンツプロバイダを自動的に見つけます。

```
dz> run scanner.provider.injection -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Injection in Projection:
  content://com.mwr.example.sieve.DBContentProvider/Keys/
  content://com.mwr.example.sieve.DBContentProvider/Passwords
  content://com.mwr.example.sieve.DBContentProvider/Passwords/
Injection in Selection:
  content://com.mwr.example.sieve.DBContentProvider/Keys/
  content://com.mwr.example.sieve.DBContentProvider/Passwords
  content://com.mwr.example.sieve.DBContentProvider/Passwords/
```

##### ファイルシステムベースのコンテンツプロバイダ

コンテンツプロバイダは基礎となるファイルシステムへのアクセスを提供できます。これによりアプリはファイルを共有できます。Android サンドボックスはそれを抑制してないでしょう。Drozer モジュール `app.provider.read` および `app.provider.download` を使用して、エクスポートされたファイルベースのコンテンツプロバイダからファイルを読み取りまたはダウンロードできます。これらのコンテンツプロバイダはディレクトリトラバーサルの脆弱性を受けやすく、ターゲットアプリケーションのサンドボックス内の保護されていないファイルを読み取ることが可能となります。

```
dz> run app.provider.download content://com.vulnerable.app.FileProvider/../../../../../../../../data/data/com.vulnerable.app/database.db /home/user/database.db
Written 24488 bytes
```

ディレクトリトラバーサルの影響を受けやすいコンテンツプロバイダを見つけるプロセスを自動化するには、`scanner.provider.traversal` モジュールを使用する必要があります。

```
dz> run scanner.provider.traversal -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Vulnerable Providers:
  content://com.mwr.example.sieve.FileBackupProvider/
  content://com.mwr.example.sieve.FileBackupProvider
```

注釈：`adb` を使用して、デバイスのコンテンツプロバイダを照会することもできます。

```bash
$ adb shell content query --uri content://com.owaspomtg.vulnapp.provider.CredentialProvider/credentials
Row: 0 id=1, username=admin, password=StrongPwd
Row: 1 id=2, username=test, password=test
...
```

##### 脆弱なブロードキャスト

インテントを盗聴するには、デバイス (実際のデバイスまたはエミュレートされたデバイス) にアプリケーションをインストールおよび実行し、Drozer や Intent Sniffer などのツールを使用してインテントやブロードキャストメッセージをキャプチャします。

#### 改善方法

_activity_, _broadcast_, _service_ に対して呼出元のパーミッションはコードまたはマニフェストで確認できます。

完全に要求されていない場合には、IPC が `AndroidManifest.xml` ファイルに `android:exported="true"` の値を持たないことを確認します。そうしないと、Android 上の他のすべてのアプリが通信および呼び出すことができてしまいます。

_intent_ が同じアプリケーションでのみブロードキャストおよび受信される場合には、`LocalBroadcastManager` を使用できます。他のアプリがブロードキャストメッセージを受信できないように設計されています。これにより機密情報が漏洩するリスクを低減します。
`LocalBroadcastManager.sendBroadcast().BroadcastReceivers` は `android:permission` 属性を使用する必要があります。そうしないと、他のアプリケーションがそれらを呼び出すことができてしまいます。`Context.sendBroadcast(intent, receiverPermission);` を使用して、レシーバーが必要とするバーミッションを指定し、ブロードキャストを読むことができます <sup>[11]</sup> 。
明示的なアプリケーションパッケージ名を設定して、このインテントが解決するコンポーネントを制限できます。デフォルト値の null のままにすると、すべてのアプリケーションのすべてのコンポーネントを考慮します。null ではない場合、インテントは指定されたアプリケーションパッケージ内のコンポーネントにのみマッチします。

IPC が他のアプリケーションからアクセスできるようにするには、`<permission>` 要素を使用してセキュリティポリシーを適用し、適切な `android:protectionLevel` を設定します。サービスの宣言で `android:permission` を使用する場合、他のアプリケーションはマニフェストに対応する `<uses-permission>` を宣言する必要があり、それによりサービスの開始、停止、またはバインドできるようになります。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.6: "機密データがIPCメカニズムを介して公開されていない。"

##### CWE
- CWE-634 - Weaknesses that Affect System Processes

##### その他
[1] IPCBinder - https://developer.android.com/reference/android/os/Binder.html
[2] IPCServices - https://developer.android.com/guide/components/services.html
[3] IPCIntent - https://developer.android.com/reference/android/content/Intent.html
[4] IPCContentProviders - https://developer.android.com/reference/android/content/ContentProvider.html
[5] IntentFilterElement - https://developer.android.com/guide/topics/manifest/intent-filter-element.html
[6] ServiceElement - https://developer.android.com/guide/topics/manifest/service-element.html
[7] ProviderElement - https://developer.android.com/guide/topics/manifest/provider-element.html
[8] ReceiverElement - https://developer.android.com/guide/topics/manifest/receiver-element.html
[9] BoundServices - https://developer.android.com/guide/components/bound-services.html
[10] AIDL - https://developer.android.com/guide/components/aidl.html
[11] SendBroadcast - https://developer.android.com/reference/android/content/Context.html#sendBroadcast(android.content.Intent)

##### ツール
* Drozer - https://labs.mwrinfosecurity.com/tools/drozer/
* IntentSniffer - https://www.nccgroup.trust/us/about-us/resources/intent-sniffer/


### ユーザーインタフェース経由の機密データ漏洩のテスト

#### 概要

多くのアプリでは、例えば、アカウントを登録したり、支払いを実行するために、ユーザーはさまざまな種類のデータをキー入力する必要があります。アプリが適切にマスクしない場合や平文でデータを表示する場合に、機密データが開示される可能性があります。

アプリのアクティビティ内の機密データをマスクすることは、漏洩防止やショルダハックなどの軽減のために実施する必要があります。

#### 静的解析

アプリケーションがユーザーによりキー入力される機密情報をマスクしているかどうかを検証するには、EditText の定義の以下の属性をチェックします。

```
android:inputType="textPassword"
```

#### 動的解析

アプリケーションが機密情報をユーザーインタフェースに漏洩しているかどうかを解析するには、アプリケーションを実行して、情報を表示しているか情報をキー入力するよう求めている、アプリの部分を特定します。

例えば、テキストフィールドの文字をアスタリスクに置き換えることなどにより、情報がマスクされている場合、アプリはユーザーインタフェースにデータを漏洩していません。

#### 改善方法

パスワードや PIN の漏洩を防ぐには、機密情報をユーザーインタフェース内でマスクする必要があります。したがって、EditText フィールドでは 属性 `android:inputType="textPassword"` を使用する必要があります。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - Unintended Data Leakage

##### OWASP MASVS
- V2.7: "パスワードやピンなどの機密データは、ユーザーインタフェースを介して公開されていない。"

##### CWE
- CWE-200 - Information Exposure


### 機密データのテスト (バックアップ)

#### 概要

他の現代的なモバイルオペレーティングシステムと同様に、Android は自動バックアップ機能を備えています。バックアップは通常、デバイスにインストールされているすべてのアプリのデータと設定のコピーが含まれます。明白な懸念として、アプリにより格納された機密のユーザーデータが意図せずこれらのデータバックアップに漏洩する可能性があるかどうかがあります。

多様なエコシステムを考えると、Android には構成される多くのバックアップオプションがあります。

- 一般的な Android には USB バックアップ機能が組み込まれています。フルデータバックアップ、または特定のアプリのデータディレクトリのバックアップを取得できます。USB デバッグを有効にして、<code>abd backup</code> コマンドを使用します。

- Google は "Back Up My Data" 機能も提供しています。すべてのアプリデータを Google のサーバーにバックアップします。

- アプリ開発者は複数の Backup API を利用できます。

  - キー・バリューバックアップ (Backup API または Android バックアップサービス) は選択したデータを Android バックアップサービスにアップロードします。

  - アプリの自動バックアップ: Android 6.0 (>= API レベル 23) では、Google は「アプリの自動バックアップ機能」を追加しました。この機能は最大25MBのアプリデータを Google Drive アカウントに自動的に同期します。

- OEM は追加のオプションを追加することがあります。例えば、HTC デバイスには "HTC Backup" オプションがあり、これをアクティブにすると、クラウドへのデイリーバックアップが実行されます。

-- [TODO - recommended approach] --

#### 静的解析

##### ローカル

すべてのアプリケーションデータをバックアップするために、Android は `allowBackup` <sup>[1]</sup> という属性を提供しています。この属性は `AndroidManifest.xml` ファイル内で設定されます。この属性の値が **true** に設定されている場合、デバイスはユーザーがアプリケーションをバックアップできます。Android Debug Bridge (ADB) - `$ adb backup` を使用します。

> 注: デバイスが暗号化されている場合、バックアップファイルも暗号化されます。

以下のフラグについて `AndroidManifest.xml` ファイルを確認します。

```xml
android:allowBackup="true"
```

その値が **true** に設定されている場合、アプリが何かしらの機密データを保存しているかどうかを調査し、テストケース「機密データのテスト (ローカルストレージ)」をチェックします。

##### クラウド
キー・バリューまたは自動バックアップのどちらを使用しているかに関わらず、以下を特定する必要があります。
* どのファイルがクラウドに送信されるか (SharedPreferences など)
* ファイルに機密情報が含まれているかどうか
* 機密情報はクラウドに送信される前に暗号化により保護されているかどうか

**自動バックアップ**
自動バックアップはアプリケーションのマニフェストファイル内でブール属性 `android:allowBackup` により設定されます。明示的に設定されていない場合、Android 6.0 (API レベル 23) 以上を対象とするアプリケーションではデフォルトで自動バックアップが有効になります <sup>[10]</sup> 。属性 `android:fullBackupOnly` を使用して、バックアップエージェントを実装する際に自動バックアップを有効にすることもできますが、Android 6.0 以降でのみ利用できます。他の Android バージョンではキー・バリューバックアップが代わりに使用されます。

```xml
android:fullBackupOnly
```

自動バックアップにはアプリのほとんどすべてのファイルが含まれ、ユーザーの Google Drive アカウントに格納されます。アプリごとに 25MB に制限されています。最新のバックアップのみが格納され、以前のバックアップは削除されます。

**キー・バリューバックアップ**
キー・バリューバックアップを有効にするには、バックアップエージェントをマニフェストファイルで定義する必要があります。`AndroidManifest.xml` 内で以下の属性を探します。

```xml
android:backupAgent
```

キー・バリューバックアップを実装するには、以下のクラスのいずれかを拡張する必要があります。
* BackupAgent
* BackupAgentHelper

ソースコード内でこれらのクラスを探して、キー・バリューバックアップの実装を確認します。


#### 動的解析

アプリを使用する際に利用可能なすべての機能を実行した後、`adb` を使用してバックアップの作成を試みます。成功した場合には、バックアップアーカイブで機密データを調べます。ターミナルを開き、以下のコマンドを実行します。

```bash
$ adb backup -apk -nosystem packageNameOfTheDesiredAPK
```

_Back up my data_ オプションを選択して、デバイスからバックアップを承認します。バックアッププロセスが終了した後、現在の作業ディレクトリに _.ab_ ファイルが作成されます。
以下のコマンドを実行し、.ab ファイルを .tar ファイルに変換します。

```bash
$ dd if=mybackup.ab bs=24 skip=1|openssl zlib -d > mybackup.tar
```

あるいは、この作業に _Android Backup Extractor_ を使用します。このツールが機能するためには、JRE7 用または JRE8 用の Oracle JCE Unlimited Strength Jurisdiction ポリシーファイル <sup>[6]</sup> <sup>[7]</sup> をダウンロードし、JRE の lib/security フォルダに配置する必要があります。以下のコマンドを実行して、tar ファイルに変換します。

```bash
java -jar android-backup-extractor-20160710-bin/abe.jar unpack backup.ab
```

現在の作業ディレクトリに tar ファイルを抽出して、機密データの解析を実行します。

```bash
$ tar xvf mybackup.tar
```

#### 改善方法

アプリデータのバックアップを防止するには、`AndroidManifest.xml` の `android:allowBackup` 属性に **false** を設定します。この属性を利用していない場合、allowBackup 設定はデフォルトで有効となります。したがって、無効にするためには明示的に設定する必要があります。

機密情報を平文でクラウドに送信してはいけません。以下のいずれかであるべきです。
* そもそも情報を格納することを避ける
* クラウドに送信する前に、装置上で情報を暗号化する

ファイルを Google Cloud で共有しない場合は、自動バックアップから除外することもできます <sup>[2]</sup> 。


#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.8: "機密データがモバイルオペレーティングシステムにより生成されるバックアップに含まれていない。"

##### CWE
* CWE-530 - Exposure of Backup File to an Unauthorized Control Sphere

##### その他
[1] Documentation for the application tag - https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup
[2] IncludingFiles - https://developer.android.com/guide/topics/data/autobackup.html#IncludingFiles
[3] Backing up App Data to the cloud - https://developer.android.com/guide/topics/data/backup.html
[4] KeyValueBackup - https://developer.android.com/guide/topics/data/keyvaluebackup.html
[5] BackupAgentHelper - https://developer.android.com/reference/android/app/backup/BackupAgentHelper.html
[6] BackupAgent - https://developer.android.com/reference/android/app/backup/BackupAgent.html
[7] Oracle JCE Unlimited Strength Jurisdiction Policy Files JRE7 - http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
[8] Oracle JCE Unlimited Strength Jurisdiction Policy Files JRE8 - http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
[9] AutoBackup - https://developer.android.com/guide/topics/data/autobackup.html
[10] Enabling AutoBackup - https://developer.android.com/guide/topics/data/autobackup.html#EnablingAutoBackup


##### ツール
* Android Backup Extractor - https://sourceforge.net/projects/adbextractor/



### 機密情報のテスト (自動生成されるスクリーンショット)

#### 概要

製造者はアプリケーションが起動や終了した際デバイスユーザーに美しく快適な効果を提供したいため、アプリケーションがバックグラウンドになるときにスクリーンショットを保存するという概念を導入しました。この機能によりアプリケーションに潜在的にセキュリティリスクが発生する可能性があります。機密データが表示されているときユーザーが意図的にアプリケーションのスクリーンショットを撮る場合、または悪意のあるアプリケーションがデバイス上で動作していて断続的に画面をキャプチャできる場合に、機密データは開示される可能性があります。この情報はローカルストレージに書き込まれます。ルート化されたデバイス上での悪意のあるアプリケーションや、デバイスを盗む何者かによりその情報を復元される可能性があります。

例えば、デバイス上で動作している銀行アプリケーションのスクリーンショットをキャプチャすると、ユーザーアカウント、預金残高、取引明細などに関する情報が写し出される可能性があります。

#### 静的解析

Android では、アプリがバックグラウンドにいくとき、現在のアクティビティのスクリーンショットが撮影され、次にアプリに遷移したときに快適な効果をもたらすために使用されます。しかし、これはアプリ内に存在する機密情報を漏洩するでしょう。

アプリケーションがタスクスイッチャーを介して機密情報を開示するかどうかを検証するには、`FLAG_SECURE` <sup>[1]</sup> オプションが設定されているかどうかを検出します。以下のコードスニペットのようなものを見つけることができるはずです。

```Java
LayoutParams.FLAG_SECURE
```

見つからない場合、アプリケーションはスクリーンキャプチャに対して脆弱です。

#### 動的解析

ブラックボックステストの中で、機密情報を含むアプリ内の任意の画面を開き、ホームボタンをクリックして、アプリがバックグラウンドにいきます。次にタスクスイッチャーボタンを押して、スナップショットを表示します。以下に示すように、`FLAG_SECURE` が設定されている場合 (右側の画像) 、スナップショットは空ですが、`FLAG_SECURE` が設定されていない場合 (左側の画像) 、アクティビティに情報が表示されます。

| `FLAG_SECURE` not set  | `FLAG_SECURE` set  |
|---|---|
| ![OMTG_DATAST_010_1_FLAG_SECURE](Images/Chapters/0x05d/1.png)   |  ![OMTG_DATAST_010_2_FLAG_SECURE](Images/Chapters/0x05d/2.png) |


#### 改善方法

ユーザーや悪意のあるアプリケーションがバックグラウンドのアプリケーションからの情報にアクセスすることを防ぐには、以下に示すように `FLAG_SECURE` を使用します。

```Java
getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);

setContentView(R.layout.activity_main);
```

さらに、以下の提案を実装して、アプリケーションセキュリティ態勢を強化することもできます。
* バックグラウンドではアプリを完全に終了します。これにより保持されている GUI 画面が破棄されます。
* 画面を離れる前、またはログアウトする前に GUI 画面のデータを無効にします。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用
* M2 - 安全でないデータストレージ

##### OWASP MASVS
- V2.9: "バックグラウンド時にアプリはビューから機密データを削除している。"

##### CWE
* CWE-200 - Information Exposure

##### その他
[1] FLAG_SECURE - https://developer.android.com/reference/android/view/Display.html#FLAG_SECURE


### 機密データのテスト (メモリ)

#### 概要

メモリを解析することで、アプリケーションがクラッシュした理由など、さまざまな問題の根本原因を特定できますが、機密データの特定にも使用できます。このセクションではプロセスメモリ内の機密データと一般的なデータの開示を確認する方法について説明します。

アプリケーションのメモリを調査できるようにするには、最初にメモリダンプを作成するか、メモリをリアルタイム更新で閲覧する必要があります。特定の機能がアプリケーション内で実行されている場合、アプリケーションはメモリに特定の情報を格納するだけであるため、これも既に問題です。。メモリの調査はもちろんアプリケーションのあらゆる段階でランダムに実行できますが、メモリの解析を行う前に、モバイルアプリケーションは何をしているのか、どのような機能を提供しているのかをまず理解し、(デコンパイルされた) ソースコードを深く研究することもより有益です。
データの復号化など、機密性の高い機能を特定したら、メモリダンプの調査が有益な場合があります。鍵や復号化された情報自体などの機密データを特定します。

#### Static Analysis

First, you need to identify which sensitive information is stored in memory. Then there are a few checks that must be executed:

- Verify that no sensitive information is stored in an immutable structure. Immutable structures are not really overwritten in the heap, even after nullification or changing them. Instead, by changing the immutable structure, a copy is created on the heap. `BigInteger` and `String` are two of the most used examples when storing secrets in memory. 
- Verify that, when mutable structures are used, such as `byte[]` and `char[]` that all copies of the structure are cleared. 


**NOTICE**: Destroying a key (e.g. `SecretKey secretKey = new SecretKeySpec("key".getBytes(), "AES"); secret.destroy();`) does *not* work, nor nullifying the backing byte-array from `secretKey.getEncoded()` as the SecretKeySpec based key returns a copy of the backing byte-array.
Therefore the developer should, in case of not using the `AndroidKeyStore` make sure that the key is wrapped and properly protected (see remediation for more details).
Understand that an RSA keypair is based on `BigInteger` as well and therefore reside in memory after first use outside of the `AndroidKeyStore`.
Lastly, some of the ciphers do not properly clean up their byte-arrays, for instance: the AES `Cipher` in `BounceyCastle` does not always clean up its latest working key.

#### Dynamic Analysis

To analyse the memory of an app in Android Studio, the app must be **debuggable**.
See the instructions in XXX (-- TODO [Link to repackage and sign] --) on how to repackage and sign an Android app to enable debugging for an app, if not already done. Also adb integration need to be activated in Android Studio in “_Tools/Android/Enable ADB Integration_” in order to take a memory dump.

For rudimentary analysis Android Studio built-in tools can be used. Android Studio includes tools in the “_Android Monitor_” tab to investigate the memory. Select the device and app you want to analyse in the "_Android Monitor_" tab and click on "_Dump Java Heap_" and a _.hprof_ file will be created.

![Create Heap Dump](Images/Chapters/0x05d/Dump_Java_Heap.png)

In the new tab that shows the _.hprof_ file, the Package Tree View should be selected. Afterwards the package name of the app can be used to navigate to the instances of classes that were saved in the memory dump.

![Create Heap Dump](Images/Chapters/0x05d/Package_Tree_View.png)

For deeper analysis of the memory dump Eclipse Memory Analyser (MAT) should be used. The _.hprof_ file will be stored in the directory "captures", relative to the project path open within Android Studio.

Before the _.hprof_ file can be opened in MAT it needs to be converted. The tool _hprof-conf_ can be found in the Android SDK in the directory platform-tools.

```bash
./hprof-conv file.hprof file-converted.hprof
```

By using MAT, more functions are available like usage of the Object Query Language (OQL). OQL is an SQL-like language that can be used to make queries in the memory dump. Analysis should be done on the dominator tree as only this contains the variables/memory of static classes.

To quickly discover potential sensitive data in the _.hprof_ file, it is also useful to run the `string` command against it. When doing a memory analysis, check for sensitive information like:
* Password and/or Username
* Decrypted information
* User or session related information
* Session ID
* Interaction with OS, e.g. reading file content

#### Remediation

In Java, no immutable structures should be used to carry secrets (E.g. `String`, `BigInteger`). Nullifying them will not be effective: the Garbage collector might collect them, but they might remain in the JVMs heap for a longer period of time. 
Rather use byte-arrays (`byte[]`) or char-arrays (`char[]`) which are cleaned after the operations are done:


```java

byte[] secret = null;
try{
	//get or generate the secret, do work with it, make sure you make no local copies
} finally {
	if (null != secret && secret.length > 0) {
		for (int i = 0; i < secret; i++) {
			array[i] = (byte) 0;
		}
	}
}
```

Keys should be handled by the `AndroidKeyStore` or the `SecretKey` class needs to be adjusted. For a better implementation of the `SecretKey` one can use the `ErasableSecretKey` class below. This class consists of two parts: 
- A wrapperclass, called `ErasableSecretKey` which takes care of building up the internal key, adding a clean method and a static convinience method. You can call the `getKey()` on a `ErasableSecretKey` to get the actual key.
- An internal `InternalKey` class which implements `javax.crypto.SecretKey, Destroyable`, so you can actually destroy it and it will behave as a SecretKey from JCE. The destroyable implementation first sets nullbytes to the internal key and then it will put null as a reference to the byte[] representing the actual key. As you can see the `InternalKey` does not provide a copy of its internal byte[] representation, instead it gives the actual version. This will make sure that you will no longer have copies of the key in many parts of your application memory.


```java
public class ErasableSecretKey implements Serializable {

    public static final int KEY_LENGTH = 256;

    private java.security.Key secKey;

	// Do not try to instantiate it: use the static methods.
	// The static construction methods only use mutable structures or create a new key directly.
    protected ErasableSecretKey(final java.security.Key key) {
        this.secKey = key;
    }
	
	//Create a new `ErasableSecretKey` from a byte-array.
	//Don't forget to clean the byte-array when you are done with the key.
    public static ErasableSecretKey fromByte(byte[] key) {
        return new ErasableSecretKey(new SecretKey.InternalKey(key, "AES"));
    }
	//Create a new key. Do not forget to implement your own 'Helper.getRandomKeyBytes()'.
    public static ErasableSecretKey newKey() {
        return fromByte(Helper.getRandomKeyBytes());
    }

	//clean the internal key, but only do so if it is not destroyed yet.
    public void clean() {
        try {
            if (this.getKey() instanceof Destroyable) {
                ((Destroyable) this.getKey()).destroy();
            }

        } catch (DestroyFailedException e) {
            //choose what you want to do now: so you could not destroy it, would you run on? Or rather inform the caller of the clean method informing him of the failure?
        }
    }
	//convinience method that takes away the null-check so you can always just call ErasableSecretKey.clearKey(thekeytobecleared)
    public static void clearKey(ErasableSecretKey key) {
        if (key != null) {
            key.clean();
        }
    }

	//internal key klass which represents the actual key.
    private static class InternalKey implements javax.crypto.SecretKey, Destroyable {
        private byte[] key;
        private final String algorithm;

        public InternalKey(final byte[] key, final String algorithm) {
            this.key = key;
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return this.algorithm;
        }

        public String getFormat() {
            return "RAW";
        }

		//Do not return a copy of the byte-array but the byte-array itself. Be careful: clearing this byte-array, will clear the key.
        public byte[] getEncoded() {
            if(null == this.key){
               throw new NullPointerException();
            }
            return this.key;
        }

		//destroy the key.
        public void destroy() throws DestroyFailedException {
            if (this.key != null) {
                Arrays.fill(this.key, (byte) 0);
            }

            this.key = null;
        }

        public boolean isDestroyed() {
            return this.key == null;
        }
    }


    public final java.security.Key getKey() {
        return this.secKey;
    }

}

```

#### References

##### OWASP Mobile Top 10 2016
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### OWASP MASVS
* V2.10: "The app does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use."

##### CWE
* CWE-316 - Cleartext Storage of Sensitive Information in Memory

##### Info
* Securely stores sensitive data in RAM - https://www.nowsecure.com/resources/secure-mobile-development/coding-practices/securely-store-sensitive-data-in-ram/

##### Tools
* Memory Monitor - http://developer.android.com/tools/debugging/debugging-memory.html#ViewHeap
* Eclipse’s MAT (Memory Analyzer Tool) standalone - https://eclipse.org/mat/downloads.php
* Memory Analyzer which is part of Eclipse - https://www.eclipse.org/downloads/
* Fridump - https://github.com/Nightbringer21/fridump
* LiME - https://github.com/504ensicsLabs/LiME


### Testing the Device-Access-Security Policy

#### Overview

Apps that are processing or querying sensitive information should ensure that they are running in a trusted and secure environment. In order to be able to achieve this, the app can enforce the following local checks on the device:

* PIN or password set to unlock the device
* Usage of a minimum Android OS version
* Detection of activated USB Debugging
* Detection of encrypted device
* Detection of rooted device (see also "Testing Root Detection")

#### Static Analysis

In order to be able to test the device-access-security policy that is enforced by the app, a written copy of the policy needs to be provided. The policy should define what checks are available and how they are enforced. For example one check could require that the app only runs on Android Marshmallow (Android 6.0) or higher and the app is closing itself if the app is running on an Android version < 6.0.

The functions within the code that implement the policy need to be identified and checked if they can be bypassed.

#### Dynamic Analysis

The dynamic analysis depends on the checks that are enforced by app and their expected behavior and need to be checked if they can be bypassed.

#### Remediation

Different checks on the Android device can be implemented by querying different system preferences from _Settings.Secure_<sup>[1]</sup>. The _Device Administration API_<sup>[2]</sup> offers different mechanisms to create security aware applications, that are able to enforce password policies or encryption of the device.


#### References

##### OWASP Mobile Top 10 2016
* M1 - Improper Platform Usage

##### OWASP MASVS
* V2.11: "The app enforces a minimum device-access-security policy, such as requiring the user to set a device passcode."

##### Info
* [1] Settings.Secure - https://developer.android.com/reference/android/provider/Settings.Secure.html
* [2] Device Administration API - https://developer.android.com/guide/topics/admin/device-admin.html


### Verifying User Education Controls

#### Overview

Educating users is a crucial part in the usage of mobile apps. Even though many security controls are already in place, they might be circumvented or misused through the users.

The following list shows potential warnings or advises for a user when opening the app the first time and using it:
* Showing a list of what kind of data is stored locally and remotely. This can also be a link to an external resource as the information might be quite extensive.
* If a new user account is created within the app it should show the user if the password provided is considered secure and applies to the  password policy.
* If the user is installing the app on a rooted device a warning should be shown that this is dangerous and deactivates security controls at OS level and is more likely to be prone to malware. See also "Testing Root Detection" for more details.
* If a user installed the app on an outdated Android version a warning should be shown. See also "Testing the Device-Access-Security Policy" for more details.

#### Static Analysis

A list of implemented education controls should be provided. The controls should be verified in the code if they are implemented properly and according to best practices.

#### Dynamic Analysis

After installing the app and also while using it, it should be checked if any warnings are shown to the user, that have an educational purpose and are aligned with the defined education controls.

#### Remediation

Warnings should be implemented that address the key points listed in the overview section.

#### References

##### OWASP Mobile Top 10 2016
* M1 - Improper Platform Usage

##### OWASP MASVS
- V2.12: "The app educates the user about the types of personally identifiable information processed, as well as security best practices the user should follow in using the app."
