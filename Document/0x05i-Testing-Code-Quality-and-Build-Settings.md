## コード品質とビルド設定のテスト (Android アプリ)

### アプリが正しく署名されていることの検証

#### 概要

Android ではすべての APK はインストールする前に証明書でデジタル署名する必要があります。デジタル署名はアプリケーションをインストール/実行する前に Android システムで必要とされ、アプリケーションの将来の更新で所有者の身元を確認するためにも使用されます。このプロセスにより不正なコードを含むような改竄や改変を防ぐことができます。

APK に署名すると、公開鍵証明書が APK に添付されます。この証明書は APK を開発者および対応する秘密鍵に一意に関連付けます。デバッグモードでアプリをビルドすると、Android SDK はデバッグ用に特別に作成されたデバッグ鍵でアプリに署名します。デバッグ鍵で署名されたアプリは配布用ではなく、Google Play ストアを含むほとんどのアプリストアで受け入れられません。最終リリースのアプリを準備するには、開発者が所有するリリース鍵で署名する必要があります。

アプリの最終リリースビルドは有効なリリース鍵で署名されている必要があります。注意。Android ではアプリの更新に同じ証明書で署名することを期待しますので、25年以上の有効期間が推奨されます。Google Play に公開されるアプリは少なくとも2033年10月22日まで有効な証明書で署名する必要があります。

JAR 署名 (v1 方式) と APK 署名方式 v2 (v2 方式) の2つの APK 署名方式が利用できます。Android 7.0 以上でサポートされる v2 署名はセキュリティとパフォーマンスが向上しています。リリースビルドは常に *両方の* 方式を使用して署名する必要があります。

#### 静的解析

リリースビルドは v1 および v2 の両方の方式で署名され、APK に含まれるコード署名証明書が開発者に属していることを確認します。

APK がローカルで使用できない場合は、まずデバイスから APK を取り出します。

```bash
$ adb shell pm list packages
(...)
package:com.awesomeproject
(...)
$ adb shell pm path com.awesomeproject
package:/data/app/com.awesomeproject-1/base.apk
$ adb pull /data/app/com.awesomeproject-1/base.apk
```

APK 署名は <code>apksigner</code> ツールを使用して確認できます。

```bash
$ apksigner verify --verbose Desktop/example.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Number of signers: 1
```

署名証明書の内容は <code>jarsigner</code> を使用して調べることができます。デバッグ証明書では、Common Name (CN) 属性が "Android Debug" に設定されていることに注意します。

デバッグ証明書で署名された APK の出力は以下のようになります。

```
$ jarsigner -verify -verbose -certs example.apk

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Android Debug, O=Android, C=US
      [certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
      [CertPath not validated: Path does not chain with any of the trust anchors]
(...)
```

「CertPathが検証されていません」エラーを無視します。このエラーは Java SDK 7 以上で発生します。代わりに、<code>apksigner</code> を使用して証明書チェーンを検証することができます。

#### 動的解析

静的解析を使用して APK 署名を検証する必要があります。

#### 改善方法

開発者はリリースビルドがリリースキーストアの適切な証明書で署名されていることを確認する必要があります。Android Studio では、手動もしくは署名設定を作成してリリースビルドタイプに割り当てることで設定できます <sup>[2]</sup> 。

署名の設定は Android Studio の GUI もしくは <code>build.gradle</code> の <code>signingConfigs {}</code> ブロックで管理できます。v1 および v2 の両方の方式を有効にするには、以下の値を設定する必要があります。

```
v1SigningEnabled true
v2SigningEnabled true
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V7.1: "アプリは有効な証明書で署名およびプロビジョニングされている。"

##### CWE
N/A

##### その他
- [1] Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
- [2] Sign your App - https://developer.android.com/studio/publish/app-signing.html

##### ツール
- jarsigner - http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html


### アプリがデバッグ可能であるかのテスト

#### 概要

Manifest の <code>Application</code> タグの <code>android:debuggable</code> 属性は Android のユーザーモードビルドで実行しているときにアプリがデバッグできるかどうかを決定します。リリースビルドでは、この属性は常に "false" (デフォルト値) に設定する必要があります。

#### 静的解析

<code>android:debuggable</code> 属性が設定されているかどうかを <code>AndroidManifest.xml</code> で確認します。

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.android.owasp">

    ...

    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <meta-data android:name="com.owasp.main" android:value=".Hook"/>
    </application>
</manifest>
```

#### 動的解析

Drozer はアプリケーションがデバッグ可能かどうかを特定するために使用できます。モジュール `app.package.attacksurface` は、アプリがデバッグ可能かどうかに加えて、アプリケーションによりエクスポートされる IPC コンポーネントに関する情報を表示します。

```
dz> run app.package.attacksurface com.mwr.dz
Attack Surface:
  1 activities exported
  1 broadcast receivers exported
  0 content providers exported
  0 services exported
    is debuggable
```

デバイス上のすべてのデバッグ可能なアプリケーションをスキャンするには、`app.package.debuggable` モジュールを使用する必要があります。

```
dz> run app.package.debuggable
Package: com.mwr.dz
  UID: 10083
  Permissions:
   - android.permission.INTERNET
Package: com.vulnerable.app
  UID: 10084
  Permissions:
   - android.permission.INTERNET
```

アプリケーションがデバッグ可能である場合は、アプリケーションのコンテキストでコマンドを実行することは簡単です。`adb` シェルで、`run-as` バイナリにパッケージ名とコマンドを付けて実行します。

```
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

アプリケーションがデバッグ可能かどうかを判断する別の方法には、実行中のプロセスを jdb にアタッチすることがあります。デバッグが無効である場合、これはエラーで失敗するはずです。

#### 改善方法

`AndroidManifest.xml` ファイルに、以下で示すように `android:debuggable` フラグに false を設定します。

```xml
<application android:debuggable="false">
...
</application>
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V7.2: "アプリはリリースモードでビルドされている。リリースビルドに適した設定である。（非デバッグなど）"

##### CWE


-- TODO [Add relevant CWE for "Testing If the App is Debuggable"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他
* [1] Application element - https://developer.android.com/guide/topics/manifest/application-element.html

##### Tools

* Drozer - https://github.com/mwrlabs/drozer

### デバッグシンボルに関するテスト

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

ネイティブバイナリでは、nm や objdump などの標準ツールを使用してシンボルテーブルを検査します。リリースビルドには一般的にデバッグシンボルを含む必要はありません。目標がライブラリの難読化である場合は、不要な動的シンボルを削除することもお勧めします。

#### 静的解析

シンボルは通常、ビルドプロセス中に削除されるため、不要なメタデータが削除されたかどうかを確認するためにはコンパイル済みのバイトコードとライブラリが必要です。

デバッグシンボルを表示するには：

```bash
export $NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm
```

```bash
$ $NM -a libfoo.so
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```
動的シンボルを表示するには：

```bash
$ $NM -D libfoo.so
```

あるいは、お気に入りの逆アセンブラでファイルを開いて手動でシンボルテーブルをチェックします。

#### 動的解析

デバッグシンボルを検証するには静的解析を使用する必要があります。

#### 改善方法

動的シンボルは <code>visibility</code> コンパイラフラグを使用して削除できます。このフラグを追加すると gcc は <code>JNIEXPORT</code> として宣言された関数の名前を保持したまま関数名を破棄します。

build.gradle に以下を追加します。

```
        externalNativeBuild {
            cmake {
                cppFlags "-fvisibility=hidden"
            }
        }
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V7.3: "デバッグシンボルはネイティブバイナリから削除されている。"

##### CWE

-- TODO [Add relevant CWE for "Testing for Debugging Symbols"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

[1] Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
[2] Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### ツール

-- TODO [Add relevant tools for "Testing for Debugging Symbols"] --
* Enjarify - https://github.com/google/enjarify



### デバッグコードや詳細エラーログに関するテスト

#### 概要
StrictMode は開発ツールであり、ディスクやネットワークアクセスなどのポリシー違反を検出できます。
高パフォーマンスコードの実装やメインスレッドでのネットワークアクセスの仕様など、優れたコーディング作法の使用状況をチェックするよう実装されています。
ポリシーはポリシー違反を示すルールやさまざまな手法とともに定義されています。

ポリシーには二つのカテゴリがあります。
* `StrictMode.ThreadPolicy`
* `StrictMode.VmPolicy`

ThreadPolicy は以下を監視します。
* Disk Reads
* Disk Writes
* Network access
* Custom Slow Code

VM ポリシーは仮想マシンのプロセス内のすべてのスレッドに適用されます。
* Leaked Activity objects
* Leaked SQLite objects
* Leaked Closable objects

`StrictMode` を有効にするには、onCreate() にコードを実装する必要があります。
上記の両方のポリシー <sup>[1]</sup> を有効にする例を以下に示します。
```
public void onCreate() {
     if (DEVELOPER_MODE) {
         StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                 .detectDiskReads()
                 .detectDiskWrites()
                 .detectNetwork()   // or .detectAll() for all detectable problems
                 .penaltyLog()
                 .build());
         StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder()
                 .detectLeakedSqlLiteObjects()
                 .detectLeakedClosableObjects()
                 .penaltyLog()
                 .penaltyDeath()
                 .build());
     }
     super.onCreate();
 }

```
#### 静的解析
`StrictMode` が有効であるかどうかを確認するには、`StrictMode.setThreadPolicy` または `StrictMode.setVmPolicy` メソッドを探します。ほとんどの場合、それらは onCreate() メソッドにあります。

Thread Policy のさまざまな検出メソッドは以下になります <sup>[3]</sup> 。
```
detectDiskWrites() //API level 9
detectDiskReads() //API level 9
detectNetwork() //API level 9
detectCustomSlowCalls()//Introduced in API level 11
detectAll()
detectCustomSlowCalls()
```

もうひとつの可能性としてすべての種類の違反を以下のように捕捉します。
```
detectAll()
detectCustomSlowCalls()
```

Thread Policy のペナルティには以下があります <sup>[3]</sup> 。
```
penaltyLog() //Logs a message to LogCat
penaltyDeath() //Crashes application, runs at the end of all enabled penalties
penaltyDialog() //Show a dialog
penaltyDeathOnNetwork() //Crashes the whole process on any network usage
penaltyDropBox() //Enable detected violations log a stacktrace and timing data to the DropBox on policy violation
penaltyFlashScreen() //Introduced in API level 11 which Flash the screen during a violation
```

StrictMode の VM Policy を考慮する場合、ポリシーは以下になります <sup>[3]</sup> 。
```
detectActivityLeaks() //API level 11. Detect leaks of Activity subclasses.
detectLeakedClosableObjects() //API level 11. Detect when an Closeable or other object with a explict termination method is finalized without having been closed.
detectLeakedSqlLiteObjects() //API level 9. Detect when an SQLiteCursor or other SQLite object is finalized without having been closed.
setClassInstanceLimit(Class.forName("my.app.sample.sampleclass"),10) //API level 11
```

VM Policy 違反のペナルティには以下があります <sup>[3]</sup> 。
```
penaltyLog()
penaltyDeath()
penaltyDropBox()
```

#### 動的解析
`StrictMode` の検出にはさまざまな方法があり、ポリシーの役割の実装方法に依存します。それらの一部として以下があります。
* Logcat
* 警告ダイアログ
* アプリケーションのクラッシュ

#### 改善方法
条件として `DEVELOPER_MODE` を指定した `if` 文にポリシーを挿入することを推奨します。
`StrictMode` を無効にするには、リリースビルドで DEVELOPER_MODE を無効にする必要があります。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V7.4: "デバッグコードは削除されており、アプリは詳細なエラーやデバッグメッセージを記録していない。"

##### CWE
-- TODO [Add relevant CWE for "Testing for Debugging Code and Verbose Error Logging"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他
- [1] Official Developer Guide - https://developer.android.com/reference/android/os/StrictMode.html
- [2] Envatotuts+ - https://code.tutsplus.com/tutorials/android-best-practices-strictmode--mobile-7581
- [3] Javabeat- http://javabeat.net/strictmode-android-1/

##### ツール
-- TODO [Add relevant tools for "Testing for Debugging Code and Verbose Error Logging"] --
* Enjarify - https://github.com/google/enjarify



### 例外処理のテスト

#### 概要
例外はアプリケーションが正常ではない状態やエラーのある状態になったときによく発生します。このような状態が発生したときに Java と C++ のいずれも例外をスローします。
例外処理のテストとは、アプリケーションで使用される UI とログ出力メカニズムの両方で機密情報を開示することなく、アプリケーションが例外を処理して安全な状態になることを再確認することです。

#### 静的解析

ソースコードをレビューして、アプリケーションがさまざまな種類のエラー(IPC 通信、リモートサービス呼び出しなど)を処理する方法を理解および特定します。この段階で実行されるチェックの例を以下に示します。

* アプリケーションが正しく設計され統一された方式を使用して例外を処理することを確認する <sup>[1]</sup>。
* 適切なヌルチェック、境界チェックなどを作成することにより、標準の `RuntimeException` 群 (`NullPointerException`, `IndexOutOfBoundsException`, `ActivityNotFoundException`, `CancellationException`, `SQLException` など) を未然に防ぐことを確認する。`RuntimeException` の提供される子クラスの概要については <sup>[2]</sup> を参照する。開発者が依然として `RuntimeException` の子をスローする場合、これは常に意図的であるべきで、その意図は呼出元のメソッドで処理すべきである。
* すべての非実行時 Throwable` について、適切な catch ハンドラが存在し、実際の例外を適切に処理することを確認する。
* UI またはログステートメントで例外を処理する際に、アプリケーションは機密情報を開示しないが、ユーザーに問題を十分詳細に説明していることを確認する。
* リスクの高いアプリケーションの場合には、鍵マテリアルや認証情報などの機密情報は `finally` ブロックで常に消去されることを確認する。


#### 動的解析
動的解析を行うにはさまざまな方法があります。

- Xposed を使用してメソッドにフックし、予期しない値でメソッドを呼び出すか、予期しない値 (NULL 値など) で既存の変数を上書きする。
- Android アプリケーションの UI フィールドに予期しない値を入力する。
- 予期しない値を使用してインテントや公開プロバイダを使用してアプリケーションと対話する。
- ネットワーク通信やアプリケーションに格納されたファイルを改竄する。

すべての場合に、アプリケーションはクラッシュしてはいけません。代わりに、以下のようにすべきです。

- エラーから回復する、もしくは継続できないことをユーザーに知らせることができる状態にする。
- 必要に応じて、ユーザーに適切な措置をとるための情報メッセージを知らせる。そのメッセージ自体に機密情報を漏らさない。
- アプリケーションで使用されるログ出力メカニズムには何の情報も提供しない。

#### 改善方法
開発者ができることはいくつかあります。
- アプリケーションが適切に設計され統一されたスキームを使用して例外を処理することを確認する <sup>[1]</sup> 。
- 例外をスローする場合には、アプリケーションが同様の振る舞いを引き起こす例外に対して一元的なハンドラを持つことを確認する。これはたとえば静的クラスにできる。メソッドのコンテキストで特定の例外が発生する場合は、特定の catch ブロックを提供すべきである。
- リスクの高い情報を含む操作を実行する場合には、Java の finally ブロックで情報を消去することを確認する。

```java
byte[] secret;
try{
	//use secret
} catch (SPECIFICEXCEPTIONCLASS | SPECIFICEXCEPTIONCLASS2  e) {
	// handle any issues
} finally {
	//clean the secret.
}
```

- 捕捉されない例外に対する汎用の例外ハンドラを追加して、クラッシュする前にアプリケーションの状態をクリアする。
```java
public class MemoryCleanerOnCrash implements Thread.UncaughtExceptionHandler {

    private static final MemoryCleanerOnCrash S_INSTANCE = new MemoryCleanerOnCrash();
    private final List<Thread.UncaughtExceptionHandler> mHandlers = new ArrayList<>();

	//initiaze the handler and set it as the default exception handler
    public static void init() {
        S_INSTANCE.mHandlers.add(Thread.getDefaultUncaughtExceptionHandler());
        Thread.setDefaultUncaughtExceptionHandler(S_INSTANCE);
    }

	 //make sure that you can still add exception handlers on top of it (required for ACRA for instance)
    public void subscribeCrashHandler(Thread.UncaughtExceptionHandler handler) {
        mHandlers.add(handler);
    }

    @Override
    public void uncaughtException(Thread thread, Throwable ex) {

			//handle the cleanup here
			//....
			//and then show a message to the user if possible given the context

        for (Thread.UncaughtExceptionHandler handler : mHandlers) {
            handler.uncaughtException(thread, ex);
        }
    }
}
```

次にカスタム `Application` クラス (`Application` から派生するクラスなど) でハンドラのイニシャライザを呼び出す必要があります。

```java

	 @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        MemoryCleanerOnCrash.init();
    }
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V7.5: "アプリは可能性のある例外をキャッチし処理している。"
* V7.6: "セキュリティコントロールのエラー処理ロジックはデフォルトでアクセスを拒否している。"

##### CWE
-- TODO [Add relevant CWE for "Testing Exception Handling"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Exceptional Behavior (ERR) - https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047
- [2] Android developer API documentation - https://developer.android.com/reference/java/lang/RuntimeException.html

##### ツール

* Xposed - http://repo.xposed.info/




### メモリ管理バグのテスト

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### 静的解析

-- TODO [Add content for white-box testing "Testing for Memory Management Bugs"] --

#### 動的解析

-- TODO [Add content for black-box testing "Testing for Memory Management Bugs"] --

#### 改善方法

-- TODO [Add remediations for "Testing for Memory Management Bugs"] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V7.7: "アンマネージドコードでは、メモリは安全に割り当て、解放、使用されている。"

##### CWE
-- TODO [Add relevant CWE for "Testing for Memory Management Bugs"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他
* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### ツール
-- TODO [Add relevant tools for "Testing for Memory Management Bugs"] --
* Enjarify - https://github.com/google/enjarify



### フリーのセキュリティ機能が有効であることの検証

#### 概要

Java クラスはデコンパイルが容易であるため、リリースバイトコードに基本的な難読化を適用することをお勧めします。Android 上の Java アプリの場合、ProGuard がコードを縮小および難読化する簡単な方法を提供します。これはクラス名、メソッド名、変数名などの識別子を無意味な文字の組み合わせに置き換えます。これはレイアウト難読化の一形態であり、プログラムのパフォーマンスに影響を与えない点で「フリー」です。

ほとんどの Android アプリケーションは Java ベースであるため、バッファオーバーフローの脆弱性に対しては免疫 <sup>[1]</sup> があります。


#### 静的解析

ソースコードが提供されている場合、build.gradle ファイルを確認することで難読化設定が適用されているか分かります。以下の例では、`minifyEnabled` と `proguardFiles` が設定されていることが分かります。"-keepclassmembers" と "-keep class" で一部のクラスの難読化を例外にするのが一般的ですが、ProGuard 構成ファイルを監査して免除されているクラスを確認することが重要です。`getDefaultProguardFile('proguard-android.txt')` メソッドはデフォルトの ProGuard 設定を `<Android SDK>/tools/proguard/` フォルダから取得し、`proguard-rules.pro` はカスタム ProGuard ルールを定義します。サンプルの `proguard-rules.pro` ファイルからは、一般的な android クラスを拡張する多くのクラスが免除されていることが分かります。特定のクラスやライブラリを除外するにはより細かく行う必要があります。

build.gradle
```
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
```

proguard-rules.pro
```
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
```

#### 動的解析

ソースコードが提供されていない場合、コードベースが難読化されているかどうかを検証するために APK を逆コンパイルします。dex2jar を使用して dex コードを jar ファイルに変換できます。JD-GUI のようなツールを使用して、クラス、メソッド、変数名が人間に読めるかどうかを調べることができます。

難読化されたコードブロックの例
```
package com.a.a.a;

import com.a.a.b.a;
import java.util.List;

class a$b
  extends a
{
  public a$b(List paramList)
  {
    super(paramList);
  }

  public boolean areAllItemsEnabled()
  {
    return true;
  }

  public boolean isEnabled(int paramInt)
  {
    return true;
  }
}
```

#### 改善方法

ProGuard を使用して、Java バイトコードから不要なデバッグ情報を削除する必要があります。デフォルトでは、ProGuard は行番号、ソースファイル名、変数名などのデバッグに役立つ属性を削除します。ProGuard はフリーの Java クラスファイル縮小化、最適化、難読化、事前検証のツールです。Android の SDK ツールに同梱されています。リリースビルドの縮小を有効にするには、build.gradle に以下を追加します。

```
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile(‘proguard-android.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
```

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V7.8: "バイトコードの軽量化、スタック保護、PIEサポート、自動参照カウントなどツールチェーンにより提供されるフリーのセキュリティ機能が有効化されている。"

##### CWE
-- TODO [Add relevant CWE for Verifying that Java Bytecode Has Been Minified] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他
[1] Java Buffer Overflows - https://www.owasp.org/index.php/Reviewing_Code_for_Buffer_Overruns_and_Overflows#.NET_.26_Java
[2] Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
[3] Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### ツール
-- TODO [Add relevant tools for Verifying that Java Bytecode Has Been Minified] --
* Enjarify - https://github.com/google/enjarify
