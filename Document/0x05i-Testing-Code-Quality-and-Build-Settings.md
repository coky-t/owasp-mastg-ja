# Android のコード品質とビルド設定

## アプリが正しく署名されていることの検証 (MSTG-CODE-1)

### 概要

Android ではすべての APK はインストールまたは実行する前に証明書でデジタル署名する必要があります。デジタル署名はアプリケーションの更新で所有者の身元を確認するためにも使用されます。このプロセスによりアプリが不正なコードを含むような改竄や改変を防ぐことができます。

APK に署名すると、公開鍵証明書が APK に添付されます。この証明書は APK を開発者および開発者の秘密鍵に一意に関連付けます。デバッグモードでアプリをビルドすると、Android SDK はデバッグ目的専用に作成されたデバッグ鍵でアプリに署名します。デバッグ鍵で署名されたアプリは配布されることを意図しておらず、Google Play ストアを含むほとんどのアプリストアで受け入れられません。

アプリの [最終リリースビルド](https://developer.android.com/studio/publish/app-signing.html "Android Application Signing") は有効なリリース鍵で署名されている必要があります。Android Studio では、アプリを手動で署名するかリリースビルドタイプに割り当てられた署名構成を作成することで署名できます。

Android 9 (API level 28) 以前では Android 上のすべてのアプリ更新に同じ証明書で署名されている必要があるため、[25年以上の有効期間が推奨されます](https://developer.android.com/studio/publish/app-signing#considerations "Android Signing Considerations") 。Google Play に公開されるアプリは2033年10月22日以降に終了する有効期間を持つ鍵で署名する必要があります。

三つの APK 署名スキームが利用可能です。

- JAR 署名 (v1 スキーム)
- APK 署名スキーム v2 (v2 スキーム)
- APK 署名スキーム v3 (v3 スキーム)

Android 7.0 (API level 24) 以上でサポートされている v2 署名は v1 スキームと比較してセキュリティとパフォーマンスが向上しています。
Android 9 (API level 28) 以上でサポートされている v3 署名により、アプリは APK 更新の一部として署名鍵を変更できます。この機能は新しい鍵と古い鍵の両方を使用できるようにすることで互換性とアプリの継続的な可用性を保証します。執筆時点では apksigner を介してのみ利用可能であることに注意します。

それぞれの署名スキームに対して、リリースビルドでは常に以前のすべてのスキームも使用して署名される必要があります。

### 静的解析

リリースビルドは Android 7.0 (API level 24) 以上に対して v1 および v2 の両方のスキームで署名されていること、Android 9 (API level 28) 以上に対して三つのすべてのスキームで署名されていること、および APK のコード署名証明書がその開発者に属していることを確認します。

APK 署名は `apksigner` ツールで検証できます。`[SDK-Path]/build-tools/[version]` にあります。

```bash
$ apksigner verify --verbose Desktop/example.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
```

署名証明書の内容は `jarsigner` で調べることができます。デバッグ証明書では Common Name (CN) 属性が "Android Debug" に設定されることに注意します。

デバッグ証明書で署名された APK の出力は以下のとおりです。

```bash

$ jarsigner -verify -verbose -certs example.apk

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Android Debug, O=Android, C=US
      [certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
      [CertPath not validated: Path doesn\'t chain with any of the trust anchors]
(...)

```

"CertPath not validated" エラーは無視します。このエラーは Java SDK 7 以上で発生します。`jarsigner` の代わりに、`apksigner` を使用して証明書チェーンを検証できます。

署名構成は Android Studio または `build.gradle` の `signingConfig` ブロックで管理できます。v1 スキームと v2 スキームの両方をアクティブにするには、以下の値をセットする必要があります。

```default
v1SigningEnabled true
v2SigningEnabled true
```

[アプリをリリース用に構成する](https://developer.android.com/tools/publishing/preparing.html#publishing-configure "Best Practices for configuring an Android App for Release") ためのいくつかのベストプラクティスが公式の Android 開発者ドキュメントに記載されています。

最後になりましたが、アプリケーションは内部テスト証明書でデプロイされることがないことを確認します。

### 動的解析

APK 署名を検証するには静的解析を使用する必要があります。

## アプリがデバッグ可能であるかのテスト (MSTG-CODE-2)

### 概要

Android マニフェストで定義されている [`Application` 要素](https://developer.android.com/guide/topics/manifest/application-element.html "Application element") の `android:debuggable` 属性はアプリがデバッグできるかどうかを決定します。

### 静的解析

`AndroidManifest.xml` をチェックして `android:debuggable` 属性が設定されているかどうかを判断し、その属性の値を見つけます。

```xml
    ...
    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
    ...
```

リリースビルドの場合、この属性は常に `"false"` (デフォルト値) に設定すべきです。

### 動的解析

Drozer を使用してアプリケーションがデバッグ可能かどうかを判断できます。Drozer モジュール `app.package.attacksurface` はアプリケーションによりエクスポートされる IPC コンポーネントに関する情報も表示します。

```bash
dz> run app.package.attacksurface com.mwr.dz
Attack Surface:
  1 activities exported
  1 broadcast receivers exported
  0 content providers exported
  0 services exported
    is debuggable
```

デバイス上のすべてのデバッグ可能なアプリケーションをスキャンするには、`app.package.debuggable` モジュールを使用します。

```bash
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

アプリケーションがデバッグ可能である場合、アプリケーションコマンドを実行することは簡単です。`adb` シェルで、バイナリ名にパッケージ名とアプリケーションコマンドを追加して `run-as` を実行します。

```bash
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

[Android Studio](https://developer.android.com/tools/debugging/debugging-studio.html "Debugging with Android Studio") を使用して、アプリケーションをデバッグし、アプリのデバッグアクティベーションを検証することもできます。

アプリケーションがデバッグ可能かどうかを判断する別の方法は、実行中のプロセスに `jdb` をアタッチすることです。これが成功する場合、デバッグが有効になります。

以下の手順を使用して `jdb` でデバッグセッションを開始できます。

1. `adb` と `jdwp` を使用して、デバッグしたいアクティブなアプリケーションの PID を特定します。

    ```bash
    $ adb jdwp
    2355
    16346  <== last launched, corresponds to our application
    ```

2. `adb` を使用してアプリケーションプロセス (PIDを使用) と解析ワークステーションの間に特定のローカルポートを使用した通信チャネルを作成します。

    ```bash
    # adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PID]
    $ adb forward tcp:55555 jdwp:16346
    ```

3. `jdb` を使用して、デバッガをローカル通信チャネルポートにアタッチし、デバッグセッションを開始します。

    ```bash
    $ jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555
    Set uncaught java.lang.Throwable
    Set deferred uncaught java.lang.Throwable
    Initializing jdb ...
    > help
    ```

デバッグに関するいくつかの注釈:

- ツール [`JADX`](https://github.com/skylot/jadx "JADX") を使用してブレークポイント挿入のための重要な場所を特定できます。
- jdb についての基本的なコマンドの使用方法は [Tutorialspoint](https://www.tutorialspoint.com/jdb/jdb_basic_commands.htm "jdb basic commands") にあります。
- `jdb` がローカル通信チャネルポートにバインドされている際に "the connection to the debugger has been closed" (デバッガへの接続が閉じられた) というエラーが表示された場合、すべての adb セッションを終了し、新しい一つのセッションを開始します。

## デバッグシンボルに関するテスト (MSTG-CODE-3)

### 概要

一般的に、コンパイルされたコードにはできるだけ説明を付けるべきではありません。デバッグ情報、行番号、説明的な関数名やメソッド名などの一部のメタデータは、リバースエンジニアがバイナリやバイトコードを理解しやすくしますが、これらはリリースビルドでは必要ないため、アプリの機能に影響を与えることなく安全に省略できます。

ネイティブバイナリを検査するには、`nm` や `objdump` などの標準ツールを使用してシンボルテーブルを調査します。リリースビルドには一般的にデバッグシンボルを含めるべきではありません。ライブラリを難読化することが目的の場合には、不要な動的シンボルを削除することもお勧めします。

### 静的解析

シンボルは通常ではビルドプロセス中に削除されるため、不要なメタデータが破棄されたことを確認するにはコンパイルされたバイトコードとライブラリが必要です。

最初に、Android NDK の `nm` バイナリを見つけてエクスポート (またはエイリアスを作成) します。

```bash
export $NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm
```

デバッグシンボルを表示するには:

```bash
$ $NM -a libfoo.so
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```

動的シンボルを表示するには:

```bash
$ $NM -D libfoo.so
```

あるいは、お気に入りの逆アセンブラでファイルを開いて手動でシンボルテーブルをチェックします。

動的シンボルは `visibility` コンパイラフラグを使用して削除できます。このフラグを追加すると `JNIEXPORT` として宣言された関数名を保持しながら gcc は関数名を破棄します。

以下が build.gradle に追加されていることを確認します。

```default
externalNativeBuild {
    cmake {
        cppFlags "-fvisibility=hidden"
    }
}
```

### 動的解析

デバッグシンボルを検証するには静的解析を使用する必要があります。

## デバッグコードと詳細エラーログに関するテスト (MSTG-CODE-4)

### 概要

StrictMode はアプリケーションのメインスレッドでの偶発的なディスクやネットワークアクセスなどの違反を検出するための開発者ツールです。効率の良いコード実装など優れたコーディングプラクティスをチェックするためにも使用できます。

メインスレッドへのディスクおよびネットワークアクセスに対してポリシーを有効にした [`StrictMode` の例](https://developer.android.com/reference/android/os/StrictMode.html "StrictMode Class") は以下のとおりです。

```java
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

`DEVELOPER_MODE` 条件で `if` ステートメントにポリシーを挿入することをお勧めします。`StrictMode` を無効にするには、リリースビルドに対して `DEVELOPER_MODE` を無効にする必要があります。

### 静的解析

`StrictMode` が有効かどうかを判断するには、`StrictMode.setThreadPolicy` または `StrictMode.setVmPolicy` メソッドを探します。ほとんどの場合、`onCreate` メソッドにあります。

[スレッドポリシーの検出方法](https://javabeat.net/strictmode-android-1/ "What is StrictMode in Android?") は以下のとおりです。

```java
detectDiskWrites()
detectDiskReads()
detectNetwork()
```

[スレッドポリシー違反のペナルティ](https://javabeat.net/strictmode-android-1/ "What is StrictMode in Android?") は以下のとおりです。

```java
penaltyLog() // Logs a message to LogCat
penaltyDeath() // Crashes application, runs at the end of all enabled penalties
penaltyDialog() // Shows a dialog
```

StrictMode を使用するための [ベストプラクティス](https://code.tutsplus.com/tutorials/android-best-practices-strictmode--mobile-7581 "Android Best Practices: StrictMode") をご覧ください。

### 動的解析

`StrictMode` を検出するにはいくつかの方法があります。最善の選択はポリシーの役割の実装方法により異なります。以下があります。

- Logcat
- 警告ダイアログ
- アプリケーションクラッシュ

## サードパーティーライブラリの脆弱性の確認 (MSTG-CODE-5)

### 概要

Android アプリは多くの場合サードパーティライブラリを使用します。開発者が問題を解決するために書く必要があるコードがより少なくなるため、これらのサードパーティライブラリは開発を加速します。ライブラリには二つのカテゴリがあります。

- 実際の製品アプリケーション内にパックされない (またはパックすべきではない) ライブラリ。テストに使用される `Mockito` や特定の他のライブラリをコンパイルするために使用される `JavaAssist` のようなライブラリなど。
- 実際の製品アプリケーション内にパックされるライブラリ。`Okhttp3` など。

これらのライブラリは望ましくない副作用を引き起こす可能性があります。

- ライブラリには脆弱性が含まれている可能性があり、これによりアプリケーションが脆弱になります。よい例は 2.7.5 より前のバージョンの `OKHTTP` で、TLS チェーン汚染により SSL ピンニングをバイパスすることが可能でした。
- ライブラリはもはや保守されていないかほとんど使用されていない可能性があり、そのため脆弱性は報告されず修正されません。これによりそのライブラリを介してアプリケーションに不正なコードや脆弱なコードが含まれる可能性があります。
- ライブラリは LGPL2.1 などのライセンスを使用している可能性があります。LGPL2.1 ではアプリケーションを使用してそのソースの中身を要求するユーザーにアプリケーションの作成者がソースコードへのアクセスを提供する必要があります。実際、アプリケーションはソースコードを変更して再配布できるようにする必要があります。これはアプリケーションの知的財産 (IP) を危険にさらす可能性があります。

この問題は複数のレベルで発生する可能性があることに注意します。WebView 内で JavaScript を実行する WebView を使用すると、その JavaScript ライブラリにもこれらの問題が発生する可能性があります。Cordova, React-native および Xamarin アプリのプラグインやライブラリについても同様です。

### 静的解析

#### サードパーティライブラリの脆弱性の検出

サードパーティーに依存する脆弱性を検出するには OWASP Dependency checker を使用して実行できます。これは `dependency-check-gradle` などの gradle プラグインを使用することが最適です。
プラグインを使用するには、以下の手順を適用する必要があります。
build.gradle に以下のスクリプトを追加して、Maven セントラルリポジトリからプラグインをインストールします。

```default
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:3.2.0'
    }
}

apply plugin: 'org.owasp.dependencycheck'
```

gradle がプラグインを呼び出したら、以下を実行してレポートを作成できます。

```bash
$ gradle assemble
$ gradle dependencyCheckAnalyze --info
```

特に設定しない限り、レポートは `build/reports` にあります。見つかった脆弱性を分析するにはレポートを使用します。ライブラリで見つかった脆弱性を考慮して対処方法を確認します。

プラグインは脆弱性フィードをダウンロードする必要があることに注意してください。プラグインで問題が発生した場合にはドキュメントを参照します。

あるいは SourceClear や Blackduck などの、使用されているライブラリに見られる依存関係をより適切にカバーできる商用ツールがあります。OWASP Dependency Checker や別のツールを使用した実際の結果は (NDK 関連または SDK 関連の) ライブラリの種類により異なります。

最後に、ハイブリッドアプリケーションの場合には、RetireJS で JavaScript の依存関係を確認する必要があることに注意します。同様に Xamarin の場合には C# の依存関係を確認する必要があります。

ライブラリに脆弱性が含まれていることが判明した場合、以下の理由が適用されます。

- ライブラリがアプリケーションにパッケージされている場合、ライブラリに脆弱性が修正されたバージョンがあるかどうかを確認します。ない場合、脆弱性が実際にアプリケーションに影響するかどうかを確認します。その場合または将来そうなる可能性がある場合、同様の機能を提供するが脆弱性のない代替手段を探します。
- ライブラリがアプリケーションにパッケージされていない場合、脆弱性が修正されたパッチ適用バージョンがあるかどうかを確認します。そうでない場合には、ビルドプロセスに対する脆弱性の影響を確認します。脆弱性がビルドを妨げるかビルドパイプラインのセキュリティを弱める可能性がある場合、脆弱性が修正されている代替手段を探してみます。

ソースが利用できない場合、アプリを逆コンパイルして JAR ファイルを確認します。Dexguard や Proguard が適切に適用されている場合、ライブラリに関するバージョン情報は難読化されていることが多く、そのため失われています。そうでない場合には特定のライブラリの Java ファイルのコメントに非常に多くの情報を見つけることができます。MobSF などのツールはアプリケーションに同梱されている可能性のあるライブラリの解析に役立ちます。コメントや特定のバージョンで使用されている特定のメソッドを介して、ライブラリのバージョンを取得できる場合には、手動で CVE を検索します。

アプリケーションがリスクの高いアプリケーションである場合、ライブラリを手動で検査することになります。その場合、ネイティブコードに対する特定の要件があり、 "[コード品質のテスト](0x04h-Testing-Code-Quality.md)" の章にあります。その次に、ソフトウェアエンジニアリングのすべてのベストプラクティスが適用されているかどうかを調査するのが適切です。

#### アプリケーションのライブラリが使用しているライセンスの検出

著作権法が侵害されていないことを確認するには、 `License Gradle Plugin` などの、さまざまなライブラリを繰り返し処理できるプラグインを使用して、依存関係をチェックすることが最善です。このプラグインは以下の手順で使用できます。

`build.gradle` ファイルに以下を追加します。

```default
plugins {
    id "com.github.hierynomus.license-report" version"{license_plugin_version}"
}
```

プラグインがピックアップされたら、以下のコマンドを使用します。

```bash
$ gradle assemble
$ gradle downloadLicenses
```

これでライセンスレポートが生成されます。これを使用してサードパーティライブラリが使用するライセンスを調べることができます。使用許諾契約をチェックして、著作権表示をアプリに含める必要があるかどうか、およびライセンスの種類がアプリケーションのコードをオープンソースにする必要があるかどうかを確認します。

依存関係チェックと同様に、 SourceClear, Snyk, Blackduck など、ライセンスもチェックできる商用ツールがあります。

> 注: サードパーティライブラリで使用されているライセンスモデルの意味合いについて不明な点がある場合には、法律の専門家に相談してください。

ライブラリにアプリケーション IP をオープンソースにする必要があるライセンスが含まれている場合、同様の機能を提供するために使用できるライブラリの代替があるかどうかを確認します。

注: ハイブリッドアプリの場合は、使用しているビルドツールを確認してください。ほとんどのツールには使用されているライセンスを見つけるためのライセンス列挙プラグインがあります。

ソースが利用できない場合、アプリを逆コンパイルして JAR ファイルを確認できます。Dexguard や Proguard が正しく適用されていると、ライブラリに関するバージョン情報が失われていることがよくありますが、そうでなければたいていは特定のライブラリの Java ファイルのコメントにあります。MobSF などのツールはアプリケーションに同梱されている可能性のあるライブラリの解析に役立ちます。ライブラリのバージョンをコメントから、または特定のバージョンで使用されている特定のメソッドから取得できる場合には、手作業でそれらのライセンスを調べることができます。

### 動的解析

このセクションの動的解析はライセンスの著作権が遵守されているかどうかを検証することを含んでいます。これは多くの場合アプリケーションが `about` や `EULA` セクションを持つべきであることを意味しています。このセクションにはサードパーティライブラリのライセンスで必要とされる著作権に関する記述が記載されています。

## 例外処理のテスト (MSTG-CODE-6 および MSTG-CODE-7)

### 概要

例外はアプリケーションが正常ではない状態やエラーのある状態になったときに発生します。 Java と C++ のいずれも例外をスローすることがあります。例外処理のテストとは UI やアプリのログ出力メカニズムを介して機密情報を開示することなく、アプリが例外を処理して安全な状態に遷移することを確認することです。

#### 静的解析

ソースコードをレビューしてアプリケーションを理解し、さまざまな種類のエラー (IPC 通信、リモートサービス呼び出しなど) を処理する方法を特定します。この段階で確認すべきことの例をいくつか以下に示します。

- アプリケーションが正しく設計され統一されたスキームを使用して [例外を処理する](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047 "Exceptional Behavior (ERR)") ことを確認します。
- 適切なヌルチェック、境界チェックなどを作成して、標準的な `RuntimeException` 群 (`NullPointerException`, `IndexOutOfBoundsException`, `ActivityNotFoundException`, `CancellationException`, `SQLException` など) に対応します。 [`RuntimeException` の利用可能なサブクラスの概要](https://developer.android.com/reference/java/lang/RuntimeException.html "Runtime Exception Class") は Android 開発者ドキュメントにあります。 `RuntimeException` の子は意図的にスローされるべきであり、そのインテントは呼び出し側のメソッドで処理されるべきです。
- すべての非実行時 `Throwable` には適切な catch ハンドラが存在し、実際の例外を適切に処理することを確認します。
- 例外がスローされたとき、アプリケーションが同様の動作を引き起こす例外のための集中化されたハンドラを持っていることを確認します。これは静的クラスにすることができます。メソッドに固有の例外については、特定の catch ブロックを提供します。
- UI やログステートメントで例外を処理する際に、アプリケーションが機密情報を開示しないことを確認します。例外がユーザーに問題を説明するのに十分詳細であることを確認します。
- リスクの高いアプリケーションにより処理されるすべての機密情報が `finally` ブロックの実行時に常に消去されることを確認します。

```java
byte[] secret;
try{
    //use secret
} catch (SPECIFICEXCEPTIONCLASS | SPECIFICEXCEPTIONCLASS2 e) {
    // handle any issues
} finally {
    //clean the secret.
}
```

キャッチされていない例外に対して汎用的な例外ハンドラを追加することは、クラッシュが差し迫っている際にアプリケーションの状態をリセットするためのベストプラクティスです。

```java
public class MemoryCleanerOnCrash implements Thread.UncaughtExceptionHandler {

    private static final MemoryCleanerOnCrash S_INSTANCE = new MemoryCleanerOnCrash();
    private final List<Thread.UncaughtExceptionHandler> mHandlers = new ArrayList<>();

    //initialize the handler and set it as the default exception handler
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

ハンドラのイニシャライザはカスタム `Application` クラス (例えば `Application` を extends するクラス) で呼び出す必要があります。

```java
@Override
protected void attachBaseContext(Context base) {
    super.attachBaseContext(base);
    MemoryCleanerOnCrash.init();
}
```

### 動的解析

動的解析を行うにはいくつかの方法があります。

- Xposed を使用してメソッドにフックし、予期しない値でメソッドを呼び出すか、予期しない値 (NULL 値など) で既存の変数を上書きします。
- Android アプリケーションの UI フィールドに予期しない値を入力します。
- 予期しない値でインテントや公開プロバイダを使用してアプリケーションと対話します。
- ネットワーク通信やアプリケーションに保存されたファイルを改竄します。

アプリケーションはクラッシュしてはいけません。以下のようにすべきです。

- エラーから回復します。もしくは継続できないことをユーザーに知らせることができる状態に遷移します。
- 必要に応じて、ユーザーに適切な対応をとるように指示します (そのメッセージは機密情報を漏洩してはいけません) 。
- アプリケーションで使用されるログ出力メカニズムにはいかなる情報も提供しません。

## メモリ破損バグ (MSTG-CODE-8)

多くの場合 Android アプリケーションはメモリ破損問題のほとんどが対処されている VM 上で実行されます。
これはメモリ破損バグがないという意味ではありません。たとえば [CVE-2018-9522](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9522 "CVE in StatsLogEventWrapper") では Parcels を使用したシリアル化の問題に関連しています。また、ネイティブコードでは、一般的なメモリ破損のセクションで説明したのと同じ問題が引き続き発生します。さらに、 [BlackHat で](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf "Stagefright") 示された Stagefright 攻撃のように、サポートサービスにメモリバグが見られます。

メモリリークもよく問題となります。これはたとえば `Context` オブジェクトへの参照が `Activity` 以外のクラスに渡される場合や、 `Activity` クラスへの参照をヘルパークラスに渡す場合に発生することがあります。

### 静的解析

いろいろなアイテムを探してみます。

- ネイティブコードの部分はありますか。もしあれば、一般的なメモリ破損のセクションで与えられた問題をチェックします。ネイティブコードは JNI ラッパー、 .CPP/.H/.C ファイル、 NDK や他のネイティブフレームワークがあれば簡単に発見できます。
- Java コードや Kotlin コードはありますか。 [Android デシリアライゼーション脆弱性の簡単な歴史](https://securitylab.github.com/research/android-deserialization-vulnerabilities "android deserialization") で説明されているような、シリアライゼーション/デシリアライゼーション問題を探します。

Java/Kotlin コードでもメモリリークが発生する可能性があることに注意します。未登録ではない BroadcastReceivers 、 `Activity` または `View` クラスへの静的参照、 `Context` への参照をもつシングルトンクラス、内部クラス参照、匿名クラス参照、 AsyncTask 参照、ハンドラ参照、スレッディングの誤り、 TimerTask 参照などさまざまなアイテムを探します。詳細は以下で確認してください。

- [Android でメモリリークを回避する9つの方法](https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e "9 ways to avoid memory leaks in Android")
- [Android のメモリリークパターン](https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570 "Memory Leak Patterns in Android").

### 動的解析

実行にはいろいろな手順があります。

- ネイティブコードの場合、 Valgrind または Mempatrol を使用して、コードによるメモリ使用量とメモリ呼び出しを解析します。
- Java/Kotlin コードの場合、アプリを再コンパイルして [Squares leak canary](https://github.com/square/leakcanary "Leakcanary") を使用してみます。
- [Android Studio の Memory Profiler](https://developer.android.com/studio/profile/memory-profiler "Memory profiler") でリークがないか確認します。
- [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda "Android Java Deserialization Vulnerability Tester") でシリアル化脆弱性がないか確認します。

## フリーのセキュリティ機能が有効であることの確認 (MSTG-CODE-9)

### 概要

Java クラスはデコンパイルが容易であるため、リリースバイトコードに基本的な難読化を適用することをお勧めします。ProGuard はコードを縮小および難読化し、 Android Java アプリのバイトコードから不要なデバッグ情報を取り除く簡易な方法を提供します。クラス名、メソッド名、変数名などの識別子を無意味な文字列に置き換えます。これはレイアウト難読化の一種であり、プログラムのパフォーマンスに影響を与えない点で「フリー」です。

ほとんどの Android アプリケーションは Java ベースであるため、 [バッファオーバーフロー脆弱性に対する免疫があります](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow "Java Buffer Overflows") 。とはいえ、 Android NDK を使用している場合には依然としてバッファオーバーフロー脆弱性が存在する可能性がありますので、セキュアなコンパイラ設定を検討します。

### 静的解析

ソースコードが提供されている場合、build.gradle ファイルを確認することで難読化設定が適用されているか分かります。以下の例では、`minifyEnabled` と `proguardFiles` が設定されていることが分かります。一部のクラスを難読化から保護するために (`-keepclassmembers` および `-keep class` を使用して) 例外を作成することが一般的です。したがって、 ProGuard 構成ファイルを監査してどのクラスが除外されているかを確認することが重要です。`getDefaultProguardFile('proguard-android.txt')` メソッドはデフォルトの ProGuard 設定を `<Android SDK>/tools/proguard/` フォルダから取得します。

アプリを縮小、難読化、最適化する方法の詳細は [Android 開発者ドキュメント](https://developer.android.com/studio/build/shrink-code "Shrink, obfuscate, and optimize your app") にあります。

> Android Studio 3.4 または Android Gradle plugin 3.4.0 以降を使用してプロジェクトをビルドする場合、プラグインはコード最適化を実行するために ProGuard を使用しなくなりました。代わりに、プラグインは R8 コンパイラで動作します。R8 は既存のすべての ProGuard ルールファイルで機能するため、 R8 を使用するように Android Gradle plugin を更新しても既存のルールを変更する必要はありません。

R8 は Google の新しいコード縮小ツールであり、 Android Studio 3.3 beta で導入されました。デフォルトでは R8 は行番号、ソースファイル名、変数名など、デバッグに役立つ属性を削除します。R8 はフリーの Java クラスファイル縮小ツール、最適化ツール、難読化ツール、事前検証ツールであり、 ProGuard よりも高速です。[詳細については Android 開発者ブログ記事](https://android-developers.googleblog.com/2018/11/r8-new-code-shrinker-from-google-is.html "R8") も参照ください。Android の SDK ツールに同梱されています。リリースビルドで縮小を有効にするには、 build.gradle に以下を追加します。

```default
android {
    buildTypes {
        release {
            // Enables code shrinking, obfuscation, and optimization for only
            // your project's release build type.
            minifyEnabled true

            // Includes the default ProGuard rules files that are packaged with
            // the Android Gradle plugin. To learn more, go to the section about
            // R8 configuration files.
            proguardFiles getDefaultProguardFile(
                    'proguard-android-optimize.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
```

`proguard-rules.pro` ファイルはカスタム ProGuard ルールを定義する場所です。`-keep` フラグで R8 により削除されない特定のコードを保持できます。そうしないとエラーが発生する可能性があります。例えば、一般的な Android クラスを保持するには、以下のサンプル `proguard-rules.pro` 構成ファイルのようにします。

```default
...
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
...
```

[以下の構文](https://developer.android.com/studio/build/shrink-code#configuration-files "Customize which code to keep") でプロジェクト内の特定クラスやライブラリに対してこれをより詳細に定義できます。

```default
-keep public class MyClass
```

### 動的解析

ソースコードが提供されていない場合には、 APK を逆コンパイルしてコードベースが難読化されているかどうかを確認できます。DEX コードを JAR ファイルに変換するために利用できるツールがいくつかあります (dex2jar など) 。JAR ファイルは JD-GUI などのツールで開くことができ、クラス名、メソッド名、変数名が人間が判読できるものではないことを確認するために使用できます。

以下に難読化されたコードブロックのサンプルを示します。

```java
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

## 参考情報

### OWASP MASVS

- MSTG-CODE-1: "アプリは有効な証明書で署名およびプロビジョニングされている。その秘密鍵は適切に保護されている。"
- MSTG-CODE-2: "アプリはリリースモードでビルドされている。リリースビルドに適した設定である（デバッグ不可など）。"
- MSTG-CODE-3: "デバッグシンボルはネイティブバイナリから削除されている。"
- MSTG-CODE-4: "デバッグコードおよび開発者支援コード (テストコード、バックドア、隠し設定など) は削除されている。アプリは詳細なエラーやデバッグメッセージをログ出力していない。"
- MSTG-CODE-5: "モバイルアプリで使用されるライブラリ、フレームワークなどのすべてのサードパーティコンポーネントを把握し、既知の脆弱性を確認している。"
- MSTG-CODE-6: "アプリは可能性のある例外をキャッチし処理している。"
- MSTG-CODE-7: "セキュリティコントロールのエラー処理ロジックはデフォルトでアクセスを拒否している。"
- MSTG-CODE-8: "アンマネージドコードでは、メモリはセキュアに割り当て、解放、使用されている。"
- MSTG-CODE-9: "バイトコードの軽量化、スタック保護、PIEサポート、自動参照カウントなどツールチェーンにより提供されるフリーのセキュリティ機能が有効化されている。"

### ツール

- ProGuard - <https://www.guardsquare.com/en/proguard>
- jarsigner - <http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html>
- Xposed - <http://repo.xposed.info/>
- Drozer - <https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-drozer-user-guide-2015-03-23.pdf>
- GNU nm - <https://ftp.gnu.org/old-gnu/Manuals/binutils-2.12/html_node/binutils_4.html>
- Black Duck - <https://www.blackducksoftware.com/>
- Sourceclear - <https://www.sourceclear.com/>
- Snyk - <https://snyk.io/>
- Gradle license plugn - <https://github.com/hierynomus/license-gradle-plugin>
- Dependency-check-gradle - <https://github.com/jeremylong/dependency-check-gradle>
- MobSF - <https://www.github.com/MobSF/Mobile-Security-Framework-MobSF>
- Squares leak canary - <https://github.com/square/leakcanary>
- Memory Profiler from Android Studio - <https://developer.android.com/studio/profile/memory-profiler>
- Android Java Deserialization Vulnerability Tester - <https://github.com/modzero/modjoda>

### Memory Analysis References

- A brief history of Android deserialization vulnerabilities - <https://securitylab.github.com/research/android-deserialization-vulnerabilities>
- 9 ways to avoid memory leaks in Android - <https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e>
- Memory Leak Patterns in Android - <https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570>

### Android Documentation

- APK signature scheme with key rotation - <https://developer.android.com/about/versions/pie/android-9.0#apk-key-rotation>
