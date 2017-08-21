## Android プラットフォーム概要

この章ではアーキテクチャの観点から Android を紹介し、セキュリティメカニズムの詳細情報を読者に提供します。次に、Android アプリケーションの構造について説明し、プロセス間通信 (IPC) のメカニズムを説明します。最後に、Android アプリケーションの公開方法を読者に説明します。

Android プラットフォームの詳細については、公式の Android developer documentation <sup>[13]</sup> をご覧ください。このセクションでは多くの例が示されていますが、このガイドはこのトピックの唯一の参考資料と考えるべきではありません。

### Android アーキテクチャとセキュリティメカニズム

Android はオープンソースプラットフォームであり、今日では多くのデバイスで利用されています。

* モバイルフォンおよびタブレット
* ウェアラブル
* TV などの一般的な「スマート」デバイス

また、デバイスにプリインストールされているアプリだけでなく、Google Play などのマーケットプレイスからダウンロードできるサードパーティのアプリをサポートするアプリケーション環境も用意されています。

Android のソフトウェアスタックはさまざまなレイヤーで構成されています。各レイヤーは特定の動作を定義しており、上のレイヤーに特定のサービスを提供しています。

![Android Software Stack](Images/Chapters/0x05a/android_software_stack.png)

最も低いレベルでは、Android は Linux Kernel を使用しており、コアオペレーティングシステムが構築されています。ハードウェア抽象化レイヤーはハードウェアベンダーのための標準インタフェースを定義しています。HAL の実装は共有ライブラリモジュール (.so ファイル) にパッケージ化されています。これらのモジュールは適切な時期に Android システムによってロードされます。Android ランタイムはコアライブラリと Dalvik VM (仮想マシン) で構成されています。アプリは大半が Java で実装され、Java クラスファイルにコンパイルされます。しかし、Android は JVM ではなく Dalvik VM を統合しているので、Java クラスファイルはさらに `dex` 形式にコンパイルされます。`dex` ファイルは APK (実行可能ファイルを含むすべてのリソースの ZIP アーカイブ) にパックされ、Dalvik VM 内でアンパックおよび実行されます。
次の画像では、Java の典型的なプロジェクトをコンパイルおよび実行する通常のプロセスと、Dalvik VM を使用する Android プロセスとの違いを示しています。

![Java vs Dalvik](Images/Chapters/0x05a/java_vs_dalvik.png)

Android 4.4 (KitKat) では Dalvik VM の後継である Android Runtime (ART) が導入されました。しかし、実際に一般向けに設定されたのは2014年11月の Android 5.0 (Lollipop) で、Dalvik を置き換えました。KitKat では、ART は「開発者」メニューで明示的に試したい方のみ利用可能でした。モバイルの通常の動作を変更するための操作をユーザーが行わない場合、Dalvik が使用されました。

Android では、アプリはランタイム環境にある Dalvik と呼ばれる仮想マシン (VM) のそれら自身の環境で実行されます。各 VM はモバイル全体をエミュレートし、このアクセスを制御しながら Linux カーネルから関連するリソースにアクセスします。アプリはハードウェアリソースに直接アクセスすることはできず、その実行環境は互いに分離されています。これにより、リソースやアプリをきめ細かくコントロールできます。例えば、アプリがクラッシュしたときに、他のアプリの動作を妨げることはなく、その環境およびアプリ自体のみを再起動します。また、実際のアプリはモバイルハードウェア上で直接実行されないため、VM がアプリの共通のハードウェアをエミュレートし、さまざまなアーキテクチャ (ARM, x86 など) で同じアプリ (同じバイトコード) を使用できます。同時に、VM はアプリに提供されるリソースの量をコントロールし、あるアプリがすべてのリソースを使用して他にリソースが残らないようにすることを防ぎます。
Android では、アプリはバイトコード (.dex ファイル、「Android アプリケーションの概要」セクションを参照) としてインストールされます。Dalvik では、このバイトコードは実行時に現在のプロセッサにあった機械語にコンパイルされます。そのようなメカニズムは Just In Time (JIT) として知られています。但しこれは、このようなコンパイルがアプリを特定のモバイルで実行するごとに行われることを意味します。その結果、Dalvik はインストール時に一度だけアプリをコンパイルするように改良されました (この原則は AOT つまり Ahead Of Time と呼ばれています) 。ART が誕生し、コンパイルは一度だけ要求され、実行時に貴重な時間を節約できました (アプリの実行時間は2つに分けられます) 。もう一つの利点は ART が Dalvik より消費電力が少なく、ユーザーがモバイルデバイスとそのバッテリーをより長く使用できることです。

#### Android ユーザーとグループ

Android は Linux カーネルをベースにしたシステムです。しかし、他の Unix ライクなシステムと同じようにユーザーを扱うわけではありません。システム内にユーザーのリストを記述する _/etc/password_ ファイルはありません。代わりに Android は Linux カーネルのマルチユーザーサポートを利用して、アプリケーションのサンドボックス化を実現しています。各アプリケーションは別々のユーザーの下で実行しています (一部の例外を除きます) 。
ファイル [system/core/include/private/android_filesystem_config.h](http://androidxref.com/7.1.1_r6/xref/system/core/include/private/android_filesystem_config.h) には、システムプロセスに使用される事前定義されたユーザーおよびグループの完全なリストがあります。他のアプリケーション用の UID はシステムにインストールされたときに追加されます。詳細については、 [overview of Android application sandbox](https://pierrchen.blogspot.mk/2016/09/an-walk-through-of-android-uidgid-based.html) を確認ください。
以下のファイルは Android Nougat 用に定義されているユーザーの一部を示しています。

```
    #define AID_ROOT             0  /* traditional unix root user */

    #define AID_SYSTEM        1000  /* system server */
	...
    #define AID_SHELL         2000  /* adb and debug shell user */
	...
    #define AID_APP          10000  /* first app user */
	...
```

### Android アプリについて

#### オペレーティングシステムとの通信

上で説明したように、Android ではアプリケーションは Java で書かれ、`dex` バイトコードにコンパイルされます。システムリソースは直接的にはアクセスされません。代わりに、オペレーティングシステムはそれらと相互作用するライブラリを提供します。例えば、
* 接続 (Wifi, Bluetooth, NFC, ...)
* ファイル
* カメラ
* 位置情報 (GPS)
* マイク
* など

Android Framework は抽象レイヤーで、Java から簡単に使用できる高水準 API を提供しています。システムライブラリを深く理解する必要はありません。他にも、セキュア IPC や暗号化などの一般的なセキュリティ機能を提供しています。このガイドの執筆時点では、Android の最新バージョンは 7.1 (Nougat)、API レベルは 25 です。

API は最初の Android バージョン (2008年9月) 以降、多くの進化を遂げました。重大なバグフィックスやセキュリティパッチは通常、いくつかのバージョンをさかのぼって適用されます。このガイドの執筆時点でサポートされているもっとも古い Android バージョンは 4.4 (KitKat) 、API レベルは 19 です。

注目すべき API バージョンは以下の通りです。
- Android 4.2 Jelly Bean (API 16) 2012年11月 (SELinux の導入)
- Android 4.3 Jelly Bean (API 18) 2013年7月 (SELinux がデフォルトで有効になる)
- Android 4.4 KitKat (API 19) 2013年10月 (いくつかの新しい API と ART が導入された)
- Android 5.0 Lollipop (API 21) 2014年11月 (ART がデフォルトになる、その他多くの新機能)
- Android 6.0 Marshmallow (API 23) 2015年10月 (多くの新機能と改善点、インストール時の是非ではなく実行時のきめ細かい権限付与を含む)
- Android 7.0 Nougat (API 24-25) 2016年8月 (ART 上の新しい JIT コンパイラ)
- Android 8.0 O (API 26) beta (主要なセキュリティの修正予定)

アプリはさまざまなソースから Android デバイスにインストールできます。ローカルで USB を介して、Google の公式ストア (Google Play Store) から、または代替のストアから。

#### アプリフォルダの構造

(Google Play Store から、または外部ソースから) インストールされた Android アプリは `/data/app/` に配置されます。このフォルダはルート権限なしでは表示できないため、APK の正確な名前を取得するには別な方法を使用する必要があります。インストールされているすべての APK を一覧表示するには、Android Debug Bridge (adb) を使用できます。ADB によりテスト技術者が実デバイスと直接対話できます。例えば、デバイスのコンソールにアクセスして、追加のコマンドを発行したり、インストールされているパッケージを一覧表示したり、プロセスを開始や終了できます。
これを行うには、デバイスが USB デバッグを有効にする必要があり (開発者設定にあります) 、USB 経由で接続する必要があります。あるいは、ADB が [TCP/IP 経由で接続](https://stackoverflow.com/questions/2604727/how-can-i-connect-to-android-with-adb-over-tcp) するようにデバイスを設定することもできます。いずれの場合も ADB は同じように動作しますが、私たちは USB 経由の接続が確立されているケースをデフォルトと想定しています。

USB デバッグが有効になると、接続されたデバイスは以下のコマンドで表示できます。

```bash
$ adb devices
List of devices attached
BAZ5ORFARKOZYDFA	device
```

次に、以下のコマンドはインストールされているすべてのアプリとその場所を表示します。

```bash
$ adb shell pm list packages -f
package:/system/priv-app/MiuiGallery/MiuiGallery.apk=com.miui.gallery
package:/system/priv-app/Calendar/Calendar.apk=com.android.calendar
package:/system/priv-app/BackupRestoreConfirmation/BackupRestoreConfirmation.apk=com.android.backupconfirm
```

これらのアプリの一つをデバイスから取得するには、以下のコマンドを使用します。

```bash
$ adb pull /data/app/com.google.android.youtube-1/base.apk
```

このファイルにはアプリの「インストーラ」のみが含まれています。つまり、これは開発者がストアにアップロードしたアプリです。
アプリのローカルデータは /data/data/PACKAGE-NAME に格納され、以下の構造を持ちます。

```bash
drwxrwx--x u0_a65   u0_a65            2016-01-06 03:26 cache
drwx------ u0_a65   u0_a65            2016-01-06 03:26 code_cache
drwxrwx--x u0_a65   u0_a65            2016-01-06 03:31 databases
drwxrwx--x u0_a65   u0_a65            2016-01-10 09:44 files
drwxr-xr-x system   system            2016-01-06 03:26 lib
drwxrwx--x u0_a65   u0_a65            2016-01-10 09:44 shared_prefs
```

* **cache**: この場所は実行時にアプリデータをキャッシュするために使用されます。WebView キャッシュを含みます。
* **code_cache**: この場所はアプリケーション固有のキャッシュディレクトリで、キャッシュされたコードを格納するためにファイルシステム上に設計されています。LOLLIPOP 以降を実行するデバイスでは、特定のアプリケーションがアップグレードされるとき、およびプラットフォーム全体がアップグレードされるときに、システムがこの場所に格納されているファイルを削除します。この場所は実行時にアプリケーションにより生成されたコンパイル済みまたは最適化されたコードを格納するために最適です。このパスはプライベートストレージに存在するため、アプリは返されたパスへの読み書きのための特別な権限は必要ありません。
* **databases**: このフォルダは、例えば、ユーザーデータを格納するために、実行時にアプリにより生成された sqlite データベースファイルを格納します。
* **files**: このフォルダは、内部ストレージを使用する場合に、アプリで作成されたファイルを格納するために使用されます。
* **lib**: このフォルダは C/C++ で書かれたネイティブライブラリを格納するために使用されます。これらのライブラリは .so, .dll (x86 サポート) のファイル拡張子を持ちます。このフォルダにはアプリがネイティブライブラリを持つプラットフォーム用のサブフォルダが含まれています。
   * armeabi: すべての ARM ベースのプロセッサ専用のコンパイル済みコード
   * armeabi-v7a: すべての ARMv7 以上をベースとしたプロセッサ専用のコンパイル済みコード
   * arm64-v8a: すべての ARMv8 arm64 以上をベースとしたプロセッサ専用のコンパイル済みコード
   * x86: x86 プロセッサ専用のコンパイル済みコード
   * x86_64: x86_64 プロセッサ専用のコンパイル済みコード
   * mips: MIPS プロセッサ専用のコンパイル済みコード
* **shared_prefs**: このフォルダは実行時にアプリにより生成された設定ファイルを格納するために使用されます。データ、設定、セッションなどアプリの現在の状態を保存します。ファイルフォーマットは XML です。

#### APK の構造

Android のアプリは拡張子 .apk のファイルです。このファイルは署名付き zip ファイルで、アプリケーションのリソース、バイトコードなどをすべて含んでいます。unzip すると、以下のディレクトリ構造が一般的に識別されます。

```bash
$ unzip base.apk
$ ls -lah
-rw-r--r--   1 sven  staff    11K Dec  5 14:45 AndroidManifest.xml
drwxr-xr-x   5 sven  staff   170B Dec  5 16:18 META-INF
drwxr-xr-x   6 sven  staff   204B Dec  5 16:17 assets
-rw-r--r--   1 sven  staff   3.5M Dec  5 14:41 classes.dex
drwxr-xr-x   3 sven  staff   102B Dec  5 16:18 lib
drwxr-xr-x  27 sven  staff   918B Dec  5 16:17 res
-rw-r--r--   1 sven  staff   241K Dec  5 14:45 resources.arsc
```

* **AndroidManifest.xml**: アプリのパッケージ名、ターゲット、最小 API バージョン、アプリの設定、コンポーネント、ユーザーが付与したパーミッションなどの定義を含みます。
* **META-INF**: このフォルダはアプリのメタデータを含みます。
   * MANIFEST.MF: アプリリソースのハッシュを格納します。
   * CERT.RSA: アプリの証明書です。
   * CERT.SF: MANIFEST.MF ファイル内の対応する行のリソースおよび SHA-1 ダイジェストのリストです。
* **assets**: アプリアセット (XML, Javascript, 画像など Android アプリ内で使用されるファイル) を含むディレクトリです。AssetManager で取得できます。
* **classes.dex**: Dalvik 仮想マシン/ Android Runtime が理解できる DEX ファイル形式でコンパイルされたクラスです。DEX は Dalvik 仮想マシン用の Java バイトコードです。小型のデバイスで動作するように最適化されています。
* **lib**: APK の一部であるライブラリを含むディレクトリです。例えば、Android SDK の一部ではないサードパーティのライブラリです。
* **res**: resources.arsc にコンパイルされていないリソースを含むディレクトリです。
* **resources.arsc**: レイアウト用の XML ファイルなどのプリコンパイル済みのリソースを含むファイルです。

APK 内の一部のリソースは非標準のアルゴリズムを使用して圧縮されているため (AndroidManifest.xml など) 、単純に unzip したファイルではすべての情報は明らかになりません。よりよい方法はツール apktool を使用して、ファイルを unpack および uncompress することです。以下は apk に含まれるファイルのリストです。

```bash
$ apktool d base.apk
I: Using Apktool 2.1.0 on base.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /Users/sven/Library/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
$ cd base
$ ls -alh
total 32
drwxr-xr-x    9 sven  staff   306B Dec  5 16:29 .
drwxr-xr-x    5 sven  staff   170B Dec  5 16:29 ..
-rw-r--r--    1 sven  staff    10K Dec  5 16:29 AndroidManifest.xml
-rw-r--r--    1 sven  staff   401B Dec  5 16:29 apktool.yml
drwxr-xr-x    6 sven  staff   204B Dec  5 16:29 assets
drwxr-xr-x    3 sven  staff   102B Dec  5 16:29 lib
drwxr-xr-x    4 sven  staff   136B Dec  5 16:29 original
drwxr-xr-x  131 sven  staff   4.3K Dec  5 16:29 res
drwxr-xr-x    9 sven  staff   306B Dec  5 16:29 smali
```

* **AndroidManifest.xml**: このファイルは圧縮されておらず、テキストエディタで開けます。
* **apktool.yml** : このファイルは apktool の出力についての情報が含まれています。
* **assets**: アプリアセット (XML, Javascript, 画像など Android アプリ内で使用されるファイル) を含むディレクトリです。AssetManager で取得できます。
* **lib**: APK の一部であるライブラリを含むディレクトリです。例えば、Android SDK の一部ではないサードパーティのライブラリです。
* **original**: このフォルダには MANIFEST.MF ファイルが含まれています。ファイルには JAR の内容に関するメタデータおよび APK の署名を格納しています。このフォルダは META-INF とも呼ばれます。
* **res**: resources.arsc にコンパイルされていないリソースを含むディレクトリです。
* **smali**: smali に逆アセンブルされた Dalvik バイトコードを含むディレクトリです。smali は Dalvik 実行可能ファイルの品源が読める形式です。

#### 通常のアプリケーションの Linux UID/GID

新しいアプリが Android にインストールされると、新しい UID が割り当てられます。一般的にアプリには 10000 (_AID_APP_) から 99999 の範囲の UID が割り当てられます。Android アプリにはその UID に基づくユーザー名も受け取ります。例えば、UID 10188 のアプリはユーザー名 _u0_a188_ を受け取ります。
アプリがいくつかのパーミッションを要求し、それらが付与されている場合、対応するグループ ID がアプリのプロセスに追加されます。
例えば、以下のアプリのユーザー ID は 10188 であり、_android.permission.INTERNET_ パーミッションに関連するグループであるグループ ID 3003 (_inet_) にも属しています。`id` コマンドの結果を以下に示します。

```
$ id
uid=10188(u0_a188) gid=10188(u0_a188) groups=10188(u0_a188),3003(inet),9997(everybody),50188(all_a188) context=u:r:untrusted_app:s0:c512,c768
```

グループ ID とパーミッションの関係はファイル [frameworks/base/data/etc/platform.xml](http://androidxref.com/7.1.1_r6/xref/frameworks/base/data/etc/platform.xml) に定義されています。
```
<permission name="android.permission.INTERNET" >
	<group gid="inet" />
</permission>

<permission name="android.permission.READ_LOGS" >
	<group gid="log" />
</permission>

<permission name="android.permission.WRITE_MEDIA_STORAGE" >
	<group gid="media_rw" />
	<group gid="sdcard_rw" />
</permission>
```

Android セキュリティを理解するうえで重要な要素は、すべてのアプリが同じレベルの権限を持っているということです。ネイティブアプリとサードパーティアプリはいずれも同じ API 上に構築され、同様の環境で実行されます。また、すべてのアプリは 'root' ではなく、ユーザーレベルの権限で実行されます。つまり、基本的にはアプリはいくつかのアクションを実行したり、ファイルシステムの一部にアクセスすることができません。'root' 特権でアプリを実行できるようにするには (ネットワークにパケットを注入する、Python などのインタプリタを実行するなど) モバイルをルート化する必要があります。

##### Zygote

Android を起動すると、init で `Zygote` というプロセスが立ち上がります <sup>[10]</sup> 。これはシステムサービスで、アプリを実行するために使用されます。Zygote は /dev/socket/zygote でソケットを開き、新しいアプリケーションを開始する要求を待ちます。`Zygote` は既に初期化されているプロセスであり、どのアプリでも必要とされるすべてのコアライブラリを含んでいます。ソケットが要求を受け取ると、Zygote プロセスをフォークすることにより Android 上で新しいアプリが始まり、アプリ固有のコードがロードおよび実行されます。

#### アプリサンドボックス

アプリは Android アプリケーションサンドボックス内で実行されます。デバイス上の他のアプリからアプリデータとコードの実行を分離し、付加的なセキュリティ層を追加します。

(Google Play Store または外部ソースから) 新しいアプリをインストールすると、ファイルシステムのパス `/data/data/<package name>` に新しいフォルダが作成されます。このフォルダは特定アプリのプライベートデータフォルダになります。

すべてのアプリは独自の一意な ID を持っていて、Android はアプリデータフォルダのモードを _read_ および _write_ に設定することをアプリの所有者にのみ割り当てます。

![Sandbox](Images/Chapters/0x05a/Selection_003.png)

この例では、Chrome と Calendar アプリは異なる UID と異なるフォルダ権限で完全に分離されています。

各フォルダに対して作成されたファイルシステム権限を調べることでことを確認できます。

```
drwx------  4 u0_a97              u0_a97              4096 2017-01-18 14:27 com.android.calendar
drwx------  6 u0_a120             u0_a120             4096 2017-01-19 12:54 com.android.chrome
```

但し、二つのアプリが同じ証明書で署名され、(_AndroidManifest.xml_ に _sharedUserId_ を含めることにより) 明示的に同じユーザー ID を共有している場合には、それぞれ他のデータディレクトリにアクセスできます。これが NFC アプリでどのように行われているかについては、以下の例を参照ください。

```
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
	package="com.android.nfc"
	android:sharedUserId="android.uid.nfc">
```


#### アプリコンポーネント

Android アプリはアーキテクチャを構成するいくつかの上位コンポーネントで構成されています。主なコンポーネントはアクティビティ、フラグメント、インテント、ブロードキャストレシーバ、コンテンツプロバイダ、およびサービスです。これらの要素はすべて Android オペレーティングシステムにより API 経由で利用可能な事前定義されたクラスの形式で提供されています。

##### Application Lifecycle

Android apps have their own lifecycles, that is under the control of the operating system. Therefore, apps need to listen to state changes and must be able to react accordingly. For instance, when the system needs resources, apps may be killed. The system selects the ones that will be killed according to the app priority: active apps have the highest priority (actually the same as Broadcast Receivers), followed by visible ones, running services, background services, and last useless processes (for instance apps that are still open but not in use since a significant time).

Apps implement several event managers to handle events: for example, the onCreate handler implements what has to be done on app creation and will be called on that event. Other managers include onLowMemory, onTrimMemory and onConfigurationChanged.

##### Manifest

Every app must have a manifest file, which embeds content in XML format. The name of this file is standardized as AndroidManifest.xml and is the same for every app. It is located in the root tree of the .apk file in which the app is published.

A manifest file describes the app structure as well as its exposed components (activities, services, content providers and intent receivers) and lists down the permissions it's requesting for. Permission filters for IPC can be implemented to refine the way the app will interact with the outside world. It also contains general metadata about the app, like its icon, its version number and the theme it uses for User Experience (UX). It may also list other information like the APIs it is compatible with (minimal, targeted and maximal SDK version) and the kind of storage it can be installed in (external or internal)<sup>[14]</sup>.

Here is an example of a manifest file, including the package name (the convention is to use a url in reverse order, but any string can be used), the app version, relevant SDKs, required permissions, exposed content providers, used broadcast receivers with intent filters, and the description of the app itself with its activities:
```
<manifest
	package="com.owasp.myapplication"
	android:versionCode="0.1" >

	<uses-sdk android:minSdkVersion="12"
		android:targetSdkVersion="22"
		android:maxSdkVersion="25" />

	<uses-permission android:name="android.permission.INTERNET" />

	<provider
		android:name="com.owasp.myapplication.myProvider"
		android:exported="false" />

	<receiver android:name=".myReceiver" >
		<intent-filter>
			<action android:name="com.owasp.myapplication.myaction" />
		</intent-filter>
	</receiver>

	<application
		android:icon="@drawable/ic_launcher"
		android:label="@string/app_name"
		android:theme="@style/Theme.Material.Light" >
		<activity
			android:name="com.owasp.myapplication.MainActivity" >
			<intent-filter>
				<action android:name="android.intent.action.MAIN" />
			</intent-filter>
		</activity>
	</application>
</manifest>
```

A manifest is a text file and can be edited within Android Studio, the preferred IDE for Android development. A lot more useful options can be added to manifest files, which are listed down in the official Android documentation<sup>[12]</sup>.

##### Activities

Activities make up the visible part of any app. More specifically, one activity exists per screen (e.g. user interface) in an app. For instance, apps that have 3 different screens implement 3 different activities, that allow the user to interact with the system (get and enter information). Activities are declared by extending the Activity class; they contain all user interface elements: fragments, views and layouts.

Activities implement manifest files. Each activity needs to be declared in the app manifest with the following syntax:

```
<activity android:name="ActivityName">
</activity>
```

When activities are not declared in manifests, they cannot be displayed and would raise an exception.

In the same way as apps do, activities also have their own lifecycle and need to listen to system changes to be able to handle them accordingly. Activities can have the following states: active, paused, stopped and inactive. These states are managed by Android operating system. Accordingly, activities can implement the following event managers:
- onCreate
- onSaveInstanceState
- onStart
- onResume
- onRestoreInstanceState
- onPause
- onStop
- onRestart
- onDestroy

An app may not explicitly implement all event managers; in that situation, default actions are taken. However, usually at least the onCreate manager is overridden by app developers, as this is the place where most user interface components are declared and initialised. onDestroy may be overridden as well in case some resources need to be explicitly released (like network connections or connections to databases) or if specific actions need to take place at the end of the app.

##### Fragments

Basically, a fragment represents a behavior or a portion of user interface in an Activity. Fragments have been introduced in Android with version Honeycomb 3.0 (API level 11).

User interfaces are made of several elements: views, groups of views, fragments and activities. As for them, fragments are meant to encapsulate parts of the interface to make reusability easier and better adapt to different size of screens. Fragments are autonomous entities in that they embed all they need to work in themselves (they have their own layout, own buttons etc.).  However, they must be integrated in activities to become useful: fragments cannot exist on their own. They have their own lifecycle, which is tied to the one of the activity that implements them.
As they have their own lifecycle, the Fragment class contains event managers, that can be redefined or extended. Such event managers can be onAttach, onCreate, onStart, onDestroy and onDetach. Several others exist; the reader should refer to Android specification for more details<sup>[15]</sup>.

Fragments can be implemented easily by extending the Fragment class provided by Android:

```Java
public class myFragment extends Fragment {
	...
}
```

Fragments don't need to be declared in manifest files as they depend on activities.

In order to manage its fragments, an Activity can use a Fragment Manager (FragmentManager class). This class makes it easy to find, add, remove and replace associated fragments.
Fragment Managers can be created simply with the following:

```Java
FragmentManager fm = getFragmentManager();
```

Fragments do not necessarily have a user interface: they can be a convenient and efficient way to manage background operations dealing with user interface in an app. For instance when a fragment is declared as persistent while its parent activity may be destroyed and created again.

##### Intents

Intents are messaging components used between apps and components. They can be used by an app to send information to its own components (for instance, start inside the app a new activity) or to other apps, and may be received from other apps or from the operating system. Intents can be used to start activities or services, run an action on a given set of data, or broadcast a message to the whole system. They are a convenient way to decouple components.

There are two kinds of intents: explicit and implicit.
* Explicit intents launch a specific app component, like an activity in your app. For instance:

```Java
	Intent intent = new Intent(this, myActivity.myClass);
```

* Implicit intents are sent to the system with a given action to perform on a given set of data ("http://www.example.com" in our example below). It is up to the system to decide which app or class will perform the corresponding service. For instance:

```Java
	Intent intent = new Intent(Intent.MY_ACTION, Uri.parse("http://www.example.com"));
```

Android uses intents to broadcast messages to apps, like an incoming call or SMS, important information on power supply (low battery for example) or network changes (loss of connection for instance). Extra data may be added to intents (through putExtra / getExtras).

Here is a short list of intents from the operating system. All constants are defined in the Intent class, and the whole list can be found in Android official documentation:
- ACTION_CAMERA_BUTTON
- ACTION_MEDIA_EJECT
- ACTION_NEW_OUTGOING_CALL
- ACTION_TIMEZONE_CHANGED

In order to improve security and privacy, a Local Broadcast Manager exists and is used to send and receive intents inside an app, without having them sent to the outside world (other apps or operating system). This is very useful to guarantee sensitive or private data do not leave the app perimeter (geolocation data for instance).

##### Broadcast Receivers

Broadcast Receivers are components that allow to receive notifications sent from other apps and from the system itself. This way, apps can react to events (either internal, from other apps or from the operating system). They are generally used to update a user interface, start services, update content or create user notifications.

Broadcast Receivers need to be declared in the Manifest file of the app. Any Broadcast Receiver must be associated to an intent filter in the manifest to specify which actions it is meant to listen with which kind of data. If they are not declared, the app will not listen to broadcasted messages. However, apps do not need to be started to receive intents: they are automatically started by the system when a relevant intent is raised.

An example of declaring a Broadcast Receiver with an Intent Filter in a manifest is:
```
	<receiver android:name=".myReceiver" >
		<intent-filter>
			<action android:name="com.owasp.myapplication.MY_ACTION" />
		</intent-filter>
	</receiver>
```

When receiving an implicit intent, Android will list all apps that have registered a given action in their filters. If more than one app is matching, then Android will list all those apps and will require the user to make a selection.

An interesting feature concerning Broadcast Receivers is that they be assigned a priority; this way, an intent will be delivered to all receivers authorized to get them according to their priority.

A Local Broadcast Manager can be used to make sure intents are received only from the internal app, and that any intent from any other app will be discarded. This is very useful to improve security.

##### Content Providers

Android is using SQLite to store data permanently: as it is in Linux, data is stored in files. SQLite is an open-source, light and efficient technology for relational data storage that does not require much processing power, making it ideal for use in the mobile world. An entire API is available to the developer with specific classes (Cursor, ContentValues, SQLiteOpenHelper, ContentProvider, ContentResolver, ...).
SQLite is not run in a separate process from a given app, but it is part of it.
By default, a database belonging to a given app is only accessible to this app. However, Content Providers offer a great mechanism to abstract data sources (including databases, but also flat files) for a more easy use in an app; they also provide a standard and efficient mechanism to share data between apps, including native ones. In order to be accessible to other apps, content providers need to be explicitly declared in the Manifest file of the app that will share it. As long as Content Providers are not declared, they are not exported and can only be called by the app that creates them.

Content Providers are implemented through a URI addressing scheme: they all use the content:// model. Whatever the nature of sources is (SQLite database, flat file, ...), the addressing scheme is always the same, abstracting what sources are and offering a unique scheme to the developer. Content providers offer all regular operations on databases: create, read, update, delete. That means that any app with proper rights in its manifest file can manipulate the data from other apps.

##### Services

Services are components provided by Android operating system (in the form of the Service class) that will perform tasks in the background (data processing, start intents and notifications, ...), without presenting any kind of user interface. Services are meant to run processing on the long term. Their system priorities are lower than the ones active apps have, but are higher than inactive ones. As such, they are less likely to be killed when the system needs resources; they can also be configured to start again automatically when enough resources become available in case they get killed. Activities are executed in the main app thread. They are great candidates to run asynchronous tasks.

##### Permissions

Because Android apps are installed in a sandbox and initially it does not have access to neither user information nor access to system components (such as using the camera or the microphone), it provides a system based on permissions where the system has a predefined set of permissions for certain tasks that the app can request.
As an example, if you want your app to use the camera on the phone you have to request the camera permission.
On Android versions before Marshmallow (API 23) all permissions requested by an app were granted at installation time. From Android Marshmallow onwards the user have to approve some permissions during app execution.

###### Protection Levels

Android permissions are classified in four different categories based on the protection level it offers.
- *Normal*: Is the lower level of protection, it gives apps access to isolated application-level feature, with minimal risk to other apps, the user or the system. It is granted during the installation of the App. If no protection level is specified, normal is the default value.
Example: `android.permission.INTERNET`
- *Dangerous*: This permission usually gives the app control over user data or control over the device that impacts the user. This type of permissoin may not be granted at installation time, leaving to the user decide whether the app should have the permission or not.
Example: `android.permission.RECORD_AUDIO`
- *Signature*: This permission is granted only if the requesting app was signed with the same certificate as the app that declared the permission. If the signature matches, the permission is automatically granted.
Example: `android.permission.ACCESS_MOCK_LOCATION`
- *SystemOrSignature*: Permission only granted to apps embedded in the system image or that were signed using the same certificated as the app that declared the permission.
Example: `android.permission.ACCESS_DOWNLOAD_MANAGER`

###### Requesting Permissions

Apps can request permissions of protection level Normal, Dangerous and Signature by inserting the XML tag `<uses-permission />` to its Android Manifest file.
The example below shows an AndroidManifes.xml sample requesting permission to read SMS messages:
```
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.permissions.sample" ...>

    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <application>...</application>
</manifest>
```
This will enable the app to read SMS messages at install time (before Android Marshmallow - 23) or will enable the app to ask the user to allow the permission at runtime (Android M onwards).

###### Declaring Permissions

Any app is able to expose its features or content to other apps installed on the system. It can expose the information openly or restrict it some apps by declaring a permission.
The example below shows an app declaring a permission of protection level *signature*.
```
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.permissions.sample" ...>

    <permission
    android:name="com.permissions.sample.ACCESS_USER_INFO"
    android:protectionLevel="signature" />
    <application>...</application>
</manifest>
```
Only apps signed with the same developer certificate can use this permission.

###### Enforcing Permissions on Android Components

It is possible to protect Android components using permissions. Activities, Services, Content Providers and Broadcast Receivers all can use the permission mechanism to protect its interfaces.
*Activities*, *Services* and *Broadcast Receivers* can enforce a permission by entering the attribute *android:permission* inside each tag in AndroidManifest.xml:
```
<receiver
    android:name="com.permissions.sample.AnalyticsReceiver"
    android:enabled="true"
    android:permission="com.permissions.sample.ACCESS_USER_INFO">
    ...
</receiver>
```
*Content Providers* are a little bit different. They allow separate permissions for read, write or access the Content Provider using a content URI.
- `android:writePermission`, `android:readPermission`: The developer can set separate permissions to read or write.
- `android:permission`: General permission that will control read and write to the Content Provider.
- `android:grantUriPermissions`: True if the Content Provider can be accessed using a content URI, temporarily overcoming the restriction of other permissions and False, if not.

### Signing and Publishing Process

Once an app has been successfully developed, the next step is to publish it to share it with others. However, apps cannot simply be put on a store and shared: for several reasons, they need to be signed. This is a convenient way to ensure that apps are genuine and authenticate them to their authors: for instance, an upgrade to an app will only be possible if the update is signed with the same certificate as the original app. Also, this is a way to allow sharing between apps that are signed with the same certificate when signature-based permissions are used.

#### Signing Process

During development, apps are signed with an automatically generated certificate. This certificate is inherently insecure and is used for debugging only. Most stores do not accept this kind of certificates when trying to publish, therefore another certificate, with more secure features, has to be created and used.

When an application  is installed onto an Android device, the Package Manager verifies that it has been signed with the certificate included in that APK. If the public key in the certificate matches the key used to sign any other APK on the device, the new APK has the option to share a UID with that APK. This facilitates interaction between multiple applications from the same vendor. Alternatively, it as also possible to specify security permissions the Signature protection level, restricting access to applications signed with the same key.

#### APK Signing Schemes

Android supports two application signing schemes: As of Android 7.0, APKs can be verified using the APK Signature Scheme v2 (v2 scheme) or JAR signing (v1 scheme). For backward compatibility, APKs signed with the v2 signature format can be installed on older Android devices, as long as these APKs are also v1-signed. Older platforms ignore v2 signatures and only verify v1 signatures <sup>[9]</sup>.

##### JAR Signing (v1 scheme):

In the original version of app signing, the signed APK is actually a standard signed JAR, which must contain exactly the entries listed in <code>META-INF/MANIFEST.MF</code>. All entries must be signed using the same certificate. This scheme does not protect some parts of the APK, such as ZIP metadata. The drawback with this scheme is that the APK verifier needs to process untrusted data structures before applying the signature, and discard data not covered by them. Also, the APK verifier must uncompress all compressed files, consuming considerable time and memory.

##### APK Signature Scheme (v2 scheme)

In the APK signature scheme, the complete APK is hashed and signed, and an APK Signing Block is created and inserted into the APK. During validation, v2 scheme treats performs signature checking across the entire file. This form of APK verification is faster and offers more comprehensive protection against modification.

<img src="Images/Chapters/0x05a/apk-validation-process.png" width="600px"/>

*APK signature verification process* <sup>[9]</sup>

##### Creating Your Certificate

Android is using the public / private certificates technology to sign Android apps (.apk files): this permits to establish the authenticity of apps and make sure the originator is the owner of the private key. Such certificates can be self-generated and signed. Certificates are bundles that contain different information the most important on the security poin of view being keys: a public certificate will contain the public key of the user, and a private certificate will contain the private key of the user. Both the public and private certificates are linked together. Certificates are unique and cannot be generated again: this means that, in case one or the two are lost, it is not possible to renew them with identical ones, therefore updating an app originally signed with a given certificate will become impossible.

The creator of an app can either reuse an existing private / public key pair that already exists and is stored in an available keystore, or generate a new pair.

Key pairs can be generated by the user with the keytool command (example for a key pair generated for my domain ("Distinguished Name"), using the RSA algorithm with a key length of 2048 bits, for 7300 days = 20 years, and that will be stored in the current directory in the secure file 'myKeyStore.jks'):
```
keytool -genkey -alias myDomain -keyalg RSA -keysize 2048 -validity 7300 -keystore myKeyStore.jks -storepass myStrongPassword
```

Safely storing a secret key and making sure it remains secret during its entire lifecycle is of paramount importance, as any other person who would get access to it would be able to publish updates to your apps with content that you would not control (therefore being able to create updates to you apps and add insecure features, access content that is shared using signature-based permissions, e.g. only with apps under your control originally). The trust a user places in an app and its developers is totally based on such certificates, hence its protection and secure management are vital for reputation and Customer retention. This is the reason why secret keys must never be shared with other individuals, and keys are stored in a binary file that can be protected using a password: such files are refered to as 'keystores'; passwords used to protect keystores should be strong and known only by the key creator (-storepass option in the command above, where a strong password shall be provided as an argument).

Android certificates must have a validity period longer than the one of the associated app (including its updates). For example, Google Play will require that the certificate remains valid till at least Oct 22nd, 2033.

##### Signing an Application

After the developer has generated its own private / public key pair, the signing process can take place. From a high-level point of view, this process is meant to associate the app file (.apk) with the public key of the developer (by encrypting the hash value of the app file with the private key, where only the associated public key can decrypt it to its actual value that anyone can calculate from the .apk file): this guarantees the authenticity of the app (e.g. that the app really comes from the user who claims it) and enforces a mechanism where it will only be possible to upgrade the app with other versions signed with the same private key (e.g. from the same developer).

Many Integrated Development Environments (IDE) integrate the app signing process to make it easier for the user. Be aware that some IDEs store private keys in clear text in configuration files; you should be aware of this and double-check this point in case others are able to access such files, and remove the information if needed.

Apps can be signed from the command line by using the 'apksigner' tool provided in Android SDK (API 24 and higher) or the 'jarsigner' tool from Java JDK in case of earlier Android versions. Details about the whole process can be found in Android official documentation; however, an example is given below to illustrate the point:
```
apksigner sign --out mySignedApp.apk --ks myKeyStore.jks myUnsignedApp.apk
```
In this example, an unsigned app ready for signing ('myUnsignedApp.apk') is going to be signed with a private key from the developer keystore 'myKeyStore.jks' located in the current directory and will become a signed app called 'mySignedApp.apk' ready for release on stores.

###### Zipalign

The <code>zipalign</code> tool should always be used to align an APK file before distribution. This tool aligns all uncompressed data within the APK, such as images or raw files, on 4-byte boundaries, which allows for improved memory management during app runtime. If using apksigner, zipalign must be performed before the APK file has been signed.

#### Publishing Process

The Android ecosystem is open, and, as such, it is possible to distribute apps from anywhere (your own site, any store, ...). However, Google Play is the more famous, trusted and popular store and is provided by Google itself.

Whereas other vendors may review and approve apps before they are actually published, such things do not happen on Google Play; this way, a short release time can be expected between the moment when the developer starts the publishing process and the moment when the app is available to users.

Publishing an app is quite straightforward, as the main operation is to make the signed .apk file itself downloadable. On Google Play, it starts with creating an account, and then delivering the app through a dedicated interface. Details are available on Android official documentation at https://developer.android.com/distribute/googleplay/start.html.


### How Apps Communicate - Android IPC

As we know, every process on Android has its own sandboxed address space. Inter-process communication (IPC) facilities enable apps to exchange signals and data in a (hopefully) secure way. Instead of relying on the default Linux IPC facilities, IPC on Android is done through Binder, a custom implementation of OpenBinder. A lot of Android system services, as well as all high-level IPC services, depend on Binder.

In the Binder framework, a client-server communication model is used. IPC clients communicate through a client-side proxy. This proxy connects to the Binder server, which is implemented as a character driver (/dev/binder).The server holds a thread pool for handling incoming requests, and is responsible for delivering messages to the destination object. Developers  write interfaces for remote services using the Android Interface Descriptor Language (AIDL).

![Binder Overview](Images/Chapters/0x05a/binder.jpg)
*Binder Overview. Image source: [Android Binder by Thorsten Schreiber](https://www.nds.rub.de/media/attachments/files/2011/10/main.pdf)*

#### High-Level Abstractions

*Intent messaging* is a framework for asynchronous communication built on top of binder. This framework enables both point-to-point and publish-subscribe messaging. An *Intent* is a messaging object that can be used to request an action from another app component. Although intents facilitate communication between components in several ways, there are three fundamental use cases:

- Starting an activity
	- An Activity represents a single screen in an app. You can start a new instance of an Activity by passing an Intent to startActivity(). The Intent describes the activity to start and carries any necessary data.
- Starting a Service
	- A Service is a component that performs operations in the background without a user interface. With Android 5.0 (API level 21) and later, you can start a service with JobScheduler.
- Delivering a broadcast
	- A broadcast is a message that any app can receive. The system delivers various broadcasts for system events, such as when the system boots up or the device starts charging. You can deliver a broadcast to other apps by passing an Intent to sendBroadcast() or sendOrderedBroadcast().

There are two types of Intents:

- Explicit intents specify the component to start by name (the fully-qualified class name).

- Implicit intents do not name a specific component, but instead declare a general action to perform, which allows a component from another app to handle it. When you create an implicit intent, the Android system finds the appropriate component to start by comparing the contents of the intent to the intent filters declared in the manifest file of other apps on the device.

An *intent filter* is an expression in an app's manifest file that specifies the type of intents that the component would like to receive. For instance, by declaring an intent filter for an activity, you make it possible for other apps to directly start your activity with a certain kind of intent. Likewise, if you do not declare any intent filters for an activity, then it can be started only with an explicit intent.

For activities and broadcast receivers, intents are the preferred mechanism for asynchronous IPC in Android. Depending on your app requirements, you might use sendBroadcast(), sendOrderedBroadcast(), or an explicit intent to a specific app component.

A BroadcastReceiver handles asynchronous requests initiated by an Intent.

Using Binder or Messenger is the preferred mechanism for RPC-style IPC in Android. They provide a well-defined interface that enables mutual authentication of the endpoints, if required.

-- TODO [Explain what vulnerabilities can be created while using IPC mechanisms. Give short examples in the form of code snippets] --

Android’s Messenger represents a reference to a Handler that can be sent to a remote process via an Intent

A reference to the Messenger can be sent via an Intent using the previously mentioned IPC mechanism

Messages sent by the remote process via the messenger are delivered to the local handler. Great for efficient call-backs from the service to the client

### References

* [1] Android Security - https://source.android.com/security/
* [2] Android Developer: App Components - https://developer.android.com/guide/components/index.html
* [3] HAL - https://source.android.com/devices/
* [4] "Android Security: Attacks and Defenses" By Anmol Misra, Abhishek Dubey
* [5] A Programmer Blog - https://pierrchen.blogspot.com.br
* [6] keesj Android internals - https://github.com/keesj/gomo
* [7] Android Versions - https://en.wikipedia.org/wiki/Android_version_history
* [8] "Professional Android 4 Application Development" by Reto Meier
* [9] APK Signing - https://source.android.com/security/apksigning/
* [10] How Android Apps are run - https://github.com/dogriffiths/HeadFirstAndroid/wiki/How-Android-Apps-are-Built-and-Run
* [11] Zygote - https://serializethoughts.com/2016/04/15/android-zygote/
* [12] Android Developer Guide for Manifest -  https://developer.android.com/guide/topics/manifest/manifest-intro.html
* [13] Android Developer Guide - https://developer.android.com/index.html
* [14] Define app install location - https://developer.android.com/guide/topics/data/install-location.html
* [15] Fragment Class - https://developer.android.com/reference/android/app/Fragment.html
