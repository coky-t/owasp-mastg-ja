---
masvs_category: MASVS-CODE
platform: android
---

# Android のコード品質とビルド設定

## 概要

### アプリ署名

Android ではすべての APK はインストールまたは実行する前に証明書でデジタル署名する必要があります。デジタル署名はアプリケーションの更新で所有者の身元を確認するためにも使用されます。このプロセスによりアプリが不正なコードを含むような改竄や改変を防ぐことができます。

APK に署名すると、公開鍵証明書が APK に添付されます。この証明書は APK を開発者および開発者の秘密鍵に一意に関連付けます。デバッグモードでアプリをビルドすると、Android SDK はデバッグ目的専用に作成されたデバッグ鍵でアプリに署名します。デバッグ鍵で署名されたアプリは配布されることを意図しておらず、Google Play ストアを含むほとんどのアプリストアで受け入れられません。

アプリの [最終リリースビルド](https://developer.android.com/studio/publish/app-signing.html "Android Application Signing") は有効なリリース鍵で署名されている必要があります。Android Studio では、アプリを手動で署名するかリリースビルドタイプに割り当てられた署名構成を作成することで署名できます。

Android 9 (API level 28) 以前では Android 上のすべてのアプリ更新に同じ証明書で署名されている必要があるため、[25年以上の有効期間が推奨されます](https://developer.android.com/studio/publish/app-signing#considerations "Android Signing Considerations") 。Google Play に公開されるアプリは2033年10月22日以降に終了する有効期間を持つ鍵で署名する必要があります。

三つの APK 署名スキームが利用可能です。

- JAR 署名 (v1 スキーム)
- APK 署名スキーム v2 (v2 スキーム)
- APK 署名スキーム v3 (v3 スキーム)

Android 7.0 (API level 24) 以上でサポートされている v2 署名は v1 スキームと比較してセキュリティとパフォーマンスが向上しています。
Android 9 (API level 28) 以上でサポートされている v3 署名により、アプリは APK 更新の一部として署名鍵を変更できます。この機能は新しい鍵と古い鍵の両方を使用できるようにすることで互換性とアプリの継続的な可用性を保証します。執筆時点では [apksigner](../tools/android/MASTG-TOOL-0123.md) を介してのみ利用可能であることに注意します。

それぞれの署名スキームに対して、リリースビルドでは常に以前のすべてのスキームも使用して署名される必要があります。

### サードパーティーライブラリ

Android アプリは多くの場合サードパーティライブラリを使用します。開発者が問題を解決するために書く必要があるコードがより少なくなるため、これらのサードパーティライブラリは開発を加速します。ライブラリには二つのカテゴリがあります。

- 実際の製品アプリケーション内にパックされない (またはパックすべきではない) ライブラリ。テストに使用される `Mockito` や特定の他のライブラリをコンパイルするために使用される `JavaAssist` のようなライブラリなど。
- 実際の製品アプリケーション内にパックされるライブラリ。`Okhttp3` など。

これらのライブラリは望ましくない副作用を引き起こす可能性があります。

- ライブラリには脆弱性が含まれている可能性があり、これによりアプリケーションが脆弱になります。よい例は 2.7.5 より前のバージョンの `OKHTTP` で、TLS チェーン汚染により SSL ピンニングをバイパスすることが可能でした。
- ライブラリはもはや保守されていないかほとんど使用されていない可能性があり、そのため脆弱性は報告されず修正されません。これによりそのライブラリを介してアプリケーションに不正なコードや脆弱なコードが含まれる可能性があります。
- ライブラリは LGPL2.1 などのライセンスを使用している可能性があります。LGPL2.1 ではアプリケーションを使用してそのソースの中身を要求するユーザーにアプリケーションの作成者がソースコードへのアクセスを提供する必要があります。実際、アプリケーションはソースコードを変更して再配布できるようにする必要があります。これはアプリケーションの知的財産 (IP) を危険にさらす可能性があります。

この問題は複数のレベルで発生する可能性があることに注意します。WebView 内で JavaScript を実行する WebView を使用すると、その JavaScript ライブラリにもこれらの問題が発生する可能性があります。Cordova, React-native および Xamarin アプリのプラグインやライブラリについても同様です。

### メモリ破損バグ

Android アプリケーションはメモリ破損問題のほとんどが対処されている VM 上で実行されます。これはメモリ破損バグがないという意味ではありません。たとえば [CVE-2018-9522](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9522 "CVE in StatsLogEventWrapper") では Parcels を使用したシリアル化の問題に関連しています。また、ネイティブコードでは、一般的なメモリ破損のセクションで説明したのと同じ問題が引き続き発生します。さらに、 [BlackHat で](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf "Stagefright") 示された Stagefright 攻撃のように、サポートサービスにメモリバグが見られます。

メモリリークもよく問題となります。これはたとえば `Context` オブジェクトへの参照が `Activity` 以外のクラスに渡される場合や、 `Activity` クラスへの参照をヘルパークラスに渡す場合に発生することがあります。

### バイナリ保護メカニズム

[バイナリ保護メカニズム](0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) の存在を検出することはアプリケーションの開発に使用された言語に大きく依存します。

一般的にはすべてのバイナリをテストすべきです。これにはメインのアプリ実行可能ファイルだけでなくすべてのライブラリや依存関係が含まれます。しかし、Android では次に説明するようにメインの実行可能ファイルは安全であると考えられるため、ネイティブライブラリに焦点を当てます。

Android は アプリの DEX ファイル (classes.dex など) から Dalvik バイトコードを最適化し、ネイティブコードを含む新しいファイルを生成します。通常、拡張子は .odex, .oat です。この Android コンパイル済みバイナリ ([アプリバイナリの探索 (Exploring the App Package)](../techniques/android/MASTG-TECH-0007.md) の "コンパイル済みアプリバイナリ" を参照) は Linux や Android がアセンブリコードをパッケージ化するために使用するフォーマットである [ELF フォーマット](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html) を使用してラップされています。

アプリの NDK ネイティブライブラリ ([アプリバイナリの探索 (Exploring the App Package)](../techniques/android/MASTG-TECH-0007.md) の "ネイティブライブラリ" を参照) も [ELF フォーマットを使用](https://developer.android.com/ndk/guides/abis) しています。

- [**PIE (Position Independent Executable)**](0x04h-Testing-Code-Quality.md#position-independent-code):
    - Android 7.0 (API レベル 24) 以降、メインの実行可能ファイルに対して PIC コンパイルは [デフォルトで有効](https://source.android.com/devices/tech/dalvik/configure) になっています。
    - Android 5.0 (API レベル 21) で PIE 非対応のネイティブライブラリのサポートは [廃止](https://source.android.com/security/enhancements/enhancements50) され、それ以降 PIE は [リンカーによって強制](https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=430) されるようになりました。
- [**メモリ管理**](0x04h-Testing-Code-Quality.md#memory-management):
    - ガベージコレクションはメインのバイナリに対して実行されるだけで、バイナリ自体は何もチェックされません。
    - ガベージコレクションは Android ネイティブライブラリには適用されません。開発者は適切な [手動メモリ管理](0x04h-Testing-Code-Quality.md#manual-memory-management) を行う責任があります。 ["メモリ破損バグ"](0x04h-Testing-Code-Quality.md#memory-corruption-bugs) を参照してください。
- [**スタックスマッシュ保護**](0x04h-Testing-Code-Quality.md#stack-smashing-protection):
    - Android アプリはメモリセーフと考えられる (少なくともバッファオーバーフローを軽減する) Dalvik バイトコードにコンパイルされます。Flutter などの他のフレームワークはその言語 (この場合は Dart) がバッファーオーバーフローを軽減する方法であるため、スタックカナリアを使用したコンパイルは行われません。
    - Android ネイティブライブラリは有効にしなければなりませんが、それを完全に判断するのは難しいかもしれません。
        - NDK ライブラリはコンパイラがデフォルトでそれを行うため有効になっているはずです。
        - 他のカスタム C/C++ ライブラリは有効になっていない可能性があります。

詳しくはこちら。

- [Android executable formats](https://lief-project.github.io/doc/latest/tutorials/10_android_formats.html)
- [Android runtime (ART)](https://source.android.com/devices/tech/dalvik/configure#how_art_works)
- [Android NDK](https://developer.android.com/ndk/guides)
- [Android linker changes for NDK developers](https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md)

### デバッグ可能アプリ

デバッグは開発者が Android アプリのエラーやバグを特定し修正するために不可欠なプロセスです。デバッガを使用することで、開発者はアプリをデバッグするデバイスを選択し、Java、Kotlin、C/C++ コードにブレークポイントを設定できます。これにより実行時に変数の解析や式の評価が可能になり、多くの問題の根本原因を特定できます。アプリをデバッグすることで、開発者はアプリの機能性とユーザー体験を向上させ、エラーやクラッシュがないスムーズな動作を確保できます。

デバッガを有効にしたすべてのプロセスでは JDWP プロトコルパケットを処理するための特別なスレッドを実行します。このスレッドは Android Manifest 内の [`Application` 要素](https://developer.android.com/guide/topics/manifest/application-element.html "Application element") に `android:debuggable="true"` 属性を持つアプリに対してのみ開始されます。

### デバッグシンボル

一般的に、コンパイルされたコードにはできるだけ説明を付けるべきではありません。デバッグ情報、行番号、説明的な関数名やメソッド名などの一部のメタデータは、リバースエンジニアがバイナリやバイトコードを理解しやすくしますが、これらはリリースビルドでは必要ないため、アプリの機能に影響を与えることなく安全に省略できます。

ネイティブバイナリを検査するには、`nm` や `objdump` などの標準ツールを使用してシンボルテーブルを調査します。リリースビルドには一般的にデバッグシンボルを含めるべきではありません。ライブラリを難読化することが目的の場合には、不要な動的シンボルを削除することもお勧めします。

### デバッグコードとエラーログ

#### StrictMode

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

### 例外処理

例外はアプリケーションが正常ではない状態やエラーのある状態になったときに発生します。 Java と C++ のいずれも例外をスローすることがあります。例外処理のテストとは UI やアプリのログ出力メカニズムを介して機密情報を開示することなく、アプリが例外を処理して安全な状態に遷移することを確認することです。
