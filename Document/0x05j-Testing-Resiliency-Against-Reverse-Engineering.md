---
masvs_category: MASVS-RESILIENCE
platform: android
---

# Android のアンチリバース防御

## 概要

### 一般的な免責事項

**これらの対策のいずれが欠けても、脆弱性を生み出すことはありません** 。むしろ、リバースエンジニアリングや特定のクライアントサイド攻撃に対するアプリの耐性を高めることを目的としています。

リバースエンジニアは常にデバイスにフルアクセスできるので (十分な時間とリソースがあれば) 必ず勝利できるため、これらの対策はいずれも 100% の効果を保証するものではありません。

たとえば、デバッグを防止することは事実上不可能です。アプリを公開している場合、攻撃者の完全な制御下にある信頼できないデバイス上で実行される可能性があります。非常に意志の固い攻撃者はアプリバイナリにパッチを当てるか Frida などのツールを使用して実行時にアプリの動作を動的に変更して、最終的にアプリのアンチデバッグ制御をすべてバイパスするでしょう。

リバースエンジニアリングとコード変更の原則と技術的リスクについての詳細は以下の OWASP ドキュメントを参照してください。

- [OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering](https://wiki.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project "OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering")
- [OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification](https://wiki.owasp.org/index.php/Technical_Risks_of_Reverse_Engineering_and_Unauthorized_Code_Modification "OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification")

### ルート検出と一般的なルート検出手法

アンチリバースの文脈では、ルート検出の目的はルート化されたデバイス上でのアプリの実行を少し難しくすることです。これにより、リバースエンジニアが使用したいツールやテクニックの一部をブロックします。他のほとんどの防御と同様に、ルート検出はそれ自体に高い効果はありませんが、複数のルートチェックをアプリ全体にちりばめて実装することで改竄対策スキーム全体の有効性を向上できます。

Android では、 "ルート検出" を少し広く定義し、カスタム ROM の検出を含みます。例えば、デバイスが純正の Android ビルドであるか、もしくはカスタムビルドであるかを判断します

以下のセクションでは、よく見かけるいくつかの一般的なルート検出手法を記します。 OWASP Mobile Testing Guide に付属する [OWASP UnCrackable Apps for Android](0x08b-Reference-Apps.md#android-crackmes) にこれらの手法がいくつかが実装されています。

ルート検出は [RootBeer](https://github.com/scottyab/rootbeer "RootBeer") などのライブラリを介して実装することもできます。

#### SafetyNet

SafetyNet は一連のサービスを提供する Android API であり、ソフトウェアとハードウェアの情報に従ってデバイスのプロファイルを作成します。このプロファイルは Android 互換性テストに合格した承認済みデバイスモデルのリストと比較されます。 Google はこの機能を "不正使用防止システムの一環としての付加的な多層防御シグナル" として使用することを [推奨](https://developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNet "SafetyNet Documentation") しています。

SafetyNet が正確な動作は十分に文書化されておらず、いつでも変更される可能性があります。この API を呼び出すと、 SafetyNet は Google から提供されるデバイス検証コードを含むバイナリパッケージをダウンロードし、リフレクションを介してコードが動的に実行されます。 [John Kozyrakis の分析](https://koz.io/inside-safetynet/ "SafetyNet: Google's tamper detection for Android") によると、 SafetyNet はデバイスがルート化されているかどうかも検出しようとしますが、これがどのように判断されるかは明確ではありません。

API を使用するには、アプリは `SafetyNetApi.attest` メソッド (_Attestation Result_ を含むメッセージを返します) を呼び出し、以下のフィールドをチェックします。

- `ctsProfileMatch`: 'true' の場合、デバイスプロファイルは Google にリストされているデバイスのいずれかと一致します。
- `basicIntegrity`: 'true' の場合、アプリを実行しているデバイスはおそらく改竄されてはいません。
- `nonces`: そのリクエストに対するレスポンスを照合します。
- `timestampMs`: リクエストしてからレスポンスが得られるまでの経過時間をチェックします。レスポンスが遅延している場合、不審な挙動を示唆している可能性があります。
- `apkPackageName`, `apkCertificateDigestSha256`, `apkDigestSha256`: 呼び出し元アプリの素性を検証するために使用される、 APK に関する情報を提供します。 API が信頼性のある APK 情報を判断できない場合、これらのパラメータはありません。

以下は attestation result の例です。

```json
{
  "nonce": "R2Rra24fVm5xa2Mg",
  "timestampMs": 9860437986543,
  "apkPackageName": "com.package.name.of.requesting.app",
  "apkCertificateDigestSha256": ["base64 encoded, SHA-256 hash of the
                                  certificate used to sign requesting app"],
  "apkDigestSha256": "base64 encoded, SHA-256 hash of the app's APK",
  "ctsProfileMatch": true,
  "basicIntegrity": true,
}
```

##### ctsProfileMatch と basicIntegrity

SafetyNet Attestation API は当初 `basicIntegrity` という単一の値を提供して、開発者がデバイスの完全性を判断できるようにしました。 API が進化するにつれ、 Google は新しく、より厳密なチェックを導入し、その結果は `ctsProfileMatch` という値で示されるようになりました。これにより開発者はアプリが実行されているデバイスをより詳細に評価できます。

大まかにいえば、 `basicIntegrity` はデバイスとその API の一般的な完全性に関するシグナルを提供します。多くのルート化デバイスは `basicIntegrity` に失敗します。エミュレータ、仮想デバイス、 API フックなどの改竄の兆候があるデバイスも同様です。

一方、 `ctsProfileMatch` はデバイスの互換性についてより厳密なシグナルを提供します。 Google により認定され、改変されていないデバイスのみが `ctsProfileMatch` をパスできます。 `ctsProfileMatch` に失敗するデバイスには以下のものがあります。

- `basicIntegrity` に失敗したデバイス
- アンロックされたブートローダを持つデバイス
- カスタムシステムイメージ (カスタム ROM) を持つデバイス
- 製造元が Google 認定を申請していない、または合格していないデバイス
- Android Open Source Program のソースファイルから直接構築されたシステムイメージを持つデバイス
- ベータ版または開発者プレビュープログラム (Android Beta Program を含む) の一部として配布されたシステムイメージを持つデバイス

##### `SafetyNetApi.attest` 使用時の推奨事項

- 暗号学的にセキュアなランダム関数を使用してサーバーに大きな (16 バイト以上) 乱数を作成して、悪意のあるユーザーが失敗した結果の代わりとして成功した認証結果を再利用できないようにします。
- `ctsProfileMatch` の値が true の場合にのみ、 APK 情報 (`apkPackageName`, `apkCertificateDigestSha256`, `apkDigestSha256`) を信頼します。
- 検証のために、セキュアな接続を使用して、 JWS レスポンス全体をサーバーに送信すべきです。アプリで直接検証を実行することはお勧めしません。その場合、検証ロジック自体が改変されていないという保証はありません。
- `verify` メソッドは JWS メッセージが SafetyNet により署名されたことを妥当性確認するだけです。判定のペイロードが期待と一致するかどうか検証されません。このサービスは便利なように思われるかもしれませんが、これはテスト目的にのみ設計されており、プロジェクトごとに一日当たり 10,000 リクエストという非常に厳しい使用制限があり、リクエストに応じて増加することはありません。したがって、 [SafetyNet 検証サンプル](https://github.com/googlesamples/android-play-safetynet/tree/master/server/java/src/main/java "Google SafetyNet Sample") を参照して、 Google のサーバーに依存しない方法でサーバー上にデジタル署名検証ロジックを実装する必要があります。
- SafetyNet Attestation API は構成証明リクエストが行われた時点でのデバイスの状態のスナップショットを提供します。構成証明が成功しても、デバイスが過去に構成証明に合格したことや、将来的に合格することを必ずしも意味しません。ユースケースを満たすために必要な最小限の構成証明を使用する戦略を計画することをお勧めします。
- 誤って `SafetyNetApi.attest` 使用制限に達して構成証明エラーが発生することを防ぐには、 API の使用状況を監視し、使用制限に達する前に警告するシステムを構築することで、使用制限を増やせるようにしておきます。また使用制限を超過したことによる構成証明失敗に対応できるように準備し、このような状況ですべてのユーザーをブロックしないようにする必要があります。使用制限に近づいている場合や、短期的な急増で使用制限を超える可能性がある場合には、この [フォーム](https://support.google.com/googleplay/android-developer/contact/safetynetqr "quota request") を送信して、 API キーの使用制限の短期的または長期的な増加を要求することができます。このプロセスと追加の使用制限は無料です。

この [チェックリスト](https://developer.android.com/training/safetynet/attestation-checklist "attestation checklist") に従い、アプリに `SafetyNetApi.attest` API を統合するために必要な各ステップを完了していることを確認します。

#### プログラムによる検出

##### ファイルの存在チェック

おそらく最も広く使用されているプログラムによる検出の手法はルート化されたデバイスに通常見つかるファイルをチェックすることです。一般的なルート化アプリのパッケージファイルや関連するファイルおよびディレクトリなどがあります。以下のものを含みます。

```default
/system/app/Superuser.apk
/system/etc/init.d/99SuperSUDaemon
/dev/com.koushikdutta.superuser.daemon/
/system/xbin/daemonsu
```

検出コードは多くの場合デバイスがルート化されたときに一般的にインストールされるバイナリも検索します。これらの検索には busybox のチェックや _su_ バイナリを別の場所で開こうとするものなどがあります。

```default
/sbin/su
/system/bin/su
/system/bin/failsafe/su
/system/xbin/su
/system/xbin/busybox
/system/sd/xbin/su
/data/local/su
/data/local/xbin/su
/data/local/bin/su
```

*su* が PATH 上にあるかどうかを確認することもできます。

```java
    public static boolean checkRoot(){
        for(String pathDir : System.getenv("PATH").split(":")){
            if(new File(pathDir, "su").exists()) {
                return true;
            }
        }
        return false;
    }
```

ファイルチェックは Java とネイティブコードの両方で簡単に実装できます。以下の JNI の例 ([rootinspector](https://github.com/devadvance/rootinspector/ "rootinspector") から改変) では `stat` システムコールを使用してファイルに関する情報を取得し、ファイルが存在する場合は "1" を返します。

```c
jboolean Java_com_example_statfile(JNIEnv * env, jobject this, jstring filepath) {
  jboolean fileExists = 0;
  jboolean isCopy;
  const char * path = (*env)->GetStringUTFChars(env, filepath, &isCopy);
  struct stat fileattrib;
  if (stat(path, &fileattrib) < 0) {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NATIVE: stat error: [%s]", strerror(errno));
  } else
  {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NATIVE: stat success, access perms: [%d]", fileattrib.st_mode);
    return 1;
  }

  return 0;
}
```

##### `su` および他のコマンドの実行

`su` が存在するかどうかを判断するもう一つの方法は `Runtime.getRuntime.exec` メソッドを使用して実行を試みることです。 `su` が PATH 上にない場合は IOException がスローされます。同じ方法を使用して、ルート化されたデバイス上によく見つかる他のプログラムを確認することができます。 busybox や一般的にそれを指すシンボリックリンクなどがあります。

##### 実行中のプロセスの確認

Supersu は最も人気のあるルート化ツールであり `daemonsu` という名前の認証デーモンを実行します。そのため、このプロセスが存在することはルート化されたデバイスのもうひとつの兆候です。実行中のプロセスは `ActivityManager.getRunningAppProcesses` および `manager.getRunningServices` API 、 `ps` コマンドで列挙でき、 `/proc` ディレクトリで閲覧できます。以下は [rootinspector](https://github.com/devadvance/rootinspector/ "rootinspector") で実装されている例です。

```java
    public boolean checkRunningProcesses() {

      boolean returnValue = false;

      // Get currently running application processes
      List<RunningServiceInfo> list = manager.getRunningServices(300);

      if(list != null){
        String tempName;
        for(int i=0;i<list.size();++i){
          tempName = list.get(i).process;

          if(tempName.contains("supersu") || tempName.contains("superuser")){
            returnValue = true;
          }
        }
      }
      return returnValue;
    }
```

##### インストール済みアプリパッケージの確認

Android パッケージマネージャを使用するとインストールされているパッケージのリストを取得できます。以下のパッケージ名は一般的なルート化ツールに属するものです。

```default
com.thirdparty.superuser
eu.chainfire.supersu
com.noshufou.android.su
com.koushikdutta.superuser
com.zachspong.temprootremovejb
com.ramdroid.appquarantine
com.topjohnwu.magisk
```

##### 書き込み可能なパーティションとシステムディレクトリの確認

sysytem ディレクトリに対する普通とは異なるアクセス許可は、カスタマイズまたはルート化されたデバイスを示している可能性があります。通常では system および data ディレクトリは読み取り専用でマウントされていますが、デバイスがルート化されていると読み書き可能でマウントされることがあります。 "rw" フラグでマウントされているこれらのファイルシステムを探すか、もしくはこれらのディレクトリにファイルを作成してみます。

##### カスタム Android ビルドの確認

テストビルドやカスタム ROM の兆候を確認することも役に立ちます。これを行う方法のひとつは BUILD タグに test-keys が含まれているかどうかを確認することです。これは一般的に [カスタム Android イメージを示します](https://resources.infosecinstitute.com/android-hacking-security-part-8-root-detection-evasion// "InfoSec Institute - Android Root Detection and Evasion") 。 [以下のように BUILD タグを確認します](https://github.com/scottyab/rootbeer/blob/master/rootbeerlib/src/main/java/com/scottyab/rootbeer/RootBeer.java#L76 "Rootbeer - detectTestKeys function") 。

```java
private boolean isTestKeyBuild()
{
String str = Build.TAGS;
if ((str != null) && (str.contains("test-keys")));
for (int i = 1; ; i = 0)
  return i;
}
```

Google Over-The-Air (OTA) 証明書の欠落はカスタム ROM のもうひとつの兆候です。純正の Android ビルドでは [OTA アップデートに Google の公開証明書を使用します](https://blog.netspi.com/android-root-detection-techniques/ "Android Root Detection Techniques") 。

### アンチデバッグ

デバッグはアプリのランタイム動作を解析する非常に効果的な方法です。これによりリバースエンジニアがコードをステップ実行し、任意の箇所でアプリの実行を停止し、変数の状態を検査し、メモリを読み取りおよび変更し、さらに多くのことを可能にします。

アンチデバッグ機能には予防型と反応型があります。名前が示すように、予防型アンチデバッグはまず第一にデバッガがアタッチすることを防ぎます。反応型アンチデバッグはデバッガを検出し、何らかの方法でそれに反応します (アプリの終了や隠された動作のトリガなど) 。「多ければ多いほど良い」ルールが適用されます。効果を最大限にするため、防御側は、さまざまな API レイヤーで動作しアプリ全体に分散される、複数の予防と検出の手法を組み合わせます。

"リバースエンジニアリングと改竄" の章で述べたように、 Android では二つの異なるデバッグプロトコルを扱う必要があります。 JDWP を使用した Java レベルと、 ptrace ベースのデバッガを使用したネイティブレイヤーでデバッグが可能です。優れたアンチデバッグスキームでは両方のデバッグタイプに対して防御する必要があります。

#### JDWP アンチデバッグ

"リバースエンジニアリングと改竄" の章では、デバッガと Java 仮想マシンとの間の通信に使用されるプロトコルである JDWP について説明しました。マニフェストファイルにパッチを適用して任意のアプリを容易にデバッグ可能にできることや、 `ro.debuggable` システムプロパティを変更することであらゆるアプリをデバッグ可能にできることを示しました。開発者が JDWP デバッガを検出および無効にするために行ういくつかのことを見てみます。

##### ApplicationInfo のデバッグ可能フラグの確認

すでに `android:debuggable` 属性は出てきています。 Android Manifest のこのフラグは JDWP スレッドがアプリに対して起動されるかどうかを決定します。その値はアプリの `ApplicationInfo` オブジェクトを使用してプログラムで決定できます。このフラグが設定されている場合、これはマニフェストが改竄されてデバッグ可能になっています。

```java
    public static boolean isDebuggable(Context context){

        return ((context.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);

    }
```

##### isDebuggerConnected

これはリバースエンジニアにとって当たり前かもしれませんが、 `android.os.Debug` クラスの `isDebuggerConnected` を使用してデバッガが接続されているかどうかを確認できます。

```java
    public static boolean detectDebugger() {
        return Debug.isDebuggerConnected();
    }
```

同じ API は DvmGlobals グローバル構造体にアクセスすることによりネイティブコードを介してコールすることができます。

```c
JNIEXPORT jboolean JNICALL Java_com_test_debugging_DebuggerConnectedJNI(JNIenv * env, jobject obj) {
    if (gDvm.debuggerConnected || gDvm.debuggerActive)
        return JNI_TRUE;
    return JNI_FALSE;
}
```

##### タイマーチェック

`Debug.threadCpuTimeNanos` は現在のスレッドがコードの実行に費やした時間量を示します。デバッグはプロセスの実行を遅くするため、 [実行時間の違いを使用して、デバッガがアタッチされているかどうかを推測することができます](https://www.yumpu.com/en/document/read/15228183/android-reverse-engineering-defenses-bluebox-labs "Bluebox Security - Android Reverse Engineering & Defenses") 。

```java
static boolean detect_threadCpuTimeNanos(){
  long start = Debug.threadCpuTimeNanos();

  for(int i=0; i<1000000; ++i)
    continue;

  long stop = Debug.threadCpuTimeNanos();

  if(stop - start < 10000000) {
    return false;
  }
  else {
    return true;
  }
}
```

##### JDWP 関連のデータ構造への干渉

Dalvik では、グローバル仮想マシンの状態は `DvmGlobals` 構造体を介してアクセス可能です。グローバル変数 gDvm はこの構造体へのポイントを保持しています。 `DvmGlobals` には JDWP デバッグに重要なさまざまな変数やポインタが含まれており、改竄可能です。

```c
struct DvmGlobals {
    /*
     * Some options that could be worth tampering with :)
     */

    bool        jdwpAllowed;        // debugging allowed for this process?
    bool        jdwpConfigured;     // has debugging info been provided?
    JdwpTransportType jdwpTransport;
    bool        jdwpServer;
    char*       jdwpHost;
    int         jdwpPort;
    bool        jdwpSuspend;

    Thread*     threadList;

    bool        nativeDebuggerActive;
    bool        debuggerConnected;      /* debugger or DDMS is connected */
    bool        debuggerActive;         /* debugger is making requests */
    JdwpState*  jdwpState;

};
```

例えば、 [gDvm.methDalvikDdmcServer_dispatch 関数ポインタに NULL を設定すると JDWP スレッドがクラッシュします](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/AndroidREnDefenses201305.pdf "Bluebox Security - Android Reverse Engineering & Defenses") 。

```c
JNIEXPORT jboolean JNICALL Java_poc_c_crashOnInit ( JNIEnv* env , jobject ) {
  gDvm.methDalvikDdmcServer_dispatch = NULL;
}
```

gDvm 変数が利用できない場合でも、 ART で同様の技法を使用してデバッグを無効にできます。 ART ランタイムは JDWP 関連のクラスの vtable の一部をグローバルシンボルとしてエクスポートします (C++ では、 vtable はクラスメソッドのポインタを保持するテーブルです) 。これには `JdwpSocketState` および `JdwpAdbState` クラスの vtable を含んでおり、これらはネットワークソケットと ADB を介した JDWP 接続をそれぞれ処理します。デバッグランタイムの動作は [関連する vtable のメソッドポインタを上書きすることにより](https://web.archive.org/web/20200307152820/https://www.vantagepoint.sg/blog/88-anti-debugging-fun-with-android-art "Anti-Debugging Fun with Android ART") (archived) 操作できます。

メソッドポインタを上書きするための方法のひとつは `jdwpAdbState::ProcessIncoming` のアドレスを `JdwpAdbState::Shutdown` のアドレスで上書きすることです。これによりデバッガは直ちに切断されます。

```c
#include <jni.h>
#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <jdwp/jdwp.h>

#define log(FMT, ...) __android_log_print(ANDROID_LOG_VERBOSE, "JDWPFun", FMT, ##__VA_ARGS__)

// Vtable structure. Just to make messing around with it more intuitive

struct VT_JdwpAdbState {
    unsigned long x;
    unsigned long y;
    void * JdwpSocketState_destructor;
    void * _JdwpSocketState_destructor;
    void * Accept;
    void * showmanyc;
    void * ShutDown;
    void * ProcessIncoming;
};

extern "C"

JNIEXPORT void JNICALL Java_sg_vantagepoint_jdwptest_MainActivity_JDWPfun(
        JNIEnv *env,
        jobject /* this */) {

    void* lib = dlopen("libart.so", RTLD_NOW);

    if (lib == NULL) {
        log("Error loading libart.so");
        dlerror();
    }else{

        struct VT_JdwpAdbState *vtable = ( struct VT_JdwpAdbState *)dlsym(lib, "_ZTVN3art4JDWP12JdwpAdbStateE");

        if (vtable == 0) {
            log("Couldn't resolve symbol '_ZTVN3art4JDWP12JdwpAdbStateE'.\n");
        }else {

            log("Vtable for JdwpAdbState at: %08x\n", vtable);

            // Let the fun begin!

            unsigned long pagesize = sysconf(_SC_PAGE_SIZE);
            unsigned long page = (unsigned long)vtable & ~(pagesize-1);

            mprotect((void *)page, pagesize, PROT_READ | PROT_WRITE);

            vtable->ProcessIncoming = vtable->ShutDown;

            // Reset permissions & flush cache

            mprotect((void *)page, pagesize, PROT_READ);

        }
    }
}
```

#### 従来のアンチデバッグ

Linux では、 [`ptrace` システムコール](http://man7.org/linux/man-pages/man2/ptrace.2.html "Ptrace man page") を使用して、プロセス (_tracee_) の実行を監視および制御し、そのプロセスのメモリとレジスタを調べて変更します。 `ptrace` はネイティブコードでシステムコールトレースとブレークポイントデバッグを実装する主要な方法です。ほとんどの JDWP アンチデバッグトリック (タイマーベースのチェックには安全かもしれません) は `ptrace` をベースとする従来のデバッガをキャッチしないため、多くの Android アンチデバッグトリックには `ptrace` が含まれており、一つのプロセスにアタッチできるのは一度に一つのデバッガのみであるという事実を悪用することがよくあります。

##### TracerPid のチェック

アプリをデバッグしてネイティブコードにブレークポイントを設定する際、 Android Studio はターゲットデバイスに必要なファイルをコピーし、プロセスにアタッチするために `ptrace` を使用する lldb-server を起動します。この時点で、デバッグされるプロセスの [ステータスファイル](http://man7.org/linux/man-pages/man5/proc.5.html "/proc/[pid]/status") (`/proc/<pid>/status` または `/proc/self/status`) を検査すると、 "TracerPid" フィールドは 0 とは異なる値を持つことがわかります。これはデバッグの兆候です。

> **これはネイティブコードにのみ適用される** ことに注意します。 Java/Kotlin のみのアプリをデバッグする場合には "TracerPid" フィールドの値は 0 になります。

この技法は通常 JNI ネイティブライブラリ内の C で適用されます。これは [Google の gperftools (Google Performance Tools)) Heap Checker](https://github.com/gperftools/gperftools/blob/master/src/heap-checker.cc#L112 "heap-checker.cc - IsDebuggerAttached") 実装の `IsDebuggerAttached` メソッドに示されています。ただし、このチェックを Java/Kotlin コードの一部として含める場合は、 [Tim Strazzere の Anti-Emulator プロジェクト](https://github.com/strazzere/anti-emulator/ "anti-emulator") から `hasTracerPid` メソッドの Java 実装を参照します。

このようなメソッドを自分で実装しようとする場合は、 ADB で TracerPid の値を手動で確認できます。以下のリストは Google の NDK サンプルアプリ [hello-jni (com.example.hellojni)](https://github.com/android/ndk-samples/tree/android-mk/hello-jni "hello-jni sample") を使用して、 Android Studio のデバッガをアタッチした後にチェックを実行しています。

```bash
$ adb shell ps -A | grep com.example.hellojni
u0_a271      11657   573 4302108  50600 ptrace_stop         0 t com.example.hellojni
$ adb shell cat /proc/11657/status | grep -e "^TracerPid:" | sed "s/^TracerPid:\t//"
TracerPid:      11839
$ adb shell ps -A | grep 11839
u0_a271      11839 11837   14024   4548 poll_schedule_timeout 0 S lldb-server
```

com.example.hellojni (PID=11657) のステータスファイルに 11839 の TracerPID がどのように含まれているかを確認できます。これは lldb-server プロセスとして識別できます。

##### fork と ptrace の使用

以下の簡単なコード例のようなコードを介して、子プロセスをフォークし、デバッガとして親プロセスにアタッチすることで、プロセスのデバッグを防止できます。

```c
void fork_and_attach()
{
  int pid = fork();

  if (pid == 0)
    {
      int ppid = getppid();

      if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
        {
          waitpid(ppid, NULL, 0);

          /* Continue the parent process */
          ptrace(PTRACE_CONT, NULL, NULL);
        }
    }
}
```

子プロセスがアタッチされていると、さらに親プロセスにアタッチしようとしても失敗します。これを検証するには、コードを JNI 関数にコンパイルし、デバイスで実行するアプリにパックします。

```bash
root@android:/ # ps | grep -i anti
u0_a151   18190 201   1535844 54908 ffffffff b6e0f124 S sg.vantagepoint.antidebug
u0_a151   18224 18190 1495180 35824 c019a3ac b6e0ee5c S sg.vantagepoint.antidebug
```

gdbserver で親プロセスにアタッチしようとすると以下のエラーで失敗します。

```bash
root@android:/ # ./gdbserver --attach localhost:12345 18190
warning: process 18190 is already traced by process 18224
Cannot attach to lwp 18190: Operation not permitted (1)
Exiting
```

ただし、子プロセスを強制終了し、親プロセスがトレースから "解放" することで、この失敗を簡単にバイパスできます。したがって、複数のプロセスとスレッド、および改竄を阻止するための何らかの形の監視を含む、より緻密なスキームが通常見つかります。一般的な手法は以下のとおりです。

- 互いにトレースする複数のプロセスをフォークします。
- 実行中のプロセスを追跡して子プロセスが生存していることを確認します。
- `/proc/pid/status` の TracerPID など、 `/proc` ファイルシステムの値を監視します。

上記の手法について簡単に改良してみましょう。最初の `fork` の後で、子プロセスのステータスを継続的に監視する追加のスレッドを親プロセスで起動します。アプリがデバッグモードまたはリリースモードのいずれでビルドされたか (マニフェストの `android:debuggable` フラグで示されます) に応じて、子プロセスは以下のいずれかを実行する必要があります。

- リリースモードの場合: ptrace のコールが失敗し、子プロセスはセグメンテーションフォルト (終了コード 11) で直ちにクラッシュします。
- デバッグモードの場合: ptrace のコールは機能し、子プロセスは無期限に実行されるはずです。したがって、 `waitpid(child_pid)` のコールは決して戻らないでしょう。もし戻るようであれば、何かが怪しいのでプロセスグループ全体を強制終了します。

以下は JNI 関数でこの改善を実装するための完全なコードです。

```c
#include <jni.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <pthread.h>

static int child_pid;

void *monitor_pid() {

    int status;

    waitpid(child_pid, &status, 0);

    /* Child status should never change. */

    _exit(0); // Commit seppuku

}

void anti_debug() {

    child_pid = fork();

    if (child_pid == 0)
    {
        int ppid = getppid();
        int status;

        if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
        {
            waitpid(ppid, &status, 0);

            ptrace(PTRACE_CONT, ppid, NULL, NULL);

            while (waitpid(ppid, &status, 0)) {

                if (WIFSTOPPED(status)) {
                    ptrace(PTRACE_CONT, ppid, NULL, NULL);
                } else {
                    // Process has exited
                    _exit(0);
                }
            }
        }

    } else {
        pthread_t t;

        /* Start the monitoring thread */
        pthread_create(&t, NULL, monitor_pid, (void *)NULL);
    }
}

JNIEXPORT void JNICALL
Java_sg_vantagepoint_antidebug_MainActivity_antidebug(JNIEnv *env, jobject instance) {

    anti_debug();
}
```

再び、これを Android アプリにパックして、機能するかどうかを確認します。以前と同様に、アプリのデバッグビルドを実行すると二つのプロセスが表示されます。

```bash
root@android:/ # ps | grep -I anti-debug
u0_a152   20267 201   1552508 56796 ffffffff b6e0f124 S sg.vantagepoint.anti-debug
u0_a152   20301 20267 1495192 33980 c019a3ac b6e0ee5c S sg.vantagepoint.anti-debug
```

ただし、この時点で子プロセスを終了すると、親プロセスも終了します。

```bash
root@android:/ # kill -9 20301
130|root@hammerhead:/ # cd /data/local/tmp
root@android:/ # ./gdbserver --attach localhost:12345 20267
gdbserver: unable to open /proc file '/proc/20267/status'
Cannot attach to lwp 20267: No such file or directory (2)
Exiting
```

これをバイパスするには、アプリの動作を少し改変する必要があります (これを行う最も簡単な方法は `_exit` へのコールを NOP でパッチするか、 `libc.so` の `_exit` 関数をフックすることです) 。この時点で、おなじみの "軍備拡張競争" に突入します。この防御をより複雑な形で実装することもそれをバイパスすることも常に可能です。

### ファイル完全性チェック

ファイル完全性に関連するトピックは二つあります。

 1. _コード完全性チェック:_ ["Android の改竄とリバースエンジニアリング"](0x05c-Reverse-Engineering-and-Tampering.md) の章では、Android の APK コード署名チェックについて説明しました。また、リバースエンジニアがアプリを再パッケージおよび再署名することで、このチェックを簡単に回避できることもわかりました。このバイパスプロセスをより複雑なものにするために、アプリのバイトコード、ネイティブライブラリ、重要なデータファイルに対する CRC チェックで保護スキームを強化できます。これらのチェックは Java とネイティブの両方のレイヤに実装できます。このアイデアは、コード署名が有効であっても、アプリが変更されていない状態でのみ正しく実行されるように、追加のコントロールを配置するというものです。
 2. _ファイルストレージ完全性チェック:_ アプリケーションが SD カードやパブリックストレージに保存するファイルの完全性、および `SharedPreferences` に保存されるキー・バリューペアの完全性を保護する必要があります。

#### サンプル実装 - アプリケーションソースコード

完全性チェックではたいてい選択したファイルに対してチェックサムやハッシュを計算します。一般的に保護されるファイルは以下のとおりです。

- AndroidManifest.xml
- クラスファイル *.dex
- ネイティブライブラリ (*.so)

以下の [Android Cracking ブログのサンプル実装](https://androidcracking.blogspot.com/2011/06/anti-tampering-with-crc-check.html "anti-tampering with crc check") では `classes.dex` の CRC を計算し、それを期待値と比較しています。

```java
private void crcTest() throws IOException {
 boolean modified = false;
 // required dex crc value stored as a text string.
 // it could be any invisible layout element
 long dexCrc = Long.parseLong(Main.MyContext.getString(R.string.dex_crc));

 ZipFile zf = new ZipFile(Main.MyContext.getPackageCodePath());
 ZipEntry ze = zf.getEntry("classes.dex");

 if ( ze.getCrc() != dexCrc ) {
  // dex has been modified
  modified = true;
 }
 else {
  // dex not tampered with
  modified = false;
 }
}
```

#### サンプル実装 - ストレージ

ストレージ自体に完全性を提供する場合、特定のキー・バリューペア (Android の `SharedPreferences` など) に対して HMAC を作成するか、ファイルシステムが提供するファイル全体に対して HMAC を作成することができます。

HMAC を使用する場合、[bouncy castle 実装または AndroidKeyStore を使用して、指定されたコンテンツを HMAC する](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html "Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm") ことができます。

BouncyCastle で HMAC を生成する場合は以下の手順を実行します。

1. BounceyCastle または SpongeyCastle がセキュリティプロバイダとして登録されていることを確認します。
2. HMAC をキーで初期化します (キーはキーストアに格納します) 。
3. HMAC を必要とするコンテンツのバイト配列を取得します。
4. HMAC とバイトコードで `doFinal` を呼び出します。
5. 手順 3 で取得したバイト配列に HMAC を追加します。
6. 手順 5 の結果を保存します。

BouncyCastle で HMAC を検証する場合は以下の手順を実行します。

1. BounceyCastle または SpongeyCastle がセキュリティプロバイダとして登録されていることを確認します。
2. メッセージと HMAC-bytes を個別の配列として抽出します。
3. HMAC を生成する手順 1-4 を繰り返します。
4. 抽出された HMAC-bytes を手順 3 の結果と比較します。

[Android Keystore](https://developer.android.com/training/articles/keystore.html "Android Keystore") に基づいて HMAC を生成する場合、Android 6.0 (API レベル 23) 以上でのみ行うことをお勧めします。

以下は `AndroidKeyStore` を使用しない便利な HMAC 実装です。

```java
public enum HMACWrapper {
    HMAC_512("HMac-SHA512"), //please note that this is the spec for the BC provider
    HMAC_256("HMac-SHA256");

    private final String algorithm;

    private HMACWrapper(final String algorithm) {
        this.algorithm = algorithm;
    }

    public Mac createHMAC(final SecretKey key) {
        try {
            Mac e = Mac.getInstance(this.algorithm, "BC");
            SecretKeySpec secret = new SecretKeySpec(key.getKey().getEncoded(), this.algorithm);
            e.init(secret);
            return e;
        } catch (NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException e) {
            //handle them
        }
    }

    public byte[] hmac(byte[] message, SecretKey key) {
        Mac mac = this.createHMAC(key);
        return mac.doFinal(message);
    }

    public boolean verify(byte[] messageWithHMAC, SecretKey key) {
        Mac mac = this.createHMAC(key);
        byte[] checksum = extractChecksum(messageWithHMAC, mac.getMacLength());
        byte[] message = extractMessage(messageWithHMAC, mac.getMacLength());
        byte[] calculatedChecksum = this.hmac(message, key);
        int diff = checksum.length ^ calculatedChecksum.length;

        for (int i = 0; i < checksum.length && i < calculatedChecksum.length; ++i) {
            diff |= checksum[i] ^ calculatedChecksum[i];
        }

        return diff == 0;
    }

    public byte[] extractMessage(byte[] messageWithHMAC) {
        Mac hmac = this.createHMAC(SecretKey.newKey());
        return extractMessage(messageWithHMAC, hmac.getMacLength());
    }

    private static byte[] extractMessage(byte[] body, int checksumLength) {
        if (body.length >= checksumLength) {
            byte[] message = new byte[body.length - checksumLength];
            System.arraycopy(body, 0, message, 0, message.length);
            return message;
        } else {
            return new byte[0];
        }
    }

    private static byte[] extractChecksum(byte[] body, int checksumLength) {
        if (body.length >= checksumLength) {
            byte[] checksum = new byte[checksumLength];
            System.arraycopy(body, body.length - checksumLength, checksum, 0, checksumLength);
            return checksum;
        } else {
            return new byte[0];
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}

```

完全性を持たせるもう一つの方法は取得したバイト配列に署名を行い、元のバイト配列に署名を加えることです。

### リバースエンジニアリングツールの検出

リバースエンジニアが一般的に使用するツール、フレームワーク、アプリが存在する場合、アプリをリバースエンジニアリングしようとしていることを示している可能性があります。これらのツールの中にはルート化されたデバイスでのみ実行できるものもあれば、アプリをデバッグモードで動作するものや、モバイルフォンでのバックグラウンドサービス開始に依存するものもあります。したがって、リバースエンジニアリング攻撃を検知してそれに対応するためにアプリが実装する方法はさまざまです。たとえば、アプリ自体を終了します。

関連するアプリケーションパッケージ、ファイル、プロセス、またはその他のツール固有の変更とアーティファクトを探すことで、変更のない状態でインストールされた一般的なリバースエンジニアリングツールを検出できます。以下の例では、このガイドで広く使用されている Frida インストルメンテーションフレームワークを検出するさまざまな方法について説明します。Substrate や Xposed などの他のツールも同様に検出できます。DBI/インジェクション/フックツールは後述するランタイム完全性チェックを通じて暗黙的に検出できることが多いことに注意してください。

たとえば、ルート化されたデバイスのデフォルト設定では Frida はデバイス上で frida-server として実行します。ターゲットアプリに (frida-trace や Frida REPL などを介して) 明示的にアタッチすると、Frida はアプリのメモリに frida-agent を注入します。したがって、アプリにアタッチした後 (前ではなく) そこにあることが期待できます。 `/proc/<pid>/maps` をチェックすると、frida-agent が frida-agent-64.so として見つかります。

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida
71b6bd6000-71b7d62000 r-xp  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7d7f000-71b7e06000 r--p  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7e06000-71b7e28000 rw-p  /data/local/tmp/re.frida.server/frida-agent-64.so
```

もう一つの方法 (非ルート化デバイスでも機能します) は APK に [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") を埋め込み、アプリがそれをネイティブライブラリの一つとしてロードすることを強制するものです。アプリの起動後に (明示的にアタッチする必要はありません) アプリのメモリマップを調べると、埋め込まれた frida-gadget が libfrida-gadget.so として見つかります。

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida

71b865a000-71b97f1000 r-xp  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b9802000-71b988a000 r--p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b988a000-71b98ac000 rw-p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
```

Frida が残したこれら二つの痕跡を見れば、それらを検出するのは簡単な作業であることがすぐに想像できるかもしれません。そして実際、その検出をバイパスすることは非常に簡単です。しかし物事はもっと複雑になる可能性があります。以下の表はいくつかの典型的な Frida 検出方法とその有効性についての簡単な説明を簡潔に示しています。

> 以下の検出方法の一部は [Berdhard Mueller の記事 "The Jiu-Jitsu of Detecting Frida"](https://web.archive.org/web/20181227120751/http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida "The Jiu-Jitsu of Detecting Frida") (archived) で紹介されています。詳細とコードスニペット例についてはそちらを参照してください。

| 手法 | 説明 | 考察 |
| --- | --- | --- |
| **アプリ署名をチェックする** | APK 内に frida-gadget を埋め込むには、再パッケージ化して再署名する必要があります。アプリの起動時に APK の署名をチェック (例: API レベル 28 以降では [GET_SIGNING_CERTIFICATES](https://developer.android.com/reference/android/content/pm/PackageManager#GET_SIGNING_CERTIFICATES "GET_SIGNING_CERTIFICATES")) し、API にピン留めしたものと比較します。 | これは残念ながら、APK にパッチを当てたり、システムコールフックを行うなどで、バイパスするのは非常に簡単です。 |
| **環境に関連するアーティファクトをチェックする** | アーティファクトにはパッケージファイル、バイナリ、ライブラリ、プロセス、一時ファイルなどがあります。Frida の場合、これはターゲット (ルート化された) システムで実行されている frida-server (TCP 経由で Frida を公開する役割を担うデーモン) である可能性があります。実行中のサービス ([`getRunningServices`](https://developer.android.com/reference/android/app/ActivityManager.html#getRunningServices%28int%29 "getRunningServices")) とプロセス (`ps`) を調べて、名前が "frida-server" であるものを探します。また、ロードされたライブラリのリストを調べて、疑わしいもの (名前に "frida" が含まれているものなど) をチェックします。 | Android 7.0 (API レベル 24) 以降、実行中のサービスやプロセスを調べても、アプリ自体によって起動されていないため、frida-server のようなデーモンは表示されません。たとえ可能であったとしても、これをバイパスするには関連する Frida アーティファクト (frida-server/frida-gadget/frida-agent) の名前を変えるだけで簡単でしょう。 |
| **オープン TCP ポートをチェックする** | frida-server プロセスはデフォルトで TCP ポート 27042 にバインドしています。このポートがオープンであるかどうかをチェックすることもデーモンを検出する方法の一つです。 | この方法はデフォルトモードの frida-server を検出しますが、リスニングポートはコマンドライン引数で変更できるため、これをバイパスすることは少し簡単すぎます。 |
| **D-Bus 認証に応答するポートをチェックする** | `frida-server` は通信に D-Bus プロトコルを使用するため、D-Bus 認証に応答することが期待できます。すべてのオープンポートに D-Bus 認証メッセージを送信し、応答をチェックし、`frida-server` が現れることを期待します。 | これは `frida-server` を検出するかなり堅実な方法ですが、Frida は frida-server を必要としない別の動作モードを提供しています。 |
| **既知のアーティファクトについてプロセスメモリをスキャンする** | メモリをスキャンして、Frida のライブラリで見つかるアーティファクト (すべてのバージョンの frida-gadget と frida-agent に現れる文字列 "LIBFRIDA" など) を探します。たとえば、 `Runtime.getRuntime().exec` を使用して、 `/proc/self/maps` や `/proc/<pid>/maps` (Android バージョンによる) にリストされているメモリマッピングを繰り返して文字列を探します。 | この方法はもう少し効果的で、特に難読化を加えている場合や複数のアーティファクトをスキャンしている場合には、Frida だけでバイパスするのは困難です。しかし、選択したアーティファクトは Frida バイナリにパッチが当てられている可能性があります。ソースコードは [Berdhard Mueller の GitHub](https://github.com/muellerberndt/frida-detection-demo/blob/master/AntiFrida/app/src/main/cpp/native-lib.cpp "frida-detection-demo") にあります。 |

この表は網羅からは程遠いことを忘れないでください。 [名前付きパイプ](https://en.wikipedia.org/wiki/Named_pipe "Named Pipes") (frida-server が外部通信に使用) について話しましょう。 [トランポリン](https://en.wikipedia.org/wiki/Trampoline_%28computing%29 "Trampolines") (関数のプロローグに挿入された間接的なジャンプベクトル) の検出は Substrate や Frida の Interceptor の検出には役立ちますが、たとえば、Frida の Stalker に対しては有効ではありません。その他多くの、多かれ少なかれ、効果的な検出方法があります。これらはそれぞれ、ルート化されたデバイスを使用しているかどうか、ルート化手法の特定のバージョンやツール自体のバージョンによって異なります。さらに、アプリはさまざまな難読化技法を使用して実装された保護メカニズムの検出をより困難にすることができます。結局のところ、これは信頼できない環境 (ユーザーデバイスで実行されているアプリ) で処理されるデータを保護するいたちごっこの一環です。

> これらのコントロールはリバースエンジニアリングプロセスの複雑さを増すだけであることに注意することが重要です。使用する場合、最善のアプローチはコントロールを個別に使用するのではなく、巧みに組み合わせることです。ただし、リバースエンジニアリングは常にデバイスにフルアクセスできるので必ず勝利できるため、いずれも 100% の効果を保証することはできません。また、いくつかのコントロールをアプリに統合すると、アプリの複雑さが増し、パフォーマンスに影響を与える可能性があることも考慮する必要があります。

### エミュレータの検出

アンチリバースのコンテキストでは、エミュレータ検出の目的はエミュレートされたデバイス上でアプリを実行する難易度を上げて、リバースエンジニアが好んで使用するツールや技法を阻むことです。この難易度の上昇により、リバースエンジニアはエミュレータチェックを破るか物理デバイスを利用することを余儀なくされ、大規模なデバイス解析に必要なアクセスを妨げます。

問題のデバイスがエミュレートされていることを示すインジケータはいくつかあります。これらの API 呼び出しはすべてフックできますが、これらのインジケータはささやかな防御の第一線を提供します。

インジケータの最初のセットは `build.prop` ファイル内にあります。

```default
API Method          Value           Meaning
Build.ABI           armeabi         possibly emulator
BUILD.ABI2          unknown         possibly emulator
Build.BOARD         unknown         emulator
Build.Brand         generic         emulator
Build.DEVICE        generic         emulator
Build.FINGERPRINT   generic         emulator
Build.Hardware      goldfish        emulator
Build.Host          android-test    possibly emulator
Build.ID            FRF91           emulator
Build.MANUFACTURER  unknown         emulator
Build.MODEL         sdk             emulator
Build.PRODUCT       sdk             emulator
Build.RADIO         unknown         possibly emulator
Build.SERIAL        null            emulator
Build.USER          android-build   emulator
```

ルート化された Android デバイスで `build.prop` ファイルを編集したり、ソースから AOSP をコンパイルするときにファイルを改変できます。いずれの技法でも上記の静的文字列チェックをバイパスできます。

次の静的インジケータのセットはテレフォニーマネージャを利用します。すべての Android エミュレータはこの API がクエリできる固定値があります。

```default
API                                                     Value                   Meaning
TelephonyManager.getDeviceId()                          0's                     emulator
TelephonyManager.getLine1 Number()                      155552155               emulator
TelephonyManager.getNetworkCountryIso()                 us                      possibly emulator
TelephonyManager.getNetworkType()                       3                       possibly emulator
TelephonyManager.getNetworkOperator().substring(0,3)    310                     possibly emulator
TelephonyManager.getNetworkOperator().substring(3)      260                     possibly emulator
TelephonyManager.getPhoneType()                         1                       possibly emulator
TelephonyManager.getSimCountryIso()                     us                      possibly emulator
TelephonyManager.getSimSerial Number()                  89014103211118510720    emulator
TelephonyManager.getSubscriberId()                      310260000000000         emulator
TelephonyManager.getVoiceMailNumber()                   15552175049             emulator
```

Xposed や Frida などのフックフレームワークはこの API をフックして偽のデータを提供する可能性があることを心に留めてください。

### ランタイム完全性検証

このカテゴリのコントロールはアプリのメモリ空間の完全性を検証して、実行時に適用されるメモリパッチからアプリを保護します。このようなパッチにはバイナリコード、バイトコード、関数ポインタテーブル、重要なデータ構造に対する望ましくない変更やプロセスメモリにロードされた不正コードが含まれます。完成性は以下のように検証します。

1. メモリの内容や内容のチェックサムを適切な値と比較して、
2. 望ましくない改変のシグネチャがないかメモリを検索します。

「リバースエンジニアリングツールとフレームワークの検出」カテゴリと重複する部分があり、実際、プロセスメモリで Frida 関連文字列を検索する方法を示した際に、その章でシグネチャベースのアプローチを説明しました。以下にさまざまな種類の完全性監視の例をいくつか挙げます。

#### Java ランタイムの改竄の検出

この検出コードは [dead && end blog](https://d3adend.org/blog/?p=589 "dead && end blog - Android Anti-Hooking Techniques in Java") から引用しました。

```java
try {
  throw new Exception();
}
catch(Exception e) {
  int zygoteInitCallCount = 0;
  for(StackTraceElement stackTraceElement : e.getStackTrace()) {
    if(stackTraceElement.getClassName().equals("com.android.internal.os.ZygoteInit")) {
      zygoteInitCallCount++;
      if(zygoteInitCallCount == 2) {
        Log.wtf("HookDetection", "Substrate is active on the device.");
      }
    }
    if(stackTraceElement.getClassName().equals("com.saurik.substrate.MS$2") &&
        stackTraceElement.getMethodName().equals("invoked")) {
      Log.wtf("HookDetection", "A method on the stack trace has been hooked using Substrate.");
    }
    if(stackTraceElement.getClassName().equals("de.robv.android.xposed.XposedBridge") &&
        stackTraceElement.getMethodName().equals("main")) {
      Log.wtf("HookDetection", "Xposed is active on the device.");
    }
    if(stackTraceElement.getClassName().equals("de.robv.android.xposed.XposedBridge") &&
        stackTraceElement.getMethodName().equals("handleHookedMethod")) {
      Log.wtf("HookDetection", "A method on the stack trace has been hooked using Xposed.");
    }

  }
}
```

#### ネイティブフックの検出

ELF バイナリを使用すると、メモリ内の関数ポインタを上書き (グローバスオフセットテーブルや PLT フックなど) したり、関数コード自体の一部にパッチを適用 (インラインフック) することでネイティブ関数フックをインストールできます。それぞれのメモリ領域の完全性をチェックすることがこの種のフックを検出する一つの方法です。

グローバルオフセットテーブル (GOT) はライブラリ関数を解決するために使用されます。実行時に、ダイナミックリンカはこのテーブルをグローバルシンボルの絶対アドレスでパッチします。 _GOT フック_ は保存されている関数アドレスを上書きし、正当な関数呼び出しを攻撃者が制御するコードにリダイレクトします。プロセスメモリマップを列挙し、それぞれの GOT エントリが正当にロードされたライブラリを指していることを検証することで、この種のフックを検出できます。

初めてシンボルアドレスが必要になったときにのみ解決を行う (遅延バインディング) GNU `ld` とは対照的に、 Android リンカーはライブラリがロードされた直後にすべての外部関数を解決してそれぞれの GOT エントリを書き込みます (即時バインディング)。したがって、すべての GOT エントリは実行時にそれぞれのライブラリのコードセクション内の有効なメモリ位置を指していることを期待できます。 GOT フック検出手法では一般的に GOT を歩いてこれを検証します。

インラインフックは関数コードの先頭または末尾にいくつかの命令を上書きすることで機能します。実行時には、このいわゆるトランポリンは注入されたコードに実行をリダイレクトします。ライブラリ関数のプロローグとエピローグに対してライブラリ外部の位置へのファージャンプなどの疑わしい命令などを検査することで、インラインフックを検出できます。

### 難読化

["モバイルアプリの改竄とリバースエンジニアリング"](0x04c-Tampering-and-Reverse-Engineering.md#obfuscation) の章ではモバイルアプリ全般に使用できるよく知られた難読化技法をいくつか紹介しています。

Android アプリはさまざまなツールを使用してこれらの難読化技法のいくつかを実装できます。たとえば、 [ProGuard](0x08a-Testing-Tools.md#proguard) はコードを縮小して難読化し、Android Java アプリのバイトコードから不要なデバッグ情報を削除する簡単な方法を提供します。それはクラス名、メソッド名、変数名などの識別子を意味のない文字列に置き換えます。これはレイアウト難読化の一種であり、プログラムのパフォーマンスに影響はありません。

> Java クラスを逆コンパイルするのは簡単なので、製品バイトコードには常になんらかの基本的な難読化を適用することをお勧めします。

Android 難読化技法について詳しくは以下をご覧ください。

- ["Security Hardening of Android Native Code"](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code/) by Gautam Arvind
- ["APKiD: Fast Identification of AppShielding Products"](https://github.com/enovella/cve-bio-enovella/blob/master/slides/APKiD-NowSecure-Connect19-enovella.pdf) by Eduardo Novella
- ["Challenges of Native Android Applications: Obfuscation and Vulnerabilities"](https://www.theses.fr/2020REN1S047.pdf) by Pierre Graux

#### ProGuard の使用

開発者は build.gradle ファイルを使用して難読化を有効にします。以下の例では `minifyEnabled` と `proguardFiles` を設定していることがわかります。一部のクラスを難読化から保護するために例外を (`-keepclassmembers` と `-keep class` で) 作成することが一般的です。したがって、ProGuard 構成ファイルを監査して、どのクラスが除外されているかを確認することが重要です。 `getDefaultProguardFile('proguard-android.txt')` メソッドは `<Android SDK>/tools/proguard/` フォルダからデフォルトの ProGuard 設定を取得します。

アプリを縮小、難読化、最適化する方法の詳細については [Android 開発者ドキュメント](https://developer.android.com/studio/build/shrink-code "Shrink, obfuscate, and optimize your app") を参照してください。

> Android Studio 3.4 や Android Gradle プラグイン 3.4.0 以降を使用してプロジェクトをビルドすると、プラグインはコンパイル時のコード最適化を実行するために ProGuard を使用しなくなります。代わりに、プラグインは R8 コンパイラを使用します。R8 は既存のすべての ProGuard ルールファイルで動作するため、R8 を使用するように Android Gradle プラグインを更新しても既存のルールを変更する必要はありません。

R8 は Google の新しいコードシュリンカーであり、Android Studio 3.3 beta で導入されました。デフォルトで R8 は行番号、ソースファイル名、変数名などのデバッグに役立つ属性を削除します。R8 はフリーの Java クラスファイルシュリンカー、オプティマイザー、オブファスケーター、プリベリファイアであり、ProGuard よりも高速です。 [Android 開発者ブログの詳細についての投稿](https://android-developers.googleblog.com/2018/11/r8-new-code-shrinker-from-google-is.html "R8") も参照してください。これは Android の SDK ツールに同梱されています。リリースビルドの縮小を有効にするには、以下を build.gradle に追加します。

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

`proguard-rules.pro` ファイルはカスタム ProGuard ルールを定義する場所です。 `-keep` フラグで R8 により削除されないように特定のコードを保持できます。フラグを使用しないとエラーが発生する可能性があります。たとえば、一般的な Android クラスを保持するには、サンプル構成 `proguard-rules.pro` ファイルのようにします。

```default
...
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
...
```

[以下の構文](https://developer.android.com/studio/build/shrink-code#configuration-files "Customize which code to keep") でプロジェクト内の特定のクラスやライブラリに対してこれをより詳細に定義できます。

```default
-keep public class MyClass
```

難読化は実行時のパフォーマンスにコストをもたらすことがよくあるため、通常はコードの特定の非常に特殊な部分、一般的にセキュリティと実行時保護を扱う部分、にのみ適用します。

### デバイスバインディング

デバイスバインディングの目的はアプリとその状態をデバイス A からデバイス B にコピーし、デバイス B でアプリの実行を継続しようとする攻撃者を阻止することです。デバイス A が信頼できると判断された後、デバイス B よりも多くの権限を持つ可能性があります。このような差分の権限はアプリがデバイス A からデバイス B にコピーされても変更すべきではありません。

使用可能な識別子を説明する前に、それらをバインディングに使用できる方法について簡単に説明します。デバイスバインディングを可能にする三つの方法があります。

- 認証に使用されるクレデンシャルをデバイス識別子で補強します。これはアプリケーション自体やユーザーを頻繁に再認証する必要がある場合に意味があります。

- デバイスに強くバインドされている鍵マテリアルでデバイスに保存されるデータを暗号化することでデバイスバインディングを強化できます。Android Keystore はエクスポートできない鍵を提供しており、これに使用できます。悪意のある攻撃者がデバイスからそのようなデータを抽出した場合、鍵にアクセスできないため、データを復号できないでしょう。これを実装するには、以下の手順を行います。

    - `KeyGenParameterSpec` API を使用して Android Keystore の鍵ペアを生成します。

      ```java
      //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
              KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
      keyPairGenerator.initialize(
              new KeyGenParameterSpec.Builder(
                      "key1",
                      KeyProperties.PURPOSE_DECRYPT)
                      .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                      .build());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
      ...

      // The key pair can also be obtained from the Android Keystore any time as follows:
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
      PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();
      ```

    - AES-GCM の暗号鍵 (secret key) を生成します。

      ```java
      //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
      KeyGenerator keyGenerator = KeyGenerator.getInstance(
              KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
      keyGenerator.init(
              new KeyGenParameterSpec.Builder("key2",
                      KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                      .build());
      SecretKey key = keyGenerator.generateKey();

      // The key can also be obtained from the Android Keystore any time as follows:
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      key = (SecretKey) keyStore.getKey("key2", null);
      ```

    - AES-GCM 暗号の暗号鍵 (secret key) を使用して、アプリケーションによって保存されている認証データやその他の機密データを暗号化し、インスタンス ID などのデバイス固有のパラメータを関連データとして使用します。

      ```java
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      final byte[] nonce = new byte[GCM_NONCE_LENGTH];
      random.nextBytes(nonce);
      GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
      cipher.init(Cipher.ENCRYPT_MODE, key, spec);
      byte[] aad = "<deviceidentifierhere>".getBytes();;
      cipher.updateAAD(aad);
      cipher.init(Cipher.ENCRYPT_MODE, key);

      //use the cipher to encrypt the authentication data see 0x50e for more details.
      ```

    - Android Keystore に保存されている公開鍵 (public key) を使用して暗号鍵 (secret key) を暗号化し、暗号化された暗号鍵 (secret key) をアプリケーションのプライベートストレージに保存します。
    - アクセストークンやその他の機密データなどの認証データが必要な場合、Android Keystore に保存されている秘密鍵 (private key) を使用して暗号鍵 (secret key) を復号し、復号した暗号鍵 (secret key) を使用して暗号文を復号します。

- トークンベースのデバイス認証 (インスタンス ID) を使用して、アプリの同じインスタンスが使用されることを確保します。
