## アンチリバース防御のテスト (Android)

### ルート検出のテスト

#### 概要

アンチリバースの文脈では、ルート検出の目的はルート化されたデバイス上でアプリを実行することをもう少し難しくすることで、その後、リバースエンジニアが使用したいツールやテクニックを妨げます。他のほとんどの防御と同様に、ルート検出はそれ自体に高い効果はありませんが、いくつかのルートチェックをアプリにちりばめることで改竄対策スキーム全体の有効性が向上します。

Android では、用語「ルート検出」をより広く定義し、カスタム ROM の検出などを含みます。例えば、デバイスが製品版の Android ビルドであるか、もしくはカスタムビルドであるかを確認します。

##### 共通ルート検出手法

以下のセクションでは、よく見かけるいくつかのルート検出手法を記します。OWASP Mobile Testing Guide に添付されている crackme サンプル <sup>[1]</sup> で実装されているチェックがいくつかあります。

###### SafetyNet

SafetyNet はソフトウェアとハードウェアの情報を使用してデバイスのプロファイルを作成する Android API です。このプロファイルは Android 互換性テストに合格したホワイトリスト化されたデバイスモデルのリストと比較されます。Google はこの機能を「不正使用防止システムの一環として付加的な多層防御シグナル」として使用することを推奨しています <sup>[2]</sup> 。

SafetyNet が正確に中で何をしているかは十分に文書化されておらず、いつでも変更される可能性があります。この API を呼び出すと、サービスは Google はデバイス検証コードを含むバイナリパッケージをダウンロードし、リフレクションを使用して動的に実行されます。John Kozyrakis の分析によると、SafetyNet により実行された検査はデバイスがルート化されているかどうかを検出しようとしますが、これがどのくらい正しいかは不明確です <sup>[3]</sup> 。

この API を使用するには、アプリは the SafetyNetApi.attest() メソッドが *Attestation Result* の JWS メッセージを返し、それから以下のフィールドをチェックします。

- ctsProfileMatch: "true" の場合、デバイスプロファイルは Android 互換性テストに合格した Google のリスト化されたデバイスのひとつと一致します。
- basicIntegrity: アプリを実行しているデバイスはおそらく改竄されてはいません。

attestation result は以下のようになります。

~~~
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
~~~

###### プログラムによる検出

**ファイルの存在チェック**

おそらく最も広く使用されている手法はルート化されたデバイスに通常見つかるファイルをチェックすることです。一般的なルート化アプリのパッケージファイルや関連するファイルおよびディレクトリなどがあります。

~~~
/system/app/Superuser.apk
/system/etc/init.d/99SuperSUDaemon
/dev/com.koushikdutta.superuser.daemon/
/system/xbin/daemonsu

~~~

検出コードはデバイスがルート化されたときに一般的にインストールされるバイナリも検索します。例として、busybox の存在チェックや、*su* バイナリを別の場所で開こうとしていることをチェックすることなどがあります。

~~~
/system/xbin/busybox

/sbin/su
/system/bin/su
/system/xbin/su
/data/local/su
/data/local/xbin/su
~~~

代わりに、*su* が PATH にあるかどうかを確認することもできます。

~~~java
    public static boolean checkRoot(){
        for(String pathDir : System.getenv("PATH").split(":")){
            if(new File(pathDir, "su").exists()) {
                return true;
            }
        }
        return false;
    }
~~~

ファイルチェックは Java とネイティブコードの両方で簡単に実装できます。以下の JNI の例では、<code>stat</code> システムコールを使用してファイルに関する情報を取得します (rootinspector <sup>[9]</sup> から改変したコード例)。ファイルが存在する場合、<code>1</code> を返します。

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

**su および他のコマンドの実行**

<code>su</code> が存在するかどうかを判断する別の方法は、<code>Runtime.getRuntime.exec()</code> で実行を試みることです。<code>su</code> が PATH にない場合、IOException がスローされます。同じ方法を使用して、ルート化されたデバイス上によく見つかる他のプログラムを確認することができます。busybox や一般的にそれを指すシンボリックリンクなどがあります。

**実行中のプロセスの確認**

Supersu は最も人気のあるルート化ツールであり、<code>daemonsu</code> という名前の認証デーモンを実行します。そのため、このプロセスが存在することはルート化されたデバイスのもうひとつの兆候です。実行中のプロセスは <code>ActivityManager.getRunningAppProcesses()</code> および <code>manager.getRunningServices()</code> API、<code>ps</code> コマンドで列挙でき、<code>/proc</code> ディレクトリで閲覧できます。例として、rootinspector <sup>[9]</sup> では以下のように実装されています。

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

**インストール済みのアプリパッケージの確認**

Android パッケージマネージャを使用するとインストールされているパッケージのリストを取得できます。以下のパッケージ名は一般的なルート化ツールに属します。

~~~
com.thirdparty.superuser
eu.chainfire.supersu
com.noshufou.android.su
com.koushikdutta.superuser
com.zachspong.temprootremovejb
com.ramdroid.appquarantine
~~~

**書き込み可能なパーティションとシステムディレクトリの確認**

sysytem ディレクトリに対する普通とは異なるアクセス許可は、カスタマイズまたはルート化されたデバイスを示します。通常の状況下では、system および data ディレクトリは常に読み取り専用でマウントされていますが、デバイスがルート化されていると読み書き可能でマウントされることがあります。これはこれらのファイルシステムが "rw" フラグでマウントされているかどうかをチェックすることでテストできます。もしくはこれらのディレクトリにファイルを作成してみます。

**カスタム Android ビルドの確認**

デバイスがルート化されているかどうかを確認するだけでなく、テストビルドやカスタム ROM の兆候を確認することも役に立ちます。これを行う方法のひとつは、BUILD タグに test-keys が含まれているかどうかを確認することです。これは一般的にカスタム Android イメージを示します <sup>[5]</sup> 。これは以下のように確認できます <sup>[6]</sup> 。

~~~
private boolean isTestKeyBuild()
{
String str = Build.TAGS;
if ((str != null) && (str.contains("test-keys")));
for (int i = 1; ; i = 0)
  return i;
}
~~~

Google Over-The-Air (OTA) 証明書の欠落はカスタム ROM のもうひとつの兆候です。出荷版の Android ビルドでは、OTA アップデートに Google の公開証明書を使用します <sup>[4]</sup> 。

##### ルート検出のバイパス

JDB, DDMS, strace やカーネルモジュールを使用して実行トレースを実行し、アプリが何をしているかを調べます。通常はオペレーティングシステムとのすべての種類の疑わしいやり取りを表示します。*su* の読み込みやプロセスリストの取得などがあります。これらのやり取りはルート検出の確実な兆候です。ルート検出メカニズムを一つ一つ特定し非アクティブにします。ブラックボックスの耐性評価を実行している場合は、ルート化検出メカニズムを無効にすることが最初のステップです。

多くのテクニックを使用してこれらのチェックをバイパスできます。これらのほとんどは「リバースエンジニアリングと改竄」の章で紹介されています。

1. バイナリの名前を変更する。例えば、場合によっては単に "su" バイナリの名前を変更するだけで、ルート検出を無効にできます (あなたの環境を壊さないようにします) 。
2. /proc をアンマウントして、プロセスリストの詠み込みなどを防止する。往々にして、proc が利用できないだけでそのようなチェックを無効にできます。
3. Frida や Xposed を使用して、Java やネイティブレイヤーに API をフックする。これを行うことにより、ファイルやプロセスを隠したり、ファイルの実際の内容を隠したり、アプリが要求するすべての種類の偽の値を返したりできます。
4. カーネルモジュールを使用して、低レベル API をフックする。
5. アプリにパッチを当て、チェックを削除する。

#### 有効性評価

ルート検出メカニズムが存在するかどうかを確認し、以下の基準を適用します。

- 複数の検出手法がアプリ全体に分散されている (ひとつの手法にすべてを任せてはいない)
- ルート検出メカニズムは複数の API レイヤ (Java API、ネイティブライブラリ関数、アセンブラ/システムコール) で動作する
- そのメカニズムはある程度の独創性を示している (StackOverflow や他のソースからコピー＆ペーストしたものではない)

ルート検出メカニズムのバイパス手法を開発し、以下の質問に答えます。

- RootCloak などの標準ツールを使用してそのメカニズムを簡単にバイパスできますか？
- ルート検出を処理するにはある程度の静的/動的解析が必要ですか？
- カスタムコードを書く必要はありましたか？
- それをうまくバイパスするにはどれくらいの時間がかかりましたか？
- 難易度の主観的評価はいくつですか？

より詳細な評価を行うには、「ソフトウェア保護スキームの評価」の章の「プログラムによる防御の評価」に記載されている基準を適用します。

#### 改善方法

ルート検出が欠落しているか、または非常に簡単にバイパスされてしまう場合は、上記の有効性基準に沿って提案を作成します。これには、より多くの検出メカニズムを追加すること、または既存のメカニズムを他の防御とより良く統合することが含まれます。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M9 - リバースエンジニアリング - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

- V8.3: "アプリは二つ以上の機能的に依存しないルート検出方式を実装しており、ユーザーに警告するかアプリを終了することでルート化デバイスの存在に応答している。"

##### CWE

N/A

##### その他

- [1] OWASP Mobile Crackmes - https://github.com/OWASP/owasp-mstg/blob/master/OMTG-Files/02_Crackmes/List_of_Crackmes.md
- [2] SafetyNet Documentation - https://developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNet
- [3] SafetyNet: Google's tamper detection for Android - https://koz.io/inside-safetynet/
- [4] NetSPI Blog - Android Root Detection Techniques - https://blog.netspi.com/android-root-detection-techniques/
- [5] InfoSec Institute - http://resources.infosecinstitute.com/android-hacking-security-part-8-root-detection-evasion/
- [6] Android – Detect Root Access from inside an app - https://www.joeyconway.com/blog/2014/03/29/android-detect-root-access-from-inside-an-app/

##### ツール

- [7] rootbeer - https://github.com/scottyab/rootbeer
- [8] RootCloak - http://repo.xposed.info/module/com.devadvance.rootcloak2
- [9] rootinspector - https://github.com/devadvance/rootinspector/

### アンチデバッグのテスト

#### 概要

デバッグはアプリのランタイム動作を解析する非常に効果的な方法です。これはリバースエンジニアがコードをステップ実行し、任意の箇所でアプリの実行を停止し、変数の状態を検査し、メモリを読み取りおよび変更し、さらに多くのことを可能にします。

「リバースエンジニアリングと改竄」の章で述べたように、Android では二つの異なるデバッグプロトコルを扱う必要があります。JDWP を使用した Java レベルと、ptrace ベースのデバッガを使用したネイティブレイヤーのデバッグが可能です。したがって、優れたアンチデバッグスキームでは両方のデバッガタイプに対して防御を実装する必要があります。

アンチデバッグ機能は予防型または反応型にできます。この名前が示すように、予防型アンチデバッグトリックはまず第一にデバッガがアタッチすることを防ぎます。反応型トリックはデバッガが存在するかどうかを検出し、何らかの方法でそれに反応させようと試みます (アプリの終了やなんらかの隠された動作のトリガなど) 。「多ければ多いほど良い」ルールが適用されます。効果を最大限にするため、防御側では、さまざまな API レイヤーで動作しアプリ全体に分散されている、複数の予防と検出の手法を組み合わせます。

##### アンチ JDWP デバッグの例

「リバースエンジニアリングと改竄」の章では、デバッガと Java 仮想マシンとの間の通信に使用されるプロトコルである JDWP について説明しました。また、Manifest ファイルにパッチを当てて任意のアプリを容易にデバッグ可能にできることや、ro.debuggable システムプロパティを変更することであらゆるアプリをデバッグ可能にできることがわかりました。開発者が JDWP デバッガを検出ないし無効にするために行ういくつかのことを見てみます。

###### ApplicationInfo のデバッグ可能フラグの確認

すでに何度か <code>android:debuggable</code> 属性が出てきました。アプリマニフェストのこのフラグは JDWP スレッドがアプリに対して起動されるかどうかを決定します。その値はアプリの ApplicationInfo オブジェクトを使用してプログラムで決定できます。このフラグが設定されている場合、これはマニフェストが改竄されてデバッグ可能になっていることを示します。

```java
    public static boolean isDebuggable(Context context){

        return ((context.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);

    }
```
###### isDebuggerConnected

Android Debug システムクラスはデバッガが現在接続されているかどうかをチェックする静的メソッドを提供します。このメソッドは単にブール値を返します。

```
    public static boolean detectDebugger() {
        return Debug.isDebuggerConnected();
    }
```

同じ API をネイティブコードから呼ぶことが可能です。DvmGlobals グローバル構造体にアクセスします。

```
JNIEXPORT jboolean JNICALL Java_com_test_debugging_DebuggerConnectedJNI(JNIenv * env, jobject obj) {
    if (gDvm.debuggerConnect || gDvm.debuggerAlive)
        return JNI_TRUE;
    return JNI_FALSE;
}
```

###### タイマーチェック

<code>Debug.threadCpuTimeNanos</code> は現在のスレッドがコードの実行に費やした時間量を示します。デバッグはプロセスの実行を遅くするため、実行時間の違いを利用して、デバッガがアタッチされているかどうかを推測することができます [2] 。

```
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
```

###### JDWP 関連のデータ構造への干渉

Dalvik では、グローバル仮想マシンの状態は DvmGlobals 構造体を介してアクセス可能です。グローバル変数 gDvm はこの構造体へのポイントを保持します。DvmGlobals には JDWP デバッグに重要なさまざまな変数やポインタが含まれており、改竄可能です。

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

例えば、gDvm.methDalvikDdmcServer_dispatch 関数ポインタに NULL を設定すると JDWP スレッドがクラッシュします <sup>[2]</sup> 。

```c
JNIEXPORT jboolean JNICALL Java_poc_c_crashOnInit ( JNIEnv* env , jobject ) {
  gDvm.methDalvikDdmcServer_dispatch = NULL;
}
```

gDvm 変数が利用できない場合でも、ART で同様の技法を使用してデバッグを無効にできます。ART ランタイムは JDWP 関連のクラスの vtable の一部をグローバルシンボルとしてエクスポートします (C++ では、vtable はクラスメソッドのポインタを保持するテーブルです) 。これには JdwpSocketState と JdwpAdbState を含むクラスの vtable を含んでいます。これら二つはネットワークソケットと ADB を介した JDWP 接続をそれぞれ処理します。デバッグランタイムの動作はこれらの vtable のメソッドポインタを上書きすることにより操作できます。

これを行うための方法のひとつは "jdwpAdbState::ProcessIncoming()" のアドレスを "JdwpAdbState::Shutdown()" のアドレスで上書きすることです。これによりデバッガは直ちに切断されます [3] 。

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

##### アンチネイティブデバッグの例

ほとんどのアンチ JDWP トリックは (おそらくタイマーベースのチェックは安全だが) 旧来の ptrace ベースのデバッガをキャッチしないため、この種のデバッグを防ぐには別の防御が必要です。多くの「従来の」Linux アンチデバッグトリックがここでは採用されています。

###### TracerPid のチェック

プロセスへのアタッチに <code>ptrace</code> システムコールを使用すると、デバッグされたプロセスのステータスファイルの "TracerPid" フィールドにアタッチプロセスの PID が表示されます。"TracerPid" のデフォルト値は "0" (他のプロセスはアタッチしていない) です。したがって、そのフィールドに "0" 以外のものを見つけることは、デバッガやその他の ptrace のいたずらの兆候です。

以下の実装は Tim Strazzere's Anti-Emulator project <sup>[3]</sup> から得ました。

```
    public static boolean hasTracerPid() throws IOException {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(new FileInputStream("/proc/self/status")), 1000);
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.length() > tracerpid.length()) {
                    if (line.substring(0, tracerpid.length()).equalsIgnoreCase(tracerpid)) {
                        if (Integer.decode(line.substring(tracerpid.length() + 1).trim()) > 0) {
                            return true;
                        }
                        break;
                    }
                }
            }

        } catch (Exception exception) {
            exception.printStackTrace();
        } finally {
            reader.close();
        }
        return false;
    }
```

**Ptraceのバリエーション***

Linux では、<code>ptrace()</code> システムコールは別のプロセス ("tracee") の実行を監視および制御し、tracee のメモリとレジスタを調査および変更するために使用されます [5] 。それはブレークポイントデバッグとシステムコールトレースを実装する主な手段です。多くのアンチデバッグトリックは何かについえ <code>ptrace</code> を使用します。一度にプロセスにアタッチできるのはひとつのデバッガだけであるという事実をよく利用します。

簡単な例として、以下のようなコードを使用して、子プロセスをフォークし、それをデバッガとして親プロセスにアタッチすることで、プロセスのデバッグを防ぐことができます。

```
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

子がアタッチされると、何かしらがさらに親に接続しようとする試みは失敗します。これを確認するには、JNI 関数のコードをコンパイルし、デバイス上で実行するアプリにパックします。

```bash
root@android:/ # ps | grep -i anti
u0_a151   18190 201   1535844 54908 ffffffff b6e0f124 S sg.vantagepoint.antidebug
u0_a151   18224 18190 1495180 35824 c019a3ac b6e0ee5c S sg.vantagepoint.antidebug
```

親プロセスに gdbserver でアタッチしようとすると、エラーで失敗します。

```bash
root@android:/ # ./gdbserver --attach localhost:12345 18190
warning: process 18190 is already traced by process 18224
Cannot attach to lwp 18190: Operation not permitted (1)
Exiting
```

しかしこれは、子を終了し、追跡から親を「解放」することにより、容易に回避されます。実際には、通常、複数のプロセスやスレッド、さらには改ざんを防ぐための監視など、より緻密なスキームがあります。一般的な方法は以下のとおりです。

- 互いに追跡する複数のプロセスをフォークします。
- 子が生存し続けていることを確認するために実行中のプロセスを追跡し続けます。
- /proc/pid/status の TracerPID など /proc ファイルシステムの値を監視します。

上記の方法を簡単に改良してみます。初期の <code>fork()</code> の後、子のステータスを継続的に監視する親の追加スレッドを実行します。アプリがデバッグモードとリリースモードのいずれでビルドされたか (マニフェストの <code>android:debuggable</code> による) に従って、子プロセスは以下のいずれかの方法で動作することが期待されます。

1. リリースモードでは、ptrace への呼び出しは失敗し、子はセグメンテーションフォルト (exit code 11) で直ちにクラッシュします。
2. デバッグモードでは、ptrace への呼び出しは機能し、子は無期限に実行されます。結果として、waitpid(child_pid) への呼び出しは決して戻らないでしょう。もし戻るのであれば、何かが怪しく、私たちはプロセスグループ全体を終了します。

これを JNI 関数として実装する完全なコードは以下のとおりです。

```c
#include <jni.h>
#include <string>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

static int child_pid;

void *monitor_pid(void *) {

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
extern "C"

JNIEXPORT void JNICALL
Java_sg_vantagepoint_antidebug_MainActivity_antidebug(
        JNIEnv *env,
        jobject /* this */) {

        anti_debug();
}
```

再び、これを Android アプリにパックして、それが機能するかどうかを確認します。前と同様に、アプリのデバッグビルドを実行すると、二つのプロセスが表示されます。

```bash
root@android:/ # ps | grep -i anti-debug
u0_a152   20267 201   1552508 56796 ffffffff b6e0f124 S sg.vantagepoint.anti-debug
u0_a152   20301 20267 1495192 33980 c019a3ac b6e0ee5c S sg.vantagepoint.anti-debug
```

但し、子プロセスを終了すると、親プロセスも終了します。

```bash
root@android:/ # kill -9 20301
130|root@hammerhead:/ # cd /data/local/tmp                                     
root@android:/ # ./gdbserver --attach localhost:12345 20267   
gdbserver: unable to open /proc file '/proc/20267/status'
Cannot attach to lwp 20267: No such file or directory (2)
Exiting
```

これを回避するには、アプリの動作を少し修正する必要があります (最も簡単なのは _exit への呼び出しを NOP でパッチするか、libc.so の関数 _exit をフックすることです) 。現時点では、よく知られた「軍拡競争」に入ります。この防御をより複雑な形で実現することは常に可能であり、それを回避する方法は常にあります。

##### デバッガ検出のバイパス

例によって、アンチデバッグを回避する一般的な方法はありません。これはデバッグを防止または検出するために使用される特定のメカニズムや、全体的な保護スキームのその他の防御に依存します。例えば、整合性チェックがない場合、またはすでに無効化している場合には、アプリにパッチを当てるのが最も簡単な方法です。他の場合には、フックフレームワークやカーネルモジュールを使用するほうが望ましいかもしれません。

1. アンチデバッグ機能をパッチアウトします。単純に NOP 命令で上書きすることで不要な動作を無効にします。アンチデバッグメカニズムが十分に検討されている場合には、より複雑なパッチが必要になることに注意します。
2. Frida または Xposedを使用して、Java およびネイティブレイヤの API をフックします。isDebuggable や isDebuggerConnected などの関数の戻り値を操作し、デバッガを隠蔽します。
3. 環境を変更します。Android はオープンな環境です。それ以外の何も機能しないのであれば、オペレーティングシステムを変更して、アンチデバッグトリックを設計する際に開発者が行った想定を覆すことができます。

###### バイパスの例: UnCrackable App for Android Level 2

難読化されたアプリを扱う場合、開発者はネイティブライブラリのデータや機能を意図的に「隠す」ことがよくあります。"UnCrackable App for Android" のレベル2にこの例があります。

一見すると、コードは以前のチャレンジと似ています。
"CodeCheck" と呼ばれるクラスはユーザーが入力したコードの検証を担当します。実際のチェックはメソッド "bar()" で行われているようです。これは *native* メソッドとして宣言されています。

-- TODO [Example for Bypassing Debugger Detection] --

```java
package sg.vantagepoint.uncrackable2;

public class CodeCheck {
    public CodeCheck() {
        super();
    }

    public boolean a(String arg2) {
        return this.bar(arg2.getBytes());
    }

    private native boolean bar(byte[] arg1) {
    }
}

    static {
        System.loadLibrary("foo");
    }
```

#### 有効性評価

アンチデバッグメカニズムの有無を確認し、以下の基準を適用します。

- JDB および ptrace ベースのデバッガはアタッチに失敗するか、アプリを終了または機能を停止する
- 複数の検出手法がアプリ全体に分散されている (すべてを単一のメソッドや関数につぎ込んではいない)
- アンチデバッグ防御は複数の API レイヤ (Java、ネイティブライブラリ関数、アセンブラ/システムコール) で動作する
- メカニズムはある程度の独創性を示す (StackOverflow や他のソースからのコピー/ペーストではない)

アンチデバッグ防御のバイパスに取り組み、以下の問いに答えます。

- 単純な手法を使用してメカニズムをバイパスすることは可能か？ (例えば、単一の API 関数をフックするなど)
- 静的および動的解析を使用してアンチデバッグコードを特定することはどの程度困難か？
- 防御を無効にするカスタムコードを書く必要はあるか？どの程度の時間を費やす必要があったか？
- 難易度の主観的評価は何か？

より詳細な評価を行うには「ソフトウェア保護スキームの評価」の章の「プログラムによる防御の評価」に記載されている基準を適用します。

#### 改善方法

アンチデバッグが欠落しているか、非常に簡単にバイパスされる場合、上記の有効性基準に沿って提案します。これにはより多くの検出メカニズムの追加や、さらに既存のメカニズムと他の防御の統合を含みます。

#### 参考情報

- [1] Matenaar et al. - Patent Application - MOBILE DEVICES WITH INHIBITED APPLICATION DEBUGGING AND METHODS OF OPERATION - https://www.google.com/patents/US8925077
- [2] Bluebox Security - Android Reverse Engineering & Defenses - https://slides.night-labs.de/AndroidREnDefenses201305.pdf
- [3] Tim Strazzere - Android Anti-Emulator - https://github.com/strazzere/anti-emulator/
- [4] Anti-Debugging Fun with Android ART - https://www.vantagepoint.sg/blog/88-anti-debugging-fun-with-android-art
- [5] ptrace man page - http://man7.org/linux/man-pages/man2/ptrace.2.html

### ファイル整合性監視のテスト

#### 概要
ファイル整合性に関連するトピックは二つあります。

 1. _アプリケーションソース関連の整合性チェック_ 「改竄とリバースエンジニアリング」の章では、Android の APK コード署名チェックについて説明しました。また、リバースエンジニアがアプリを再パッケージおよび再署名することで、このチェックを簡単に回避できることも説明しました。このプロセスをより複雑にするために、アプリのバイトコードやネイティブライブラリ、重要なデータファイルの CRC チェックを使用して、保護スキームを拡張できます。これらのチェックは Java とネイティブの両方のレイヤで実装できます。この考えは、コード署名が有効であっても、変更されていない状態でのみ正しく実行されるように、追加のコントロールを用意することです。
 2. _ファイルストレージ関連の整合性チェック_ ファイルがアプリケーションにより SD カードまたはパブリックストレージに格納される場合、またはキー・バリューペアが `SharedPreferences` に格納される場合、それらの整合性は保護される必要があります。

##### サンプル実装 - アプリケーションソース

整合性チェックでは選択したファイルに対してチェックサムやハッシュを計算することがよくあります。一般的に保護されているファイルは以下のとおりです。

- AndroidManifest.xml
- クラスファイル *.dex
- ネイティブライブラリ (*.so)

Android Cracking Blog <sup>[1]</sup> の以下のサンプル実装では classes.dex に対して CRC を計算し、期待値と比較します。


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
##### サンプル実装 - ストレージ

ストレージ自体に整合性を提供する場合。Android の `SharedPreferences` のようにキー・バリューペアを介して HMAC を作成することも、ファイルシステムが提供する完全なファイルに対して HMAC を作成することもできます。
HMAC を使用する場合、bouncy castle 実装を使用して指定されたコンテンツまたは AndroidKeyStore を HMAC にして、後でその HMAC を検証します。処理をするにはいくつかのステップがあります。
暗号化が必要な場合。[2] で説明されているように暗号化してから HMAC することを確認してください。

BouncyCastle で HMAC を生成する場合:

1. BounceyCastle または SpongeyCastle がセキュリティプロバイダとして登録されていることを確認します。
2. HMAC をキーで初期化します。キーはキーストアに格納します。
3. HMAC を必要とするコンテンツのバイト配列を取得します。
4. HMAC とバイトコードで `doFinal` を呼び出します。
5. 手順3のバイト配列に HMAC を追加します。
6. 手順5の結果を格納します。

BouncyCastle で HMAC を検証する場合:

1. BounceyCastle または SpongeyCastle がセキュリティプロバイダとして登録されていることを確認します。
2. メッセージと hmacbytes を個別の配列として抽出します。
3. データに対して hmac を生成する手順1-4を繰り返します。
4. ここで抽出された hmacbytes を手順3の結果と比較します。

Android キーストアに基づいて HMAC を生成する場合、Android 6 以降でのみこれを行うことが最適です。その場合、[3] で説明されているように hmac のためのキーを生成します。
`AndroidKeyStore` なしでの便利な HMAC 実装を以下に示します。

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

整合性を提供する他の方法には、取得されるバイト配列への署名があります。署名の生成方法については [3] を確認してください。署名を元のバイト配列に追加することを忘れないでください。

##### ファイル整合性監査のバイパス

*アプリケーションソースの整合性チェックをバイパスしようとする場合*

1. アンチデバッグ機能にパッチを当てます。それぞれのバイトコードまたはネイティブコードを NOP 命令で上書きするだけで望まれない動作を無効にします。
2. Frida または Xposed を使用して Java およびネイティブレイヤ上のファイルシステム API をフックします。改変されたファイルの代わりに元のファイルへのハンドルを返します。
3. カーネルモジュールを使用して、ファイル関連システムコールを傍受します。プロセスが改変されたファイルを開こうとすると、代わりに改変されていないバージョンのファイルのファイル記述子が返ります。

パッチ、コードインジェクション、カーネルモジュールの例については、「改竄とリバースエンジニアリング」のセクションを参照ください。

*ストレージの整合性チェックをバイパスしようとする場合*

1. デバイスバインディングのセクションで記載されているように、デバイスからデータを取得します。
2. 取得されたデータを変更し、ストレージに戻します。

#### 有効性評価

*アプリケーションソースの完全性チェックの場合*
変更されていない状態でデバイス上でアプリを実行し、すべてが機能することを確認します。次に、アプリパッケージに含まれている classes.dex とすべての .so ライブラリに簡単なパッチを適用します。「セキュリティテスト入門」の章で説明されているようにアプリを再パッケージおよび再署名し、実行します。アプリは変更を検出して、何らかの方法で応答する必要があります。少なくとも、アプリはユーザーに警告したり、アプリを終了したりする必要があります。防御をバイパスするように作業し、以下の質問に答えます。

- 単純な手法を使用してメカニズムをバイパスすることは可能か？ (例えば、単一の API 関数をフックするなど)
- 静的および動的解析を使用してアンチデバッグコードを特定することはどの程度困難か？
- 防御を無効にするカスタムコードを書く必要はあるか？どの程度の時間を費やす必要があったか？
- 難易度の主観的評価は何か？

より詳細な評価を行うには「ソフトウェア保護スキームの評価」の章の「プログラムによる防御の評価」に記載されている基準を適用します。

*ストレージの完全性チェックの場合*
同様のアプローチをここで考え、以下の質問に答えます。
- 単純な手法を使用してメカニズムをバイパスすることは可能か？ (例えば、ファイルまたはキー・バリューの内容を変更するなど)
- HMAC 鍵や非対称秘密鍵を取得することはどの程度困難か？
- 防御を無効にするカスタムコードを書く必要はあるか？どの程度の時間を費やす必要があったか？
- 難易度の主観的評価は何か？

#### 参考情報

##### OWASP Mobile Top 10 2016

* M9 - リバースエンジニアリング - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

-- V8.3: "アプリは実行ファイルや重要なデータの改竄を検出し応答している。"

##### CWE

- N/A

##### その他

- [1] Android Cracking Blog - http://androidcracking.blogspot.sg/2011/06/anti-tampering-with-crc-check.html
- [2] Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm - http://cseweb.ucsd.edu/~mihir/papers/oem.html
- [3] Android Keystore System - https://developer.android.com/training/articles/keystore.html

### リバースエンジニアリングツールの検出のテスト

#### 概要

リバースエンジニアは多くのツール、フレームワーク、アプリを使用し、このガイドで遭遇した多くのリバースプロセスを支援します。結果として、デバイス上にそのようなツールが存在することは、ユーザーがアプリをリバースエンジニアリング使用としているか、少なくともそのようなツールをインストールすることによるリスクが増大していることを示している可能性があります。

##### 検出手法

一般的なリバースエンジニアリングツールは、変更されていない形式でインストールされている場合、関連するアプリケーションパッケージ、ファイル、プロセス、またはその他のツール固有の修正やアーティファクトを探すことにより検出できます。以下の例では、このガイドで広く使用されている frida 計装フレームワークを検出するさまざまな方法を示します。Substrate や Xposed などの他のツールは同様の手段を使用して検出できます。DBI/インジェクション/フックツールはランタイムの完全性チェックによって暗黙的に検出されることもあります。以下で個別に説明します。

###### 例: Frida を検出する方法

frida や類似のフレームワークを検出する明白な方法は、パッケージファイル、バイナリ、ライブラリ、プロセス、一時ファイルなどの関連するアーティファクトの環境をチェックすることです。一例として、fridaserver について考えます。これは TCP を介して frida を公開するデーモンです。fridaserver が動作しているかどうかを確認するために実行中のプロセスリストをたどる Java メソッドを使用できます。

```c
public boolean checkRunningProcesses() {

  boolean returnValue = false;

  // Get currently running application processes
  List<RunningServiceInfo> list = manager.getRunningServices(300);

  if(list != null){
    String tempName;
    for(int i=0;i<list.size();++i){
      tempName = list.get(i).process;

      if(tempName.contains("fridaserver")) {
        returnValue = true;
      }
    }
  }
  return returnValue;
}
```

これは frida がデフォルト設定で動作している場合に機能します。おそらくリバースエンジニアリングの最初のほんの小さな一歩を行う一部のスクリプトキディを困惑させるには十分です。しかし、fridaserver バイナリの名前を "lol" や別の名前に変更することで簡単にバイパスできるので、もっと良い方法を見つけるべきです。

デフォルトでは、fridaserver は TCP ポート 27047 にバインドするので、このポートが開いているかどうかを確認することもひとつの考えです。ネイティブコードでは、以下のようになります。

```c
boolean is_frida_server_listening() {
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27047);
    inet_aton("127.0.0.1", &(sa.sin_addr));

    int sock = socket(AF_INET , SOCK_STREAM , 0);

    if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {
      /* Frida server detected. Do something… */
    }

}   
```

この場合も、デフォルトモードの fridaserver を検出しますが、リスニングポートはコマンドライン引数で簡単に変更できるため、これをバイパスすることは非常に簡単です。この状況は nmap -sV をプルすることで改善できます。fridaserver は D-Bus プロトコルを使用して通信するため、開いているすべてのポートに D-Bus AUTH メッセージを送信し、答えをチェックします。fridaserver の期待は自身を公開することです。

```c
/*
 * Mini-portscan to detect frida-server on any local port.
 */

for(i = 0 ; i <= 65535 ; i++) {

    sock = socket(AF_INET , SOCK_STREAM , 0);
    sa.sin_port = htons(i);

    if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {

        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "FRIDA DETECTION [1]: Open Port: %d", i);

        memset(res, 0 , 7);

        // send a D-Bus AUTH message. Expected answer is “REJECT"

        send(sock, "\x00", 1, NULL);
        send(sock, "AUTH\r\n", 6, NULL);

        usleep(100);

        if (ret = recv(sock, res, 6, MSG_DONTWAIT) != -1) {

            if (strcmp(res, "REJECT") == 0) {
               /* Frida server detected. Do something… */
            }
        }
    }
    close(sock);
}
```

私たちは fridaserver を検出する非常に安定した手法を持っていますが、目立った問題がいくつかあります。最も重要なこととして、frida は fridaserver を必要としない代替の操作モードを提供しています。それらをどのように検出しますか。

frida のすべてのモードでの共通のテーマはコードインジェクションです。したがって、frida が使用されるときはいつでも、frida 関連のライブラリがメモリにマップされていることが期待できます。それらを検出する簡単な方法は、ロードされているライブラリのリストを調べて、疑わしいものをチェックすることです。

```c
char line[512];
FILE* fp;

fp = fopen("/proc/self/maps", "r");

if (fp) {
    while (fgets(line, 512, fp)) {
        if (strstr(line, "frida")) {
            /* Evil library is loaded. Do something… */
        }
    }

    fclose(fp);

    } else {
       /* Error opening /proc/self/maps. If this happens, something is of. */
    }
}
```

これは名前に "frida" を含むライブラリを検出します。表面上ではこれは機能しますが、いくつかの大きな問題があります。

- fridaserver と呼ばれる fridaserver に頼るのは良い考えではなかったことを覚えていますか。同じことがここに当てはまります。frida に小さな変更を加えることで、frida エージェントライブラリは簡単に名前を変更できます。- 検出は fopen() や strstr() などの標準ライブラリコールに依存します。本質的には、あなたが察するように frida で簡単にフックできる関数を使用して frida を検出しようとしています。明らかにこれはあまり強固な戦略ではありません。

課題番号一は古典的なウイルススキャナ風の戦略を実装することで対応できます。frida のライブラリにある「ガジェット」が存在するかどうかメモリをスキャンします。私はすべてのバージョンの frida-gadget と frida-agent に存在すると思われる文字列 "LIBFRIDA" を選択しました。以下のコードを使用して、/proc/self/maps にリストされているメモリマッピングを繰り返し、各実行可能セクション内の文字列を検索します。簡潔にするために瑣末な機能は除外していることに注意します。それらは GitHub にあります。

```c
static char keyword[] = "LIBFRIDA";
num_found = 0;

int scan_executable_segments(char * map) {
    char buf[512];
    unsigned long start, end;

    sscanf(map, "%lx-%lx %s", &start, &end, buf);

    if (buf[2] == 'x') {
        return (find_mem_string(start, end, (char*)keyword, 8) == 1);
    } else {
        return 0;
    }
}

void scan() {

    if ((fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)) >= 0) {

    while ((read_one_line(fd, map, MAX_LINE)) > 0) {
        if (scan_executable_segments(map) == 1) {
            num_found++;
        }
    }

    if (num_found > 1) {

        /* Frida Detected */
    }

}
```

通常の libc ライブラリ関数の代わりに my_openat() などを使用することに注意します。これらは Bionic libc と同様に機能するカスタム実装です。それぞれのシステムコールの引数を設定し、swi 命令を実行します (下記参照) 。これによりパブリック API の依存がなくなり、典型的な libc フックの影響を受けにくくなります。完全な実装は syscall.S にあります。以下は my_openat() のアセンブラ実装です。

```
#include "bionic_asm.h"

.text
    .globl my_openat
    .type my_openat,function
my_openat:
    .cfi_startproc
    mov ip, r7
    .cfi_register r7, ip
    ldr r7, =__NR_openat
    swi #0
    mov r7, ip
    .cfi_restore r7
    cmn r0, #(4095 + 1)
    bxls lr
    neg r0, r0
    b __set_errno_internal
    .cfi_endproc

    .size my_openat, .-my_openat;
```

これは全体としては多少効果的ですが、frida でのみバイパスすることは困難です。特にいくつかの難読化が加えられた場合には。それでも、これをバイパスする方法は多くあります。パッチ適用とシステムコールのフックが思い浮かびます。覚えておいて。リバースエンジニアは常に勝利することを。

上記の検出方法を試すには、Android Studio Project をダウンロードしてビルドします。frida が注入されると、アプリは以下のようなエントリを生成します。

##### リバースエンジニアリングツールの検出のバイパス

1. アンチデバッグ機能にパッチを当てます。それぞれのバイトコードまたはネイティブコードを NOP 命令で上書きするだけで望まれない動作を無効にします。
2. Frida または Xposed を使用して Java およびネイティブレイヤ上のファイルシステム API をフックします。改変されたファイルの代わりに元のファイルへのハンドルを返します。
3. カーネルモジュールを使用して、ファイル関連システムコールを傍受します。プロセスが改変されたファイルを開こうとすると、代わりに改変されていないバージョンのファイルのファイル記述子が返ります。

パッチ、コードインジェクション、カーネルモジュールの例については、「改竄とリバースエンジニアリング」のセクションを参照ください。

#### 有効性評価

さまざまなアプリやフレームワークをインストールして、アプリを体系的に起動します。少なくとも以下のもので行います。

- Substrate for Android
- Xposed
- Frida
- Introspy-Android
- Drozer
- RootCloak
- Android SSL Trust Killer

アプリはこれらのツールの存在を検出して、何らかの方法で応答する必要があります。少なくとも、アプリはユーザーに警告したり、アプリを終了したりする必要があります。防御をバイパスするように作業し、以下の質問に答えます。

- 単純な手法を使用してメカニズムをバイパスすることは可能か？ (例えば、単一の API 関数をフックするなど)
- 静的および動的解析を使用してアンチデバッグコードを特定することはどの程度困難か？
- 防御を無効にするカスタムコードを書く必要はあるか？どの程度の時間を費やす必要があったか？
- 難易度の主観的評価は何か？

より詳細な評価を行いには、「ソフトウェア保護スキームの評価」の章の「プログラムによる防御の評価」に記載されている基準を適用します。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M9 - リバースエンジニアリング - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

- V8.4: "アプリはコードインジェクションツール、フッキングフレームワーク、デバッグサーバーなど広く使用されているリバースエンジニアリングツールの存在を検出している。"

##### CWE

N/A

##### その他

- [1] Netitude Blog - Who owns your runtime? - https://labs.nettitude.com/blog/ios-and-android-runtime-and-anti-debugging-protections/

##### ツール

* frida - https://www.frida.re/

### エミュレータ検出のテスト

#### 概要

アンチリバースの文脈では、エミュレータ検出の目的はエミュレートされたデバイスでのアプリの実行をもう少し難しくすることです。これはリバースエンジニアが使用したいツールやテクニックを次々に妨げます。これによりリバースエンジニアはエミュレータチェックを無効にしたり物理デバイスを使用したりします。これは大規模なデバイス解析のためのエントリに障壁を提供します。

#### エミュレータ検出の例

問題のデバイスがエミュレートされていることを示すいくつかのインジケータがあります。これらの API コールのすべてがフックされている可能性がありますが、これは控えめな第一線の防御を提供します。

The first set of indicaters stem from the build.prop file

```
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
Build.TAGS          test-keys       emulator
Build.USER          android-build   emulator
```

build.prop ファイルはルート化された android デバイスで変更することや、ソースから AOSP をコンパイルする際に変更できることに注意する必要があります。これらの技法はいずれも上記の静的文字列チェックをバイパスします。

以下の静的インジケータセットは Telephony マネージャを使用します。すべての android エミュレータはこの API が照会できる固定値を持っています。

```
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

Xposed や Frida などのフッキングフレームワークはこの API をフックして誤ったデータを提供する可能性があることに注意します。

#### エミュレータ検出のバイパス

1. エミュレータ検出機能にパッチを当てます。それぞれのバイトコードまたはネイティブコードを NOP 命令で上書きするだけで望まれない動作を無効にします。
2. Frida または Xposed を使用して Java およびネイティブレイヤ上のファイルシステム API をフックします。エミュレータを示す値の代わりに (できれば実デバイスから取得した) 無害に見える値を返します。例えば、<code>TelephonyManager.getDeviceID()</code> をオーバーライドして IMEI 値を返します。

パッチ、コードインジェクション、カーネルモジュールについては「改竄とリバースエンジニアリング」セクションを参照します。

#### 有効性評価

エミュレータにアプリをインストールして実行します。アプリはこれを検出して終了するか、保護されている機能を実行することを拒否する必要があります。

防御をバイパスするように作業し、以下の質問に答えます。

- 静的および動的解析を使用してエミュレータ検出コードを特定することはどの程度困難か？
- 単純な手法を使用して検出メカニズムをバイパスすることは可能か？ (例えば、単一の API 関数をフックするなど)
- アンチエミュレータ機能を無効にするカスタムコードを書く必要はあるか？どの程度の時間を費やす必要があったか？
- 難易度の主観的評価は何か？

より詳細な評価を行いには、「ソフトウェア保護スキームの評価」の章の「プログラムによる防御の評価」に記載されている基準を適用します。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M9 - リバースエンジニアリング - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

- V8.5: "アプリは任意の方法を使用してエミュレータ内で動作しているかどうかを検出し応答している。"

##### CWE

N/A

##### その他

- [1] Timothy Vidas & Nicolas Christin - Evading Android Runtime Analysis via Sandbox Detection - https://users.ece.cmu.edu/~tvidas/papers/ASIACCS14.pdf

##### ツール

N/A

### ランタイム整合性監視のテスト

#### 概要

このカテゴリのコントロールはアプリ自身のメモリ空間の整合性を検証することです。実行時に適用されるメモリパッチから保護することを目的とします。これにはバイナリコードやバイトコード、関数ポインタテーブル、重要なデータ構造、プロセスメモリにロードされる不正なコードなどの望まれない変更が含まれます。整合性は以下のいずれかにより検証できます。

1. メモリの内容、または内容のチェックサムを既知の正しい値と比較する
2. 望まれない改変のシグネチャがないかメモリを検索する

カテゴリ「リバースエンジニアリングツールとフレームワークの検出」と一部重複があります。また、実際、その章でシグネチャベースのアプローチをすでに説明しました。プロセスメモリ内の frida 関連文字列を検索する方法を示しています。以下にさまざまな種類の整合性監視についていくつかの例を示します。

##### Runtime Integrity Check Examples

**Detecting tampering with the Java Runtime**

Detection code from the dead && end blog <sup>[3]</sup>.

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

**Detecting Native Hooks**

With ELF binaries, native function hooks can be installed by either overwriting function pointers in memory (e.g. GOT or PLT hooking), or patching parts of the function code itself (inline hooking). Checking the integrity of the respective memory regions is one technique to detect this kind of hooks.

The Global Offset Table (GOT) is used to resolve library functions. During runtime, the dynamic linker patches this table with the absolute addresses of global symbols. *GOT hooks* overwrite the stored function addresses and redirect legitimate function calls to adversary-controlled code. This type of hook can be detected by enumerating the process memory map and verifying that each GOT entry points into a legitimately loaded library.

In contrast to GNU <code>ld</code>, which resolves symbol addresses only once they are needed for the first time (lazy binding), the Android linker resolves all external function and writes the respective GOT entries immediately when a library is loaded (immediate binding). One can therefore expect all GOT entries to point valid memory locations within the code sections of their respective libraries during runtime. GOT hook detection methods usually walk the GOT and verify that this is indeed the case.

*Inline hooks* work by overwriting a few instructions at the beginning or end of the function code. During runtime, this so-called trampoline redirects execution to the injected code. Inline hooks can be detected by inspecting the prologues and epilogues of library functions for suspect instructions, such as far jumps to locations outside the library.

#### Bypass and Effectiveness Assessment

Make sure that all file-based detection of reverse engineering tools is disabled. Then, inject code using Xposed, Frida and Substrate, and attempt to install native hooks and Java method hooks. The app should detect the "hostile" code in its memory and respond accordingly. For a more detailed assessment, identify and bypass the detection mechanisms employed and use the criteria listed under "Assessing Programmatic Defenses" in the "Assessing Software Protection Schemes" chapter.

Work on bypassing the checks using the following techniques:

1. Patch out the integrity checks. Disable the unwanted behaviour by overwriting the respective bytecode or native code with NOP instructions.
2. Use Frida or Xposed to hook APIs to hook the APIs used for detection and return fake values. 

Refer to the "Tampering and Reverse Engineering section" for examples of patching, code injection and kernel modules.

#### Effectiveness Assessment



#### 参考情報

##### OWASP Mobile Top 10 2016

* M9 - Reverse Engineering - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below and description] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE
-- TODO [Add relevant CWE for "Testing Memory Integrity Checks"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Michael Hale Ligh, Andrew Case, Jamie Levy, Aaron Walters (2014) *The Art of Memory Forensics.* Wiley. "Detecting GOT Overwrites", p. 743.
- [2] Netitude Blog - "Who owns your runtime?" - https://labs.nettitude.com/blog/ios-and-android-runtime-and-anti-debugging-protections/
- [3] dead && end blog - Android Anti-Hooking Techniques in Java - http://d3adend.org/blog/?p=589

##### ツール

-- TODO [Add link to relevant tools for "Testing Memory Integrity Checks"] --
* Enjarify - https://github.com/google/enjarify

### デバイス結合のテスト

#### 概要

The goal of device binding is to impede an attacker when he tries to copy an app and its state from device A to device B and continue the execution of the app on device B. When device A has been deemend trusted, it might have more privileges than device B, which should not change when an app is copied from device A to device B.

#### Static Analysis

In the past, Android developers often relied on the Secure ANDROID_ID (SSAID) and MAC addresses. However, the behavior of the SSAID has changed since Android O and the behavior of MAC addresses have changed in Android N <sup>[1]</sup>. Google has set a new set of recommendations in their SDK documentation regarding identifiers as well <sup>[2]</sup>.
When the source-code is available, then there are a few codes you can look for, such as:
- The presence of unique identifiers that no longer work in the future
  - `Build.SERIAL` without the presence of `Build.getSerial()`
  - `htc.camera.sensor.front_SN` for HTC devices
  - `persist.service.bdroid.bdadd`
  - `Settings.Secure.bluetooth_address`, unless the system permission LOCAL_MAC_ADDRESS is enabled in the manifest.

- The presence of using the ANDROID_ID only as an identifier. This will influence the possible binding quality over time given older devices.
- The absence of both InstanceID, the `Build.SERIAL` and the IMEI.

```java
  TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
  String IMEI = tm.getDeviceId();
```


Furthermore, to reassure that the identifiers can be used, the AndroidManifest.xml needs to be checked in case of using the IMEI and the Build.Serial. It should contain the following permission: `<uses-permission android:name="android.permission.READ_PHONE_STATE"/>`.

#### Dynamic Analysis

There are a few ways to test the application binding:

##### Dynamic Analysis using an Emulator

1. Run the application on an Emulator
2. Make sure you can raise the trust in the instance of the application (e.g. authenticate)
3. Retrieve the data from the Emulator This has a few steps:
- ssh to your simulator using ADB shell
- run-as <your app-id (which is the package as described in the AndroidManifest.xml)>
- chmod 777 the contents of cache and shared-preferences
- exit the current user
- copy the contents of /dat/data/<your appid>/cache & shared-preferences to the sdcard
- use ADB or the DDMS to pull the contents
4. Install the application on another Emulator
5. Overwrite the data from step 3 in the data folder of the application.
- copy the contents of step 3 to the sdcard of the second emulator.
- ssh to your simulator using ADB shell
- run-as <your app-id (which is the pacakge as described in the AndroidManifest.xml)>
- chmod 777 the folders cache and shared-preferences
- copy the older contents of the sdcard to /dat/data/<your appid>/cache & shared-preferences
6. Can you continue in an authenticated state? If so, then binding might not be working properly.

##### Google InstanceID

Google InstanceID <sup>[5]</sup> uses tokens to authenticate the application instance running on the device. The moment the application has been reset, uninstalled, etc., the instanceID is reset, meaning that you have a new "instance" of the app.
You need to take the following steps into account for instanceID:
0. Configure your instanceID at your Google Developer Console for the given application. This includes managing the PROJECT_ID.

1. Setup Google play services. In your build.gradle, add:
```groovy
  apply plugin: 'com.android.application'
    ...

    dependencies {
        compile 'com.google.android.gms:play-services-gcm:10.2.4'
    }
```
2. Get an instanceID
```java
  String iid = InstanceID.getInstance(context).getId();
  //now submit this iid to your server.
```

3. Generate a token
```java
String authorizedEntity = PROJECT_ID; // Project id from Google Developer Console
String scope = "GCM"; // e.g. communicating using GCM, but you can use any
                      // URL-safe characters up to a maximum of 1000, or
                      // you can also leave it blank.
String token = InstanceID.getInstance(context).getToken(authorizedEntity,scope);
//now submit this token to the server.
```
4. Make sure that you can handle callbacks from instanceID in case of invalid device information, security issues, etc.
For this you have to extend the `InstanceIDListenerService` and handle the callbacks there:

```java
public class MyInstanceIDService extends InstanceIDListenerService {
  public void onTokenRefresh() {
    refreshAllTokens();
  }

  private void refreshAllTokens() {
    // assuming you have defined TokenList as
    // some generalized store for your tokens for the different scopes.
    // Please note that for application validation having just one token with one scopes can be enough.
    ArrayList<TokenList> tokenList = TokensList.get();
    InstanceID iid = InstanceID.getInstance(this);
    for(tokenItem : tokenList) {
      tokenItem.token =
        iid.getToken(tokenItem.authorizedEntity,tokenItem.scope,tokenItem.options);
      // send this tokenItem.token to your server
    }
  }
};

```
Lastly register the service in your AndroidManifest:
```xml
<service android:name=".MyInstanceIDService" android:exported="false">
  <intent-filter>
        <action android:name="com.google.android.gms.iid.InstanceID"/>
  </intent-filter>
</service>
```

When you submit the iid and the tokens to your server as well, you can use that server together with the Instance ID Cloud Service to validate the tokens and the iid. When the iid or token seems invalid, then you can trigger a safeguard procedure (e.g. inform server on possible copying, possible security issues, etc. or removing the data from the app and ask for a re-registration).

Please note that Firebase has support for InstanceID as well <sup>[4]</sup>.
-- TODO [SHOULD WE ADD THE SERVER CODE HERE TOO TO EXPLAIN HOW TOKENS CAN BE USED TO EVALUATE?] --

##### IMEI & Serial

Please note that Google recommends against using these identifiers unless there is a high risk involved with the application in general.

For pre-Android O devices, you can request the serial as follows:

```java
   String serial = android.os.Build.SERIAL;
```

From Android O onwards, you can request the device its serial as follows:

1. Set the permission in your Android Manifest:
```xml
  <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
```
2. Request the permission at runtime to the user: See https://developer.android.com/training/permissions/requesting.html for more details.
3. Get the serial:

```java
  String serial = android.os.Build.getSerial();
```

Retrieving the IMEI in Android works as follows:

1. Set the required permission in your Android Manifest:
```xml
  <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
```

2. If on Android M or higher: request the permission at runtime to the user: See https://developer.android.com/training/permissions/requesting.html for more details.

3. Get the IMEI:
```java
  TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
  String IMEI = tm.getDeviceId();
```

##### SSAID

Please note that Google recommends against using these identifiers unless there is a high risk involved with the application in general. you can retrieve the SSAID as follows:

```java
  String SSAID = Settings.Secure.ANDROID_ID;
```
#### Effectiveness Assessment

When the source-code is available, then there are a few codes you can look for, such as:
- The presence of unique identifiers that no longer work in the future
  - `Build.SERIAL` without the presence of `Build.getSerial()`
  - `htc.camera.sensor.front_SN` for HTC devices
  - `persist.service.bdroid.bdadd`
  - `Settings.Secure.bluetooth_address`, unless the system permission LOCAL_MAC_ADDRESS is enabled in the manifest.

- The presence of using the ANDROID_ID only as an identifier. This will influence the possible binding quality over time given older devices.
- The absence of both InstanceID, the `Build.SERIAL` and the IMEI.

```java
  TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
  String IMEI = tm.getDeviceId();
```

Furthermore, to reassure that the identifiers can be used, the AndroidManifest.xml needs to be checked in case of using the IMEI and the Build.Serial. It should contain the following permission: `<uses-permission android:name="android.permission.READ_PHONE_STATE"/>`.

There are a few ways to test device binding dynamically:

##### Using an Emulator

1. Run the application on an Emulator
2. Make sure you can raise the trust in the instance of the application (e.g. authenticate)
3. Retrieve the data from the Emulator This has a few steps:
- ssh to your simulator using ADB shell
- run-as <your app-id (which is the package as described in the AndroidManifest.xml)>
- chmod 777 the contents of cache and shared-preferences
- exit the current user
- copy the contents of /dat/data/<your appid>/cache & shared-preferences to the sdcard
- use ADB or the DDMS to pull the contents
4. Install the application on another Emulator
5. Overwrite the data from step 3 in the data folder of the application.
- copy the contents of step 3 to the sdcard of the second emulator.
- ssh to your simulator using ADB shell
- run-as <your app-id (which is the pacakge as described in the AndroidManifest.xml)>
- chmod 777 the folders cache and shared-preferences
- copy the older contents of the sdcard to /dat/data/<your appid>/cache & shared-preferences
6. Can you continue in an authenticated state? If so, then binding might not be working properly.

##### Using two different rooted devices.

1. Run the application on your rooted device
2. Make sure you can raise the trust in the instance of the application (e.g. authenticate)
3. Retrieve the data from the first rooted device
4. Install the application on the second rooted device
5. Overwrite the data from step 3 in the data folder of the application.
6. Can you continue in an authenticated state? If so, then binding might not be working properly.

#### Remediation

The behavior of the SSAID has changed since Android O and the behavior of MAC addresses have changed in Android N <code>[1]</code>. Google has set a new set of recommendations in their SDK documentation regarding identifiers as well <code>[2]</code>. Because of this new behavior, we recommend developers to no relie on the SSAID alone, as the identifier has become less stable. For instance: The SSAID might change upon a factory reset or when the app is reinstalled after the upgrade to Android O. Please note that there are amounts of devices which have the same ANDROID_ID and/or have an ANDROID_ID that can be overriden.
Next, the Build.Serial was often used. Now, apps targetting Android O will get "UNKNOWN" when they request the Build.Serial.
Before we describe the usable identifiers, let's quickly discuss how they can be used for binding. There are 3 methods which allow for device binding:

- augment the credentials used for authentication with device identifiers. This can only make sense if the application needs to re-authenticate itself and/or the user frequently.
- obfuscate the data stored on the device using device-identifiers as keys for encryption methods. This can help in binding to a device when a lot of offline work is done by the app or when access to APIs depends on access-tokens stored by the application.
- Use a token based device authentication (InstanceID) to reassure that the same instance of the app is used.

The following 3 identifiers can be possibly used.

#### 参考情報

##### OWASP Mobile Top 10 2016

* M9 - Reverse Engineering - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

- V8.10: "The app implements a 'device binding' functionality using a device fingerprint derived from multiple properties unique to the device."

##### CWE

N/A

##### その他
- [1] Changes in the Android device identifiers - https://android-developers.googleblog.com/2017/04/changes-to-device-identifiers-in.html
- [2] Developer Android documentation - https://developer.android.com/training/articles/user-data-ids.html
- [3] Documentation on requesting runtime permissions - https://developer.android.com/training/permissions/requesting.html
- [4] Firebase InstanceID documentation - https://firebase.google.com/docs/reference/android/com/google/firebase/iid/FirebaseInstanceId
- [5] Google InstanceID documentation - https://developers.google.com/instance-id/

##### ツール

* ADB & DDMS
* Android Emulator or 2 rooted devices.

### 難読化のテスト

#### 概要

Obfuscation is the process of transforming code and data to make it more difficult to comprehend. It is an integral part of every software protection scheme. What's important to understand is that obfuscation isn't something that can be simply turned on or off. Rather, there's a whole lot of different ways in which a program, or part of it, can be made incomprehensible, and it can be done to different grades.

In this test case, we describe a few basic obfuscation techniques that are commonly used on Android. For a more detailed discussion of obfuscation, refer to the "Assessing Software Protection Schemes" chapter.

#### Effectiveness Assessment

Attempt to decompile the bytecode and disassemble any included libary files, and make a reasonable effort to perform static analysis. At the very least, you should not be able to easily discern the app's core functionality (i.e., the functionality meant to be obfuscated). Verify that: 

- Meaningful identifiers such as class names, method names and variable names have been discarded;
- String resources and strings in binaries are encrypted;
- Code and data related to the protected functionality is encrypted, packed, or otherwise concealed.

For a more detailed assessment, you need to have a detailed understanding of the threats defended against and the obfuscation methods used. Refer to the "Assessing Obfuscation" section of the  "Assessing Software Protection Schemes" chapter for more information.

#### 参考情報

##### OWASP Mobile Top 10 2016

* M9 - Reverse Engineering - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

- V8.8: "All executable files and libraries belonging to the app are either encrypted on the file level and/or important code and data segments inside the executables are encrypted or packed. Trivial static analysis does not reveal important code or data."
- v8.9: "Obfuscating transformations and functional defenses are interdependent and well-integrated throughout the app."
- V8.12: "If the architecture requires sensitive computations be performed on the client-side, these computations are isolated from the operating system by using a hardware-based SE or TEE. Alternatively, the computations are protected using obfuscation. Considering current published research, the obfuscation type and parameters are sufficient to cause significant manual effort to reverse engineers seeking to comprehend the sensitive portions of the code and/or data."

##### CWE

- N/A

##### その他

- N/A

##### ツール

- N/A
