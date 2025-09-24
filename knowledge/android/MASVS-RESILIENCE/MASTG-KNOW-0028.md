---
masvs_category: MASVS-RESILIENCE
platform: android
title: アンチデバッグ (Anti-Debugging)
---

デバッグはアプリのランタイム動作を解析する非常に効果的な方法です。これによりリバースエンジニアがコードをステップ実行し、任意の箇所でアプリの実行を停止し、変数の状態を検査し、メモリを読み取りおよび変更し、さらに多くのことを可能にします。

アンチデバッグ機能には予防型と反応型があります。名前が示すように、予防型アンチデバッグはまず第一にデバッガがアタッチすることを防ぎます。反応型アンチデバッグはデバッガを検出し、何らかの方法でそれに反応します (アプリの終了や隠された動作のトリガなど) 。「多ければ多いほど良い」ルールが適用されます。効果を最大限にするため、防御側は、さまざまな API レイヤーで動作しアプリ全体に分散される、複数の予防と検出の手法を組み合わせます。

"リバースエンジニアリングと改竄" の章で述べたように、 Android では二つの異なるデバッグプロトコルを扱う必要があります。 JDWP を使用した Java レベルと、 ptrace ベースのデバッガを使用したネイティブレイヤーでデバッグが可能です。優れたアンチデバッグスキームでは両方のデバッグタイプに対して防御する必要があります。

## JDWP アンチデバッグ

"リバースエンジニアリングと改竄" の章では、デバッガと Java 仮想マシンとの間の通信に使用されるプロトコルである JDWP について説明しました。マニフェストファイルにパッチを適用して任意のアプリを容易にデバッグ可能にできることや、 `ro.debuggable` システムプロパティを変更することであらゆるアプリをデバッグ可能にできることを示しました。開発者が JDWP デバッガを検出および無効にするために行ういくつかのことを見てみます。

## ApplicationInfo のデバッグ可能フラグの確認

すでに `android:debuggable` 属性は出てきています。 Android Manifest のこのフラグは JDWP スレッドがアプリに対して起動されるかどうかを決定します。その値はアプリの `ApplicationInfo` オブジェクトを使用してプログラムで決定できます。このフラグが設定されている場合、これはマニフェストが改竄されてデバッグ可能になっています。

```java
    public static boolean isDebuggable(Context context){

        return ((context.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);

    }
```

## isDebuggerConnected

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

## タイマーチェック

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

## JDWP 関連のデータ構造への干渉

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

例えば、 [gDvm.methDalvikDdmcServer_dispatch 関数ポインタに NULL を設定すると JDWP スレッドがクラッシュします](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/AndroidREnDefenses201305.pdf "Bluebox Security - Android Reverse Engineering & Defenses")。

```c
JNIEXPORT jboolean JNICALL Java_poc_c_crashOnInit ( JNIEnv* env , jobject ) {
  gDvm.methDalvikDdmcServer_dispatch = NULL;
}
```

gDvm 変数が利用できない場合でも、 ART で同様の技法を使用してデバッグを無効にできます。 ART ランタイムは JDWP 関連のクラスの vtable の一部をグローバルシンボルとしてエクスポートします (C++ では、 vtable はクラスメソッドのポインタを保持するテーブルです) 。これには `JdwpSocketState` および `JdwpAdbState` クラスの vtable を含んでおり、これらはネットワークソケットと [adb](../../../tools/android/MASTG-TOOL-0004.md) を介した JDWP 接続をそれぞれ処理します。デバッグランタイムの動作は [関連する vtable のメソッドポインタを上書きすることにより](https://web.archive.org/web/20200307152820/https://www.vantagepoint.sg/blog/88-anti-debugging-fun-with-android-art "Anti-Debugging Fun with Android ART") (archived) 操作できます。

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

## 従来のアンチデバッグ

Linux では、 [`ptrace` システムコール](http://man7.org/linux/man-pages/man2/ptrace.2.html "Ptrace man page") を使用して、プロセス (_tracee_) の実行を監視および制御し、そのプロセスのメモリとレジスタを調べて変更します。 `ptrace` はネイティブコードでシステムコールトレースとブレークポイントデバッグを実装する主要な方法です。ほとんどの JDWP アンチデバッグトリック (タイマーベースのチェックには安全かもしれません) は `ptrace` をベースとする従来のデバッガをキャッチしないため、多くの Android アンチデバッグトリックには `ptrace` が含まれており、一つのプロセスにアタッチできるのは一度に一つのデバッガのみであるという事実を悪用することがよくあります。

## TracerPid のチェック

アプリをデバッグしてネイティブコードにブレークポイントを設定する際、 Android Studio はターゲットデバイスに必要なファイルをコピーし、プロセスにアタッチするために `ptrace` を使用する lldb-server を起動します。この時点で、デバッグされるプロセスの [ステータスファイル](http://man7.org/linux/man-pages/man5/proc.5.html "/proc/[pid]/status") (`/proc/<pid>/status` または `/proc/self/status`) を検査すると、 "TracerPid" フィールドは 0 とは異なる値を持つことがわかります。これはデバッグの兆候です。

> **これはネイティブコードにのみ適用される** ことに注意します。 Java/Kotlin のみのアプリをデバッグする場合には "TracerPid" フィールドの値は 0 になります。

この技法は通常 JNI ネイティブライブラリ内の C で適用されます。これは [Google の gperftools (Google Performance Tools)) Heap Checker](https://github.com/gperftools/gperftools/blob/master/src/heap-checker.cc#L112 "heap-checker.cc - IsDebuggerAttached") 実装の `IsDebuggerAttached` メソッドに示されています。ただし、このチェックを Java/Kotlin コードの一部として含める場合は、 [Tim Strazzere の Anti-Emulator プロジェクト](https://github.com/strazzere/anti-emulator/ "anti-emulator") から `hasTracerPid` メソッドの Java 実装を参照します。

このようなメソッドを自分で実装しようとする場合は、 [adb](../../../tools/android/MASTG-TOOL-0004.md) で TracerPid の値を手動で確認できます。以下のリストは Google の NDK サンプルアプリ [hello-jni (com.example.hellojni)](https://github.com/android/ndk-samples/tree/android-mk/hello-jni "hello-jni sample") を使用して、 Android Studio のデバッガをアタッチした後にチェックを実行しています。

```bash
$ adb shell ps -A | grep com.example.hellojni
u0_a271      11657   573 4302108  50600 ptrace_stop         0 t com.example.hellojni
$ adb shell cat /proc/11657/status | grep -e "^TracerPid:" | sed "s/^TracerPid:\t//"
TracerPid:      11839
$ adb shell ps -A | grep 11839
u0_a271      11839 11837   14024   4548 poll_schedule_timeout 0 S lldb-server
```

com.example.hellojni (PID=11657) のステータスファイルに 11839 の TracerPID がどのように含まれているかを確認できます。これは lldb-server プロセスとして識別できます。

## fork と ptrace の使用

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
