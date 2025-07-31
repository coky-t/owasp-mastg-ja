---
masvs_category: MASVS-RESILIENCE
platform: android
title: ルート検出 (Root Detection)
---

アンチリバースの文脈では、ルート検出の目的はルート化されたデバイス上でのアプリの実行を少し難しくすることです。これにより、リバースエンジニアが使用したいツールやテクニックの一部をブロックします。他のほとんどの防御と同様に、ルート検出はそれ自体に高い効果はありませんが、複数のルートチェックをアプリ全体にちりばめて実装することで改竄対策スキーム全体の有効性を向上できます。

Android では、 "ルート検出" を少し広く定義し、カスタム ROM の検出を含みます。例えば、デバイスが純正の Android ビルドであるか、もしくはカスタムビルドであるかを判断します

ルート検出は [RootBeer](https://github.com/scottyab/rootbeer "RootBeer") などのライブラリを介して実装することもできます。

## ファイルの存在チェック

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

`su` が PATH 上にあるかどうかを確認することもできます。

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

## 特権コマンドの実行

`su` が存在するかどうかを判断するもう一つの方法は `Runtime.getRuntime.exec` メソッドを使用して実行を試みることです。 `su` が PATH 上にない場合は IOException がスローされます。同じ方法を使用して、ルート化されたデバイス上によく見つかる他のプログラムを確認することができます。 busybox や一般的にそれを指すシンボリックリンクなどがあります。

## 実行中のプロセスの確認

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

## インストール済みアプリパッケージの確認

Android パッケージマネージャを使用するとインストールされているパッケージのリストを取得できます。以下のパッケージ名は一般的なルート化ツールに属するものです。

```txt
eu.chainfire.supersu
com.noshufou.android.su
com.koushikdutta.superuser
com.zachspong.temprootremovejb
com.ramdroid.appquarantine
com.topjohnwu.magisk
```

## 書き込み可能なパーティションとシステムディレクトリの確認

sysytem ディレクトリに対する普通とは異なるアクセス許可は、カスタマイズまたはルート化されたデバイスを示している可能性があります。通常では system および data ディレクトリは読み取り専用でマウントされていますが、デバイスがルート化されていると読み書き可能でマウントされることがあります。 "rw" フラグでマウントされているこれらのファイルシステムを探すか、もしくはこれらのディレクトリにファイルを作成してみます。

## カスタム Android ビルドの確認

テストビルドやカスタム ROM の兆候を確認することも役に立ちます。これを行う方法のひとつは BUILD タグに test-keys が含まれているかどうかを確認することです。これは一般的に [カスタム Android イメージを示します](https://resources.infosecinstitute.com/android-hacking-security-part-8-root-detection-evasion// "InfoSec Institute - Android Root Detection and Evasion")。[以下のように BUILD タグを確認します](https://github.com/scottyab/rootbeer/blob/master/rootbeerlib/src/main/java/com/scottyab/rootbeer/RootBeer.java#L76 "Rootbeer - detectTestKeys function")。

```java
private boolean isTestKeyBuild()
{
String str = Build.TAGS;
if ((str != null) && (str.contains("test-keys")));
for (int i = 1; ; i = 0)
  return i;
}
```

Google Over-The-Air (OTA) 証明書の欠落はカスタム ROM のもうひとつの兆候です。純正の Android ビルドでは [OTA アップデートに Google の公開証明書を使用します](https://www.netspi.com/blog/technical-blog/mobile-application-penetration-testing/android-root-detection-techniques/ "Android Root Detection Techniques")。
