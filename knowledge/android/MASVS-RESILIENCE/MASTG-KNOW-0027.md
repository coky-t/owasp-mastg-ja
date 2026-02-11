---
masvs_category: MASVS-RESILIENCE
platform: android
title: ルート検出 (Root Detection)
---

アンチリバースの文脈では、ルート検出の目的はルート化されたデバイス上でのアプリの実行を少し難しくすることです。これにより、リバースエンジニアが使用したいツールやテクニックの一部をブロックします。他のほとんどの防御と同様に、ルート検出はそれ自体に高い効果はありませんが、複数のルートチェックをアプリ全体にちりばめて実装することで改竄対策スキーム全体の有効性を向上できます。

Android では、 "ルート検出" を少し広く定義し、カスタム ROM の検出を含みます。例えば、デバイスが純正の Android ビルドであるか、もしくはカスタムビルドであるかを判断します

ルート検出は [RootBeer](../../../tools/android/MASTG-TOOL-0146.md) や [Android RASP](../../../tools/android/MASTG-TOOL-0147.md) などのライブラリを介して実装することもできます (いずれも OWASP に承認されたものではありません。それぞれのセクションの免責事項をご覧ください)。これらのライブラリは、Java とネイティブコードの両方を使用して複数のルート検出技法を実装し、バイパスをより困難にしています。また、それらの機能を実演するためのサンプルアプリも提供しています。[RootBeer Sample](apps/android/MASTG-APP-0032.md) および [Android RASP Sample](apps/android/MASTG-APP-0033.md) をご覧ください。

## ファイルの存在チェック

おそらく最も広く使用されているプログラムによる検出の手法はルート化されたデバイスに通常見つかるファイルをチェックすることです。一般的なルート化アプリのパッケージファイルや関連するファイルおよびディレクトリなどがあります。以下のものを含みます。

```sh
/system/app/Superuser.apk
/system/etc/init.d/99SuperSUDaemon
/dev/com.koushikdutta.superuser.daemon/
/system/xbin/daemonsu
```

検出コードは多くの場合デバイスがルート化されたときに一般的にインストールされるバイナリも検索します。これらの検索には busybox のチェックや _su_ バイナリを別の場所で開こうとするものなどがあります。

```sh
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

`PackageManager` を使用して既知のルートマネージャパッケージを調べることができます。たとえば、特定のパッケージ名に対して `getPackageInfo` を呼び出します。よくある例としては以下があります。

```sh
eu.chainfire.supersu
com.noshufou.android.su
com.koushikdutta.superuser
com.topjohnwu.magisk
```

Android 11 以降では、[パッケージの可視性制限](https://developer.android.com/training/package-visibility) がこの技法に影響します。パッケージがインストールされているにもかかわらずアプリには可視ではない場合、[`getPackageInfo`](https://developer.android.com/reference/android/content/pm/PackageManager#getPackageInfo(java.lang.String,%20int)) はそのパッケージがインストールされていない場合と同じように動作し、通常は [`PackageManager.NameNotFoundException`](https://developer.android.com/reference/android/content/pm/PackageManager.NameNotFoundException) をスローします。これはパッケージベースのルート検出で検出漏れを生み出す可能性があります。

開発者は Android 11 以降ではアプリのマニフェストで `<queries>` 要素を使用して特定のパッケージを照会できます。

```xml
<queries>
    <package android:name="com.topjohnwu.magisk" />
</queries>
```

それ以外では、`QUERY_ALL_PACKAGES` パーミッションを使用して、インストールされているすべてのアプリへの可視性を付与できるが、[Google Play 制限への対象](https://support.google.com/googleplay/android-developer/answer/10158779) となり、多くのユースケースでは正当化されない可能性があります。

## 書き込み可能なパーティションとシステムディレクトリの確認

sysytem ディレクトリに対する普通とは異なるアクセス許可は、カスタマイズまたはルート化されたデバイスを示している可能性があります。通常では system および data ディレクトリは読み取り専用でマウントされていますが、デバイスがルート化されていると読み書き可能でマウントされることがあります。 "rw" フラグでマウントされているこれらのファイルシステムを探すか、もしくはこれらのディレクトリにファイルを作成してみます。

## カスタム Android ビルドの確認

テストビルドやカスタム ROM の兆候を確認することも役に立ちます。これを行う方法のひとつは `BUILD.TAGS` に [`test-keys`](https://source.android.com/docs/core/ota/sign_builds#release-keys) が含まれているかどうかを確認することです。これは一般的に [カスタム Android イメージを示します](https://www.infosecinstitute.com/resources/application-security/android-hacking-security-part-8-root-detection-evasion/)。たとえば、[RootBeer](../../../tools/android/MASTG-TOOL-0146.md) は [以下のように BUILD.TAGS を確認します](https://github.com/scottyab/rootbeer/blob/0.1.1/rootbeerlib/src/main/java/com/scottyab/rootbeer/RootBeer.java#L71-L80)。

```java
public boolean detectTestKeys() {
    String buildTags = android.os.Build.TAGS;

    return buildTags != null && buildTags.contains("test-keys");
}
```

Google Over-The-Air (OTA) 証明書の欠落はカスタム ROM のもうひとつの兆候です。純正の Android ビルドでは [OTA アップデートに Google の公開証明書を使用します](https://www.netspi.com/blog/technical-blog/mobile-application-penetration-testing/android-root-detection-techniques/ "Android Root Detection Techniques")。
