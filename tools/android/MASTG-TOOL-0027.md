---
title: Xposed
platform: android
source: https://github.com/ElderDrivers/EdXposed
---

> Xposed は Android 9 (API レベル 28) では動作しません。しかし、2019 年に EdXposed という名前で非公式に移植され、Android 8 ～ 10 (API レベル 26 から 29) をサポートしています。コードと使用例は [EdXposed](https://github.com/ElderDrivers/EdXposed "EdXposed") GitHub リポジトリにあります。

[Xposed](https://f-droid.org/de/packages/de.robv.android.xposed.installer/ "Xposed Installer") は、Android アプリケーションパッケージ (APK) を変更したり再フラッシュすることなく、実行時にシステムやアプリケーションの概観や動作を変更できるフレームワークです。技術的には、Zygote の拡張バージョンであり、新しいプロセスを開始する際に Java コードを実行するための API をエクスポートします。新しくインスタンス化されたアプリのコンテキストで Java コードを実行すると、アプリに属する Java メソッドを解決、フック、オーバーライドできるようになります。Xposed は [reflection](https://docs.oracle.com/javase/tutorial/reflect/ "Reflection Tutorial") を使用して、実行中のアプリを調べて変更します。アプリケーションのバイナリは変更されないため、変更はメモリ内に適用され、プロセスの実行中のみ持続します。

Xposed を使用するには、[XDA-Developers Xposed フレームワークハブ](https://www.xda-developers.com/xposed-framework-hub/ "Xposed framework hub from XDA") で説明されているように、まずルート化済みデバイスに Xposed フレームワークをインストールする必要があります。モジュールは Xposed Installer アプリからインストールでき、GUI でオンとオフを切り替えることができます。

注: Xposed フレームワークのプレーンインストールは SafetyNet で簡単に検出されるため、Magisk を使用して Xposed をインストールすることをお勧めします。そうすることで、SafetyNet 認証を持つアプリケーションは Xposed モジュールでテストできる可能性が高くなります。

Xposed は Frida と比較されてきました。ルート化済みデバイスで Frida を実行すると、同様に効果的なセットアップになります。どちらのフレームワークも動的計装を行いたい場合に多くの価値を提供します。Frida がアプリをクラッシュする場合は、Xposed で同様のことを試すことができます。次に、Frida スクリプトの豊富さと同様に、Xposed に付属する多くのモジュールの一つを簡単に使用できます。たとえば、前に説明した SSL ピン留めをバイパスするモジュール ([JustTrustMe](https://github.com/Fuzion24/JustTrustMe "JustTrustMe") や [SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "SSL Unpinning")) などです。Xposed は、[Inspeckage](https://github.com/ac-pm/Inspeckage "Inspeckage") など、他のモジュールも含み、より詳細なアプリケーションテストを行うこともできます。そのうえ、Android アプリケーションでよく使われるセキュリティメカニズムにパッチを適用するために、独自のモジュールを作成することもできます。

Xposed は以下のスクリプトを使用してエミュレータにインストールすることもできます。

```bash
#!/bin/sh
echo "Start your emulator with 'emulator -avd NAMEOFX86A8.0 -writable-system -selinux permissive -wipe-data'"
adb root && adb remount
adb install SuperSU\ v2.79.apk #binary can be downloaded from http://www.supersu.com/download
adb push root_avd-master/SuperSU/x86/su /system/xbin/su
adb shell chmod 0755 /system/xbin/su
adb shell setenforce 0
adb shell su --install
adb shell su --daemon&
adb push busybox /data/busybox #binary can be downloaded from https://busybox.net/
# adb shell "mount -o remount,rw /system && mv /data/busybox /system/bin/busybox && chmod 755 /system/bin/busybox && /system/bin/busybox --install /system/bin"
adb shell chmod 755 /data/busybox
adb shell 'sh -c "./data/busybox --install /data"'
adb shell 'sh -c "mkdir /data/xposed"'
adb push xposed8.zip /data/xposed/xposed.zip #can be downloaded from https://dl-xda.xposed.info/framework/
adb shell chmod 0755 /data/xposed
adb shell 'sh -c "./data/unzip /data/xposed/xposed.zip -d /data/xposed/"'
adb shell 'sh -c "cp /data/xposed/xposed/META-INF/com/google/android/*.* /data/xposed/xposed/"'
echo "Now adb shell and do 'su', next: go to ./data/xposed/xposed, make flash-script.sh executable and run it in that directory after running SUperSU"
echo "Next, restart emulator"
echo "Next, adb install XposedInstaller_3.1.5.apk"
echo "Next, run installer and then adb reboot"
echo "Want to use it again? Start your emulator with 'emulator -avd NAMEOFX86A8.0 -writable-system -selinux permissive'"
```
