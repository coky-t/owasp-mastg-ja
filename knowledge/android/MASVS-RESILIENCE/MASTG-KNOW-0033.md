---
masvs_category: MASVS-RESILIENCE
platform: android
title: 難読化 (Obfuscation)
---

["モバイルアプリの改竄とリバースエンジニアリング"](../../../Document/0x04c-Tampering-and-Reverse-Engineering.md#obfuscation) の章ではモバイルアプリ全般に使用できるよく知られた難読化技法をいくつか紹介しています。

Android アプリはさまざまなツールを使用してこれらの難読化技法のいくつかを実装できます。たとえば、 [ProGuard](../../../tools/android/MASTG-TOOL-0022.md) はコードを縮小して難読化し、Android Java アプリのバイトコードから不要なデバッグ情報を削除する簡単な方法を提供します。それはクラス名、メソッド名、変数名などの識別子を意味のない文字列に置き換えます。これはレイアウト難読化の一種であり、プログラムのパフォーマンスに影響はありません。

> Java クラスを逆コンパイルするのは簡単なので、製品バイトコードには常になんらかの基本的な難読化を適用することをお勧めします。

Android 難読化技法について詳しくは以下をご覧ください。

- ["Security Hardening of Android Native Code"](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code/) by Gautam Arvind
- ["APKiD: Fast Identification of AppShielding Products"](https://github.com/enovella/cve-bio-enovella/blob/master/slides/APKiD-NowSecure-Connect19-enovella.pdf) by Eduardo Novella ([APKiD](../../../tools/android/MASTG-TOOL-0009.md))
- ["Challenges of Native Android Applications: Obfuscation and Vulnerabilities"](https://theses.hal.science/tel-03164744/document) by Pierre Graux

## ProGuard の使用

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
