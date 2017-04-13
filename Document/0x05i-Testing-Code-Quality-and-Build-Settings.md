## コード品質とビルド設定のテスト

### アプリが正しく署名されていることの検証

#### 概要

Android ではすべての APK はインストールする前に証明書でデジタル署名する必要があります。デジタル署名はアプリケーションをインストール/実行する前に Android システムで必要とされ、アプリケーションの将来の更新で所有者の身元を確認するためにも使用されます。このプロセスにより不正なコードを含むような改竄や改変を防ぐことができます。

APK に署名すると、公開鍵証明書が APK に添付されます。この証明書は APK を開発者および対応する秘密鍵に一意に関連付けます。デバッグモードでアプリをビルドすると、Android SDK はデバッグ用に特別に作成されたデバッグ鍵でアプリに署名します。デバッグ鍵で署名されたアプリは配布用ではなく、Google Play ストアを含むほとんどのアプリストアで受け入れられません。最終リリースのアプリを準備するには、開発者が所有するリリース鍵で署名する必要があります。

アプリの最終リリースビルドは有効なリリース鍵で署名されている必要があります。注意。Android ではアプリの更新に同じ証明書で署名することを期待しますので、25年以上の有効期間が推奨されます。Google Play に公開されるアプリは少なくとも2033年10月22日まで有効な証明書で署名する必要があります。

#### 静的解析

APK signatures can be verified using the <code>jarsigner</code> tool. For a properly signed APK, <code>jarsigner</code> should print the attributes of the signing certificate used. Note the in the debug certificate, the Common Name(CN) attribute is set to "Android Debug".

The output for an APK signed with a Debug certificate looks as follows:

```
$ jarsigner -verify -verbose -certs example-debug.apk 

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Android Debug, O=Android, C=US
      [certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
      [CertPath not validated: Path does not chain with any of the trust anchors]

```

The output for an APK signed with a Release certificate looks as follows:

```
$ jarsigner -verify -verbose -certs example-release.apk 

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Awesome Corporation, OU=Awesome, O=Awesome Mobile, L=Palo Alto, ST=CA, C=US
      [certificate is valid from 9/1/09 4:52 AM to 9/26/50 4:52 AM]
      [CertPath not validated: Path does not chain with any of the trust anchors]

```

#### 動的解析

静的解析を使用して APK 署名を検証する必要があります。APK をローカルで使用できない場合は、まずデバイスから APK を取り出します。

```bash
$ adb shell pm list packages
(...)
package:com.awesomeproject
(...)
$ adb shell pm path com.awesomeproject
package:/data/app/com.awesomeproject-1/base.apk
$ adb pull /data/app/com.awesomeproject-1/base.apk
```

#### 改善方法

開発者はリリースビルドがリリースキーストアの適切な証明書で署名されていることを確認する必要があります。Android Studio では、手動もしくは署名設定を設定してリリースビルドタイプに割り当てることで設定できます [2] 。

#### 参考情報

##### OWASP Mobile Top 10 2016

M7 - Client Code Quality

##### OWASP MASVS

- V7.1: "アプリは有効な証明書で署名およびプロビジョニングされている。"

##### CWE

N/A

##### その他

- [1] Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
- [2] Sign your App - https://developer.android.com/studio/publish/app-signing.html

##### ツール

- jarsigner - http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html

### アプリがデバッグ可能であるかのテスト

#### 概要

The <code>android:debuggable</code> attiribute in the <code>Application</code> tag in the Manifest determines whether or not the app can be debugged when running on a user mode build of Android. In a release build, this attribute should always be set to "false" (the default value).

#### 静的解析

Check in <code>AndroidManifest.xml</code> whether the <code>android:debuggable</code> attribute is set:

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.android.owasp">

    ...

    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <meta-data android:name="com.owasp.main" android:value=".Hook"/>
    </application>
</manifest>
```

#### 動的解析

Set the <code>android:debuggable</code> to false, or simply leave omit it from the <code>Application</code> tag.

#### 改善方法

For production releases, the attribute android:debuggable must be set to false within the application element. This ensures that a debugger cannot attach to the process of the application.

#### 参考情報

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Testing If the App is Debuggable"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Testing If the App is Debuggable"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* [1] Application element - https://developer.android.com/guide/topics/manifest/application-element.html


### デバッグシンボルに関するテスト

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

For native binaries, use a standard tool like nm or objdump to inspect the symbol table. A release build should generally not contain any debugging symbols. If the goal is to obfuscate the library, removing unneeded dynamic symbols is also recommended.

#### 静的解析

Symbols  are usually stripped during the build process, so you need the compiled bytecode and libraries to verify whether the any unnecessary metadata has been discarded. 

To display debug symbols:

```bash
export $NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm
```

```bash
$ $NM -a libfoo.so 
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```
To display dynamic symbols:

```bash
$ $NM -D libfoo.so 
```

Alternatively, open the file in your favorite disassembler and check the symbol tables manually. 

#### 動的解析

#### 改善方法

Dynamic symbols can be stripped using the <code>visibility</code> compiler flag. Adding this flag causes gcc to discard the function names while still preserving the names of functions declared as <code>JNIEXPORT</code>.

Add the following to build.gradle:

```
        externalNativeBuild {
            cmake {
                cppFlags "-fvisibility=hidden"
            }
        }
```

#### 参考情報

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Testing for Debugging Symbols"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Testing for Debugging Symbols"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### ツール

-- TODO [Add relevant tools for "Testing for Debugging Symbols"] --
* Enjarify - https://github.com/google/enjarify


### デバッグコードや詳細エラーログに関するテスト

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### ホワイトボックステスト

-- TODO [Add content on white-box testing for "Testing for Debugging Code and Verbose Error Logging"] --

#### ブラックボックステスト

-- TODO [Add content on black-box testing for "Testing for Debugging Code and Verbose Error Logging"] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Debugging Code and Verbose Error Logging"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Testing for Debugging Code and Verbose Error Logging"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Testing for Debugging Code and Verbose Error Logging"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### ツール

-- TODO [Add relevant tools for "Testing for Debugging Code and Verbose Error Logging"] --
* Enjarify - https://github.com/google/enjarify


### 例外処理のテスト

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### ホワイトボックステスト

Review the source code to understand/identify who the application handle various types of errors (IPC communications, remote services invokation, etc). Here are some examples of the checks to be performed at this stage :

* Verify that the application use a [well-designed] (https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047) (an unified) scheme to handle exceptions.
* Verify that the application doesn't expose sensitive information while handeling exceptions, but are still verbose enough to explain the issue to the user.
* C3

#### ブラックボックステスト

-- TODO [Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Exception Handling"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Testing Exception Handling"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Testing Exception Handling"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### ツール

-- TODO [Add relevant tools for "Testing Exception Handling"] --
* Enjarify - https://github.com/google/enjarify


### コンパイラ設定の検証

#### 概要

Since most Android applications are Java based, they are [immunue](https://www.owasp.org/index.php/Reviewing_Code_for_Buffer_Overruns_and_Overflows#.NET_.26_Java) to buffer overflow vulnerabilities.

#### ホワイトボックステスト

-- TODO [Describe how to assess this with access to the source code and build configuration] --

#### ブラックボックステスト

-- TODO [Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying Compiler Settings"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Verifying Compiler Settings"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Verifying Compiler Settings"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for "Verifying Compiler Settings"] --
* Enjarify - https://github.com/google/enjarify


### Testing for Memory Management Bugs

#### 概要

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### ホワイトボックステスト

-- TODO [Add content for white-box testing "Testing for Memory Management Bugs"] --

#### ブラックボックステスト

-- TODO [Add content for black-box testing "Testing for Memory Management Bugs"] --

#### 改善方法

-- TODO [Add remediations for "Testing for Memory Management Bugs"] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- V7.7: "アンマネージドコードでは、メモリは安全に割り当て、解放、使用されている。"

##### CWE

-- TODO [Add relevant CWE for "Testing for Memory Management Bugs"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### ツール

-- TODO [Add relevant tools for "Testing for Memory Management Bugs"] --
* Enjarify - https://github.com/google/enjarify


### JavaバイトコードがMinifyされていることの検証

#### 概要

Because Java classes are trivial to decompile, applying some basic obfuscation to the release bytecode is recommended. For Java apps on Android, ProGuard offers an easy way to shrink and obfuscate code. It replaces identifiers such as  class names, method names and variable names with meaningless character combinations. This is a form of layout obfuscation, which is “free” in that it doesn't impact the performance of the program.

#### ホワイトボックステスト

If source code is provided, build.gradle file can be check to see if obfuscation settings are set. From the example below, we can see that minifyEnabled and proguardFiles are set. It is common to see application exempts some class from obfuscation with "-keepclassmembers" and "-keep class", so it is important to audit proguard configuration file to see what class are exempted. The getDefaultProguardFile('proguard-android.txt') method gets the default ProGuard settings from the Android SDK tools/proguard/ folder and proguard-rules.pro is where you defined custom proguard rules. From our sample proguard-rules.pro file, we can see that many classes that extend common android classes are exempted, which should be done more granular on exempting specific classes or library.

build.gradle
```
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
```

proguard-rules.pro
```
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
```

#### ブラックボックステスト

If source code is not provided, apk can be decompile to verify if codebase have been obfuscated. dex2jar can be used to convert dex code to jar file. Tools like JD-GUI can be used to check if class, method and variable name is human readable.

Sample obfuscated code block
```
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

#### 改善方法

ProGuard should be used to strip unneeded debugging information from the Java bytecode. By default, ProGuard removes attributes that are useful for debugging, including line numbers, source file names and variable names. ProGuard is a free Java class file shrinker, optimizer, obfuscator, and preverifier. It is shipped with Android’s SDK tools. To activate shrinking for the release build, add the following to build.gradle:

~~~~
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile(‘proguard-android.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
~~~~

#### 参考情報

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Verifying that Java Bytecode Has Been Minified"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for Verifying that Java Bytecode Has Been Minified] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### ツール

-- TODO [Add relevant tools for Verifying that Java Bytecode Has Been Minified] --
* Enjarify - https://github.com/google/enjarify

