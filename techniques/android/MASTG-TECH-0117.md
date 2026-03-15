---
title: AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)
platform: android
---

[AndroidManifest.xml](../../Document/0x05a-Platform-Overview.md) ファイルは Android アプリケーションに不可欠の構成要素であり、アプリの構造、パーミッション、コンポーネント、構成に関する重要な情報を提供します。セキュリティ評価において、マニフェストを解析することで、攻撃者に悪用される可能性のある脆弱性や構成ミスを明らかにできます。

AndroidManifest はバイナリ XML 形式で保存されており、APK を展開するだけでは抽出できません。マニフェストを適切に解析するには、まず抽出して、人間が読みやすい XML 形式にデコードする必要があります。

さまざまなツールがさまざまな形式でマニフェストを抽出しますが、中には元の構造を保持するものもあれば、デコード時に解釈や変更を加えるものもあります。

## [jadx](../../tools/android/MASTG-TOOL-0018.md) を使用する

jadx CLI に `--no-src` を付けて使用し、すべてのソースを逆コンパイルせずにリソースのみを抽出します。

```sh
jadx --no-src -d out_dir MASTG-DEMO-0001.apk
```

jadx はマニフェスト全体を `out_dir/resources/AndroidManifest.xml` に出力します。`<uses-sdk>` 要素を含みますが、これは apktool など他のツールを使用する場合には含まれません。

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" ...>
    <uses-sdk
        android:minSdkVersion="29"
        android:targetSdkVersion="35" />
```

## [Apktool](../../tools/android/MASTG-TOOL-0011.md) を使用する

AndroidManifest は apktool を使用して抽出できます。

```sh
$ apktool d -s -f -o output_dir MASTG-DEMO-0001.apk
I: Using Apktool 2.11.1 on MASTG-DEMO-0001.apk with 8 threads
I: Copying raw classes.dex file...
...
I: Loading resource table...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Decoding AndroidManifest.xml with resources...
```

`-s` は dex ファイルのバックスマリングをスキップし、より高速になります。

AndroidManifest.xml は抽出され、`output_dir/AndroidManifest.xml` にデコードされます。これはそのまま開いて閲覧できます。

apktool で APK をデコードする場合、逆コンパイルされた AndroidManifest.xml には `<uses‑sdk>` 要素 (`minSdkVersion` と `targetSdkVersion` を含む) が欠落していることに気が付くかもしれません。これは想定された動作です。

apktool はこれらの値を、デコードされた XML マニフェストに挿入するのではなく、apktool.yml という別のファイルに移動します。このファイルには、以下のようなものがあります。

```yml
sdkInfo:
  minSdkVersion: 29
  targetSdkVersion: 35
```

## [aapt2](../../tools/android/MASTG-TOOL-0124.md) を使用する

マニフェストの特定の値のみに関心がある場合には、aapt2 を使用できます。

**出力は XML ファイルではない** ことに注意してください。

```bash
$ aapt2 d badging MASTG-DEMO-0001.apk
package: name='org.owasp.mastestapp' versionCode='1' versionName='1.0' platformBuildVersionName='15' platformBuildVersionCode='35' compileSdkVersion='35' compileSdkVersionCodename='15'
sdkVersion:'29'
targetSdkVersion:'35'
uses-permission: name='android.permission.INTERNET'
uses-permission: name='org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'
application-label:'MASTestApp'
...
```
