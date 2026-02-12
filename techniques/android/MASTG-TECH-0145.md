---
title: XAPK ファイルの扱い (Working with XAPK Files)
platform: android
---

APKPure や APKMirror などの代替ストアからアプリをダウンロードする場合、単一の APK ではなく XAPK ファイルを受け取ることがあります。XAPK は Android の標準フォーマットではありません。これはサードパーティストアが一つ以上の APK とオプションの追加データを一緒にバンドルするために使用される単なる ZIP アーカイブです。

## XAPK が含むもの

XAPK ファイルは通常の ZIP アーカイブであり、一般的に以下を含みます。

- ベース APK
- Android App Bundle から生成されるオプションの分割 APK
- オプションの OBB データファイル
- パッケージの内容を記述した manifest.json ファイル

## XAPK の抽出

XAPK はただの ZIP ファイルであるため、標準的なツールを使用して抽出できます。

```bash
unzip app.xapk -d app_extracted
```

抽出後、単一の APK ファイルまたは複数の APK ファイルが現れます。たとえば、以下のようになります。

```sh
ls -1 app_extracted
base.apk
config.ar.apk
config.arm64_v8a.apk
...
config.xxxhdpi.apk
icon.png
manifest.json
```

## XAPK からアプリのインストール

### 単一 APK の場合

抽出したディレクトリが一つの APK のみを含む場合、通常どおりにインストールできます。

```bash
adb install app_extracted/*.apk
```

### 分割 APK の場合

複数の APK が存在する場合、アプリは Android App Bundle としてビルドされています。これらの分割を一つのユニバーサル APK に変換する確実な方法やサポートされた方法はありません。正しいアプローチは、ベース APK と、対象デバイスに適した分割を一緒にインストールすることです。

```bash
adb install-multiple -r app_extracted/*.apk
```

### OBB データ

XAPK が OBB ファイルを含む場合、まず APK をインストールし、それから OBB ディレクトリをデバイスにプッシュします。

```bash
adb push app_extracted/Android/obb/<package.name> /sdcard/Android/obb/
```

## リバースエンジニアリング

リバースエンジニアリングと静的解析には、この以下のように [jadx](../../tools/android/MASTG-TOOL-0018.md) を使用して、ベース APK と関連するすべての分割 APK を一緒にオープンできます。

```bash
jadx app_extracted/*.apk
```

Android アプリの逆コンパイルの詳細については [Java コードの逆コンパイル (Decompiling Java Code)](MASTG-TECH-0017.md) を参照してください。
