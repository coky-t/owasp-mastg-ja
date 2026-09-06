---
title: AndroidManifest の解析 (Analyzing the AndroidManifest)
platform: android
---

[AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](MASTG-TECH-0117.md) で説明されているように `AndroidManifest.xml` を抽出したら、その内容を解析して、特定の属性、フラグ、パーミッション、コンポーネント制限を探します。

使用する抽出ツールによって出力形式が異なることに注意します。

- jadx や apktool などのツールは、属性に `android:` 名前空間接頭辞 (例: `android:debuggable="true"`) が付いた **標準 XML** を出力します。
- aapt2 などのツールは、異なる命名規則 (例: `application-debuggable`) を使用する **独自のデコード形式** (XML ではない) を出力します。

## grep を使用する

`grep` を使用して、XML 出力の特定の属性やフラグを検索します。

```bash
grep -i "android:debuggable" output_dir/AndroidManifest.xml
```

フラグが設定されている場合の出力例:

```xml
android:debuggable="true"
```

この属性がない場合、リリースビルドではそのフラグのデフォルトは `false` になります。

## aapt2 を使用する

aapt2 を使用して、事前にそれを抽出することなくマニフェストを照会します。

```bash
aapt2 d badging app.apk | grep -i debuggable
```

フラグが設定されている場合の出力例:

```txt
application-debuggable
```

この行がない場合、そのフラグは設定されていません (デフォルトは `false` になります)。

## xmllint や xmlstarlet を使用する

構造化 XML クエリでは、抽出された XML マニフェストに `xmllint` や `xmlstarlet` を使用します。

```bash
xmlstarlet sel -t -v "//application/@android:debuggable" -n output_dir/AndroidManifest.xml
```
