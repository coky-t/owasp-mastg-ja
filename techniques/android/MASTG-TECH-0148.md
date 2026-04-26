---
title: Android コンテンツプロバイダとのやり取り (Interacting with Android ContentProviders)
platform: android
---

Android の `ContentProvider` の概要 (URI 構造、アクセス制御、クエリ処理など) については [Android コンテンツプロバイダ (Android ContentProvider)](../../knowledge/android/MASVS-CODE/MASTG-KNOW-0117.md) を参照してください。

## [adb](../../tools/android/MASTG-TOOL-0004.md) を使用する

[adb](../../tools/android/MASTG-TOOL-0004.md) を使用して、`content` コマンドを介してデバイスまたはエミュレータ上の `ContentProvider` とやり取りできます。

### 行を照会する

```bash
adb shell content query --uri content://org.owasp.mastestapp.provider/students
adb shell content query --uri content://org.owasp.mastestapp.provider/students --where "name='Bob'"
```

### 行を挿入する

```bash
adb shell content insert \
    --uri content://org.owasp.mastestapp.provider/students \
    --bind name:s:Eve
```

### 行を更新する

```bash
adb shell content update \
    --uri content://org.owasp.mastestapp.provider/students \
    --where "id=1" \
    --bind name:s:"Alice Jr"
```

### 行を削除する

```bash
adb shell content delete \
    --uri content://org.owasp.mastestapp.provider/students \
    --where "id=3"
```

## 注記

- `--where` 引数は `ContentProvider.query()` の `selection` パラメータに直接対応します。
- このコマンドはシェルユーザーのコンテキストで実行するため、アクセスはプロバイダがエクスポートされているかどうか、および適用されるパーミッションによって異なります。
- 文字列を渡す場合やテスト入力を作成する場合、特に SQL 演算子を使用する場合、引用符付けとエスケープ化が重要です。
