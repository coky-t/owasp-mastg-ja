---
title: plistlib
platform: ios
host:
- macOS
- windows
- linux
---

[plistlib モジュール](https://docs.python.org/3/library/plistlib.html) は Python 標準ライブラリの一部であり、`.plist` (プロパティリスト) ファイルをプログラムで読み取り、変更、書き込みを可能にします。XML とバイナリの両方の plist 形式をサポートし、ネイティブの辞書ベースの API を提供します。

これにより `plistlib` は [PlistBuddy](MASTG-TOOL-0135.md) のクロスプラットフォームでの代替物となり、スクリプトや自動化のユースケースに適しています。

## Plist ファイルの読み取り

以下の例では plist ファイルの内容を Python 辞書にロードして表示しています。

```python
import plistlib

with open("Info.plist", "rb") as f:
    plist = plistlib.load(f)

print(plist)
```

これは plist の辞書表現を表示し、他の Python 辞書と同様に検査および変更できます。

## 特定の Plist エントリの読み取り

plist を解析した後、通常の Python 構文を使用して辞書のキーや配列要素にアクセスできます。以下の例では三番目のアプリアイコン形式を表示しています。

```python
print(plist["CFBundleIcons~ipad"]["CFBundlePrimaryIcon"]["CFBundleIconFiles"][2])
# Output: AppIcon-140x40
```

## Plist の値の変更

`CFBundleDisplayName` のようなエントリを変更するには、新しい値を代入し、`plistlib.dump` を使用して、更新した辞書を書き戻します。

```python
plist["CFBundleDisplayName"] = "My New App Name"

with open("Info.plist", "wb") as f:
    plistlib.dump(plist, f)
```

## Plist の値の追加と削除

通常の Python 辞書操作を使用して、新しい値を追加や削除できます。

```python
# Add a new dictionary
plist["CustomDictionary"] = {"CustomProperty": "OWASP MAS"}

# Delete a key
del plist["CustomDictionary"]["CustomProperty"]

# Save the updated plist
with open("Info.plist", "wb") as f:
    plistlib.dump(plist, f)
```
