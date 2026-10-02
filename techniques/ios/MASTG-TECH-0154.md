---
title: Info.plist ファイルの解析 (Analyzing Info.plist Files)
platform: ios
---

[Info.plist ファイルの取得 (Retrieving Info.plist Files)](MASTG-TECH-0153.md) で説明されているように `Info.plist` ファイルを入手すると、その内容を解析し、パーミッション、エンタイトルメント、ATS 設定といったセキュリティ関連の設定を調査できます。

ファイルがバイナリ plist 形式である場合には、まず [Plist ファイルを JSON に変換する (Convert Plist Files to JSON)](MASTG-TECH-0138.md) を使用して変換します。

## plutil を使用する

[Plutil](../../tools/ios/MASTG-TOOL-0062.md) を使用して、`Info.plist` ファイル内のすべてのキーと値のペアを人間が読みやすい形式で出力します。

```sh
plutil -p MyApp.app/Info.plist
```

これは plist の内容を構造化した形式で出力します。

```sh
{
  "CFBundleDisplayName" => "MyApp"
  "CFBundleIdentifier" => "com.example.myapp"
  "CFBundleShortVersionString" => "1.0"
  "NSAppTransportSecurity" => {
    "NSAllowsArbitraryLoads" => 0
    "NSExceptionDomains" => {
      "example.com" => {
        "NSExceptionAllowsInsecureHTTPLoads" => 1
        "NSIncludesSubdomains" => 1
      }
    }
  }
  ...
}
```

特定のキーをクエリするには、plist を JSON に変換し、`jq` を使用します。

```sh
plutil -convert json -o Info.json MyApp.app/Info.plist
cat Info.json | jq '.NSAppTransportSecurity'
```

## PlistBuddy を使用する

ビルトインの `PlistBuddy` ツールを使用して、特定のキーを読みます。

```sh
/usr/libexec/PlistBuddy -c "Print :NSAppTransportSecurity" MyApp.app/Info.plist
```

これは `NSAppTransportSecurity` サブツリーのみを出力します。

```sh
Dict {
    NSAllowsArbitraryLoads = false
    NSExceptionDomains = Dict {
        example.com = Dict {
            NSExceptionAllowsInsecureHTTPLoads = true
            NSIncludesSubdomains = true
        }
    }
}
```

## plistlib を使用する

Python のビルトイン [plistlib](../../tools/ios/MASTG-TOOL-0136.md) モジュールを使用して、プログラムから plist を解析および調査します。

```python
import plistlib
import json

with open('MyApp.app/Info.plist', 'rb') as fp:
    data = plistlib.load(fp)

print(json.dumps(data, indent=2, default=str))
```
