---
title: ATS 構成の解析 (Analyzing the ATS Configuration)
platform: ios
---

App Transport Security (ATS) 設定は `Info.plist` ファイルに `NSAppTransportSecurity` キーで宣言されています。ATS は [URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) を通じて (例: `URLSession` を介して) 行われるネットワーク接続のセキュリティ要件を制御します。デフォルトでは、ATS は TLS 1.2 以降での HTTPS を必要とし、Forward Secrecy を強制します。アプリは `Info.plist` での例外を通じてこれらのデフォルトを弱めたり無効にすることができます。

[Info.plist ファイルの取得 (Retrieving Info.plist Files)](MASTG-TECH-0153.md) で `Info.plist` を取得した後、[Info.plist ファイルの解析 (Analyzing Info.plist Files)](MASTG-TECH-0154.md) を使用してその内容を解析し、以下のキーを探します。ATS 構成や例外に関する詳細については [iOS App Transport Security](../../knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071.md) を参照してください。

## plutil と jq を使用する

`Info.plist` を JSON に変換し、ATS 構成全体を抽出します。

```sh
plutil -convert json -o Info.json MyApp.app/Info.plist
cat Info.json | jq '.NSAppTransportSecurity'
```

複数の例外が構成されたアプリの出力例:

```json
{
  "NSAllowsArbitraryLoads": false,
  "NSExceptionDomains": {
    "example.com": {
      "NSExceptionAllowsInsecureHTTPLoads": true,
      "NSIncludesSubdomains": true
    },
    "legacy.example.com": {
      "NSExceptionMinimumTLSVersion": "TLSv1.0",
      "NSExceptionRequiresForwardSecrecy": false
    }
  }
}
```

Forward Secrecy を無効にしているドメインをチェックするには:

```sh
cat Info.json | jq '.NSAppTransportSecurity.NSExceptionDomains | to_entries[] | select(.value.NSExceptionRequiresForwardSecrecy == false) | .key'
```

グローバルの `NSAllowsArbitraryLoads` フラグをチェックするには:

```sh
cat Info.json | jq '.NSAppTransportSecurity.NSAllowsArbitraryLoads'
```

## PlistBuddy を使用する

ビルトインの `PlistBuddy` ツールを使用して、ATS サブツリーのみを表示します。

```sh
/usr/libexec/PlistBuddy -c "Print :NSAppTransportSecurity" MyApp.app/Info.plist
```
