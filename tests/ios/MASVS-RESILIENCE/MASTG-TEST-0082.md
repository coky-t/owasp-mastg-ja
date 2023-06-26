---
masvs_v1_id:
- MSTG-CODE-2
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: ios
title: アプリがデバッグ可能かどうかのテスト (Testing whether the App is Debuggable)
masvs_v1_levels:
- R
---

## 概要

## 静的解析

アプリのエンタイトルメントを調べて `get-task-allow` キーの値を確認します。 `true` に設定されていれば、そのアプリはデバッグ可能です。

codesign を使用する場合:

```bash
$ codesign -d --entitlements - iGoat-Swift.app

Executable=/Users/owasp/iGoat-Swift/Payload/iGoat-Swift.app/iGoat-Swift
[Dict]
    [Key] application-identifier
    [Value]
        [String] TNAJ496RHB.OWASP.iGoat-Swift
    [Key] com.apple.developer.team-identifier
    [Value]
        [String] TNAJ496RHB
    [Key] get-task-allow
    [Value]
        [Bool] true
    [Key] keychain-access-groups
    [Value]
        [Array]
            [String] TNAJ496RHB.OWASP.iGoat-Swift
````

ldid を使用する場合:

```xml
$ ldid -e iGoat-Swift.app/iGoat-Swift

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>application-identifier</key>
    <string>TNAJ496RHB.OWASP.iGoat-Swift</string>
    <key>com.apple.developer.team-identifier</key>
    <string>TNAJ496RHB</string>
    <key>get-task-allow</key>
    <true/>
    <key>keychain-access-groups</key>
    <array>
        <string>TNAJ496RHB.OWASP.iGoat-Swift</string>
    </array>
</dict>
</plist>
```

## 動的解析

Xcode を使用して、直接デバッガをアタッチできるかどうかを確認します。次に、脱獄済みデバイスで Clutch を行った後にアプリをデバッグできるかどうかを確認します。これは Cydia の BigBoss リポジトリにある debug-server を使用して行われます。

注意: アプリケーションにアンチリバースエンジニアリングコントロールが装備されている場合、デバッガを検出して停止することがあります。
