---
masvs_v1_id:
- MSTG-CODE-2
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: ios
title: アプリがデバッグ可能かどうかのテスト (Testing whether the App is Debuggable)
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0261]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

アプリのエンタイトルメントを抽出 ([MachO バイナリからエンタイトルメントの抽出 (Extracting Entitlements from MachO Binaries)](../../../techniques/ios/MASTG-TECH-0111.md)) して、`get-task-allow` キーの値を確認します。 `true` に設定されていれば、そのアプリはデバッグ可能です。

```bash
$ ldid -e iGoat-Swift.app/iGoat-Swift
```

```xml
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

[デバッグ (Debugging)](../../../techniques/ios/MASTG-TECH-0084.md) で説明されているように、直接デバッガをアタッチできるかどうかを確認します。

注意: アプリケーションにアンチリバースエンジニアリングコントロールが装備されている場合、デバッガを検出して停止することがあります。
