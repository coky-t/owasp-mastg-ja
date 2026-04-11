---
title: Plist ファイルを JSON に変換する (Convert Plist Files to JSON)
platform: ios
---

`Info.plist` や `PrivacyInfo.xcprivacy` (拡張子が '.xcprivacy' ですが Plist ファイルです) などの Plist ファイルを JSON に変換することで、可読性と解析を容易にできます。

## plutil を使用する

[Plutil](../../tools/ios/MASTG-TOOL-0062.md) を使用して、`PrivacyInfo.xcprivacy` などの Plist ファイルを JSON 形式に変換します。

```console
plutil -convert json -o PrivacyInfo.xcprivacy.json SocialApp.app/PrivacyInfo.xcprivacy
```

## plistlib を使用する

Python のビルトイン [plistlib](../../tools/ios/MASTG-TOOL-0136.md) モジュールを使用して、PrivacyInfo.xcprivacy` などの Plist ファイルを JSON 形式に変換します。

```python
import plistlib
import json

with open('SocialApp.app/PrivacyInfo.xcprivacy', 'rb') as fp:
    data = plistlib.load(fp)

with open('PrivacyInfo.json', 'w', encoding='utf-8') as fp:
    json.dump(data, fp, indent=2, ensure_ascii=False)
```

出力結果:

```json
{
  "NSPrivacyAccessedAPITypes": [
    {
      "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
      "NSPrivacyAccessedAPITypeReasons": [
        "CA92.1",
        "1C8F.1",
        "C56D.1"
      ]
    },
    ...
  ],
  "NSPrivacyCollectedDataTypes": [
    {
      "NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeName",
      "NSPrivacyCollectedDataTypeLinked": true,
      "NSPrivacyCollectedDataTypePurposes": [
        "NSPrivacyCollectedDataTypePurposeAppFunctionality",
        "NSPrivacyCollectedDataTypePurposeOther"
      ],
      "NSPrivacyCollectedDataTypeTracking": false
    },
    ...
  ],
  "NSPrivacyTracking": true,
  "NSPrivacyTrackingDomains": [
    "trk-v2.socialapp.com",
    "trk-v2.socialapp.us",
    ...
  ]
}
```

## IPSW を使用する

[IPSW](../../tools/ios/MASTG-TOOL-0105.md) を使用して、`Info.plist` などの Plist ファイルを JSON 形式に変換します。

```bash
$ ipsw plist ./Info.plist
{
    "BuildMachineOSBuild": "23B74",
    "CFBundleDevelopmentRegion": "en",
    "CFBundleExecutable": "MASTestApp",
    "CFBundleIdentifier": "org.owasp.mastestapp.MASTestApp",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "MASTestApp",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": "1.0",
    "CFBundleSupportedPlatforms": [
        "iPhoneOS"
    ],
    ...
}
```
