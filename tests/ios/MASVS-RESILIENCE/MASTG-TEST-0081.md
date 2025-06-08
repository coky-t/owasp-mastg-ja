---
masvs_v1_id:
- MSTG-CODE-1
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: ios
title: アプリが正しく署名されていることの確認 (Making Sure that the App Is Properly Signed)
masvs_v1_levels:
- R
profiles: [R]
covered_by: [MASTG-TEST-0220]
status: deprecated
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

アプリが [最新のコード署名形式を使用している](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format) ことを確認する必要があります。[codesign](../../../tools/ios/MASTG-TOOL-0114.md) でアプリの .app ファイルから署名証明書情報を取得できます。codesign はコード署名の作成、確認、表示、およびシステム内の署名済みコードの動的ステータスの照会に使用されます。

アプリケーションの IPA ファイルを取得した後、ZIP ファイルとして再度保存し、ZIP ファイルを展開します。アプリケーションの .app ファイルがある Payload ディレクトリに移動します。

以下の `codesign` コマンドを実行して、署名情報を表示します。

```bash
$ codesign -dvvv YOURAPP.app
Executable=/Users/Documents/YOURAPP/Payload/YOURAPP.app/YOURNAME
Identifier=com.example.example
Format=app bundle with Mach-O universal (armv7 arm64)
CodeDirectory v=20200 size=154808 flags=0x0(none) hashes=4830+5 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha1=455758418a5f6a878bb8fdb709ccfca52c0b5b9e
CandidateCDHash sha256=fd44efd7d03fb03563b90037f92b6ffff3270c46
Hash choices=sha1,sha256
CDHash=fd44efd7d03fb03563b90037f92b6ffff3270c46
Signature size=4678
Authority=iPhone Distribution: Example Ltd
Authority=Apple Worldwide Developer Relations Certification Authority
Authority=Apple Root CA
Signed Time=4 Aug 2017, 12:42:52
Info.plist entries=66
TeamIdentifier=8LAMR92KJ8
Sealed Resources version=2 rules=12 files=1410
Internal requirements count=1 size=176
```

[Apple ドキュメント](https://developer.apple.com/business/distribute/ "Apple Business") で説明されているように、アプリを配布するにはいくつかの方法があります。App Store を使用する方法や、カスタムディストリビューションや組織内ディストリビューション向けに Apple Business Manager を使用する方法があります。組織内ディストリビューションスキームの場合、ディストリビューション用にアプリに署名する際にアドホック証明書が使用されていないことを確認します。
