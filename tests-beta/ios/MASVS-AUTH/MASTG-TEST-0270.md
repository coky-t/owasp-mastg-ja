---
platform: ios
title: >-
  生体認証登録の変更を検出する API への参照 (References to APIs Detecting Biometric Enrollment
  Changes)
id: MASTG-TEST-0270
apis:
  - kSecAccessControlBiometryCurrentSet
  - SecAccessControlCreateWithFlags
type:
  - static
  - code
weakness: MASWE-0046
profiles:
  - L2
knowledge:
  - MASTG-KNOW-0056
---

# MASTG-TEST-0270 生体認証登録の変更を検出する API への参照 (References to APIs Detecting Biometric Enrollment Changes)

### 概要

このテストでは、生体認証登録の変更後にアプリが機密性の高い操作を不正アクセスから保護できないかどうかをチェックします。デバイスのパスコードを入手した攻撃者は、システム設定を介して新しい指紋または顔認証を追加し、アプリで認証するために使用する可能性があります。

このテストでは、[`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags\(_:_:_:_:\)) を介してキーチェーンに機密性の高いアイテムを保存する際に、[`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) アクセス制御フラグが存在しないことを検出します。このフラグは、生体認証データベースが変更された場合 (新しい指紋や顔が追加された場合など)、関連付けられたキーチェーンアイテムにアクセスできないようにします。その結果、アイテムが作成された時点で生体認証データが登録されていたユーザーのみがロック解除できるため、後から登録された生体認証による不正アクセスを防止できます。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

### 評価

保護が必要な機密データリソースに対して、アプリが `kSecAccessControlBiometryCurrentSet` フラグ以外のフラグを指定した `SecAccessControlCreateWithFlags` を使用している場合、そのテストケースは不合格です。
