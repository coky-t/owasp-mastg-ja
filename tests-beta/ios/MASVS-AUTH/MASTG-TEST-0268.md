---
platform: ios
title: 非生体認証へのフォールバックを許可する API への参照 (References to APIs Allowing Fallback to Non-Biometric Authentication)
id: MASTG-TEST-0268
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0045
---

## 概要

このテストでは、アプリが生体認証ではなくユーザーのパスコードに依存する認証メカニズムを使用しているか、または生体認証が失敗した場合にデバイスのパスコードへのフォールバックを許可する認証メカニズムを使用しているかをチェックします。具体的には、[`kSecAccessControlDevicePasscode`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/devicepasscode) または [`kSecAccessControlUserPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence) の使用をチェックします。

`kSecAccessControlUserPresence` フラグは「現在の状況に応じて、システムにメカニズムを選択させる」ため、一般的に使用されるオプションとして Apple のドキュメントに記載されています。しかし、これは場合によっては (生体認証がまだ設定されていない場合など) パスコードへのフォールバックを可能にします。パスコードは (ショルダーサーフィンなどによる) 侵害の影響を受けやすいため、生体認証のみを要求する場合よりも脆弱であると考えられています。

**注:** このテストでは LocalAuthentication フローにおいて [`LAPolicy.deviceOwnerAuthentication`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication) を考慮していません。これは単独で使用すべきではないためです。[イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)](MASTG-TEST-0266.md) を参照してください。

## 手順

1. [radare2 for iOS](../../../tools/ios/MASTG-TOOL-0073.md) で静的解析スキャンを実行し、`kSecAccessControlUserPresence` または `kSecAccessControlDevicePasscode` フラグを指定した `SecAccessControlCreateWithFlags` の使用を検出します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

保護が必要な機密データリソースに対して、アプリが `kSecAccessControlUserPresence` または `kSecAccessControlDevicePasscode` フラグを指定した `SecAccessControlCreateWithFlags` を使用している場合、そのテストは不合格です。

アプリが [`kSecAccessControlBiometryAny`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany), [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) などのより厳しいフラグを指定した `SecAccessControlCreateWithFlags` を使用して、保護が必要な機密データリソースに対するアクセスを生体認証のみに強制する場合にのみ、そのテストは合格です (`kSecAccessControlBiometryCurrentSet` が最も安全であると考えられています)。

**注:** `kSecAccessControlUserPresence` や `kSecAccessControlDevicePasscode` の使用は本質的に脆弱性ではありませんが、高セキュリティアプリケーション (金融、行政、医療など) では、これらの使用は弱点や設定ミスとなり、意図したセキュリティ態勢を減らす可能性があります。したがって、この問題は重大な脆弱性ではなく、セキュリティの弱点または堅牢化の問題として分類する方が適切です。
