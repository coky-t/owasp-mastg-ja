---
platform: ios
title: 非生体認証へのフォールバックを許可する API への参照 (References to APIs Allowing Fallback to Non-Biometric Authentication)
id: MASTG-TEST-0268
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
type: [static, code]
weakness: MASWE-0045
profiles: [L2]
knowledge: [MASTG-KNOW-0056]
---

## 概要

このテストでは、アプリが生体認証ではなくユーザーのパスコードに依存する認証メカニズムを使用しているか、または生体認証が失敗した場合にデバイスのパスコードへのフォールバックを許可する認証メカニズムを使用しているかをチェックします。具体的には、[`kSecAccessControlDevicePasscode`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/devicepasscode) または [`kSecAccessControlUserPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence) フラグを指定した [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags) の使用をチェックします。

`kSecAccessControlUserPresence` フラグは「現在の状況に応じて、システムにメカニズムを選択させる」ため、一般的に使用されるオプションとして Apple のドキュメントに記載されています。しかし、これは場合によっては (生体認証がまだ設定されていない場合など) パスコードへのフォールバックを可能にします。パスコードは (ショルダーサーフィンなどによる) 侵害の影響を受けやすいため、生体認証のみを要求する場合よりも脆弱であると考えられています。

**注:** このテストでは LocalAuthentication フローにおいて [`LAPolicy.deviceOwnerAuthentication`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication) を考慮していません。これは単独で使用すべきではないためです。[イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)](MASTG-TEST-0266.md) を参照してください。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

保護が必要な機密データリソースに対して、アプリが `kSecAccessControlUserPresence` または `kSecAccessControlDevicePasscode` フラグを指定した `SecAccessControlCreateWithFlags` を使用している場合、そのテストケースは不合格です。

> [!NOTE]
> `kSecAccessControlUserPresence` や `kSecAccessControlDevicePasscode` の使用は本質的に脆弱性ではありませんが、高セキュリティアプリケーション (金融、行政、医療など) では、これらの使用は弱点や設定ミスとなり、意図したセキュリティ態勢を減らす可能性があります。したがって、この問題は重大な脆弱性ではなく、セキュリティの弱点または堅牢化の問題として分類する方が適切です。
