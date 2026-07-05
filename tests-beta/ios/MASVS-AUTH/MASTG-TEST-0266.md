---
platform: ios
title: >-
  イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric
  Authentication)
id: MASTG-TEST-0266
apis:
  - LAContext.evaluatePolicy
type:
  - static
  - code
weakness: MASWE-0044
profiles:
  - L2
knowledge:
  - MASTG-KNOW-0056
  - MASTG-KNOW-0057
---

# MASTG-TEST-0266 イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)

### 概要

このテストでは、Keychain API を使用したりユーザーの存在を要求するのではなく、アクセス制御に LocalAuthentication API のみに依存して、ユーザー認証によって保護する必要がある機密リソース (トークン、キーなど) にアプリが安全でない方法でアクセスしていないかどうかをチェックします。

**LocalAuthentication** API (例: `LAContext`) はユーザー認証 (Touch ID, Face ID, デバイスパスコード) を提供し、成功または失敗の結果のみを返します。ただし、シークレットを安全に保存したり、セキュリティを強化することは **できません**。そのため、ロジック操作の影響を受けやすくなります (例: `if authenticated { ... }` チェックのバイパスなど)。

対照的に、**Keychain** API は機密データを安全に保存し、`kSecAccessControl` フラグを介してアクセス制御ポリシー (例: 生体認証などのユーザーの存在を要求するなど) を設定できます。これは、認証が単なる一回限りのブール値ではなく、**安全なデータ取得パス (プロセス外)** の一部であることを確保するため、認証のバイパスが著しく難しくなります。

Keychain API は、機密データアクセスにユーザー認証を強制するための `SecItemAdd`, `SecItemCopyMatching`, `SecAccessControlCreateWithFlags` (`kSecAccessControlUserPresence` などのフラグと一緒に) を含みます。詳細については [キーチェーンサービス (Keychain Services)](../../../knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057.md) を参照してください。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力にはコードベースで `LAContext.evaluatePolicy` および Keychain API が使用されている (または使用されていない) 場所を含む可能性があります。

### 評価

保護する価値のある機密データリソースごとに、以下が該当する場合、そのテストケースは不合格です。

* `LAContext.evaluatePolicy` が明示的に使用されている。
* [可能なフラグのいずれか](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags) でユーザーの存在を要求する `SecAccessControlCreateWithFlags` の呼び出しがない。
