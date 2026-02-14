---
platform: ios
title: イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)
id: MASTG-TEST-0266
apis: [LAContext.evaluatePolicy]
type: [static]
weakness: MASWE-0044
profiles: [L2]
knowledge: [MASTG-KNOW-0056]
---

## 概要

このテストでは、Keychain API を使用したりユーザーの存在を要求するのではなく、アクセス制御に LocalAuthentication API のみに依存して、ユーザー認証によって保護する必要がある機密リソース (トークン、キーなど) にアプリが安全でない方法でアクセスしていないかどうかをチェックします。

**LocalAuthentication** API (例: `LAContext`) はユーザー認証 (Touch ID, Face ID, デバイスパスコード) を提供し、成功または失敗の結果のみを返します。ただし、シークレットを安全に保存したり、セキュリティを強化することは **できません**。そのため、ロジック操作の影響を受けやすくなります (例: `if authenticated { ... }` チェックのバイパスなど)。

対照的に、**Keychain** API は機密データを安全に保存し、`kSecAccessControl` フラグを介してアクセス制御ポリシー (例: 生体認証などのユーザーの存在を要求するなど) を設定できます。これは、認証が単なる一回限りのブール値ではなく、**安全なデータ取得パス (プロセス外)** の一部であることを確保するため、認証のバイパスが著しく難しくなります。

## 手順

1. [radare2 (iOS)](../../../tools/ios/MASTG-TOOL-0073.md) で静的解析スキャンを実行し、`LAContext.evaluatePolicy` の使用を検出します。
2. [radare2 (iOS)](../../../tools/ios/MASTG-TOOL-0073.md) で静的解析スキャンを実行し、Keychain API、特に `SecAccessControlCreateWithFlags` (`SecItemAdd` や `SecItemCopyMatching` などの他の API と一緒に使用する必要がある) の使用を検出します。

## 結果

解析ではコードベースで `LAContext.evaluatePolicy` および Keychain API が使用されている (または使用されていない) 場所を出力する可能性があります。

## 評価

保護する価値のある機密データリソースごとに、以下が該当する場合、そのテストは不合格です。

- `LAContext.evaluatePolicy` が明示的に使用されている。
- [可能なフラグのいずれか](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags) でユーザーの存在を要求する `SecAccessControlCreateWithFlags` の呼び出しがない。
