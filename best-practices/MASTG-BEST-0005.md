---
title: 安全な暗号モードを使用する (Use Secure Encryption Modes)
alias: use-secure-encryption-modes
id: MASTG-BEST-0005
platform: android
---

安全でない暗号モードを、機密性、完全性、真正性を提供する認証された暗号モードである [AES-GCM または AES-CCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) などの安全なブロック暗号モードに置き換えます。

CBC は ECB よりも安全ですが、不適切な実装、特に間違ったパディングにより、パディングオラクル攻撃などの脆弱性につながる可能性があるため、避けることをお勧めします。

Android で安全な暗号モードを実装するための包括的なガイダンスについては、公式の Android 開発者ドキュメント [暗号機能](https://developer.android.com/privacy-and-security/cryptography) を参照してください。
