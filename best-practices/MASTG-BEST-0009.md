---
title: 安全な暗号アルゴリズムを使用する (Use Secure Encryption Algorithms)
alias: use-secure-encryption-algorithms
id: MASTG-BEST-0009
platform: android
---

安全でない暗号アルゴリズムを AES-256 (GCM モードが望ましい) や ChaCha20 などの安全なものに置き換えます。

Android で安全な暗号を実装するための包括的なガイダンスについては、公式 Android Developers ウェブサイトの ["暗号機能"](https://developer.android.com/privacy-and-security/cryptography) および ["Broken or risky cryptographic algorithm"](https://developer.android.com/privacy-and-security/risks/broken-cryptographic-algorithm#weak-or-broken-cryptographic-encryption-functions-use-strong-cryptographic-algorithms-in-encryption-1B2M2Y8Asg) のドキュメントを参照してください。
