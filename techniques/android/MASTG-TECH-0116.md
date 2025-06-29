---
title: APK 署名に関する情報の取得 (Obtaining Information about the APK Signature)
platform: android
---

## APK 署名の検証

[apksigner](../../tools/android/MASTG-TOOL-0123.md) を使用して APK 署名を検証できます。

```bash
$ apksigner verify --verbose example.apk
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
```

## 署名の追加情報

署名証明書のフィールド、ダイジェスト、鍵情報など署名に関する追加情報も [apksigner](../../tools/android/MASTG-TOOL-0123.md) で確認できます。

```bash
$ apksigner verify --print-certs --verbose example.apk
[...]
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 certificate SHA-256 digest: 1fc4de52d0daa33a9c0e3d67217a77c895b46266ef020fad0d48216a6ad6cb70
Signer #1 certificate SHA-1 digest: 1df329fda8317da4f17f99be83aa64da62af406b
Signer #1 certificate MD5 digest: 3dbdca9c1b56f6c85415b67957d15310
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 public key SHA-256 digest: 296b4e40a31de2dcfa2ed277ccf787db0a524db6fc5eacdcda5e50447b3b1a26
Signer #1 public key SHA-1 digest: 3e02ebf64f1bd4ca85732186b3774e9ccd60cb86
Signer #1 public key MD5 digest: 24afa3496f98c66343fc9c8a0a7ff5a2
```
