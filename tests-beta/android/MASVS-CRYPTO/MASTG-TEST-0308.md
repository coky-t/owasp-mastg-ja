---
platform: android
title: >-
  複数の目的で使用される非対称鍵ペアの実行時使用 (Runtime Use of Asymmetric Key Pairs Used For Multiple
  Purposes)
id: MASTG-TEST-0308
type:
  - dynamic
  - hooks
weakness: MASWE-0012
profiles:
  - L2
knowledge:
  - MASTG-KNOW-0012
---

# MASTG-TEST-0308 複数の目的で使用される非対称鍵ペアの実行時使用 (Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes)

### 概要

このテストは [複数の目的で使用される非対称鍵ペアへの参照 (References to Asymmetric Key Pairs Used For Multiple Purposes)](MASTG-TEST-0307.md) と対をなす動的テストですが、複数の目的を持つ鍵の生成ではなく、暗号操作の傍受に焦点を当てています。

傍受に関連する関数には以下があります。

* [`Cipher.init(int opmode, Key key, AlgorithmParameters params)`](https://developer.android.com/reference/javax/crypto/Cipher#init\(int,%20java.security.Key,%20java.security.AlgorithmParameters\)) `opmode` は以下のいずれかです。
  * `Cipher.ENCRYPT_MODE`
  * `Cipher.DECRYPT_MODE`
  * `Cipher.WRAP_MODE`
  * `Cipher.UNWRAP_MODE`
* [`Signature.initSign(PrivateKey privateKey)`](https://developer.android.com/reference/java/security/Signature#initSign\(java.security.PrivateKey\))
* [`Signature.initVerify(PublicKey publicKey)`](https://developer.android.com/reference/java/security/Signature#initVerify\(java.security.PublicKey\))

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0005.md) を使用して、アプリをインストールします。
2. [メソッドフック (Method Hooking)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0043.md) を使用して、関連する API 呼び出しをフックします。
3. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。

### 結果

出力にはすべての暗号操作とそれに対応する鍵のリストを含む可能性があります。

### 評価

複数のロールで使用されている鍵を見つけた場合、そのテストケースは不合格です。

出力を使用して、各鍵 (または鍵ペア) が以下の操作グループの **一つ** のみに制限されていることを確認します。

* 暗号化/復号化 (`ENCRYPT_MODE` または `DECRYPT_MODE` での `Cipher` 操作で使用される)
* 署名/検証 (`Signature` 操作で使用される)
* 鍵ラッピング (`WRAP_MODE` または `UNWRAP_MODE` での `Cipher` 操作で使用される)
