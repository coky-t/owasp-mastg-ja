---
platform: android
title:  複数の目的で使用される非対称鍵ペアへの参照 (References to Asymmetric Key Pairs Used For Multiple Purposes)
id: MASTG-TEST-0307
type: [static]
weakness: MASWE-0012
profiles: [L2]
---

## 概要

[NIST SP 800-57 part 1 revision 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) (参考: [IPA 翻訳版](https://www.ipa.go.jp/security/crypto/gmcbt80000005u4j-att/SP800-57part1rev5.pdf)) の "5.2 Key Usage" セクションによれば、暗号鍵には特定の目的 (暗号化、完全性認証、鍵ラッピング、ランダムビット生成、デジタル署名など) が割り当てられ、その目的にのみ使用される必要があります。たとえば、暗号用の鍵は署名に使用すべきではありません。

Android では、非対称鍵は一般的に [`android.security.keystore.KeyGenParameterSpec`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec) を通じて構成された [`java.security.KeyPairGenerator`](https://developer.android.com/reference/java/security/KeyPairGenerator) で生成されます。

[`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder) コンストラクタは `keystoreAlias` と `purposes` の二つの引数を持ちます。これは [`android.security.keystore.KeyProperties`](https://developer.android.com/reference/android/security/keystore/KeyProperties) に記載されている許可された操作のビットマスクです。

- [`KeyProperties.PURPOSE_SIGN`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_SIGN)
- [`KeyProperties.PURPOSE_VERIFY`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_VERIFY)
- [`KeyProperties.PURPOSE_ENCRYPT`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_ENCRYPT)
- [`KeyProperties.PURPOSE_DECRYPT`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_DECRYPT)
- [`KeyProperties.PURPOSE_WRAP_KEY`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_WRAP_KEY)

## 手順

1. アプリに対して [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を実行して、非対称鍵の鍵生成コードを探します。

## 結果

出力には `KeyGenParameterSpec.Builder` を使用して非対称鍵が作成される場所と関連する目的のリストを含む可能性があります。

## 評価

複数のロール (目的のグループ) で使用されている鍵を見つけた場合、そのテストケースは不合格です。

出力を使用して、各鍵 (または鍵ペア) が以下の操作グループの **一つ** のみに制限されていることを確認します。

- 暗号化/復号化  (`PURPOSE_ENCRYPT` / `PURPOSE_DECRYPT`)
- 署名/検証 (`PURPOSE_SIGN` / `PURPOSE_VERIFY`)
- 鍵ラッピング (`PURPOSE_WRAP_KEY`)

アプリをリバースエンジニアリングすると、税術の目的定数が一つの整数値に結合されていることがわかります。たとえば、`15` の目的値は四つのすべての目的を結合していますが、これは許容されません。

(`PURPOSE_ENCRYPT` = 1) | (`PURPOSE_DECRYPT` = 2) | (`PURPOSE_SIGN` = 4) | (`PURPOSE_VERIFY` = 8) = 15

許容される目的の組み合わせは以下のとおりです。

- (`PURPOSE_ENCRYPT` = 1) = 1
- (`PURPOSE_DECRYPT` = 2) = 2
- (`PURPOSE_SIGN` = 4) = 4
- (`PURPOSE_VERIFY` = 8) = 8
- `PURPOSE_WRAP_KEY` = 32
- (`PURPOSE_ENCRYPT` = 1) | (`PURPOSE_DECRYPT` = 2) = 3
- (`PURPOSE_SIGN` = 4) | (`PURPOSE_VERIFY` = 8) = 12
