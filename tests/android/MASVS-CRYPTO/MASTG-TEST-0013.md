---
masvs_v1_id:
- MSTG-CRYPTO-1
masvs_v2_id:
- MASVS-CRYPTO-1
platform: android
title: 対称暗号のテスト (Testing Symmetric Cryptography)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: ['MASTG-TEST-0212', 'MASTG-TEST-0221']
deprecation_reason: New version available in MASTG V2
---

## 概要

## 静的解析

コード内の対称鍵暗号のすべてのインスタンスを特定し、対称鍵をロードまたは提供するメカニズムを探します。以下のものを探すことができます。

- 対称アルゴリズム (`DES`, `AES`, など)
- 鍵生成器の仕様 (`KeyGenParameterSpec`, `KeyPairGeneratorSpec`, `KeyPairGenerator`, `KeyGenerator`, `KeyProperties`, など)
- `java.security.*`, `javax.crypto.*`, `android.security.*`, `android.security.keystore.*` をインポートしているクラス

[よくある暗号設定の問題のリスト](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues) も確認してください。

特定された各インスタンスについて、使用されている対称鍵について以下を検証します。

- アプリケーションリソースの一部ではないこと
- 既知の値から導出できないこと
- コード内にハードコードされていないこと

ハードコードされた各対称鍵について、セキュリティ上重要なコンテキストで唯一の暗号化方法として使用されていないことを検証します。

例として、ハードコードされた暗号鍵の使用箇所を見つける方法を説明します。まず、アプリを逆アセンブルおよび逆コンパイル ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md)) して Java コードを入手します。たとえば、 [jadx](../../../tools/android/MASTG-TOOL-0018.md) を使用します。

ここで `SecretKeySpec` クラスが使われているファイルを検索します。例えば、再帰的に grep するか、jadx 検索機能を使用するだけです。

```bash
grep -r "SecretKeySpec"
```

これにより `SecretKeySpec` クラスを使用しているすべてのクラスを返します。次にこれらのファイルを調べて、鍵マテリアルを渡すために使用される変数を追跡します。以下の図は出荷可能アプリケーションでこの評価を実行した結果を示しています。静的な暗号鍵が使用されていることがはっきりとわかります。この鍵はハードコードされており、静的なバイト配列 `Encrypt.keyBytes` に初期化されます。

<img src="../../../Document/Images/Chapters/0x5e/static_encryption_key.png" width="600px"/>

## 動的解析

暗号メソッドで [メソッドトレース (Method Tracing)](../../../techniques/android/MASTG-TECH-0033.md) を使用して、使用されている鍵などの入出力値を判別できます。暗号操作の実行中にファイルシステムへのアクセスを監視し、鍵マテリアルの書き込み先または読み取り元を評価します。たとえば、[RMS Runtime Mobile Security](../../../tools/generic/MASTG-TOOL-0037.md) の [API monitor](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#8-api-monitor---android-only) を使用してファイルシステムを監視します。
