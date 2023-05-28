---
masvs_v1_id:
- MSTG-CRYPTO-1
- MSTG-CRYPTO-5
masvs_v2_id:
- MASVS-CRYPTO-2
platform: ios
title: 鍵管理のテスト (Testing Key Management)
masvs_v1_levels:
- L1
- L2
---

## 概要

## 静的解析

探すべきさまざまなキーワードがあります。鍵がどのように格納されているかを最もよく確認できるキーワードについては「暗号標準アルゴリズムの構成の検証」セクションの概要と静的解析で言及されているライブラリをチェックします。

常に以下のことを確認します。

- 鍵がデバイス間で同期されていないこと (リスクの高いデータを保護するために使用される場合) 。
- 鍵が追加の保護なしで保存されていないこと。
- 鍵がハードコードされていないこと。
- 鍵がデバイスの固定機能から導出されたものではないこと。
- 鍵が低レベル言語 (C/C++ など) の使用により隠されていないこと。
- 鍵が安全でない場所からインポートされていないこと。

[よくある暗号化設定の問題のリスト](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues) も確認してください。

静的解析に関する推奨事項のほとんどは「iOS のデータストレージのテスト」の章にすでに記載されています。次に、以下のページで読むことができます。

- [Apple 開発者ドキュメント: 証明書と鍵](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys "Certificates and keys")
- [Apple 開発者ドキュメント: 新しい鍵の生成](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys "Generating new keys")
- [Apple 開発者ドキュメント: 鍵生成属性](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/key_generation_attributes "Key Generation attributes")

## 動的解析

暗号メソッドをフックし、使用している鍵を解析します。暗号操作が実行される際にファイルシステムへのアクセスを監視し、鍵マテリアルが書き込み先や読み取り元を評価します。
