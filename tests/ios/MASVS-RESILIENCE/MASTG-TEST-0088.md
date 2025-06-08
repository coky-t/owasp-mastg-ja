---
masvs_v1_id:
- MSTG-RESILIENCE-1
masvs_v2_id:
- MASVS-RESILIENCE-1
platform: ios
title: 脱獄検出のテスト (Testing Jailbreak Detection)
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0240, MASTG-TEST-0241]
deprecation_note: New version available in MASTG V2
---

## 概要

脱獄検出をテストするには、脱獄済みデバイスにアプリをインストールします。

**アプリを起動して、何が起こるか確認する:**

脱獄検出を実装している場合、以下のいずれかに気づくかもしれません。

- アプリがクラッシュし、何の通知もなくすぐに終了します。
- ポップアップウィンドウはアプリが脱獄済みデバイス上では実行できないことを示します。

クラッシュは脱獄検出を示すものであるかもしれませんが、アプリは他の理由 (たとえば、バグがあるかもしれません) でクラッシュしている可能性があることに注意します。特に試作バージョンをテストしているのであれば、まず脱獄していないデバイスでアプリをテストすることをお勧めします。

**アプリを起動して、自動ツールを使用して脱獄検出をバイパスしてみる:**

脱獄検出を実装している場合、ツールの出力でその指標をみることができるかもしれません。["自動化された脱獄検出のバイパス"](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#automated-jailbreak-detection-bypass) のセクションを参照してください。

**アプリをリバースエンジニアする:**

アプリはあなたがこれまでに使用した自動ツールで実装されていない技法を使用しているかもしれません。その場合、アプリをリバースエンジニアして証拠を見つけなければなりません。["手動の脱獄検出のバイパス"](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#manual-jailbreak-detection-bypass) のセクションを参照してください。
