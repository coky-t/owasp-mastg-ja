---
masvs_v1_id:
- MSTG-RESILIENCE-6
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: android
title: ランタイム完全性チェックのテスト (Testing Runtime Integrity Checks)
masvs_v1_levels:
- R
---

## 有効性評価

リバースエンジニアリングのファイルベースの検出がすべて無効になっていることを確認します。次に Xposed, Frida, Substrate を使用してコードを注入し、ネイティブフックと Java メソッドフックをインストールしてみます。アプリはメモリ内の「敵対的な」コードを検出して、それに応じて反応を示すはずです。

以下の技法でチェックのバイパスに取り組みます。

1. 完全性チェックにパッチを適用します。望まない動作を無効にするには、関連するバイトコードやネイティブコードを NOP 命令で上書きするだけです。
2. Frida か Xposed を使用して、検出に使用される API をフックし、偽の値を返します。
