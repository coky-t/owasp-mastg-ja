---
masvs_v1_id:
- MSTG-RESILIENCE-9
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: ios
title: 難読化のテスト (Testing Obfuscation)
masvs_v1_levels:
- R
---

## 概要

IPA 内の Mach-O と "Frameworks" ディレクトリにあるインクルードされたライブラリファイル (.dylib や .framework ファイル) を逆アセンブルし、静的解析を実行してみます。少なくとも、アプリのコア機能 (つまり、難読化することを意図した機能) は容易に識別できないはずです。以下を検証します。

- クラス名、メソッド名、変数名など、意味のある識別子が破棄されていること。
- 文字列リソースとバイナリ内の文字列が暗号化されていること。
- 保護される機能に関連するコードとデータが暗号化、パック化、あるいはその他の方法で隠されていること。

より詳細な評価を行うには、関連する脅威と使用されている難読化手法を詳細に理解する必要があります。