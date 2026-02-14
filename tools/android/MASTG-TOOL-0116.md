---
title: blutter
platform: android
hosts: [linux, windows, macOS]
source: https://github.com/worawit/blutter
---

blutter は Flutter アプリケーションのリバースエンジニアリングをサポートするために作成されたオープンソースツールです。他の Flutter ツールとは異なり、blutter はデバイス上でアプリを実行する必要なく、libapp.so ファイルを静的に解析します。blutter は以下のことが可能です。

- Dart オブジェクトの抽出と解析
- 命令に対する注釈の提供 (適用可能な関数名やプールオブジェクトなど)
- さらなる解析のための Frida スクリプトの生成

このツールが機能するためには特定の環境が必要です。[セットアップ手順](https://github.com/worawit/blutter?tab=readme-ov-file#environment-setup) で説明されています。あるいは、[便利な Docker ファイルが PR にあります](https://github.com/worawit/blutter/pull/50)。

詳細については [B(l)utter – Reversing Flutter Applications presentation](https://www.youtube.com/watch?v=EU3KOzNkCdI) をご覧ください。
