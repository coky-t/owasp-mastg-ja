---
platform: ios
title: 未宣言の既知のトラッキングドメイン (Undeclared Known Tracking Domains)
id: MASTG-TEST-0281
type: [static, dynamic]
weakness: MASWE-0108
profiles: [P]
---

## 概要

このテストは、アプリが [プライバシーマニフェスト](https://developer.apple.com/documentation/bundleresources/privacy_manifest_files) で宣言されていない既知のトラッキングドメインと通信しているかどうかを識別します。これには、[DuckDuckGo iOS Trackers](https://github.com/duckduckgo/tracker-blocklists/blob/main/web/v5/ios-tds.json) などのソースにリストされているドメインを含み、広告ネットワーク、分析プロバイダ、ユーザープロファイリングサービスに関連付けられています。

## 手順

1. アプリのプライバシーマニフェスト (メインバイナリと依存関係の両方) を取得します。
2. [semgrep](../../../tools/generic/MASTG-TOOL-0110.md) を使用してトラッキングドメイン名を静的に検索するか、[mitmproxy](../../../tools/network/MASTG-TOOL-0097.md) を使用してネットワークリスエストを動的に傍受します。

## 結果

出力には以下を含む可能性があります。

- アプリがやり取りした、またはやり取りする可能性のあるトラッキングドメインのリスト。
- アプリのすべてのプライバシーマニフェスト (ファイル形式)。

## 評価

アプリがプライバシーマニフェストで宣言されていないトラッキングドメインと通信する場合、そのテストケースは不合格です。
