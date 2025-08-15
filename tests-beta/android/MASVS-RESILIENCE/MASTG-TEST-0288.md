---
platform: android
title: ネイティブバイナリのデバッグシンボル (Debugging Symbols in Native Binaries)
alias: debugging-symbols-in-native-binaries
id: MASTG-TEST-0288
type: [static]
weakness: MASWE-0093
best-practices: []
profiles: [R]
---

## 概要

このテストはアプリのネイティブバイナリにデバッグシンボルを含むかどうかをチェックします。デバッグシンボルは、関数名、変数名、ソースファイル参照などの機密性の高い実装詳細を公開することで、リバースエンジニアリングや脆弱性解析において貴重な情報を提供できます。

## 手順

1. 静的解析 ([デバッグ情報とシンボルの取得 (Obtaining Debugging Information and Symbols)](../../../techniques/android/MASTG-TECH-0140.md)) を実行して、ネイティブバイナリ内に存在するデバッグ情報を取得します。

## 結果

出力にはネイティブバイナリ内のデバッグ情報のすべてのインスタンスを識別する可能性があります。

## 評価

実際のデバッグシンボルが正常に抽出されたかどうかも含め、ネイティブバイナリ内にデバッグ情報が存在する場合、そのテストは **不合格です**。
