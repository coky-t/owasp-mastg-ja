---
platform: ios
title: 古いコード署名フォーマットの使用 (Usage of Outdated Code Signature Format)
id: MASTG-TEST-0220
type: [static]
weakness: MASWE-0104
---

## 概要

iOS では、コード署名はアプリのバイナリの完全性と信頼性を検証し、認可されていない変更を防止し、アプリがオペレーティングシステムによって信頼されていることを確保します。Apple は [コード署名フォーマット](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format) を定期的に更新し、暗号強度を高め、改竄に対する保護を強化しています。

古いコード署名フォーマットを使用すると、アプリがセキュリティリスクにさらされる可能性があります。古いフォーマットは現在の暗号標準をサポートしておらず、操作に対してより脆弱である可能性があるためです。最新のコード署名フォーマットを採用すると、アプリの完全性を維持し、iOS の最新のセキュリティ機能との互換性を確保できます。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) の説明に従ってパッケージを抽出します。
2. [コード署名フォーマットバージョンの取得 (Obtaining the Code Signature Format Version)](../../../techniques/ios/MASTG-TECH-0112.md) の説明に従ってコード署名フォーマットのバージョンを取得します。

## 結果

出力にはコード署名フォーマットのバージョンを含む可能性があります。

## 評価

バージョンが [推奨バージョン](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format "Apple Developer") より低い場合、テストは不合格です。

アプリが [最新のコード署名フォーマット](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format "Apple Developer") を使用していることを確認します。署名証明書フォーマットは [コード署名フォーマットバージョンの取得 (Obtaining the Code Signature Format Version)](../../../techniques/ios/MASTG-TECH-0112.md) で取得できます。これによる、アプリの完全性が最新の暗号標準に従って保護され、アプリバイナリの改竄を保護し、変更されていないコピーがユーザーに配布されるようになります。
