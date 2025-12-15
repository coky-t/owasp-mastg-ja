---
platform: ios
title: プライベートストレージでのファイルのデータ保護クラス (Data Protection Classes for Files in Private Storage)
id: MASTG-TEST-0299
type: [dynamic, filesystem]
prerequisites:
- identify-sensitive-data
profiles: [L1]
weakness: MASWE-0006
best-practices: [MASTG-BEST-0024]
knowledge: [MASTG-KNOW-0091, MASTG-KNOW-0108]
---

## 概要

このテストは、通常のアプリ使用時にアプリのプライベートストレージで作成または変更されたファイルのデータ保護クラスを取得します。目標はデバイスがロックされている際に機密データを含むファイルを保護するように適切なデータ保護クラスを割り当てられるようにすることです。

## 手順

1. デバイス / シミュレータがクリーンな状態 (以前のテストアーティファクトがない状態) であることを確認します。実行中である場合はアプリを終了します。
2. アプリを起動して実行し、一般的なワークフロー (認証、プロファイルの読み込み、メッセージング、キャッシュ、オフライン使用、暗号操作) をトリガーします。
3. アプリのプライベートストレージ (サンドボックス) ディレクトリツリー (`/var/mobile/Containers/Data/Application/<UUID>/`) からデータ保護クラス ([アプリデータディレクトリのアクセス (Accessing App Data Directories)](../../../techniques/ios/MASTG-TECH-0059.md)) を含むファイルのリストを取得します。

## 結果

出力には以下を含む可能性があります。

- 少なくともパスとデータ保護クラスを含む、プライベートストレージ内のファイルのリスト。

## 評価

**機密データを含むファイル** が `NSFileProtectionNone` に設定されたデータ保護クラスを持つ場合、そのテストケースは不合格です。
