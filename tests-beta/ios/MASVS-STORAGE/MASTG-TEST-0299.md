---
platform: ios
title: >-
  プライベートストレージでのファイルのデータ保護クラス (Data Protection Classes for Files in Private
  Storage)
id: MASTG-TEST-0299
type:
  - dynamic
  - filesystem
prerequisites:
  - identify-sensitive-data
profiles:
  - L1
weakness: MASWE-0006
best-practices:
  - MASTG-BEST-0024
knowledge:
  - MASTG-KNOW-0082
  - MASTG-KNOW-0091
  - MASTG-KNOW-0108
---

# MASTG-TEST-0299 プライベートストレージでのファイルのデータ保護クラス (Data Protection Classes for Files in Private Storage)

### 概要

このテストは、通常のアプリ使用時にアプリのローカルストレージで作成または変更されたファイルのデータ保護クラスを取得します。目標はデバイスがロックされている際に機密データを含むファイルを保護するように適切なデータ保護クラスを割り当てられるようにすることです。

これはアプリのプライベートストレージ (サンドボックス) だけでなく、アプリとその拡張機能が使用する [アプリグループ共有コンテナ](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups) にも適用されます ([App Extension (App extensions)](https://github.com/coky-t/owasp-mastg-ja/blob/master/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082.md) を参照)。共有コンテナ内のファイルにも、プライベートストレージと同様にデータ保護を適用するためです。

デバイス / シミュレータがクリーンな状態 (以前のテストアーティファクトがない状態) であることを確認します。アプリを実行する際、一般的なワークフロー (認証、プロファイルの読み込み、メッセージング、キャッシュ、オフライン使用、暗号操作) をトリガーすることを確認します。

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。
3. [アプリデータディレクトリのアクセス (Accessing App Data Directories)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0059.md) を使用して、アプリのプライベートストレージ (サンドボックス) ディレクトリツリー (`/var/mobile/Containers/Data/Application/<UUID>/`) およびアプリグループ共有コンテナ (`/private/var/mobile/Containers/Shared/AppGroup/<UUID>/`) からデータ保護クラスを含むファイルのリストを取得します。

### 結果

出力には以下を含む可能性があります。

* 少なくともパスとデータ保護クラスを含む、アプリのプライベートストレージとアプリグループ共有コンテナ内のファイルのリスト。

### 評価

**機密データを含むファイル** が `NSFileProtectionNone` に設定されたデータ保護クラスを持つ場合、そのテストケースは不合格です。
