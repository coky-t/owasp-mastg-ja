---
platform: ios
title: >-
  プライベートストレージファイル内の暗号化されていない機密データ (Sensitive Data Unencrypted in Private Storage
  Files)
id: MASTG-TEST-0302
type:
  - dynamic
  - filesystem
prerequisites:
  - identify-sensitive-data
profiles:
  - L2
weakness: MASWE-0006
best-practices:
  - MASTG-BEST-0024
knowledge:
  - MASTG-KNOW-0108
---

# MASTG-TEST-0302 プライベートストレージファイル内の暗号化されていない機密データ (Sensitive Data Unencrypted in Private Storage Files)

### 概要

このテストは [プライベートストレージに暗号化されていないデータを保存するための API の実行時使用 (Runtime Use of APIs for Storing Unencrypted Data in Private Storage)](MASTG-TEST-0301.md) を補完するように設計されています。実行中の API を監視する代わりに、アプリを実行する前後に取得したスナップショットを比較することで、アプリのプライベートストレージの差分解析を実行します。また、セッション中に作成または変更されたキーチェーンアイテムも列挙します。

目標は、新規または変更されたファイルを識別し、それらがプレーンテキストまたは簡単にエンコードされた形式の機密データを含むかどうかを判断し、機密データまたはファイル暗号化に使用される鍵を含む可能性のある新しいキーチェーンエントリを識別することです。

デバイス / シミュレータがクリーンな状態 (以前のテストアーティファクトがない状態) であることを確認します。アプリを実行する際、一般的なワークフロー (認証、プロファイルの読み込み、メッセージング、キャッシュ、オフライン使用、暗号操作) をトリガーすることを確認します。

### 手順

1. [アプリのインストール (Installing Apps)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0056.md) を使用して、アプリをインストールします。
2. [アプリデータディレクトリのアクセス (Accessing App Data Directories)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0059.md) を使用して、アプリのプライベートストレージ (サンドボックス) ディレクトリツリーのファイルのベースラインリストを取得します。
3. [キーチェーンデータのダンプ (Dumping KeyChain Data)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0061.md) を使用して、キーチェーンアイテムの最初のスナップショットを取得します。必要に応じて、属性 (アクセス可能なクラス、アクセス制御フラグなど) を記録します。
4. アプリを徹底的に動かして、できるだけ多くのフローをトリガーし、可能な限り機密データを入力します。
5. [アプリデータディレクトリのアクセス (Accessing App Data Directories)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0059.md) を使用して、ファイルのリストを再び取得します。
6. 二つのプライベートストレージスナップショットを比較し、新規、削除、変更されたファイルを識別します。変更されたファイルについては、コンテンツの変更が機密の値を含む可能性があるかどうかを判断します。
7. [キーチェーンデータのダンプ (Dumping KeyChain Data)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0061.md) を使用して、キーチェーンアイテムの二つ目のスナップショットを取得します。
8. [キーチェーンデータのダンプ (Dumping KeyChain Data)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0061.md) を使用して、二つのキーチェーンスナップショットを比較し、新規、削除、変更されたアイテムを識別します。

### 結果

出力には以下を含む可能性があります。

* 新規または変更されたファイルと、パス、サイズ、ハッシュ、推定タイプ、エンコーディング/暗号化ステータス (プレーンテキスト / エンコード済み / 暗号化済み / 不明)、のリスト。
* 新規または変更されたキーチェーンエントリのリスト。

### 評価

機密データがプレーンテキストで現れたり、新規または変更されたファイルに簡単にエンコードされている場合、そのテストケースは不合格です。

ファイルとキーチェーンエントリのリストに機密データがないか検査します。Base64 エンコーディング、16 進数表現、URL エンコーディング、エスケープシーケンス、バイナリ plist ファイル、zip などの圧縮アーカイブ、ワイド文字、XOR などの一般的なデータ難読化手法などの手法を使用してエンコードされたデータの識別とデコードを試みます。また、tar や zip などの圧縮ファイルを識別し展開することも検討します。これらの手法は機密データを難読化しますが保護するものではありません。
