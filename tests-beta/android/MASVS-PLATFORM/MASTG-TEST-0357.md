---
title: ファイルベースのコンテンツプロバイダのオーバーシェアリングへの参照 (References to Oversharing of File-Based Content Providers)
platform: android
id: MASTG-TEST-0357
weakness: MASWE-0018
type: [static, config, code, manual]
best-practices: [MASTG-BEST-0049]
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0020, MASTG-KNOW-0117]
---

## 概要

アプリがアクセス制限を適用することなく、Android コンテンツプロバイダをエクスポートする場合、外部の呼び出し元が `content://` URI を通じてプライベートファイルをオープンできる可能性があります。このテストは、エクスポートされたプロバイダが、必要なパーミッションを持たない呼び出し元に、機密性の高い保存データを開示しているかどうかをチェックします。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [ファイルベースのコンテンツプロバイダの使用の検証 (Verify Usage of File-Based Content Providers)](../../../techniques/android/MASTG-TECH-0159.md) を使用して、エクスポートされたファイルベースのコンテンツプロバイダを特定し、そのパス設定を調査します。
3. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、関連する API を探します。

## 結果

出力には、パス設定を持つエクスポートされたファイルベースのコンテンツプロバイダのリストと、プロバイダの背後でファイルアクセスが発生するコード箇所のリストを含む可能性があります。

## 評価

アプリが `FileProvider` をエクスポートしており、そのプロバイダのパス設定が、意図した共有ディレクトリの外部へのアクセスを可能にしている場合 (例: `<root-path>`, `path="/"`, `path="."`, `path=""` など)、そのテストケースは不合格です。

**さらなるバリデーションが必要となります:**

[逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md) を使用して、報告された各コード箇所を検査し、その露出がセキュリティ関連であるかどうかを判断します。

- `FileProvider.getUriForFile()` が、攻撃者が制御する入力 (URI クエリパラメータやユーザー入力に由来する値など) とともに呼び出されているかどうかを判断します。
- Android マニフェストで `android:permission` と、`dangerous` や `signature` などの適切な保護レベルを使用して、プロバイダが適切なアクセス制御を適用しているかどうかを判断します。
