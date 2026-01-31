---
title: Android での静的解析 (Static Analysis on Android)
platform: android
---

静的解析はモバイルアプリケーションのソースコードを実行せずに調査及び評価するための技法です。この手法は潜在的なセキュリティ脆弱性、コーディングエラー、コンプライアンス問題を特定するのに役立ちます。静的解析ツールはコードベース全体を自動的にスキャンでき、開発者やセキュリティ監査担当者にとって貴重な資産となります。

静的解析ツールの良い例としては grep と [semgrep](../../tools/generic/MASTG-TOOL-0110.md) の二つがあります。しかし、他にも多くのツールが利用可能であり、ニーズに最適なものを選択する必要があります。

## 例: Android アプリの Manifest 解析に grep を使用する

静的解析のシンプルかつ効果的な使用は `grep` コマンドラインを使用して Android アプリの `AndroidManifest.xml` ファイルを検査することです。たとえば、以下の `grep` コマンドで最小 SDK バージョン (アプリがサポートする Android の最低バージョンを示す) を抽出できます。

```bash
grep 'android:minSdkVersion' AndroidManifest.xml
```

このコマンドはマニフェストファイル内の `android:minSdkVersion` 属性を検索します。古いバージョンの Android は最新のセキュリティ機能や修正を含まない可能性があるため、より高い `minSdkVersion` を確保することでセキュリティリスクを軽減できます。

## 例: エントロピーが不十分なシードを特定するために semgrep を使用する

semgrep はコードのパターンマッチングに使用できるより高度なツールです。セキュリティ脆弱性につながる可能性のある複雑なコーディングパターンを特定するのに特に役立ちます。たとえば、`SecureRandom` クラスで決定論的なシードが使用されているインスタンス (ランダム性ひいてはセキュリティを損なう可能性がある) を見つけるには、以下のような semgrep ルールを使用できます。

```yaml
rules:
  - id: insecure-securerandom-seed
    patterns:
      - pattern: new SecureRandom($SEED)
      - pattern-not: $SEED = null
    message: "Using a deterministic seed with SecureRandom. Consider using a more secure seed."
    languages: [java]
    severity: WARNING
```

このルールは、シードが null (安全なランダムシードを意味する) 場合を除いて、コード内で `SecureRandom` が特定のシードで初期化されているすべてのインスタンスをフラグ付けします。
