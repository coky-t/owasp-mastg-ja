---
platform: ios
title: コード内の脱獄検出 (Jailbreak Detection in Code)
id: MASTG-TEST-0240
type:
  - static
  - code
weakness: MASWE-0097
false_negative_prone: true
profiles:
  - R
knowledge:
  - MASTG-KNOW-0084
---

# MASTG-TEST-0240 コード内の脱獄検出 (Jailbreak Detection in Code)

### 概要

このテストではモバイルアプリが、それが実行されている iOS デバイスが脱獄されているかどうかを検出できるかどうかを検証します。これはアプリバイナリを静的に解析して、一般的な脱獄検出チェック ([脱獄検出 (Jailbreak Detection)](../../../knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084.md)) を探すことによって行います。たとえば、アプリはサードパーティアプリストア (Sileo, Zebra など) の存在や、脱獄済みデバイスを示す特定のファイルやディレクトリの存在をチェックすることがあります。

静的解析の限界を考慮すべきです。アプリは、使用されているツールでは検出されない、より洗練された脱獄検出技法を使用する可能性があります。そのような場合、脱獄検出チェックを識別するには、慎重な手作業によるリバースエンジニアリングと難読化解除が必要になります。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [iOS での静的解析 (Static Analysis on iOS)](../../../techniques/ios/MASTG-TECH-0066.md) を使用して、アプリバイナリ内の関連する API を探します。

### 結果

出力にはアプリバイナリの一般的な脱獄検出チェックのインスタンスを含む可能性があります。

### 評価

脱獄検出が実装されていない場合、テストケースは不合格です。ただし、このテストは網羅的ではなく、すべての脱獄検出チェックを検出できない可能性があることに注意してください。より洗練された脱獄検出チェックを識別するには、手作業によるリバースエンジニアリングと難読化解除が必要になるかもしれません。
