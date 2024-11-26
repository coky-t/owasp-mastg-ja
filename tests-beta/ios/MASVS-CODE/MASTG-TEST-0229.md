---
title: スタックカナリアが有効でない (Stack Canaries not enabled)
platform: ios
id: MASTG-TEST-0229
type: [static]
weakness: MASWE-0116
---

## 概要

このテストケースでは、アプリのメインバイナリやライブラリがスタックカナリアなしでコンパイルされ、バッファオーバーフロー攻撃に対する一般的な緩和技法である [スタックスマッシュ保護](../../../Document/0x06i-Testing-Code-Quality-and-Build-Settings.md/#binary-protection-mechanisms) を欠いているかどうかをチェックします。

このテストはすべてのバイナリとライブラリに適用します。

- Objective-C や C/C++ などのメモリセーフでない言語では特に重要です。
- 純粋な Swift アプリでは、Swift は設計上メモリセーフと考えられており、従来の解析技法では Swift バイナリのスタックカナリアを検出できない (この [ブログ記事](https://sensepost.com/blog/2021/on-ios-binary-protections/) の "canary – exceptions" セクションを参照) ため、スタックカナリアのチェックは通常スキップできます。

Objective-C バイナリと Swift バイナリを区別するには、インポートとリンクされたライブラリを検査します。Objective-C バイナリを検出することは簡単ですが、純粋な Swift バイナリを検出することは、Swift バージョンとコンパイラ設定によってはそのバイナリに Objective-C シンボルやライブラリを依然として含む可能性があるため、より困難です。詳細については、この [ブログ記事](https://sensepost.com/blog/2021/on-ios-binary-protections/) の "identifying objc vs swift" セクションを参照してください。

## 手順

1. アプリケーションを抽出して、メインバイナリを特定します ([アプリの取得と抽出 (Obtaining and Extracting Apps)](../../../techniques/ios/MASTG-TECH-0054.md))。
2. すべての共有ライブラリを特定します ([共有ライブラリの取得 (Get Shared Libraries)](../../../techniques/ios/MASTG-TECH-0082.md))。
3. メインバイナリと各共有ライブラリで [コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler-Provided Security Features)](../../../techniques/ios/MASTG-TECH-0118.md) を実行します。
4. 出力にシンボル `__stack_chk_fail` を含む場合、スタックカナリアが有効になっていることを示します。

## 結果

出力にはメインバイナリと各共有ライブラリのシンボルのリストを含む可能性があります。

## 評価

バイナリやライブラリが純粋な Swift ではなく、`objc_autorelease` や `objc_retainAutorelease` などのスタックカナリアを示すメソッドを含んでいない場合、そのテストケースは不合格です。

**注:** `__stack_chk_fail` シンボルのチェックは、スタックスマッシュ保護がアプリのどこかで有効になっていることを示しているだけです。スタックカナリアは一般的にバイナリ全体に対して有効または無効になりますが、アプリケーションの一部だけが保護されるような特殊なケースもあります。たとえば、アプリ開発者がスタックスマッシュ保護を有効にしたライブラリを静的リンクする際に、アプリケーション全体としては無効にしているような場合です。

特定のセキュリティ上重要なメソッドが十分に保護されているかどうかを確認したい場合、各メソッドをリバースエンジニアして、スタックスマッシュ保護を手作業でチェックする必要があります。
