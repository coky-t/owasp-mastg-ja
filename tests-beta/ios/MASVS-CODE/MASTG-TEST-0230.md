---
title: 自動参照カウント (ARC) が有効でない (Automatic Reference Counting (ARC) not enabled)
platform: ios
id: MASTG-TEST-0230
type: [static, code]
weakness: MASWE-0116
profiles: [L2]
knowledge: [MASTG-KNOW-0061]
---

## 概要

このテストケースでは、iOS アプリで [ARC (Automatic Reference Counting)](../../../Document/0x04h-Testing-Code-Quality.md#automatic-reference-counting) が有効になっているかどうかをチェックします。ARC は Objective-C と Swift のコンパイラ機能で、メモリ管理を自動化し、メモリリークやその他の関連問題の可能性を減らします。ARC を有効にすることは、iOS アプリケーションのセキュリティと安定性を維持するために不可欠です。

- **Objective-C コード:** ARC は Clang の `-fobjc-arc` フラグでコンパイルすることで有効にできます。
- **Swift コード:** ARC はデフォルトで有効になります。
- **C/C++ コード:** ARC は Objective-C と Swift に特有のものであるため、適用できません。

ARC が有効な場合、バイナリには `objc_autorelease` や `objc_retainAutorelease` などのシンボルを含みます。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [共有ライブラリの取得 (Get Shared Libraries)](../../../techniques/ios/MASTG-TECH-0082.md) を使用して、すべての共有ライブラリを特定します。
3. [コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler-Provided Security Features)](../../../techniques/ios/MASTG-TECH-0118.md) をメインバイナリと各共有ライブラリに使用して、`objc_autorelease` や `objc_retainAutorelease` などの ARC シンボルを探します。

## 結果

出力にはメインバイナリと各共有ライブラリのシンボルのリストを含む可能性があります。

## 評価

Objective-C や Swift を含むバイナリやライブラリに ARC 関連のシンボルがない場合、そのテストケースは不合格です。対応する ARC シンボルがない `_objc_msgSend` (Objective-C) や `_swift_allocObject` (Swift) などのシンボルが存在する場合、ARC が有効になっていない可能性があることを示しています。

> [!NOTE]
> これらのシンボルのチェックは、ARC がアプリのどこかで有効になっていることを示しているだけです。ARC は一般的にバイナリ全体に対して有効または無効になりますが、アプリケーションの一部だけが保護されるような特殊なケースもあります。たとえば、アプリ開発者が ARC を有効にしたライブラリを静的リンクする際に、アプリケーション全体としては無効にしているような場合です。
> 
> 特定のセキュリティ上重要なメソッドが十分に保護されているかどうかを確認したい場合、各メソッドをリバースエンジニアして ARC を手作業でチェックするか、開発者にソースコードを要求する必要があります。
