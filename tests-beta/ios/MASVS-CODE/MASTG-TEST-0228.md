---
title: 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) not Enabled)
platform: ios
id: MASTG-TEST-0228
type:
  - static
  - code
weakness: MASWE-0116
profiles:
  - L2
knowledge:
  - MASTG-KNOW-0061
---

# MASTG-TEST-0228 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) not Enabled)

### 概要

[PIE (Position Independent Executables)](../../../Document/0x04h-Testing-Code-Quality.md#position-independent-code) は、実行可能ファイルをランダムなメモリアドレスにロードできるようにすることでセキュリティを強化し、特定の種類の攻撃を緩和するように設計されています。

iOS アプリケーションの Mach-O ファイルフォーマットの場合:

* PIE は `MH_EXECUTE` ファイルタイプの実行可能ファイルに適用できます。これは基本的にメインアプリバイナリ (例: `YourApp.app/YourApp`) を意味します。
* `MH_DYLIB` ファイルタイプの共有ライブラリ (dylib および framework) は本質的に位置独立であるため、`MH_PIE` フラグを利用しません。

このテストケースでは、メイン実行可能ファイルが PIE でコンパイルされているかどうかをチェックします。

### 手順

1. [アプリパッケージの探索 (Exploring the App Package)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/ios/MASTG-TECH-0058.md) を使用して、アプリパッケージから関連するバイナリを抽出します。
2. [コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler-Provided Security Features)](../../../techniques/ios/MASTG-TECH-0118.md) をメインバイナリに使用して、"pic" または選択したツールで使用される対応するキーワードを grep で検索します。

### 結果

出力には PIC が有効か無効かをリストする可能性があります。

### 評価

PIC が無効になっている場合、そのテストケースは不合格です。
