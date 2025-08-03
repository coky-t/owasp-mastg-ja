---
title: 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) Not Enabled)
platform: android
id: MASTG-TEST-0222
deprecated_since: 21
type: [static]
weakness: MASWE-0116
profiles: [L2]
---

## 概要

このテストケースでは、アプリの [ネイティブライブラリ](../../../Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#binary-protection-mechanisms) が、メモリ破損攻撃に対する一般的な緩和技法である [位置独立コード (PIC)](../../../Document/0x04h-Testing-Code-Quality.md#position-independent-code) を有効にせずにコンパイルされているかどうかをチェックします。

Android 5.0 (API レベル 21) 以降、Android は [すべてのダイナミックリンクされた実行可能ファイルが PIE をサポートすること](https://source.android.com/docs/security/enhancements/#android-5) を必須としています。

> [Build System Maintainers Guide - Additional Required Arguments](https://android.googlesource.com/platform/ndk/%2B/master/docs/BuildSystemMaintainers.md#additional-required-arguments): API 21 以降、Android は位置非依存実行可能ファイルを必須としています。Clang はデフォルトで PIE 実行可能ファイルをビルドします。リンカーを直接呼び出す場合や Clang を使用しない場合は、リンク時に `-pie` を使用します。

## 手順

1. アプリのコンテンツを抽出します ([アプリパッケージの探索 (Exploring the App Package)](../../techniques/android/MASTG-TECH-0007.md))。
2. 各共有ライブラリで [コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler Provided Security Features)](MASTG-TECH-0115) を実行し、"pic" または選択したツールで使用される対応するキーワードを grep で検索します。

## 結果

出力には PIC が有効か無効かをリストする可能性があります。

## 評価

PIC が無効になっている場合、そのテストケースは不合格です。
