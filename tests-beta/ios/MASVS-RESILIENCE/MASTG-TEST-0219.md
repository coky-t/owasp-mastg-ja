---
platform: ios
title: デバッグシンボルのテスト (Testing for Debugging Symbols)
id: MASTG-TEST-0219
type: [static]
weakness: MASWE-0093
profiles: [R]
---

## 概要

このテストケースでは、アプリに含まれるすべてのバイナリの [デバッグシンボル](../../../weaknesses/MASVS-RESILIENCE/MASWE-0093.md) をチェックします。

デバッグシンボルは [開発を容易にするためにコンパイラ](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information "Building your app to include debugging information") によって追加され、クラッシュのシンボル化を可能にします。しかし、これらはアプリのリバースエンジニアにも使用される可能性があり、リリースされるアプリには存在すべきではありません。別の dSYM ファイルで [シンボル化を実行することも可能です](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report "Adding identifiable symbol names to a crash report")。

Xcode でデバッグシンボルを管理するために、開発者は以下のビルド設定を調整できます。

- **Generate Debug Symbols**: [`"Build Settings" > "Apple Clang - Code Generation" > "Generate Debug Symbols"`](https://developer.apple.com/documentation/xcode/build-settings-reference#Generate-Debug-Symbols) が `"Yes"` に設定されている場合、Xcode はデバッグシンボルを追加します。
- **Debug Information Format**: [`"Build Settings" > "Build Options > "Debug Information Format"`](https://developer.apple.com/documentation/xcode/build-settings-reference#Debug-Information-Format) にあるこの設定はデバッグ情報のフォーマットを決定します。オプションは以下のとおりです。
    - **DWARF**: デバッグ情報をバイナリに直接埋め込みます。
    - **DWARF with dSYM File**: デバッグ情報を含む別の dSYM ファイルを生成します。

コンパイルされた iOS アプリケーションでは、シンボル名が **名前マングリング** や追加の **難読化技法** を施してさらにわかりにくくなり、リバースエンジニアリングがより困難になるかもしれないことに注意してください。デマングリングツールは標準のマングル(名前修飾)された名前をデコードできます ([シンボルのデマングリング (Demangling Symbols)](../../../techniques/ios/MASTG-TECH-0114.md) を参照) が、カスタムの難読化手法を効果的にリバースできないかもしれません。

## 手順

1. [アプリパッケージの探索 (Exploring the App Package)](../../../techniques/ios/MASTG-TECH-0058.md) を適用して、IPA ファイルからコンテンツを抽出します。
2. すべての実行可能ファイルとライブラリについて、[デバッグシンボルの取得 (Obtaining Debugging Symbols)](../../../techniques/ios/MASTG-TECH-0113.md) を使用して、デバッグシンボルが存在しないことを検証します。

## 結果

出力には各実行可能ファイルとライブラリのシンボルのリストを含む可能性があります。

## 評価

出力にデバッグシンボルとしてマークされたシンボルがある場合、テストは不合格です。

iOS アプリをリリースする前に、`"Build Settings" > "Apple Clang - Code Generation" > "Generate Debug Symbols"` 設定が `"No"` に設定されていることを検証します。さらに、[デバッグシンボルの取得 (Obtaining Debugging Symbols)](../../../techniques/ios/MASTG-TECH-0113.md) で使用されているようなツールを利用して、最終的なバイナリにデバッグシンボルが残っていないか検査します。

リリースビルドでは、`"Build Settings" > "Build Options > "Debug Information Format"` を `"DWARF with dSYM File"` に設定し、dSYM ファイルが安全に保存され、アプリと一緒に配布されないようにすることをお勧めします。このアプローチは配布バイナリにデバッグシンボルを公開することなく、リリース後のクラッシュ解析を容易にします。
