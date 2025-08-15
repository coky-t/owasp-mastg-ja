---
masvs_category: MASVS-CODE
platform: ios
title: デバッグ情報とデバッグシンボル (Debugging Information and Debug Symbols)
---

iOS アプリケーションがコンパイルされると、コンパイラはアプリ内に各バイナリ (メイン実行ファイル、フレームワーク、拡張機能など) に対するデバッグシンボルを生成します。これらのシンボルには、クラス名、グローバル変数、メソッド名、関数名を含み、特定のソースファイルと行番号にマップされています。テスト担当者として、アプリに含まれるすべてのバイナリを調査し、意味のあるデバッグシンボルが存在しないことを検証する必要があります。

[デバッグビルド](https://developer.apple.com/documentation/xcode/building-your-app-to-include-debugging-information "Building Your App to Include Debugging Information") はこれらのシンボルをデフォルトでコンパイル済みバイナリに含めます。対照的に、[Debug Information Format](https://developer.apple.com/documentation/xcode/build-settings-reference#Debug-Information-Format) を `DWARF with dSYM File` に設定して構成されたリリースビルドは、個別の _Debug Symbol ファイル_ (dSYM) を生成し、配布されるアプリのサイズを削減します。

このアプローチは Linux ツールチェーンで一般的な [split DWARF](https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-gsplit-dwarf) に似ています。dSYM ファイルは [クラッシュレポートのシンボル化](https://developer.apple.com/documentation/xcode/adding-identifiable-symbol-names-to-a-crash-report) のために Apple のシンボルサーバーにアップロードできます。

ベストプラクティスとして、実行に必要なメタデータのみがコンパイル済みバイナリに含まれる必要があります。デバッグシンボルとその他の必須ではないメタデータは、関数名など、その目的を示す内部実装詳細を公開する可能性があります。この情報はアプリの実行には不要であり、適切なコンパイラ設定を使用してリリースビルドから削除する必要があります。
