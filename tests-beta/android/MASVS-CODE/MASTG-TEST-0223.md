---
title: スタックカナリアが有効でない (Stack Canaries Not Enabled)
platform: android
id: MASTG-TEST-0223
type: [static]
weakness: MASWE-0116
profiles: [L2]
knowledge: [MASTG-KNOW-0006]
---

## 概要

このテストケースでは、アプリの [ネイティブライブラリ](../../../Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#binary-protection-mechanisms) がスタックカナリアなしでコンパイルされ、バッファオーバーフロー攻撃に対する一般的な緩和技法である [スタックスマッシュ保護](../../../Document/0x04h-Testing-Code-Quality.md#stack-smashing-protection) が欠けているかどうかをチェックします。

- NDK ライブラリでは、スタックカナリアが有効になっているはずです。[コンパイラがデフォルトでそれを行っている](https://android.googlesource.com/platform/ndk/%2B/master/docs/BuildSystemMaintainers.md#additional-required-arguments) ためです。
- 他のカスタム C/C++ ライブラリでは、スタックカナリアが有効になっていないかもしれません。必要なコンパイラフラグ (`-fstack-protector-strong` または `-fstack-protector-all`) が欠如していたり、カナリアがコンパイラによって最適化により削除されてしまうためです。詳細については [評価](#evaluation) セクションを参照してください。

## 手順

1. アプリのコンテンツを抽出します ([アプリパッケージの探索 (Exploring the App Package)](../../techniques/android/MASTG-TECH-0007.md))。
2. 各共有ライブラリで [コンパイラが提供するセキュリティ機能の取得 (Obtaining Compiler Provided Security Features)](MASTG-TECH-0115) を実行し、"canary" または選択したツールで使用される対応するキーワードを grep で検索します。

## 結果

出力にはスタックカナリアが有効か無効かを表示する可能性があります。

## 評価

スタックカナリアが無効になっている場合、そのテストケースは不合格です。

開発者は、すべてのネイティブライブラリのコンパイラフラグにフラグ `-fstack-protector-strong` または `-fstack-protector-all` が設定されていることを確認する必要があります。これは NDK の一部ではないカスタム C/C++ ライブラリにとって特に重要です。

これを評価する際には、テストケースが合格とみなされる可能性がある潜在的な **予期される誤検出** があることに注意してください。これらのケースを確実にするには、元のソースコードと使用されているコンパイラフラグを手作業でレビューする必要があります。

以下の例は遭遇する可能性のある誤検出のケースをいくつか示しています。

### メモリセーフ言語の使用

Flutter フレームワークは、[Dart がバッファオーバーフローを緩和する](https://docs.flutter.dev/reference/security-false-positives#shared-objects-should-use-stack-canary-values) 方法のため、スタックカナリアを使用しません。

### コンパイラによる最適化

場合によっては、ライブラリのサイズとコンパイラによって適用される最適化により、ライブラリがもともとスタックカナリアを備えてコンパイルされていても、最適化により削除されてしまう可能性があります。たとえば、一部の [react native アプリ](https://github.com/facebook/react-native/issues/36870#issuecomment-1714007068) がこれに該当します。これらは `-fstack-protector-strong` でビルドされていますが、`.so` ファイル内で stack_chk_fail` を探してみても見つかりません。

- **空の .so ファイル**: libruntimeexecutor.so` や `libreact_render_debug.so` などの一部の .so ファイルはリリースでは実質的に空であるため、シンボルを含みません。`-fstack-protector-all` でビルドしようとしても、そこにはメソッド呼び出しがないため、`stack_chk_fail` 文字列を見ることはできないでしょう。
- **スタックバッファ呼び出しの欠如**: `libreact_utils.so`, `libreact_config.so`, `libreact_debug.so` などの他のファイルは空ではなく、メソッド呼び出しを含みますが、それらのメソッドはスタックバッファ呼び出しを含まないため、その中には `stack_chk_fail` 文字列はありません。

このケースで React Native 開発者は `-fstack-protector-all` を追加しないと宣言しています。それは [そうすることでセキュリティ上の効果が得られず、パフォーマンスが低下すると考えている](https://github.com/OWASP/mastg/pull/3049#pullrequestreview-2420837259) ためです。
