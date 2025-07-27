---
title: シンボルのデマングリング (Demangling Symbols)
platform: ios
---

プログラム内の一部の識別子を一意にするために、コンパイラはシンボル名を処理します。この処理は「名前マングリング (name mangling)」または単に「マングリング (mangling)」と呼ばれます。結果として得られるシンボルは人間には理解しにくいものになることがよくあります。さらに、その形式は入力言語やコンパイラに固有であり、バージョンに依存することもあります。

デマングリングツールを使用して、マングリングプロセスを元に戻すことができます。Swift の場合は [swift-demangle](../../tools/ios/MASTG-TOOL-0067.md)、C++ 関数の場合は [c++filt](../../tools/ios/MASTG-TOOL-0122.md) があります。

## swift-demangle

マングルされたシンボルを [swift-demangle](../../tools/ios/MASTG-TOOL-0067.md) に渡します。

```bash
$ xcrun swift-demangle __T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO
_T0So9WKWebViewCABSC6CGRectV5frame_So0aB13ConfigurationC13configurationtcfcTO ---> @nonobjc __C.WKWebView.init(frame: __C_Synthesized.CGRect, configuration: __C.WKWebViewConfiguration) -> __C.WKWebView
```

## c++filt

[c++filt](../../tools/ios/MASTG-TOOL-0122.md) で C++ シンボルをデマングルできます。

```bash
c++filt _ZSt6vectorIiSaIiEE
std::vector<int, std::allocator<int>>
```
