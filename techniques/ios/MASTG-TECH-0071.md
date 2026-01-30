---
title: 文字列の取得 (Retrieving Strings)
platform: ios
---

文字列は、関連するコードへのコンテキストを提供するため、バイナリを解析する際には常に良い出発点となります。たとえば、"Cryptogram generation failed" などのエラーログ文字列は、隣接するコードが暗号文の生成に関与している可能性があることを示唆しています。

iOS バイナリから文字列を抽出するには、Ghidra や [iaito](https://github.com/radareorg/iaito "iaito") などの GUI ツールを使用するか、_strings_ Unix ユーティリティ (`strings <path_to_binary>`) や radare2 の [rabin2](../../tools/generic/MASTG-TOOL-0129.md) (`rabin2 -zz <path_to_binary>`) などの CLI ベースのツールに頼ることができます。CLI ベースのツールを使用する場合、grep (正規表現を使用) などの他のツールを活用して、結果をさらにフィルタして解析できます。
