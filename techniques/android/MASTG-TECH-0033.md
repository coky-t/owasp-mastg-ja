---
title: メソッドトレース (Method Tracing)
platform: android
---

メソッドが呼び出される頻度を示すメソッドプロファイリングとは対照的に、メソッドトレースはメソッドの入出力値を測定するのにも役立ちます。この技法は、大規模なコードベースであったり難読化されているアプリケーションを扱う際に非常に役立ちます。

GUI ベースのアプローチを好む場合は、[RMS Runtime Mobile Security](../../tools/generic/MASTG-TOOL-0037.md) などのツールを使用できます。これはより視覚的な体験を可能にし、いくつかの便利な [トレースオプション](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security#3-hook-on-the-fly-classesmethods-and-trace-their-args-and-return-values) も備えています。

コマンドラインを好む場合、Frida は Java クラスとメソッドをクエリするための便利な構文と、`-j` 経由で frida-trace の Java メソッドトレースサポートを提供します (frida-tools 8.0, Frida 12.10 以降)。

- Frida スクリプトの場合: 例: `Java.enumerateMethods('*youtube*!on*')` は glob を使用して、名前の一部に "youtube" を含むすべてのクラスを取得し、"on" で始まるすべてのメソッドを列挙します。
- frida-trace の場合: 例: `-j '*!*certificate*/isu'` は、大文字と小文字を区別しないクエリ (`i`) をトリガーし、メソッドシグネチャ (`s`) を含め、システムクラス (`u`) を除外します。

この新機能の詳細については [Frida 12.10 のリリースノート](https://frida.re/news/2020/06/29/frida-12-10-released/ "Frida 12.10") を参照してください。高度な使用方法に関するすべてのオプションの詳細については [Frida の公式ウェブサイトのドキュメント](https://frida.re/docs/frida-trace/ "documentation") をチェックしてください。
