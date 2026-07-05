---
title: ネイティブコードトレース (Native Code Tracing)
platform: ios
---

# MASTG-TECH-0087 ネイティブコードトレース (Native Code Tracing)

この章の前半で説明したように、iOS アプリケーションにはネイティブコード (C/C++) も含むことがあり、`frida-trace` CLI でトレースすることができます。たとえば、以下のコマンドを実行することで `open` 関数の呼び出しをトレースできます。

```bash
frida-trace -U -i "open" sg.vp.UnCrackable1
```

Frida を使用してネイティブコードをトレースするための全体的なアプローチとさらなる改良は [ネイティブコードトレース (Native Code Tracing)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0034.md) で説明しているものと同様です。

残念ながら、iOS アプリのシステムコールや関数呼び出しをトレースするために利用できる `strace` や `ftrace` などのツールはありません。強力で多機能なトレースツールである `DTrace` だけが存在しますが、これは MacOS でのみ利用可能で、iOS では利用できません。
