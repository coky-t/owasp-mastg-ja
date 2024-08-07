---
masvs_v1_id:
- MSTG-RESILIENCE-9
masvs_v2_id:
- MASVS-RESILIENCE-3
platform: android
title: 難読化のテスト (Testing Obfuscation)
masvs_v1_levels:
- R
---

## 概要

## 静的解析

APK を逆コンパイル ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md)) し、レビュー ([逆コンパイルされた Java コードのレビュー (Reviewing Decompiled Java Code)](../../../techniques/android/MASTG-TECH-0023.md)) して、コードベースが難読化されているかどうかを判断します。

以下に難読化されたコードブロックの例を示します。

```java
package com.a.a.a;

import com.a.a.b.a;
import java.util.List;

class a$b
  extends a
{
  public a$b(List paramList)
  {
    super(paramList);
  }

  public boolean areAllItemsEnabled()
  {
    return true;
  }

  public boolean isEnabled(int paramInt)
  {
    return true;
  }
}
```

以下にいくつか考察を示します。

- クラス名、メソッド名、変数名など、意味のある識別子が破棄されている可能性があります。
- 文字列リソースとバイナリ内の文字列が暗号化されている可能性があります。
- 保護される機能に関連するコードとデータが暗号化、パック化、あるいはその他の方法で隠されている可能性があります。

ネイティブコードの場合:

- [libc API](https://man7.org/linux/man-pages/dir_section_3.html) (open, read など) は OS [syscalls](https://man7.org/linux/man-pages/man2/syscalls.2.html) に置き換えられている可能性があります。
- [Obfuscator-LLVM](https://github.com/obfuscator-llvm/obfuscator "Obfuscator-LLVM") を適用して ["制御フローの平坦化"](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening) や ["偽の制御フロー"](https://github.com/obfuscator-llvm/obfuscator/wiki/Bogus-Control-Flow) を実行した可能性があります。

これらの技法のいくつかは Gautam Arvind によるブログ記事 ["Security hardening of Android native code"](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code/) や Eduardo Novella によるプレゼンテーション ["APKiD: Fast Identification of AppShielding Products"](https://github.com/enovella/cve-bio-enovella/blob/master/slides/APKiD-NowSecure-Connect19-enovella.pdf) で説明および分析されています。

より詳細な評価を行うには、関連する脅威と使用される難読化手法を詳細に理解する必要があります。 [APKiD](../../../tools/android/MASTG-TOOL-0009.md) などのツールでは、難読化ツール、パッカー、アンチデバッグ対策など、ターゲットアプリにどのような技法が使われたかについての追加情報を得られることがあります。

## 動的解析

[APKiD](../../../tools/android/MASTG-TOOL-0009.md) を使用して、アプリが難読化されているかどうかを検出できます。

[Android UnCrackable L4](../../../apps/android/MASTG-APP-015.md) を使用した例:

```sh
apkid owasp-mastg/Crackmes/Android/Level_04/r2pay-v1.0.apk
[+] APKiD 2.1.2 :: from RedNaga :: rednaga.io
[*] owasp-mastg/Crackmes/Android/Level_04/r2pay-v1.0.apk!classes.dex
 |-> anti_vm : Build.TAGS check, possible ro.secure check
 |-> compiler : r8
 |-> obfuscator : unreadable field names, unreadable method names
```

この場合、アプリには読み取り不可のフィールド名やメソッド名などがあることを検出しています。
