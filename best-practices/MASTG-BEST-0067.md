---
title: iOS のソースコード完全性チェックを実装する (Implementing Source Code Integrity Checks on iOS)
alias: implementing-source-code-integrity-checks-ios
id: MASTG-BEST-0067
platform: ios
knowledge: [MASTG-KNOW-0140]
---

iOS アプリにソースコード完全性チェックを実装して、アプリバイナリへの不正な改変を検出します。これらのチェックは、特に脱獄済みデバイス上や、アプリが別の証明書で再署名された際に、アプリを改竄しようと試みる攻撃者にとってコストを高めます。

OS は、起動前にアプリバイナリの真正性と完全性を検証するためのコード署名を提供します。しかしながら、脱獄済みデバイス上や、攻撃者が自身の証明書でアプリに再署名した場合には、この保護はバイパスされる可能性があります。

OS レベル保護を補完するために、実行時のソースコード完全性チェックを実装します。これらのチェックは [Mach-O バイナリ構造](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html) を解析して `__TEXT/__text` セクションを見つけ、その暗号論的ハッシュを計算し、ハードコードまたは安全に保管された参照値とそのハッシュを比較します (実装例については [ソースコード完全性チェック (Source Code Integrity Checks)](../knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0140.md) を参照してください)。

暗号論的に弱い MD5 ではなく、(CommonCrypto から `CC_SHA256` を介して) SHA-256 のような強力なハッシュ関数を使用します。

参照ハッシュ値を改変から保護された場所 (たとえば、バイナリ内に難読化された形式でハードコードするなど) に保存します。

> [!WARNING]
> 実行時のソースコード完全性チェックは脱獄済みデバイスでは本質的にバイパス可能です。攻撃者はそのチェック自体をフックしたり、参照ハッシュをパッチ適用したり、Frida を使用してファイルシステム呼び出しを傍受し、元のバイナリを返すことができます。これらのチェックは保証ではなくコスト増加策として扱われるべきです。
