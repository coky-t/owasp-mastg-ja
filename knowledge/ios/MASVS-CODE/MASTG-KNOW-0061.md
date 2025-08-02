---
masvs_category: MASVS-CODE
platform: ios
title: バイナリ保護メカニズム (Binary Protection Mechanisms)
---

[バイナリ保護メカニズム](../../../Document/0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) の存在を検出するためにはアプリケーションの開発に使用された言語に大きく依存します。

Xcode はデフォルトですべてのバイナリセキュリティ機能を有効にしますが、古いアプリケーションに対してこれを検証したり、コンパイラフラグの設定ミスをチェックすることが適切な場合があります。以下の機能が適用可能です。

- [**PIE (Position Independent Executable)**](../../../Document/0x04h-Testing-Code-Quality.md#position-independent-code):
    - PIE は実行形式バイナリ (Mach-O タイプ `MH_EXECUTE`) に適用されます。 [情報源](https://web.archive.org/web/20230328221404/https://opensource.apple.com/source/cctools/cctools-921/include/mach-o/loader.h.auto.html)
    - ただし、ライブラリ (Mach-O タイプ `MH_DYLIB`) には適用されません。
- [**メモリ管理**](../../../Document/0x04h-Testing-Code-Quality.md#memory-management):
    - 純粋な Objective-C、Swift、ハイブリッドバイナリのいずれも ARC (Automatic Reference Counting) を有効にすべきです。
    - C/C++ ライブラリでは、開発者は適切な [手動メモリ管理](../../../Document/0x04h-Testing-Code-Quality.md#manual-memory-management) を行う責任があります。 ["メモリ破損バグ"](../../../Document/0x04h-Testing-Code-Quality.md#memory-corruption-bugs) を参照してください。
- [**スタックスマッシュ保護**](../../../Document/0x04h-Testing-Code-Quality.md#stack-smashing-protection): 純粋な Objective-C バイナリでは、これは常に有効にすべきです。Swift はメモリセーフに設計されているので、ライブラリが純粋に Swift で書かれていれば、スタックカナリアが有効にされていなくても、リスクは最小限に抑えられます。

詳しくはこちら。

- [OS X ABI Mach-O File Format Reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
- [On iOS Binary Protections](https://sensepost.com/blog/2021/on-ios-binary-protections/)
- [Security of runtime process in iOS and iPadOS](https://support.apple.com/en-gb/guide/security/sec15bfe098e/web)
- [Mach-O Programming Topics - Position-Independent Code](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/dynamic_code.html)

これらの保護メカニズムの存在を検出するためのテストはアプリケーションの開発に使用される言語に大きく依存します。たとえば、スタックカナリアの存在を検出するための既存の技法は純粋な Swift アプリでは機能しません。

## Xcode プロジェクト設定

### Stack Canary 保護

iOS アプリケーションで Stack Canary 保護を有効にする手順。

1. Xcode の "Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックしてターゲットの設定を表示します。
2. "Other C Flags" セクションで "-fstack-protector-all" オプションが選択されていることを確認します。
3. Position Independent Executables (PIE) support が有効になっていることを確認します。

### PIE 保護

iOS アプリケーションを PIE としてビルドする手順。

1. Xcode の "Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックしてターゲットの設定を表示します。
2. iOS Deployment Target を iOS 4.3 以降に設定します。
3. "Generate Position-Dependent Code" ("Apple Clang - Code Generation" セクション) がデフォルト値 ("NO") に設定されていることを確認します。
4. "Generate Position-Dependent Executable" ("Linking" セクション) がデフォルト値 ("NO") に設定されていることを確認します。

### ARC 保護

Swift アプリでは `swiftc` コンパイラによって ARC が自動的に有効になります。一方 Objective-C アプリでは以下の手順で有効になっていることを確認します。

1. Xcode の "Targets" セクションでターゲットを選択し、"Build Settings" タブをクリックしてターゲットの設定を表示します。
2. "Objective-C Automatic Reference Counting" がデフォルト値 ("YES") に設定されていることを確認します。

[Technical Q&A QA1788 Building a Position Independent Executable](https://developer.apple.com/library/mac/qa/qa1788/_index.html "Technical Q&A QA1788 Building a Position Independent Executable") を参照してください。
