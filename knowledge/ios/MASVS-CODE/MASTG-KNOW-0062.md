---
masvs_category: MASVS-CODE
platform: ios
title: デバッグ可能アプリ (Debuggable Apps)
---

アプリがデバッグ可能 ([デバッグ (Debugging)](../../../techniques/ios/MASTG-TECH-0084.md)) であるかどうかをテストするには、アプリのエンタイトルメントを調べて [`get-task-allow`](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues "Resolving common notarization issues") キーの値が `true` に設定されているかを確認します。

デバッグはアプリを開発する際に便利な機能ですが、App Store やエンタープライズプログラム内にアプリをリリースする前にオフにしなければなりません。そのためにはアプリを生成するモードを決定して、環境内のフラグを確認する必要があります。

- プロジェクトのビルド設定を選択します。
- 'Apple LVM - Preprocessing' と 'Preprocessor Macros' で、'DEBUG' または 'DEBUG_MODE' が選択されていないことを確認します (Objective-C) 。
- "Debug executable" オプションが選択されていないことを確認します。
- もしくは 'Swift Compiler - Custom Flags' セクションの 'Other Swift Flags' で、'-D DEBUG' エントリが存在しないことを確認します。
