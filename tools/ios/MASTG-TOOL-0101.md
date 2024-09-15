---
title: codesign
platform: ios
source: https://www.unix.com/man-page/osx/1/codesign/
alternatives:
- MASTG-TOOL-0102
---

codesign ツールは主にコード署名を作成、検証、表示し、およびシステム内の署名済みコードの動的ステータスを照会するために使用される。Xcode は一般的にビルド時および配布前にコードに署名するプロセスを自動化しますが、codesign での手動介入が必要なシナリオもあります。これには、アプリのコード署名の詳細を検査または検証すること、アプリを手動で再署名することなどがあります。このような詳細なタスクについては、Apple のコード署名ガイドで説明されているように、codesign コマンドラインツールを直接使用できます。

詳細はこちら:

- ["Examining a Code Signature"](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW10)
- ["Signing Code Manually"](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW3) in Apple's Code Signing Guide
- [Using the latest code signature format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format)
- [codesign manpage](https://www.unix.com/man-page/osx/1/codesign/)
- [codesign source code](https://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c.auto.html)
