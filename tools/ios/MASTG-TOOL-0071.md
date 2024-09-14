---
title: Xcode Command Line Tools
platform: ios
source: https://developer.apple.com/download/more/
---

[Xcode](MASTG-TOOL-0070.md) をインストールした後、すべての開発ツールをシステム全体で利用可能にするために、Xcode Command Line Tools パッケージをインストールすることをお勧めします。これは、iOS アプリのテスト時に便利です。一部のツール (objection など) はこのパッケージの可用性にも依存しているためです。[Apple の公式ウェブサイトからダウンロードする](https://developer.apple.com/download/more/ "Apple iOS SDK") か、ターミナルから直接インストールできます。

```bash
xcode-select --install
```
