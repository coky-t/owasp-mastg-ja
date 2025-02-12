---
title: Sideloadly
platform: ios
hosts:
- windows
- macos
source: https://sideloadly.io/
---

[Sideloadly](https://sideloadly.io/ "Sideloadly") は、特定の IPA ファイルの有効な署名を取得し、接続された iOS デバイスにインストールできます。IPA ファイルの署名とインストールだけでなく、Sideloadly は微調整を注入したり、アプリ名やバンドル名を変更したり、IPA メタデータにその他の限定的な変更を加えることもできます。Sideloadly は macOS と Windows の両方で利用できます。

!!! 警告 「個人の Apple アカウントを使用しないでください」
    IPA ファイルに署名するには、無償または有償の有効な iOS 開発者アカウントが必要です。[非脱獄デバイスでの動的解析 (Dynamic Analysis on Non-Jailbroken Devices)](techniques/ios/MASTG-TECH-0079.md) で説明されているように、どちらのタイプにも一定の制限があります。テストアプリケーションを署名するための専用の開発者アカウントを作成し、個人の Apple アカウントを使用 **しない** ことをお勧めします。
