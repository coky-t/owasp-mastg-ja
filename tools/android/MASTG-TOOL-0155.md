---
title: Android CLI
platform: android
source: https://developer.android.com/tools/agents/android-cli
hosts: [windows, linux, macOS]
---

[Android CLI](https://developer.android.com/tools/agents/android-cli) は Google によるコマンドラインツールであり、スクリプト、CI パイプライン、コーディングエージェントに、Android プロジェクト、デバイス、エミュレータへの単一のインタフェースを提供します。中でも、接続されたデバイスやエミュレータ上で実行しているアプリのスクリーンショットを撮影できたり、UI レイアウトを取得できます。

## インストール

[公式ダウンロードページ](https://developer.android.com/tools/agents/android-cli/download) の手順に従います。Linux, macOS, Windows 向けのインストーラを提供しています。たとえば、macOS では Homebrew でインストールできます。

```bash
brew tap android/tap
brew install android-cli
```

以下で最新に維持します。

```bash
android update
```

## 使用方法

接続されたデバイスのスクリーンショットを撮影します。

```bash
android screen capture --output=screenshot.png
```

`--annotate` を追加して、スクリーン上で検出された UI 要素の周りに、ラベル付きバウンディングボックスを描画します。

実行中のアプリの UI レイアウトを JSON で返します。

```bash
android layout --pretty --output=layout.json
```

すべてのコマンドとオプションについては [Android CLI ドキュメント](https://developer.android.com/tools/agents/android-cli) を参照してください。
