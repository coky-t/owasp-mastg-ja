---
title: Grapefruit
platform: ios
source: https://github.com/ChiChou/grapefruit
---

Grapefruit は、iOS デバイス上の Firida サーバーを使用し、多くのペネトレーションテストタスクをウェブ UI に抽象化している iOS アプリ評価ツールです。`npm` 経由でインストールできます。

```bash
$ npm install -g igf
$ grapefruit
listening on http://localhost:31337
```

`grapefruit` コマンドを実行すると、ローカルサーバーがポート 31337 で起動します。Frida サーバーが動作している脱獄済みデバイス、または Frida を含む再パッケージ化されたアプリを備えた脱獄されていないデバイスを USB 経由でマシンに接続します。"iPhone" アイコンをクリックすると、インストールされているすべてのアプリの概要を取得します。

Grapefruit では、iOS アプリに関するさまざまな種類の情報を探索できます。iOS アプリを選択すると、以下のような多くのタスクを実行できます。

- そのバイナリに関する情報を取得します
- アプリケーションで使用されるフォルダとファイルを表示してダウンロードします
- Info.plist を検査します
- iOS デバイスに表示されるアプリ画面の UI ダンプを取得します
- アプリによってロードされるモジュールをリストします
- クラス名をダンプします
- キーチェーンアイテムをダンプします
