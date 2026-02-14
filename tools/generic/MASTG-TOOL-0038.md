---
title: objection
platform: generic
source: https://github.com/sensepost/objection
---

objection は「Frida を搭載したランタイムモバイル探索ツールキット」です。その主な目的は、直感的なインタフェースを通じて、ルート化されていないデバイスでのセキュリティテストを可能にすることです。[機能の完全なリスト](https://github.com/sensepost/objection/wiki/Features) はプロジェクトのページにありますが、プラットフォームにに依存しないものをいくつか記します。

- ファイルをダウンロードまたはアップロードするためにアプリケーションストレージにアクセスします
- カスタム Frida スクリプトを実行します
- メモリを検索、置換、ダンプします
- フックとスクリプトをアンロードするためのジョブ制御します
- SQLite データベースをインラインでやり取りします
- カスタムプラグインをサポートします

objection はアプリケーションを再パッケージすることにより、アプリケーションに Frida ガジェットを簡単に挿入するツールを提供することで、この目標を達成します。このようにして、再パッケージしたアプリをサイドローディングすることで、ルート化されていない/脱獄していないデバイスにデプロイできます。objection はアプリケーションとやり取りできる REPL も提供し、アプリケーションが実行できるあらゆるアクションを実行できるようにします。

objection は [objection の Wiki](https://github.com/sensepost/objection/wiki/Installation "Objection Wiki - Installation") で説明されているように、pip 経由でインストールできます。

```bash
pip3 install objection
```

pip のバージョンが最新リリースと同期していない場合、または最新の開発バージョンを使用したい場合は、ソースリポジトリの main ブランチから直接 Objection をインストールできます。手順については [Development Environment Installation](https://github.com/sensepost/objection/wiki/Development-Environment-Installation) を参照してください。
