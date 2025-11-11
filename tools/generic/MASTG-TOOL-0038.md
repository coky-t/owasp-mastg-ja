---
title: objection
platform: generic
source: https://github.com/sensepost/objection
---

[Objection](https://github.com/sensepost/objection "Objection on GitHub") は「Frida を搭載したランタイムモバイル探索ツールキット」です。その主な目的は、直感的なインタフェースを通じて、ルート化されていないデバイスでのセキュリティテストを可能にすることです。[機能の完全なリスト](https://github.com/sensepost/objection/wiki/Features) はプロジェクトのページにありますが、プラットフォームにに依存しないものをいくつか記します。

- ファイルをダウンロードまたはアップロードするためにアプリケーションストレージにアクセスします
- カスタム Frida スクリプトを実行します
- メモリを検索、置換、ダンプします
- フックとスクリプトをアンロードするためのジョブ制御します
- SQLite データベースをインラインでやり取りします
- カスタムプラグインをサポートします

Objection はアプリケーションを再パッケージすることにより、アプリケーションに Frida ガジェットを簡単に挿入するツールを提供することで、この目標を達成します。このようにして、再パッケージしたアプリをサイドローディングすることで、ルート化されていない/脱獄していないデバイスにデプロイできます。Objection はアプリケーションとやり取りできる REPL も提供し、アプリケーションが実行できるあらゆるアクションを実行できるようにします。

Objection は [Objection の Wiki](https://github.com/sensepost/objection/wiki/Installation "Objection Wiki - Installation") で説明されているように、pip 経由でインストールできます。

```bash
pip3 install objection
```

### !!! 警告 "objection の pip/PyPI パッケージは古く、Frida 17+ に準拠していません"
ソースリポジトリの `master` ブランチからインストールすることで、objection を Frida 17+ で引き続き使用できます。[Development Environment Installation](https://github.com/sensepost/objection/wiki/Development-Environment-Installation) を参照してください。

新しいリリースが存在し、Python Package Index (PyPI) で利用可能になれば、`pip` を使用してインストールできます。
