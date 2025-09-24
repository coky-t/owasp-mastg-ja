---
title: Angr
platform: android
---

Angr はバイナリを解析するための Python フレームワークです。静的および動的の両方のシンボリック (「コンコリック」) 解析に役立ちます。言い換えると、バイナリと要求された状態が与えられると、Angr はブルートフォースだけでなく、形式手法 (静的コード解析に使用される手法) を使用してパスを見つけ、その状態への到達を試みます。Angr を使用して要求された状態に到達することは、デバッグして手動でステップを踏んで要求された状態に向かうパスを探すよりもはるかに高速であることがよくあります。Angr は VEX 中間言語で動作し、ELF/ARM バイナリ用のローダーが付属しているため、ネイティブ Android バイナリなどのネイティブコードを扱うのに最適です。

Angr には多数のプラグインがあり、逆アセンブル、プログラム計装、シンボリック実行、コントロールフロー解析、データ依存性解析、逆コンパイルなどが可能になります。

バージョン 8 以降、Angr は Python 3 ベースであり、\*nix オペレーティングシステム、macOS、Windows において pip でインストールできます。

```bash
pip install angr
```

> Angr の依存関係の中には、Python モジュール Z3 と PyVEX のフォークされたバージョンを含み、オリジナルバージョンを上書きしてしまいます。これらのモジュールを他の用途に使用するのであれば、[Virtualenv](https://docs.python.org/3/tutorial/venv.html "Virtualenv documentation") で専用の仮想環境を作成すべきです。あるいは、提供されている Docker コンテナを使うこともできます。詳細については [インストールガイド](https://docs.angr.io/introductory-errata/install "angr Installation Guide") を参照してください。

インストールガイド、チュートリアル、使用例など、包括的なドキュメントは [Angr の Gitbooks ページ](https://docs.angr.io/ "angr") にあります。完全な [API リファレンス](https://api.angr.io/ "angr API") もあります。

iPython などの Python REPL から Angr を使用することや、スクリプトでアプローチすることができます。Angr の習得には少し時間がかかりますが、実行可能ファイルの特定の状態までブルートフォースしたいときに使用することをお勧めします。これがどのように機能するかについては [シンボリック実行 (Symbolic Execution)](../../techniques/android/MASTG-TECH-0037.md) の優れた例を参考にしてください。
