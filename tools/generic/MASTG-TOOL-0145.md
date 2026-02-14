---
title: Frooky
platform: generic
source: https://github.com/cpholguera/frooky
hosts: [ windows, linux, macOS ]
---

Frooky は Android および iOS アプリケーション用の Frida ベースの動的解析ツールです。セキュリティ研究者は JSON ベースのフック設定を使用してモバイルアプリを計装でき、カスタム Frida スクリプトを記述することなく、メソッドインターセプションへの宣言的なアプローチを提供します。

## 機能

- Java/Kotlin メソッドとネイティブ C/C++ 関数のフック
- 特定の引数シグネチャを備えたメソッドオーバーロードのサポート
- 設定可能な深さでのスタックトレースのキャプチャ
- 複数のデータ型に対する柔軟な引数デコード
- 引数値やスタックパターンに基づく条件付きフックのトリガー
- 効率的なデータ処理のための JSON Lines (NDJSON) 出力形式
- 複数のフックファイルのマージのサポート

## インストール

Frooky には Python 3.10 以降が必要です。pip でインストールします。

```bash
pip install frooky // pip3, or pipx
```

## 使用法

すでに実行中のアプリへアタッチする:

```bash
frooky -U -n "My App" --platform android hooks.json
```

アプリを起動して計装する:

```bash
frooky -U -f com.example.app --platform android storage.json crypto.json
```

コマンドラインオプションと構成の詳細については [公式ドキュメント](https://github.com/cpholguera/frooky#usage) を参照してください。
