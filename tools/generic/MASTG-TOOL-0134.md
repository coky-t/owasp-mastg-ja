---
title: cdxgen
platform: generic
source: https://github.com/CycloneDX/cdxgen
---

[cdxgen](https://cdxgen.github.io/cdxgen/#/) は、ほとんどのアプリケーションとコンテナイメージのソフトウェア部品表 (SBOM) を一つのコマンドで生成できます。iOS では SwiftPM、Android では Maven をサポートしています。生成された SBOM は [dependency-track](MASTG-TOOL-0132.md) などの解析ツールに送信できます。

コンパイル済みの Android アプリ (APK または AAB) 用の SBOM の作成はサポートされていますが、制限があり、ほとんどが不完全です。これは主にアプリで使用されるライブラリからメタデータが削除されるためです。したがって、完全な SBOM を作成するには、Android アプリのプロジェクトフォルダで cdxgen を実行することをお勧めします。
