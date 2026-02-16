---
title: SBOM を作成することによる iOS 依存関係のソフトウェアコンポジション分析 (SCA) (Software Composition Analysis (SCA) of iOS Dependencies by Creating a SBOM)
platform: ios
---

SwiftPM を使用している場合は、[cdxgen](../../tools/generic/MASTG-TOOL-0134.md) を使用して CycloneDX 形式のソフトウェア部品表 (SBOM) を生成できます。現在、Carthage と CocoaPods はサポートされていません。開発チームに SBOM ファイルの提供を依頼するか、自分で作成します。作成するには、スキャンしたい Xcode プロジェクトのルートディレクトリに移動し、以下のコマンドを実行します。

```bash
$ cdxgen -o sbom.json
```

SBOM ファイルは、分析のために Base64 エンコードして [dependency-track](../../tools/generic/MASTG-TOOL-0132.md) にアップロードする必要があります。

```bash
$ cat sbom.json | base64
$ curl -X "PUT" "http://localhost:8081/api/v1/bom" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: <YOUR API KEY>>' \
     -d $'{
  "project": "<YOUR PROJECT ID>",
  "bom": "<BASE64-ENCODED SBOM>"
  }'
```

また、生成された JSON ファイルが大きすぎる場合は、SBOM ファイルを [アップロードするための代替手段](https://docs.dependencytrack.org/usage/cicd/) もチェックしてください。

[Visual Studio Code (vscode)](../../tools/generic/MASTG-TOOL-0133.md) Docker コンテナのデフォルト設定を使用している場合、[dependency-track](../../tools/generic/MASTG-TOOL-0132.md) のフロントエンド <http://localhost:8080> に移動します。SBOM をアップロードしたプロジェクトを開き、脆弱な依存関係があるかどうかを検証します。

> [!NOTE]
> [cdxgen](../../tools/generic/MASTG-TOOL-0134.md) では [SwiftPM](https://cdxgen.github.io/cdxgen/#/PROJECT_TYPES) に対して推移的依存関係をサポートしていません。
