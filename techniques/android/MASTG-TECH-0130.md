---
title: SBOM を作成することによる Android の依存関係のソフトウェアコンポジション解析 (Software Composition Analysis (SCA) of Android Dependencies by Creating a SBOM)
platform: android
---

[cdxgen](../../tools/generic/MASTG-TOOL-0134.md) を使用して、CycloneDX 形式のいわゆるソフトウェア部品表 (SBOM) を作成できます。スキャンしたい Android Studio プロジェクトのルートディレクトリに移動し、以下のコマンドを実行します。

```bash
$ cdxgen -t java -o sbom.json
```

作成された SBOM ファイルは Base64 エンコードする必要があり、[dependency-track](../../tools/generic/MASTG-TOOL-0132.md) にアップロードして解析できます。

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

dependency-track Docker コンテナのデフォルト設定を使用している場合には、<http://localhost:8080> にある dependency-check のフロントエンドに行きます。SBOM をアップロードしたプロジェクトを開き、脆弱な依存関係があるかどうかを検証できます。

> [!NOTE]
> [dependency-track](../../tools/generic/MASTG-TOOL-0132.md) では [Java および Kotlin](https://cyclonedx.github.io/cdxgen/#/PROJECT_TYPES) に対して推移的依存関係がサポートされています。
