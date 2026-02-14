---
title: dependency-track
platform: generic
source: https://github.com/DependencyTrack/dependency-track
---

Dependency-Track は、組織がソフトウェアサプライチェーンのリスクを特定して軽減できるようにするコンポーネント解析プラットフォームです。

- **インストール**: [docker](https://docs.dependencytrack.org/getting-started/deploy-docker/) を使用して Dependency-Track をインストールできます。デフォルトクレデンシャルは [initial setup](https://docs.dependencytrack.org/getting-started/initial-startup/) にあります。
- **入力**: Dependency-Track はソフトウェア部品表 (SBOM) を使用して、脆弱な依存関係を特定します。SBOM は [cdxgen](MASTG-TOOL-0134.md) などのツールを使用して生成し、[API](https://docs.dependencytrack.org/usage/cicd/) 経由でアップロードできます。
- **REST API**: REST API は [API キー](https://docs.dependencytrack.org/integrations/rest-api/) と、SBOM をアップデートできるプロジェクトで使用できます。
