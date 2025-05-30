---
platform: ios
title: アプリの SBOM での既知の脆弱性を持つ依存関係 (Dependencies with Known Vulnerabilities in the App's SBOM)
id: MASTG-TEST-0275
type: [static, developer]
weakness: MASWE-0076
---

## 概要

このテストケースでは、ソフトウェア部品表 (SBOM) を使用して、iOS アプリケーションにおける既知の脆弱性を持つ依存関係をチェックします。SBOM はソフトウェアのコンポーネントと依存関係を記述するための標準である CycloneDX 形式である必要があります。

## 手順

1. 開発チームに CycloneDX 形式の SBOM を共有するように依頼するか、元のソースコードにアクセスできる場合は、[dependency-track](../../../tools/generic/MASTG-TOOL-0132.md) に従って SBOM を作成します。
2. SBOM を [dependency-track](../../../tools/generic/MASTG-TOOL-0132.md) にアップロードします。
3. [dependency-track](../../../tools/generic/MASTG-TOOL-0132.md) プロジェクトに脆弱な依存関係の使用がないか検査します。

## 結果

出力には名前と CVE 識別子 (存在する場合) を持つ依存関係のリストを含む可能性があります。

## 評価

既知の脆弱性を持つ依存関係を見つけた場合、そのテストケースは不合格です。
