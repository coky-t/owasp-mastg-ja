---
platform: ios
title: アプリの SBOM での既知の脆弱性を持つ依存関係 (Dependencies with Known Vulnerabilities in the App's SBOM)
id: MASTG-TEST-0275
type: [static, developer]
weakness: MASWE-0076
profiles: [L1, L2]
---

## 概要

このテストケースでは、ソフトウェア部品表 (SBOM) を使用して、iOS アプリケーションにおける既知の脆弱性を持つ依存関係をチェックします。SBOM はソフトウェアのコンポーネントと依存関係を記述するための標準である CycloneDX 形式である必要があります。

## 手順

1. [SBOM を作成することによる iOS 依存関係のソフトウェアコンポジション分析 (SCA) (Software Composition Analysis (SCA) of iOS Dependencies by Creating a SBOM)](../../../techniques/ios/MASTG-TECH-0132.md) を使用して、SBOM を生成するか、開発チームから CycloneDX 形式のものをリクエストします。
2. SBOM を [dependency-track](../../../tools/generic/MASTG-TOOL-0132.md) にアップロードします。
3. [dependency-track](../../../tools/generic/MASTG-TOOL-0132.md) プロジェクトに脆弱な依存関係の使用がないか検査します。

## 結果

出力には名前と CVE 識別子 (存在する場合) を持つ依存関係のリストを含む可能性があります。

## 評価

既知の脆弱性を持つ依存関係を見つけた場合、そのテストケースは不合格です。
