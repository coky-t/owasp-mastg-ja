---
platform: ios
title: アプリの SBOM での既知の脆弱性を持つ依存関係 (Dependencies with Known Vulnerabilities in the App's SBOM)
id: MASTG-TEST-0275
type: [static, developer]
weakness: MASWE-0076
---

## 概要

This test case checks for dependencies with known vulnerabilities in iOS applications by using a Software Bill of Materials (SBOM). The SBOM should be in CycloneDX format, which is a standard for describing the components and dependencies of software.

## 手順

1. 開発チームに CycloneDX 形式の SBOM を共有するように依頼するか、元のソースコードにアクセスできる場合は、[dependency-track](../../../tools/generic/MASTG-TOOL-0132.md) に従って SBOM を作成します。
2. SBOM を [dependency-track](../../../tools/generic/MASTG-TOOL-0132.md) にアップロードします。
3. [dependency-track](../../../tools/generic/MASTG-TOOL-0132.md) プロジェクトに脆弱な依存関係の使用がないか検査します。

## 結果

出力には名前と CVE 識別子 (存在する場合) を持つ依存関係のリストを含む可能性があります。

## 評価

既知の脆弱性を持つ依存関係を見つけた場合、そのテストケースは不合格です。
