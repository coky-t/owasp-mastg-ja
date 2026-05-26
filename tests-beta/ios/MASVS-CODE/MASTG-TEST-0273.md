---
platform: ios
title: 依存関係マネージャのアーティファクトをスキャンして既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known Vulnerabilities by Scanning Dependency Managers Artifacts)
id: MASTG-TEST-0273
type: [static, code]
weakness: MASWE-0076
profiles: [L1, L2]
---

## 概要

このテストケースでは、iOS の既知の脆弱性を持つ依存関係を特定します。依存関係は依存関係マネージャを通じて統合されており、一つ以上の依存関係マネージャが使用されている可能性があります。したがって、SCA スキャンツールで解析するには、依存関係マネージャによって作成されたすべての関連するアーティファクトが必要です。

## 手順

1. [パッケージマネージャのアーティファクトをスキャンしての iOS 依存関係のソフトウェアコンポジション解析 (SCA) (Software Composition Analysis (SCA) of iOS Dependencies by Scanning Package Manager Artifacts)](../../../techniques/ios/MASTG-TECH-0133.md) をパッケージマネージャの概要について使用して、開発チームからの関連するアーティファクトファイルをリクエストします。
2. [パッケージマネージャのアーティファクトをスキャンしての iOS 依存関係のソフトウェアコンポジション解析 (SCA) (Software Composition Analysis (SCA) of iOS Dependencies by Scanning Package Manager Artifacts)](../../../techniques/ios/MASTG-TECH-0133.md) を使用して、依存関係マネージャによって作成されたアーティファクトファイルをスキャンし、脆弱な依存関係を探します。

## 結果

出力には依存関係の名前と、既知の脆弱性を持つ依存関係の CVE 識別子を含む可能性があります。

## 評価

既知の脆弱性を持つ依存関係を見つけた場合、そのテストケースは不合格です。
