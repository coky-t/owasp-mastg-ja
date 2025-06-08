---
platform: ios
title: 依存関係マネージャのアーティファクトをスキャンして既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known Vulnerabilities by Scanning Dependency Managers Artifacts)
id: MASTG-TEST-0273
type: [static]
weakness: MASWE-0076
profiles: [L1, L2]
---

## 概要

このテストケースでは、iOS の既知の脆弱性を持つ依存関係を特定します。依存関係は依存関係マネージャを通じて統合されており、一つ以上の依存関係マネージャが使用されている可能性があります。したがって、SCA スキャンツールで解析するには、依存関係マネージャによって作成されたすべての関連するアーティファクトが必要です。

## 手順

1. 最も効率的な方法でこれを行うには、開発者にどの依存関係マネージャが使用されているかを尋ね、その開発者が作成した関連ファイルを共有する必要があります。パッケージマネージャの概要と関連するファイルのリクエストについては [パッケージマネージャのアーティファクトをスキャンしての iOS 依存関係のソフトウェアコンポジション解析 (SCA) (Software Composition Analysis (SCA) of iOS Dependencies by Scanning Package Manager Artifacts)](techniques/ios/MASTG-TECH-0133.md) に従います。

2. 依存関係マネージャによって作成されたファイルに対して [dependency-check](../../../tools/generic/MASTG-TOOL-0131.md) などの SCA 解析ツールを実行し、脆弱な依存関係の使用を探します。

## 結果

出力には依存関係の名前と、既知の脆弱性を持つ依存関係の CVE 識別子を含む可能性があります。

## 評価

既知の脆弱性を持つ依存関係を見つけた場合、そのテストケースは不合格です。
