---
title: Maestro
platform: generic
source: https://github.com/mobile-dev-inc/maestro
hosts: [windows, linux, macOS]
---

[Maestro](https://github.com/mobile-dev-inc/maestro) は、Android、iOS、ウェブアプリ向けのオープンソース UI テストフレームワークです。フローと呼ばれる YAML ファイルに、要素のタップ、テキストの入力、スクリーンショットの撮影といった操作を記述すると、Maestro は、接続されたデバイスやエミュレータ上のアプリに対してそれらを実行します。

セキュリティテストでは、スクリーンの UI 階層を調査したり、たとえば、他のツールを実行する前に特定のスクリーンに到達するように、反復的な UI 操作を自動化する際に、Maestro が役立ちます。

## インストール

Maestro は Java 17 以降を必要とします。以下のコマンドでそれをインストールします。

```bash
curl -fsSL "https://get.maestro.mobile.dev" | bash
```

他のインストールオプションについては [公式ドキュメント](https://docs.maestro.dev/) を参照してください。

## 使用方法

現在のスクリーンの UI 階層を JSON で出力します。

```bash
maestro hierarchy
```

フローを実行します。

```bash
maestro test flow.yaml
```

> [!NOTE]
> Android では、Maestro はアクセシビリティフレームワークを通じて UI を読み取ります。そのため、その階層はアクセシビリティフレームワークが公開する属性のみを含みます。この手法は他の手法と比較して何を明らかにするかについては [UI 階層の評価 (Inspecting the UI Hierarchy)](../../techniques/android/MASTG-TECH-0177.md) を参照してください。
