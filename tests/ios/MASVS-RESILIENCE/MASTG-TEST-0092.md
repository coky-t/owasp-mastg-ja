---
masvs_v1_id:
- MSTG-RESILIENCE-5
masvs_v2_id:
- MASVS-RESILIENCE-1
platform: ios
title: エミュレータ検出のテスト (Testing Emulator Detection)
masvs_v1_levels:
- R
---

## 概要

エミュレータ検出をテストするには、["エミュレータ検出"](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#emulator-detection) のセクションで示されているように、さまざまなエミュレータ上でアプリを実行してみて、何が起こるかを確認します。

アプリは何らかの反応を示すはずです。たとえば以下のようなものです。

- ユーザーに警告し、責任を負うことを求めます。
- 穏やかに終了して、実行を防止します。
- 不正検出など、バックエンドサーバーに報告します。

また、["エミュレータ検出"](../../../Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md#emulator-detection) のセクションの文字列やメソッドのアイデアを使用して、アプリをリバースエンジニアできます。

次に、この検出のバイパスに取り組み、以下の質問に回答します。

- そのメカニズムは簡単に (たとえば、一つの API 関数をフックするなどで) バイパスできますか？
- 静的解析および動的解析によって検出コードを特定することはどのくらい難しいですか？
- その防御を無効にするカスタムコードを書くことは必要はありますか？どのくらい時間がかかりましたか？
- そのメカニズムをバイパスすることの難しさをどのように評価しますか？
