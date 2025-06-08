---
masvs_v1_id:
- MSTG-PLATFORM-2
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: ローカルストレージの入力バリデーションのテスト (Testing Local Storage for Input Validation)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

パブリックにアクセス可能なデータストレージでは、どのプロセスでもデータをオーバーライドできます。つまり、データを再び読み取る瞬間に入力バリデーションを適用する必要があります。

> 注意: ルート化されたデバイス上のプライベートにアクセス可能なデータについても同じことが当てはまります。

## 静的解析

### Shared Preferences の使用

`SharedPreferences.Editor` を使用して int/boolean/long 値を読み書きする場合、データがオーバーライドされているかどうかをチェックできません。しかし、値を連鎖する以外の実際の攻撃にはほとんど使用できません (たとえば、制御フローを引き継ぐような追加のエクスプロイトをパックすることはできません) 。 `String` や `StringSet` の場合にはデータの解釈方法に注意する必要があります。
リフレクションベースの永続化を使用していますか？Android の「オブジェクト永続化のテスト」のセクションをチェックして、どのように検証すべきか確認してください。
`SharedPreferences.Editor` を使用して証明書やカギを保存したり読み取りますか？ [Bouncy Castle](https://www.cvedetails.com/cve/CVE-2018-1000613/ "Key reading vulnerability due to unsafe reflection") で見つかったような脆弱性を考慮して、セキュリティプロバイダにパッチ適用していることを確認してください。

どのような場合でも、コンテンツを HMAC 化することで、追加や変更が適用されていないことを確認できます。

### 他のストレージメカニズムの使用

他のパブリックストレージメカニズム (`SharedPreferences.Editor` 以外) が使用されている場合、データはストレージメカニズムから読み取られた瞬間に検証される必要があります。
