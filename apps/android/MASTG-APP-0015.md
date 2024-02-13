---
title: Android UnCrackable L4
platform: android
source: https://mas.owasp.org/crackmes/Android#android-uncrackable-l4
---

Radare2 コミュニティは、r2 ファンがさまざまな場所で支払いをしたり、r2 ユーザー間で送金できる、分散型のフリー通貨をいつも夢見ていました。r2Pay アプリのデバッグバージョンが開発され、まもなく多くの店舗やウェブサイトでサポートされる予定です。これが暗号的に解読できないことを検証できますか？

ヒント: アプリを少し動かすには、改竄していないデバイスで APK を実行します。

1. 画面上に緑色のトークン (別名 r2coins) を生成するマスター PIN コードがあります。赤色の r2coin が表示された場合、このトークンはコミュニティによって検証されません。4 桁の PIN コードと採用されているソルトを見つけ出す必要があります。フラグ: `r2con{PIN_NUMERIC:SALT_LOWERCASE}`
2. 「r2pay マスターキー」が難読化と保護の層に埋もれています。ホワイトボックスを破ることができますか？フラグ: `r2con{ascii(key)}`

**バージョン:**

- `v0.9` - OWASP MAS 向けリリース: ソースコードが利用可能であり、初心者にとって挑戦がより簡単で楽しめるようにコンパイルは多くの方法で柔弱化しています。
- `v1.0` - R2con CTF 2020 向けリリース: ソースコードは利用可能ではなく、多くの特別な保護を施しています。

> [Eduardo Novella](https://github.com/enovella "Eduardo Novella") と [Gautam Arvind](https://github.com/darvincisec "Gautam Arvind") によって作成および保守されています。この crackme をサポートしてくれた [NowSecure](https://www.nowsecure.com "NowSecure") に心から感謝します。
