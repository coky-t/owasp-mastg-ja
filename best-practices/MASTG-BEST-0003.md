---
title: プライバシー規制とベストプラクティスの遵守 (Comply with Privacy Regulations and Best Practices)
alias: comply-with-privacy-regulations
id: MASTG-BEST-0003
platform: android
---


[CWE-359](https://cwe.mitre.org/data/definitions/359.html) からの推奨事項。

## フェーズ: 要件

個人のプライバシーに関するすべての関連規制を特定して考慮します。組織は、その所在地、執り行う事業の種類、取り扱う個人データの性質に応じて、特定の連邦および州の規制に準拠することを要求されることがあります。規制には、セーフハーバープライバシーフレームワーク [REF-340]、グラムリーチブライリー法 (GLBA) [REF-341]、医療保険の相互運用性と説明責任に関する法律 (HIPAA) [REF-342]、一般データ保護規則 (GDPR) [REF-1047]、カリフォルニア州消費者プライバシー法 (CCPA) [REF-1048] などがあります。

## フェーズ: アーキテクチャと設計

安全な設計がプライバシーにどのように影響するか、またその逆はどうかを慎重に評価します。セキュリティとプライバシーの懸念は互いに競合しているように見えることがよくあります。

- セキュリティの観点からは、重要な操作はすべて記録して、異常なアクティビティを後で特定できるようにすべきです。
- しかし、個人データが関連する場合、このやり方は実際にリスクを生み出す可能性があります。個人データが安全でない扱われ方をする方法は多数ありますが、よくあるリスクは誤った信頼に起因するものです。

プログラマーはプログラムを実行するオペレーティング環境を信頼することが多く、そのため、ファイルシステム、レジストリ、その他のローカルで制御されたリソースに個人情報を保存しても構わないと考えています。しかし、たとえ特定のリソースへのアクセスが制限されていたとしても、アクセスできる個人が信頼できるとは限りません。

## 参考情報

- [REF-340] U.S. Department of Commerce. "Safe Harbor Privacy Framework". <https://web.archive.org/web/20010223203241/http://www.export.gov/safeharbor/>. URL validated: 2023-04-07.
- [REF-341] Federal Trade Commission. "Financial Privacy: The Gramm-Leach Bliley Act (GLBA)". <https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act>. URL validated: 2023-04-07.
- [REF-342] U.S. Department of Human Services. "Health Insurance Portability and Accountability Act (HIPAA)". <https://www.hhs.gov/hipaa/index.html>. URL validated: 2023-04-07.
- [REF-1047] Wikipedia. "General Data Protection Regulation". <https://en.wikipedia.org/wiki/General_Data_Protection_Regulation>.
- [REF-1048] State of California Department of Justice, Office of the Attorney General. "California Consumer Privacy Act (CCPA)". <https://oag.ca.gov/privacy/ccpa>.
