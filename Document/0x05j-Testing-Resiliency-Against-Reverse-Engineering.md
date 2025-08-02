---
masvs_category: MASVS-RESILIENCE
platform: android
---

# Android のアンチリバース防御

## 概要

**一般的な免責事項:**

**これらの対策のいずれが欠けても、脆弱性を生み出すことはありません** 。むしろ、リバースエンジニアリングや特定のクライアントサイド攻撃に対するアプリの耐性を高めることを目的としています。

リバースエンジニアは常にデバイスにフルアクセスできるので (十分な時間とリソースがあれば) 必ず勝利できるため、これらの対策はいずれも 100% の効果を保証するものではありません。

たとえば、デバッグを防止することは事実上不可能です。アプリを公開している場合、攻撃者の完全な制御下にある信頼できないデバイス上で実行される可能性があります。非常に意志の固い攻撃者はアプリバイナリにパッチを当てるか Frida などのツールを使用して実行時にアプリの動作を動的に変更して、最終的にアプリのアンチデバッグ制御をすべてバイパスするでしょう。

リバースエンジニアリングとコード変更の原則と技術的リスクについての詳細は以下の OWASP ドキュメントを参照してください。

- [OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering](https://wiki.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project "OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering")
- [OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification](https://wiki.owasp.org/index.php/Technical_Risks_of_Reverse_Engineering_and_Unauthorized_Code_Modification "OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification")
