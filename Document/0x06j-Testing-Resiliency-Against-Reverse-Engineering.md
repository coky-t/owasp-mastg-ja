---
masvs_category: MASVS-RESILIENCE
platform: ios
---

# iOS のアンチリバース防御

## 概要

この章では機密データや機能を処理したり、アクセスを許可するアプリに推奨される多層防御対策について説明します。調査によると [多くの App Store アプリにはこれらの対策が含まれていることがよくあります](https://seredynski.com/articles/a-security-review-of-1-300-appstore-applications "A security review of 1,300 AppStore applications - 5 April 2020") 。

アプリの不正改竄やコードのリバースエンジニアリングによって引き起こされるリスクの評価に基づいて、必要に応じてこれらの対策を適用すべきです。

- アプリはこれらの対策を決してセキュリティコントロールの代わりとして使用してはいけません。つまり、別の MASVS セキュリティコントロールなど、他の基本的なセキュリティ対策を満たすことが期待されます。
- アプリはこれらの対策を個別に使用するのではなく、巧みに組み合わせるべきです。その目的はリバースエンジニアがさらなる解析を行うことを阻止することです。
- アプリにいくつかのコントロールを統合すると、アプリの複雑さが増し、パフォーマンスに影響を与えることがあります。

リバースエンジニアリングとコード変更の原則と技術的リスクについての詳細は以下の OWASP ドキュメントを参照してください。

- [OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering](https://wiki.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project "OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering")
- [OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification](https://wiki.owasp.org/index.php/Technical_Risks_of_Reverse_Engineering_and_Unauthorized_Code_Modification "OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification")

**一般的な免責事項:**

**これらの対策のいずれが欠けても、脆弱性を生み出すことはありません**。むしろ、リバースエンジニアリングや特定のクライアントサイド攻撃に対するアプリの耐性を高めることを目的としています。

リバースエンジニアは常にデバイスにフルアクセスできるので (十分な時間とリソースがあれば) 必ず勝利できるため、これらの対策はいずれも 100% の効果を保証するものではありません。

たとえば、デバッグを防止することは事実上不可能です。アプリを公開している場合、攻撃者の完全な制御下にある信頼できないデバイス上で実行される可能性があります。非常に意志の固い攻撃者はアプリバイナリにパッチを当てるか Frida などのツールを使用して実行時にアプリの動作を動的に変更して、最終的にアプリのアンチデバッグ制御をすべてバイパスするでしょう。

後述するテクニックによって、攻撃者がアプリを標的とする可能性のあるさまざまな方法を検出できます。これらのテクニックは公開されているため、一般的に簡単にバイパスできます。オープンソースの検出テクニックを使用することは、アプリの耐性を向上するための良い第一歩ですが、標準的なアンチ検出ツールで簡単にバイパスできます。商用製品は、以下のような複数のテクニックを組み合わせることで、一般的により高い耐性を提供します。

- 文書化されていない検出テクニックを使用すること
- 同じテクニックをさまざまな方法で実装すること
- さまざまなシナリオで検出ロジックをトリガーすること
- ビルドごとにユニークな検出の組み合わせを提供すること
- バックエンドコンポーネントと連携して、追加の検証と HTTP ペイロードの暗号化を行うこと
- 検出ステータスをバックエンドに伝達すること
- 高度な静的難読化
