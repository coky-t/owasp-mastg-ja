## 機密データの特定 (Identifying Sensitive Data)

機密情報の分類は業界や国によって異なります。さらに、組織は機密データに制限的な見方をしたり、機密情報を明確に定義したデータ分類ポリシーを設けていることもあります。

データにアクセスできる状態には、一般的に以下の三つがあります。

- **保存時** - データはファイルやデータストアに保存されています
- **使用時** - アプリがデータをアドレス空間にロードしています
- **転送時** - データは、モバイルアプリとエンドポイントまたはデバイス上の消費プロセス (IPC (プロセス間通信) 時など) との間で交換されています

各状態に適した精査の程度は、データの重要性とアクセスされる可能性によって異なります。たとえば、アプリのメモリに保持されているデータはウェブサーバー上のデータよりコアダンプ経由でのアクセスに対してより脆弱かもしれません。攻撃者はウェブサーバーよりモバイルデバイスに物理的にアクセスする可能性が高くなるためです。

データ分類ポリシーが利用できない場合には、一般的に機密とみなされる情報の以下のリストを使用します。

- ユーザー認証情報 (クレデンシャル、PIN など)
- なりすましに悪用される可能性がある個人を識別できる情報 (PII) : 社会保障番号、クレジットカード番号、銀行口座番号、医療情報
- 個人を特定できる可能性があるデバイス識別子
- 漏洩すると風評被害や金銭的損失につながるような機密性の高いデータ
- 保護が法的義務であるデータ
- アプリ (またはその関連システム) によって生成され、他のデータやシステム自体を保護するために使用される技術データ (暗号鍵など)

「機密データ」の定義はテストを開始する前に決めておかなければなりません。定義なしに機密データの漏洩を検出することは不可能となるかもしれないためです。
