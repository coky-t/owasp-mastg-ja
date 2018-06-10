# 扉

## OWASP モバイルセキュリティテストガイドについて

OWASP モバイルセキュリティテストガイド (MSTG) はモバイルアプリのセキュリティをテストするための包括的なマニュアルです。[モバイルアプリケーションセキュリティ検証標準 (MASVS)](https://github.com/OWASP/owasp-masvs) [(日本語訳)](https://github.com/coky-t/owasp-masvs-ja) に記載される要件を検証するためのプロセスと技法について説明し、完全かつ一貫したセキュリティテストのベースラインを提供します。

OWASP は多くの著者、レビュー担当者、編集者がこのガイドの開発に熱心に取り組んでくれたことに感謝しています。モバイルセキュリティテストガイドにコメントや提案がある場合は、[OWASP Mobile Security Project Slack Channel](https://owasp.slack.com/messages/project-mobile_omtg/details/) に参加して MASVS や MSTG の議論に参加してください。[http://owasp.herokuapp.com/](http://owasp.herokuapp.com/) で Slack チャンネルにサインアップできます。

## 著作権とライセンス

![license](Images/license.jpg)
Copyright © 2017 The OWASP Foundation. 本書は [クリエイティブコモンズ 表示 - 継承 4.0 国際 ライセンス](https://creativecommons.org/licenses/by-sa/4.0/deed.ja) に基づいて公開されています。再使用または配布する場合は、他者に対し本著作物のライセンス条項を明らかにする必要があります。

## 謝辞

**注意**: この寄稿者テーブルは [GitHub contribution statistics](https://github.com/OWASP/owasp-mstg/graphs/contributors) に基づいて作成しています。これらの統計情報の詳細については、[GitHub Repository README](https://github.com/OWASP/owasp-mstg/blob/master/README.md) を参照ください。数週間ごとに手動でテーブルを更新しますので、あなたがすぐにリストに載らなくてもあわてないでください。

### 執筆者

#### Bernhard Mueller

Bernhard はあらゆる種類のシステムをハックする才能を持つサイバーセキュリティの専門家です。業界で10年以上にわたり、MS SQL Server, Adobe Flash Player, IBM Director, Cisco VOIP, ModSecurity などのソフトウェアに対するゼロデイエクスプロイトを多数公表しています。それに名前をつけることができても、おそらく少なくとも一度はそれを破棄しているでしょう。BlackHat USA は Pwnie Award for Best Research でモバイルセキュリティの先駆的な取り組みを賞賛しました。

#### Sven Schleier

Sven は経験豊かなペネトレーションテスト技術者であり、ウェブアプリケーション、iOS アプリ、Android アプリのセキュアな SDLC の実装を専門とするセキュリティアーキテクトです。彼は OWASP モバイルセキュリティテストガイドのプロジェクトリーダーであり、OWASP Mobile Hacking Playground の製作者です。Sven はウェブとモバイルアプリのセキュリティテストに関するハンズオンワークショップで、フリーでコミュニティのサポートもしています。

### 共同執筆者

共同執筆者は一貫して質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 2,000 件の追加が記録されています。

#### Romuald Szkudlarek

Romuald はウェブ、モバイル、IoT、クラウドの分野で 15 年以上の経験を持つ情熱的なサイバーセキュリティおよびプライバシーの専門家です。彼のキャリアの中で、彼はソフトウェアとセキュリティの分野を進歩させることを目標に、さまざまなプロジェクトに余暇をささげていました。彼はさまざまな機関で定期的に指導しています。彼は CISSP, CCSP, CSSLP, CEH の資格を保持しています。

#### Jeroen Willemsen

Jeroen は Xebia の IT セキュリティ専門のフルスタック開発者であり、モバイルとリスク管理に情熱を持っています。技術課題を説明する愛に駆り立てられ、彼は学生を卒業する前に PHP の先生を始め、セキュリティ、リスク管理、プログラミングの問題を聞いて学びたいと思う人と議論しています。

### 主寄稿者

主寄稿者は一貫して質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 500 件の追加が記録されています。

- Pawel Rzepa
- Francesco Stillavato
- Andreas Happe
- Alexander Anthuk
- Henry Hoggard
- Wen Bin Kong
- Abdessamad Temmar
- Bolot Kerimbaev
- Slawomir Kosowski

### 寄稿者

寄稿者は質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 50 件の追加が記録されています。

Jin Kung Ong, Sjoerd Langkemper, Gerhard Wagner, Michael Helwig, Pece Milosev, Denis Pilipchuk, Ryan Teoh, Dharshin De Silva, Anatoly Rosencrantz, Abhinav Sejpa, Daniel Ramirez Martin, Claudio André, Enrico Verzegnassi, Yogesh Sharma, Dominique Righetto, Raul Siles, Prathan Phongthiproek, Tom Welch, Luander Ribeiro, Dario Incalza, Akanksha Bana, Oguzhan Topgul, Carlos Holguera, David Fern, Pishu Mahtani, Anuruddha E.

### レビュー担当者

レビュー担当者は GitHub issues および pull request コメントを通して有用なフィードバックを一貫して提供しています。

- Sjoerd Langkemper
- Anant Shrivastava

### 編集者

- Heaven Hodges
- Caitlin Andrews
- Nick Epson
- Anita Diamond
- Anna Szkudlarek

### その他

他の多くの寄稿者が単一の単語や文章など (追加数が 50 件未満) の少量のコンテンツをコミットしています。寄稿者の完全なリストは GitHub にあります。

https://github.com/OWASP/owasp-mstg/graphs/contributors

### 旧版

モバイルセキュリティテストガイドは2015年に Milan Singh Thakur によって開始されました。元のドキュメントは Google ドライブでホストされていました。ガイド開発は2016年10月に GitHub に移されました。

**OWASP MSTG "Beta 2" (Google Doc)**

| 執筆者 | レビュー担当者 | 主寄稿者 |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Blessen Thomas, Dennis Titze, Davide Cioccia, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh, Anant Shrivastava, Stephen Corbiaux, Ryan Dewhurst, Anto Joseph, Bao Lee, Shiv Patel, Nutan Kumar Panda, Julian Schütte, Stephanie Vanroelen, Bernard Wagner, Gerhard Wagner, Javier Dominguez | Andrew Muller, Jonathan Carter, Stephanie Vanroelen, Milan Singh Thakur  | Jim Manico, Paco Hope, Pragati Singh, Yair Amit, Amin Lalji, OWASP Mobile Team|

**OWASP MSTG "Beta 1" (Google Doc)**

| 執筆者 | レビュー担当者 | 主寄稿者 |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh | Andrew Muller, Jonathan Carter | Jim Manico, Paco Hope, Yair Amit, Amin Lalji, OWASP Mobile Team  |
