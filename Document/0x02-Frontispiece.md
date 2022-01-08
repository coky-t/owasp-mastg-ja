# 扉

![OWASP MSTG](Images/OWASP_logo.png) \

## OWASP モバイルセキュリティテストガイドについて

OWASP モバイルセキュリティテストガイド (MSTG) はモバイルアプリのセキュリティをテストするための包括的なマニュアルです。[モバイルアプリケーションセキュリティ検証標準 (MASVS)](https://github.com/OWASP/owasp-masvs "MASVS") に記載される要件を検証するためのプロセスと技法について説明し、完全かつ一貫したセキュリティテストのベースラインを提供します。

OWASP は多くの執筆者、レビュー担当者、編集者がこのガイドの開発に熱心に取り組んでくれたことに感謝しています。モバイルセキュリティテストガイドにコメントや提案がある場合は、[OWASP Mobile Security Project Slack Channel](https://owasp.slack.com/messages/project-mobile_omtg/details/ "OWASP Mobile Security Project Slack Channel") に参加して MASVS や MSTG の議論に参加してください。あなたは [この URL](https://owasp.slack.com/join/shared_invite/zt-g398htpy-AZ40HOM1WUOZguJKbblqkw# "Slack channel sign up") を使用して自分で Slack チャネルにサインアップできます。

> 招待状の有効期限が切れている場合は私たちの GitHub Repo で issue を開いてください。

## 免責事項

MSTG の資料を利用してモバイルアプリに対するテストを実行する前に、お住まいの国の法律を参照してください。MSTG に記載されているもので法律に違反してはいけません。

[行動規範](https://github.com/OWASP/owasp-mstg/blob/master/CODE_OF_CONDUCT.md "Code of Conduct") に詳細があります。

## 著作権とライセンス

Copyright © 2021 The OWASP Foundation. 本書は [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/ "Creative Commons Attribution-ShareAlike 4.0 International License") に基づいて公開されています。再使用または配布する場合は、他者に対し本著作物のライセンス条項を明らかにする必要があります。

![OWASP MSTG](Images/CC-license.png) \

## ISBN

ISBN 番号は 978-1-257-96636-3 です。 MSTG のハードコピーは [lulu.com](https://www.lulu.com/search?adult_audience_rating=00&page=1&pageSize=10&q=mobile+security+testing+guide) で注文できます。

## 謝辞

**注意**: この寄稿者テーブルは [GitHub contribution statistics](https://github.com/OWASP/owasp-mstg/graphs/contributors "GitHub contribution statistics") に基づいて作成しています。これらの統計情報の詳細については、[GitHub Repository README](https://github.com/OWASP/owasp-mstg/blob/master/README.md "GitHub Repository README") を参照ください。手動でテーブルを更新しますので、あなたがすぐにリストに載らなくてもあわてないでください。

### 執筆者

#### Bernhard Mueller

Bernhard はあらゆる種類のシステムをハックする才能を持つサイバーセキュリティの専門家です。業界で10年以上にわたり、MS SQL Server, Adobe Flash Player, IBM Director, Cisco VOIP, ModSecurity などのソフトウェアに対するゼロデイエクスプロイトを多数公表しています。それに名前をつけることができても、おそらく少なくとも一度はそれを破棄しているでしょう。BlackHat USA は Pwnie Award for Best Research でモバイルセキュリティの先駆的な取り組みを賞賛しました。

#### Sven Schleier

Sven は経験豊かなウェブおよびモバイルのペネトレーションテスト技術者であり、歴史上有名な Flash アプリケーションからプログレッシブモバイルアプリまでのすべてを評価しています。彼はセキュリティエンジニアでもあり、SDLC の中でエンドツーエンドで多くのプロジェクトをサポートし「セキュリティを構築」しています。彼はローカルおよびインターナショナルの会議やカンファレンスで講演し、ウェブアプリケーションやモバイルアプリのセキュリティに関するハンズオンワークショップを行っています。

#### Jeroen Willemsen

Jeroen は Xebia の主要なセキュリティアーキテクトであり、モバイルセキュリティとリスク管理に対する情熱を持っています。彼はセキュリティコーチ、セキュリティエンジニアとして企業をサポートしておりフルスタックの開発者としてどんな仕事でもこなします。彼は、セキュリティ問題からプログラミングの課題まで、技術的な問題を議論するのが大好きです。

#### Carlos Holguera

Carlos は ESCRYPT のモバイルペネトレーションテストチームを率いるセキュリティエンジニアです。彼はモバイルアプリや自動車のコントロールユニットや IoT デバイスなどの組込みシステムのセキュリティテストの分野で長年の実務経験を積んできました。彼はモバイルアプリのリバースエンジニアリングと動的計装に熱心に取り組んでおり、継続的に学び、知識を共有しています。

### 共同執筆者

共同執筆者は一貫して質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 2,000 件の追加が記録されています。

#### Romuald Szkudlarek

Romuald はウェブ、モバイル、IoT、クラウドの分野で 15 年以上の経験を持つ情熱的なサイバーセキュリティおよびプライバシーの専門家です。彼のキャリアの中で、彼はソフトウェアとセキュリティの分野を進歩させることを目標に、さまざまなプロジェクトに余暇をささげていました。彼はさまざまな機関で定期的に指導しています。彼は CISSP, CCSP, CSSLP, CEH の資格を保持しています。

#### Jeroen Beckers

Jeroen は NVISO のモバイルセキュリティのリーダーであり、モバイルセキュリティプロジェクトの品質保証とモバイルに関するあらゆることの研究開発を担当しています。彼は高校および大学で Flash 開発者として従事していましたが、卒業してからはサイバーセキュリティのキャリアに切り替え、現在ではモバイルセキュリティの分野で 5 年以上の経験があります。彼は高専、大学、クライアント、カンファレンスでの多くの講演や研修で明らかなように、他の人たちと自分の知識を共有することを大事にしています。

#### Vikas Gupta

Vikas はモバイルセキュリティの専門知識を持つ経験豊富なサイバーセキュリティ研究者です。これまでのキャリアではフィンテック、銀行、政府機関などさまざまな業界のアプリケーションをセキュアにすることに取り組んできました。リバースエンジニアリング、特に難読化されたネイティブコードと暗号化を得意としています。セキュリティとモバイルコンピューティングの修士号と OSCP 資格を保有しています。彼は自分の知識を共有し、アイデアを交換することに常にオープンです。

### 主寄稿者

主寄稿者は一貫して質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 500 件の追加が記録されています。

- Pawel Rzepa
- Francesco Stillavato
- Henry Hoggard
- Andreas Happe
- Kyle Benac
- Paulino Calderon
- Alexander Anthuk
- Caleb Kinney
- Abderrahmane Aftahi
- Koki Takeyama
- Wen Bin Kong
- Abdessamad Temmar
- Cláudio André
- Slawomir Kosowski
- Bolot Kerimbaev
- Lukasz Wierzbicki

<br/>
<br/>

### 寄稿者

寄稿者は質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 50 件の追加が記録されています。彼らの GitHub ハンドルは以下のとおりです。

kryptoknight13, DarioI, luander, oguzhantopgul, Osipion, mpishu, pmilosev, isher-ux, thec00n, ssecteam, jay0301, magicansk, jinkunong, nick-epson, caitlinandrews, dharshin, raulsiles, righettod, karolpiateknet, mkaraoz, Sjord, bugwrangler, jasondoyle, joscandreu, yog3shsharma, ryantzj, rylyade1, shivsahni, diamonddocumentation, 51j0, AnnaSzk, hlhodges, legik, abjurato, serek8, mhelwig, locpv-ibl, ThunderSon

### 他の寄稿者

他の多くの寄稿者が単一の単語や文章など (追加数が 50 件未満) の少量のコンテンツをコミットしています。彼らの GitHub ハンドルは以下のとおりです。

jonasw234, zehuanli, jadeboer, Isopach, prabhant, jhscheer, meetinthemiddle-be, bet4it, aslamanver, juan-dambra, OWASP-Seoul, hduarte, TommyJ1994, forced-request, D00gs, vasconcedu, mehradn7, whoot, LucasParsy, DotDotSlashRepo, enovella, ionis111, vishalsodani, chame1eon, allRiceOnMe, crazykid95, Ralireza, Chan9390, tamariz-boop, abhaynayar, camgaertner, EhsanMashhadi, fujiokayu, decidedlygray, Ali-Yazdani, Fi5t, MatthiasGabriel, colman-mbuya, anyashka

### レビュー担当者

レビュー担当者は GitHub issues および pull request コメントを通して有用なフィードバックを一貫して提供しています。

- Jeroen Beckers
- Sjoerd Langkemper
- Anant Shrivastava

### 編集者

- Heaven Hodges
- Caitlin Andrews
- Nick Epson
- Anita Diamond
- Anna Szkudlarek

### 支援者

MASVS と MSTG のいずれもコミュニティにより無償奉仕で作成および維持されていますが、時にはいくらかの外的支援が必要となることもあります。したがって、テクニカルエディタを雇うことができる資金を提供した支援者に感謝します。彼らの支援は MASVS や MSTG の内容にいかなる形であれ影響を与えないことに注意します。支援パッケージは [OWASP Project Wiki](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide#tab=Sponsorship_Packages "OWASP Mobile Security Testing Guide Donation Packages") に記載されています。

### 特別栄誉支援者 (God Mode Donators)

![OWASP MSTG](Images/Donators/NowSecure_logo.png) \

[OWASP Bay Area Chapter](https://twitter.com/OWASPBayArea?ref_src=twsrc%5Egoogle%7Ctwcamp%5Eserp%7Ctwgr%5Eauthor "Twitter Bay Area")

#### 名誉後援者 (Honorable Benefactor)

![OWASP MSTG](Images/Donators/SEC_Consult_logo.png) \

![OWASP MSTG](Images/Donators/ZIMPERIUM_logo.png) \

#### 慈善後援者 (Good Samaritan Benefactor)

![OWASP MSTG](Images/Donators/Randorisec_logo.png) \

### 旧版

モバイルセキュリティテストガイドは2015年に Milan Singh Thakur によって開始されました。元のドキュメントは Google ドライブでホストされていました。ガイド開発は2016年10月に GitHub に移されました。

#### OWASP MSTG "Beta 2" (Google Doc)

| 執筆者 | レビュー担当者 | 主寄稿者 |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Blessen Thomas, Dennis Titze, Davide Cioccia, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Ali Yazdani, Mirza Ali, Rahil Parikh, Anant Shrivastava, Stephen Corbiaux, Ryan Dewhurst, Anto Joseph, Bao Lee, Shiv Patel, Nutan Kumar Panda, Julian Schütte, Stephanie Vanroelen, Bernard Wagner, Gerhard Wagner, Javier Dominguez | Andrew Muller, Jonathan Carter, Stephanie Vanroelen, Milan Singh Thakur  | Jim Manico, Paco Hope, Pragati Singh, Yair Amit, Amin Lalji, OWASP Mobile Team|

#### OWASP MSTG "Beta 1" (Google Doc)

| 執筆者 | レビュー担当者 | 主寄稿者 |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh | Andrew Muller, Jonathan Carter | Jim Manico, Paco Hope, Yair Amit, Amin Lalji, OWASP Mobile Team  |
