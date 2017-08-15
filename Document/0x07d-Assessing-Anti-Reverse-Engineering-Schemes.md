# ソフトウェア保護スキームの評価

ソフトウェア保護は議論の余地のあるトピックです。一部のセキュリティ専門家はクライアント側の保護を完全に棄却しています。Security-by-obscurity (隠蔽によるセキュリティ) は *現実には* セキュリティではなく、セキュリティの観点からは価値が加味されないと主張しています。MASVS と MSTG では、より実用的なアプローチを採用しています。ソフトウェア保護コントロールはモバイルの世界でかなり広く使用されています。明確な目的と現実的な期待を念頭に置いて使用され、堅牢なセキュリティコントロールを *置き換える* ために使用されない限り、そのようなコントロールに *何らかの* 利点があると私たちは主張します。

さらに、モバイルアプリのセキュリティテスト技術者は日常業務の中でアンチリバースメカニズムに遭遇し、動的解析を可能にするためにそれらを「処理」する方法だけでなく、これらのメカニズムが適切かつ効果的に使用されているかどうかを評価する必要もあります。「難読化を使用する必要がある」または「役に立たないためコードを難読化しない」などのアドバイスをクライアントに与えることでそれを無視することはありません。しかし、ほとんどのモバイルアプリのセキュリティテスト技術者はネットワークやウェブアプリケーションのセキュリティをバックグラウンドに持ちますが、意見を形成するために要求されるリバースエンジニアリングやクラッキングのスキルが欠けています。それに加えて、アンチリバーススキームをどのように評価すべきかについての方法論や業界のコンセンサスさえありません。

ソフトウェアベースのリバーシング防御のポイントはまさに不明瞭さを加えることです。一部の攻撃者が特定の目標を達成することを阻止するのに十分なほどの。開発者がこれを行うことを選択する理由はいくつかあります。例えば、その目的には、ソースコードや IP を盗み出すことをより困難にすることや、同じデバイス上で実行されているマルウェアがアプリの実行時の動作を改竄することを防ぐことがあります。

耐性のテストは特定の脅威に対するソフトウェア保護スキームの堅牢性を評価するプロセスです。通常、この種のテストはブラックボックスアプローチを使用して実行されます。ソフトウェア保護スキームの回避や、機密資産の抽出などのあらかじめ定義された目標に達するという目的です。このプロセスは一般的にペネトレーションテストに関連しないスキルを要求します。テスト技術者は高度なアンチリバーストリックと難読化技術を処理できる必要があります。伝統的に、これはマルウェアアナリストの領域です。

この形式のテストは通常のモバイルアプリのセキュリティテストのコンテキストで実行することも、ソフトウェア保護スキームの有効性を検証するためにスタンドアロンで実行することもできます。このプロセスは以下の高レベルの手順で構成されます。

1. 適切かつ合理的な脅威モデルが存在し、アンチリバースコントロールが脅威モデルに適合しているかどうかを評価する。
2. 静的解析と動的解析を組み合わせて使用して、特定された脅威に対抗する防御の有効性を評価する。言い換えると、攻撃者の役割を果たして、防御を破る。
3. 一部のシナリオでは、ホワイトボックステストを追加して、保護スキームの特定の機能を独立した方法で評価する (特定の難読化メソッドなど) 。

ソフトウェア保護はセキュリティコントロールの代替として使用してはいけないことに注意します。MASVS-R にリストされているコントロールは、MASVS のセキュリティ要件を満たしているアプリに、脅威に特有の追加の保護コントロールを追加することを意図しています。

ソフトウェア保護スキームの有効性はある程度まで独創性と秘密性に依存します。特定のスキームを標準化することはそのスキームを無効にするという不幸な副作用があります。時を置かずに、スキームをバイパスする汎用ツールが利用可能になります。保護を実装する標準的な方法を定義する代わりに、以下のアプローチを採用します。

1. 防御すべきリバースエンジニアリングプロセスに関する高水準の要件を列挙する。
2. メカニズムと全体的なスキームの有効性を決定するプロパティを強調する。
3. 特定のタイプの難読化および改竄のための堅牢性基準を列挙する。
4. テスト技術者に有効性を検証するための知識、プロセス、ツールを提供する。

項目1と2は MASVS (MASVS-R) のコントロールの「リバースエンジニアリングに対する耐性」グループにカバーされ、さらにテストガイドで詳述されています。MSTG はまた、項目3と4について非常に詳しく説明し、広範な攻撃と防御の技法を文書化しています。但し、すべての可能な保護スキームをテストするための完全なステップバイステップガイドを提供することは不可能です。有意義な評価を行うには、モバイルアプリのリバースおよびアンチリバースに精通している熟練のリバースエンジニアがテストを実施する必要があります。

## 脅威モデルとソフトウェア保護アーキテクチャの評価

クライアント側の保護は場合によっては望ましいのですが、不必要であるか逆効果となることさえあります。最悪の場合、ソフトウェア保護はセキュリティに関する誤った意識を引き起こし、悪いプログラミングプラクティスを推奨します。可能性のあるすべての場合に「うまく機能する」耐性コントロールの一般的にセットを提供することは不可能です。このため、何らかの形のソフトウェア保護を実装する前に、適切な攻撃モデルが必要な前提条件となります。脅威モデルは防御するクライアント側脅威を明確にする必要があります。脅威モデルは合理的な必要があることに注意します。例えば、ホワイトボックス実装で暗号化鍵を隠すことは、攻撃者がホワイトボックス全体を簡単にコードリフトできるかどうかがポイントになります。また、スキームの有効性に関する期待を明示する必要があります。

OWASP Reverse Engineering and Code Modification Prevention Project <sup>[1]</sup> にはリバースエンジニアリングと改竄に関連する以下の技術的脅威が記載されています。

- なりすまし - 攻撃者は被害者のデバイス上のコードを改変して、アプリケーションがユーザーの認証資格情報 (ユーザー名およびパスワード) を第三者の悪意のあるサイトに送信するように強制する可能性があります。それにより、攻撃者は将来のトランザクションでそのユーザーとして偽装する可能性があります。

- 改竄 - 攻撃者はアプリケーションに埋め込まれた上位レベルのビジネスロジックを改変して、自由にいくつかの追加の価値を得ることを望む可能性があります。例えば、攻撃者はモバイルアプリケーションに埋め込まれたデジタル著作権管理コードを改変して、自由に音楽などのデジタル資産を得る可能性があります。

- 否認 - 攻撃者はモバイルアプリケーションに埋め込まれたログ出力または監査コントロールを無効にして、ユーザーが特定のトランザクションを実行したことを組織が検証できないようにする可能性があります。

- 情報開示 - 攻撃者はモバイルアプリケーションを改変して、モバイルアプリケーション内に含まれる非常に機密性の高い資産を開示する可能性があります。重要な資産には次のものがあります。デジタル鍵、証明書、資格情報、メタデータ、プロプライエタリであるアルゴリズム。

- サービス拒否 - 攻撃者はモバイルデバイスアプリケーションを改変して、定期的にクラッシュさせるもしくは永久に無効化して、ユーザーがそのデバイスを介してオンラインサービスにアクセスできないようにする可能性があります。

- 権限昇格 - 攻撃者はモバイルアプリケーションを改変し、再パッケージ化されたものを再配布して、ユーザーがアプリでできる範囲外の操作を実行する可能性があります。

## 評価プロセス

ソフトウェア保護の有効性はホワイトボックスまたはブラックボックスのアプローチを使用して評価できます。「通常の」セキュリティ評価と同様に、テスト担当者は静的および動的解析を実行しますが目的が異なります。セキュリティ上の欠陥を特定するのではなく、アンチリバース防御の穴を特定することが目標です。評価されるプロパティは *耐性* であり、*セキュリティ* とは対照的です。また、評価の範囲と深さは、特定の機能の改竄など、具体的なシナリオに合わせて調整する必要があります。耐性の評価は通常のセキュリティ評価の一環として実行することもできます。

### 設計レビュー

ソフトウェア保護スキームとその個々のコンポーネント (改竄防止、デバッグ防止、デバイスバインディング、難読化変換など) をレビューおよび評価する。

### ブラックボックスの耐性テスト

特定の攻撃に対するホワイトボックスの暗号ソリューションの堅牢性を評価します。実装についての事前の知識なしに、保護を破るまたは回避することを目的とします。

ブラックボックスアプローチの利点はリバースエンジニアリング保護の実世界での有効性を反映していることです。同等のスキルレベルとツールセットを持つ実攻撃者に要求される労力は評価者が投じた労力に近くなります。

--[ TODO ] --

欠点：一例として、その結果は評価者のスキルレベルに大きく影響を受けます。また、最先端の保護を備えたプログラムを完全にリバースエンジニアリングするための労力は非常に高くなります (まさにそれを持つことがポイントです) 。一部のアプリではリバースエンジニアを数週間占有する可能性があります。経験豊富なリバースエンジニアは安くはありませんし、アプリのリリースを遅らせることは「アジャイルな」世界では可能ではないかもしれません。

<img src="Images/Chapters/0x07b/blackbox-resiliency-testing.png" width="650px" />

### 難読化の有効性評価

ホワイトボックス暗号または仮想マシンのカスタム実装などの複雑な難読化スキームは、ホワイトボックスアプローチを使用して独立した方式で適切に評価します。このような評価には特定の種類の難読化をクラックする際の専門知識を要求します。この種類の評価では、現在の最先端の逆難読化技法に対する耐性を判断し、手動解析に対する堅牢性の見積りを提供することを目標としています。

## 主要な質問

耐性テストでは以下の質問に回答すべきです。

**保護スキームは想定している脅威を防ぐものですか？**

アンチリバースの銀の弾丸はないことを繰り返す価値があります。

**保護スキームの耐性は期待するレベル達していますか？**

アンチリバースの銀の弾丸はないことを繰り返す価値があります。

**スキームはリバースエンジニアが使用するプロセスやツールに対して包括的に防御していますか？**

--[ TODO ] --

**適切な種類の難読化が適切な場所で適切なパラメータとともに使用されていますか？**

--[ TODO ] --

- プログラムによる防御は「アンチリバーストリック」に対する耳当たりのよい言葉です。保護スキームが有効であると考えられるためには、これらの防御を多く組み込む必要があります。「プログラムによる」とはこれらの種類の防御が物事を *行う* ことを意味しています。それらはリバースエンジニアの行動を防止する、またはそれに反応する機能です。これはプログラムの見た目を変える難読化とは異なります。

- 難読化とは元の意味や機能を保持しながら、理解しにくくなるような方法でコードおよびデータを変換するプロセスです。英語の文章を同じ内容のフランス語に翻訳することを考えてください (あるいはあなたがフランス語を話す場合は別の言葉を選ぶことで要点が分かります) 。

これらの二つのカテゴリは時おり重複することに注意します。例えば、自己コンパイルコードや自己改変コードがあります。多くが難読化の意味で参照され、また「何かを行う」とも言えます。しかし、一般的にはそれは有用な区別です。

プログラムによる防御はさらに二つのモードに分類されます。

1. 予防：リバースエンジニアの予想された行動を *防止* することを目的とした機能です。例えば、アプリはオペレーティングシステム API を使用して、デバッガがアタッチすることを防止できます。

2. 反応：リバースエンジニアのツールや行動を検出および反応することを目的とした機能です。例えば、アプリはエミュレータで実行されている疑いがある場合に終了したり、デバッガが検出された場合に何らかの方法でその動作を変更することがあります。

あなたは通常、所定のソフトウェア保護スキームで上記のすべての組み合わせを見つけるでしょう。

## プログラムによる防御の全体的な有効性

アンチリバースの主なモットーは **総和は部分に勝る** です。防御者は解析のための最初の足掛かりを可能な限り困難にしたいと考えています。彼らは攻撃者が取り掛かる前にタオルを投げて欲しいのです。一旦、攻撃者が取り掛かれば、カードの家が崩壊するのはたいてい時間の問題です。

この抑止効果を達成するには、多数の防御を組み合わせる必要があり、できれば独自のものを含めます。防御はアプリ全体に散りばめる必要がありますが、全体をよりよくするために協調もして機能します。以下のセクションでは、プログラムによる防御の有効性に寄与する主な基準について説明します。

#### カバレッジ

--[ TODO ] --

<img src="Images/Chapters/0x07b/reversing-processes.png" width="600px" />


```
8.1 アプリはユーザーに警告するかアプリを終了することでルート化デバイスや脱獄済みデバイスの存在を検出し応答している。
```


```
8.2: アプリはデバッグを防止し、デバッガのアタッチを検出し応答している。利用可能なすべてのデバッグプロトコルを網羅している必要がある (Android: JDWP および ptrace, iOS: Mach IPC および ptrace) 。
```


```
8.3: アプリはそれ自身のコンテナ内の実行ファイルや重要なデータの改竄を検出し応答している。
```


```
8.4: アプリはコードインジェクション、フック、計装、デバッグをサポートする広く使用されるリバースエンジニアリングツールおよびフレームワークの存在を検出している。
```


```
8.5: アプリはエミュレータ内で動作していることを検出し応答している。
```

```
8.6: アプリはそれ自身のメモリ空間内の重要なコードとデータ構造の完全性を継続的に検証している。
```


#### 量と多様性

--[ TODO ] --

一般的な経験則として、少なくとも二つから三つの防御コントロールを各カテゴリに実装すべきです。これらのコントロールは互いに独立して動作する必要があります。つまり、さまざまな技法や API を使用します。

```
8.7 アプリは要件8.1から8.6を満たす複数のメカニズムを実装している。耐性は使用されるメカニズムのオリジナリティの量、多様性と比例することに注意する。
```

```
8.8 検出メカニズムはさまざまな応答をトリガーしている。単にアプリを終了しないステルス応答を含む。
```

```
8.10: 難読化変換と機能的防御は相互依存であり、アプリ全体でうまく統合している。
```

##### 独創性

アプリケーションをリバースエンジニアするために必要な労力は、攻撃者が最初にどれだけの情報を入手できるかに大きく依存します。これには、ターゲットアプリケーションにより使用される難読化や改竄防止技法についての知識だけでなく、リバースされる機能についての情報も含まれます。したがって、アンチリバーストリックを設計するに至る技術革新のレベルは重要な要素です。

攻撃者はリバースエンジニアリングの書籍、論文、プレゼンテーション、チュートリアルで繰り返し記述されている遍在的な技法に精通しています。そのようなトリックは一般的なツールを使用するか、たいした技術革新なしでバイパスできます。対照的に、どこにも提示されていない秘密のトリックは、その内容を本当に理解しているリバーサによってのみバイパスされ、さらなる研究やスクリプティング、コーディングを行うことを強要する可能性があります。

防御は独創性の観点から以下のカテゴリに大別されます。

- 標準 API: この機能はリバースエンジニアリングを防ぐことを明確に意図した API に依存しています。一般的なツールを使用して容易にバイパスできます。
- 公知: 十分に文書化され、一般的に使用される技法が使用されます。一般的に利用可能なツールを適度にカスタマイズして使用することでバイパスできます。
- プロプライエタリ: この機能は一般的にリバースに関する資料や研究論文がありません。あるいは、既知の技法が十分に拡張、カスタマイズされ、リバースエンジニアに多大な労力をもたらします。

##### API 層

一般的に、オペレーティングシステム API の動作に依存するメカニズムが少ないほど、検出およびバイパスすることが難しくなる、と言われています。また、より低レベルのコールは高レベルのコールよりも無効化しにくくなります。この説明として、いくつか例を見てみます。

あなたが学んだように


```c
#define PT_DENY_ATTACH 31

void disable_gdb() {
    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}
```

```c
void disable_gdb() {

	asm(
		"mov	r0, #31\n\t"	// PT_DENY_ATTACH
		"mov	r1, #0\n\t"
		"mov	r2, #0\n\t"
		"mov 	ip, #26\n\t"	// syscall no.
		"svc    0\n"
	);
}
```

```c
struct VT_JdwpAdbState *vtable = ( struct VT_JdwpAdbState *)dlsym(lib, "_ZTVN3art4JDWP12JdwpAdbStateE");

	unsigned long pagesize = sysconf(_SC_PAGE_SIZE);
	unsigned long page = (unsigned long)vtable & ~(pagesize-1);

	mprotect((void *)page, pagesize, PROT_READ | PROT_WRITE);

	vtable->ProcessIncoming = vtable->ShutDown;

	// Reset permissions & flush cache

	mprotect((void *)page, pagesize, PROT_READ);
```

- システムライブラリ: この機能は公開ライブラリ関数またはメソッドに依存しています。
- システムコール: アンチリバース機能は直接カーネルをコールします。
- 自己完結型: この機能はライブラリやシステムコールが動作することを必要としません。


##### 並列処理

複数のスレッドやプロセスが関与している場合、メカニズムのデバッグおよび無効化は難しくなります。

- シングルスレッド
- マルチスレッドまたはプロセスMultiple threads or processes

--[ TODO - description and examples ] --

<img src="Images/Chapters/0x07b/multiprocess-fork-ptrace.png" width="500px" />


##### 応答

攻撃者に与える情報という観点ではより少ないことがよりよいことです。この原則は改竄防止コントロールにも当てはまります。目に見える方法で直ちに改竄に反応するコントロールは、明白な即時の結果を伴わない何らかの隠れた応答をトリガとするコントロールよりも簡単に発見されます。例えば、大きく、赤く、すべて大文字で "DEBUGGER DETECTED!" というメッセージボックスを表示するデバッガ検出メカニズムを想像します。これは何が起こったのかを正確に示し、リバースエンジニアに探すべき何か (メッセージボックスを表示するコード) を与えます。ここで、デバッガを検出した場合に静かに関数ポインタを変更して、後でクラッシュに導くイベントのシーケンスをトリガするメカニズムを想像します。これはリバースエンジニアリングプロセスをはるかに苦痛なものにします。

最も効果的な防御機能はステルスモードで応答するように設計されています。攻撃者は防御メカニズムがトリガされたことにまったく気付きません。最大限の効果を得るには、以下のようなさまざまなタイプの応答を組み合わせることを推奨します。

- フィードバック: 改竄防御の応答がトリガされた場合、エラーメッセージがユーザーに表示されるか、ログファイルに書き込まれます。攻撃者は防御機能の性質と、メカニズムがトリガされた時間をすぐに識別できます。
- 識別不明: 防御メカニズムはエラーの詳細を提供することなく、および終了の理由をログに記録することなく、アプリを終了します。攻撃者は防御木の性質についての情報を習得しませんが、機能がトリガされたおおよその時間を識別できます。
- ステルス: 改竄防止機能は検出された改竄に目に見えた応答をまったくしないか、もしくは応答が大幅に遅れて発生します。

MASVS V8.8: "アプリは改竄、デバッグ、エミュレーションに複数の異なる応答を実装している。単にアプリを終了しないステルス応答を含む。" も参照ください。

#### 散乱

--[ TODO ] --

#### 統合

--[ TODO ] --

## 難読化の評価

コードを理解しにくくする最も簡単な方法は、関数や変数名など人間にとって意味のある情報を取り除くことです。ソフトウェアの作成者によって、多くのより複雑な方法が考え出されました。特にマルウェアや DRM システムを開発してきた人たちによって、過去数十年にわたり、コードやデータの一部を暗号化することから、自己改変コードや自己コンパイルコードに至るまで。

暗号プリミティブの標準実装は、元の暗号鍵がメモリに開示されないように、鍵依存のルックアップテーブルのネットワークで置き換えられます (「ホワイトボックス暗号」) 。コードは、インタプリタ上で実行される秘密のバイトコード言語にできます (「仮想化」) 。コードとデータをエンコードおよび変換する方法は無限にあります。

正確な学術的定義を示そうとすると、物事は複雑になります。よく引用される論文では、Barak らは難読化のブラックボックスモデルを記述しています。ブラックボックスモデルは、P' から学ぶことができる任意の特性が P へのアクセスを達成するシミュレータによっても得られる場合、プログラム P' は難読化されていると考えます。言い換えると、P' は入出力の振る舞い以外は何も明らかにしません。著者らは難読化できないプログラムを構築することにより、難読化が自身の定義を与えることは不可能であることも示しています <sup>[2]</sup> 。

これは難読化が不可能であることを意味するでしょうか。それはあなたが何を難読化し、難読化をどのように定義するかによります。Barak の結論は *一部の* プログラムは難読化できないことを示していますが、私たちが難読化に非常に強い定義を使用している場合に限ります。直感的に、私たちの大部分はコードの分かりやすさが異なり、コードの複雑さが増すとコードを理解することが難しくなることを経験から知っています。多くの場合、これは意図せず起こりますが、難読化プログラムの実装が存在し、実際には多かれ少なかれ仕様に成功しています <sup>[3]</sup> 。

残念なことに、研究者は難読化の有効性が証明もしくは定量化できるかどうかには同意しておらず、それを行うために広く受け入れられている方法はありません。以下のセクションでは、一般的に使用されるタイプの難読化の分類を提供します。それから、執筆時点で入手可能な逆難読化ツールおよび研究を考慮して、*堅牢な* 難読化を考慮するうえで達成すべき要件を概説します。但し、この分野は急速に発展しているため、実際には、最新の動向を常に考慮する必要があります。

### MASVS の難読化コントロール

MASVS には難読化を扱う要件が二つだけ記載されています <sup>[4]</sup> 。最初の要件は V8.11 です。

```
"8.11 アプリに属するすべての実行ファイルとライブラリはファイルレベルで暗号化されているか、実行形式内の重要なコードやデータセグメントが暗号化またはパックされている。単純な静的解析では重要なコードやデータは明らかにならない。"
```

この要件は、一般的な逆アセンブラや逆コンパイラでコードを検査している人にとって、コードを理解しづらいものにする必要があるということだけです。これは以下を組み合わせることで実現できます。

**情報の除去**

最初のシンプルで非常に効果的なステップは説明的な情報を取り除くことです。これは人間にとって意味がありますが、実際にプログラムを実行するためには必要ありません。マシンコードやバイトコードに行番号、関数名、変数名をマップするデバッグシンボルはよくある例です。

例えば、標準の Java コンパイラで生成されたクラスファイルにはクラス、メソッド、フィールドの名前が含まれているため、ソースコードを容易に再構築できます。ELF および Mach-O バイナリにはデバッグ情報を含むシンボルテーブルがあり、実行可能ファイルで使用される関数、グローバル変数、型の名前が含まれています。

この情報を除去すると、コンパイルされたプログラムはその機能を完全に保持したまま、理解しにくくなります。可能な方法にはデバッグシンボルテーブルの削除や、関数や変数を意味のある名前の代わりにランダムな文字の組み合わせへの変更があります。このプロセスでは時折コンパイルされたプログラムのサイズが縮小されますが、実行時の動作に影響を与えません。

**パッキング、暗号化、およびその他のトリック**

情報の除去に加えて、以下のようにアプリを困難にし、解析を難しくする多くの方法があります。

- Java バイトコードとネイティブコードの間でコードとデータを分割する
- 文字列を暗号化する
- プログラムを使用してコードとデータの一部を暗号化する
- バイナリファイルやクラスファイル全体を暗号化する

この種の変換は、ランタイムオーバーヘッドを増やさないという意味で「安い」ものです。特定の脅威モデルに関係なく、効果的なソフトウェア保護スキームの一部を形成します。目標は、何が起こっているかを理解することを難しくし、保護の全体的な有効性を高めることです。切り離してみた場合、これらの技法は手動または自動の逆難読化に対して高い耐性はありません。

第二の要件 V8.12 は、暗号鍵を隠す、機密扱いと考えられるコードの一部を隠すなど、難読化が特定の機能を実行することを意図している場合を扱います。

```
8.12: 難読化の目的が機密性の高い計算を保護することである場合、現在公開されている研究を考慮して、特定のタスクに適しており手動および自動の逆難読化メソッドに対して堅牢な難読化スキームを使用している。難読化スキームの有効性は手動テストにより検証する必要がある。可能であればハードウェアベースの隔離機能が難読化より優先されることに注意する。"
```

これは、ホワイトボックス暗号化のような、より「高度な」（そしてしばしば論争の的となる）形態の難読化が作用するものです。この種の難読化は人間および自動解析の両方に対して真に堅牢であることを意味し、通常、プログラムのサイズと複雑さを増加させます。この方法は、より複雑な方法で同じ関数を計算するか、簡単には理解できない方法でコードとデータをエンコードすることにより、計算の意味を隠すことを目指しています。

このような種類の難読化についての簡単な例として Opaque Predicates があります。Opaque Predicates はプログラムに追加された冗長なコードブランチであり、常に同じ方法で実行されます。これはプログラマには先験的に知られていますが、アナライザにはそうではありません。例えば、if (1 + 1) = 1 のような文は常に false と評価され、したがって常に同じ場所にジャンプします。Opaque Predicates は静的解析での識別および削除が困難となる方法で構築されます。

このカテゴリに該当するその他の難読化手法には以下があります。

- パターンベースの難読化、命令がより複雑な命令シーケンスに置き換えられる
- コントロールフローの難読化
- コントロールフローの平坦化
- 関数のインライン化
- データのエンコード化および配置換え
- 変数の分割
- 仮想化
- ホワイトボックス暗号

### 難読化の有効性

特定の難読化スキームを決定することは「有効」の正確な定義に左右されます。スキームの目的がカジュアルなリバースエンジニアを抑止することであれば、コスト効率の高いトリックの混合で十分です。目的が熟練のリバースエンジニアによる高度な解析に対して一定の耐性を達成することを目的としている場合、スキームは以下を考慮する必要があります。

1. Potency: プログラムの複雑さは人間や手作業による解析を著しく阻害するのに十分な量だけ増加する必要があります。複雑さおよびサイズとパフォーマンスとの間には常にトレードオフがあることに注意します。
2. 自動プログラム解析に対する耐性。例えば、難読化のタイプがコンコリック解析に対して「脆弱」であることが知られている場合、このスキームはこのタイプの解析で問題を引き起こす変換を含む必要があります。

#### 一般的な基準

--[ TODO - describe effectiveness criteria ] --

**全体的なプログラムの複雑さの増加**

--[ TODO ] --

**CFG 復元の難しさ**

--[ TODO ] --

**自動プログラム解析に対する耐性**

--[ TODO ] --

#### 複雑さメトリクスの使用

--[ TODO  - what metrics to use and how to apply them] --

#### 一般的な変換

--[ TODO  - describe commonly used schemes, and criteria associated with each scheme. e.g., white-box must incorportate X to be resilient against DFA,  etc.] --

##### コントロールフローの難読化

--[ TODO ] --

##### ポリモーフィックコード

--[ TODO ] --

##### 仮想化

--[ TODO ] --

##### ホワイトボックス暗号

--[ TODO ] --

## 背景と注意

--[ TODO ] --

### 難読化メトリクスに関する学術研究

-- TODO [Insert and link references] --

Collberg らはリバースエンジニアリングの難易度の推計として Potency を紹介しています。強力な難読化変換はプログラムの複雑さを増加させる変換です。さらに、自動逆難読化プログラムからの攻撃にもとで変換がどのくらいうまく持ちこたえるかを測定する耐性の概念を提案しています。同じ論文には難読化変換の有用な分類も含まれています <sup>[5]</sup> 。

Potency はいくつかの方法を使用して推計できます。Anaeckart らは実行コードから生成されたコントロールフローグラフに従来のソフトウェア複雑度メトリクスを適用しています <sup>[6]</sup> 。適用されるメトリクスは命令数、サイクロマティック数 (すなわち、グラフ内の分岐点の数)、結合点数 (関数のコントロールフローグラフの交差数) です。簡単に言えば、より多くの命令があり、より多くの代替パスとより少ない期待される構造をコードが持つほど、より複雑になります。

Jacubowsky らは同じ方法を使用し、命令ごとの変数の数、変数の間接参照、操作の間接参照、コードの均質性、データフローの複雑さなどのメトリクスを追加しています <sup>[7]</sup> 。プログラムのすべての分岐のネストレベルにより決定される N-Scope <sup>[8]</sup> などの他の複雑さメトリクスは同じ目的で使用できます <sup>[9]</sup> 。

これらのメソッドはすべて、プログラムの複雑さを近似するために多かれ少なかれ有用ですが、難読化変換の堅牢性を常に正確に反映するとは限りません。Tsai らは元のプログラムと難読化されたプログラムの間の差異の度合いを反映する distance メトリクスを追加することにより、これの修正を試みました。基本的に、このメトリクスは難読化されたコールグラフが元のものとどのように異なるかを捕捉します。まとめると、大きな distance と potency はリバースエンジニアリングに対する優れた堅牢性と相関していると考えられます <sup>[10]</sup> 。

同じ論文で執筆者らは、難読化の尺度は元のプログラムと変換されたプログラムとの関係を表していますが、リバースエンジニアリングに必要な労力の量を定量化することはできないという重要な見解も示しています。彼らはこれらの尺度が単にヒューリスティックで一般的なセキュリティ指標として役立つことを認識しています。

人間中心アプローチにより、Tamada らは難読化を評価するためのメンタルシミュレーションモデルについて述べています <sup>[11]</sup> 。このモデルでは、人間である攻撃者の短期記憶は限られたサイズの FIFO キューとしてシミュレートされます。執筆者らはプログラムをリバースエンジニアリングする際に攻撃者が遭遇する困難を反映すると思われる六つのメトリクスを計算します。Nakamura らはメンタルシミュレーションのコストを反映した同様のメトリクスを提案しています <sup>[12]</sup> 。

最近では、Rabih Mosen と Alexandre Miranda Pinto が難読化の有効性のメトリクスとして Kolmogorov の複雑さの正規化バージョンの使用を提案しています。彼らのアプローチの背後にある洞察は次の議論に基づいています。攻撃者が難読化されたコード内のいくつかのパターン (規則性) を捕らえることができない場合、攻撃者はそのコードを理解することが難しくなります。妥当で簡潔な、つまり簡単な説明を提供することはできません。一方で、これらの規則性を説明することが簡単であれば、それらを記述することは容易になり、その結果、コードを理解することは難しくありません。執筆者らは一般的な難読化技法が提案されたメトリクスを大幅に増加できたことを示す実証結果も提供しています。彼らは元の難読化されていないコードと比較して、複雑さの増加を検出する際に、そのメトリクスが循環的な尺度よりもより感度が高いことを発見しました <sup>[13]</sup> 。

これは直感的な感覚であり、必ずしも正しいわけではありませんが、Kolmogorov の複雑さメトリクスはプログラムにランダムなノイズを加えるコントロールフローおよびデータ難読化スキームの影響を定量化のに役立つと思われます。

### 実験データ

既存の複雑さの尺度の限界を念頭において、この課題におけるより多くの人間の研究が役立つことがわかります。残念ながら、実験に基づく研究の大部分は比較的小さく、実際、実証研究の欠如は研究者が直面する主要な課題のひとつです <sup>[14]</sup> 。しかし、いくつかのタイプの難読化と、より高いリバースエンジニアリングの難易度を結びつける興味深い論文があります。

Nakamura らは同じ論文で提案するいくつかの新しいコストメトリクスの影響を調べるために実証研究を行いました <sup>[12]</sup> 。実験では、十二人の被験者に三つの Java プログラムの二つの異なるバージョン (複雑さが異なる) を頭の中で実行するように求めました。実験の中で特定の時間に、被験者はプログラムの状態 (すなわち、プログラム内のすべての変数の値) を記述するように求めました。次に、実感を実行する際の参加者の正確さとスピードを使用して、提案されたコストメトリクスの妥当性を評価しました。結果は、提案された複雑さのメトリクスがタスクを解決するために被験者が必要とする時間と (他のものより幾分) 相関していることを示しました。

Sutherland らはリバースエンジニアリングの尺度を収集するためのフレームワークを調査し、リバースエンジニアリングの実験を行いました <sup>15</sup> 。研究者らは十名の学生のグループにいくつかのバイナリプログラムの静的解析と動的解析を実行するよう求め、学生のスキルレベルとタスクの成功のレベルとの間に有意な相関があることを発見しました (大きな驚きはありませんが、幸運だけではリバースエンジニアリングははかどらないという前提的な証拠として価値があります) 。

一連の対照実験において、M. Ceccato らは識別子の名前変更と Opaque Predicates の影響をテストし、攻撃に必要な労力を増加させました <sup>[3] [16] [17]</sup> 。これらの研究では、Java プログラミングの知識が豊富な修士課程および博士課程の学生に、クライアント－サーバー Java アプリケーションの逆コンパイル済み (難読化済みまたは難読化なしの) クライアントコードのタスクの理解またはタスクの変更の実行を求めました。この実験では難読化によりソースコードを理解および変更するための被験者の能力が低下することが示されました。興味深いことに、この結果は難読化の存在が高度に熟練した攻撃者と低技能の者の間のギャップを縮小することも示しました。高度に熟練した攻撃者は難読化されていないソースコードの解析が十分に高速でしたが、難読化されたバージョンを解析するとその差は小さくなりました。他の結果の中でも、識別子の名前変更は攻撃が成功して完了するために必要な時間が少なくとも二倍になることが示されました <sup>[16]</sup> 。

<img src="Images/Chapters/0x07b/boxplot.png" width="650px" />

*識別子の名前変更がプログラムの理解に及ぼす影響を測定する Ceccato らの実験による攻撃効率の箱ひげ図。難読化されたコードを解析する被験者は一分当たりの正答が少なかった。*

### デバイスバインディングの問題

In many cases it can be argued that obfuscating some secret functionality misses the point, as for all practical purposes, the adversary does not need to know all the details about the obfuscated functionality. Say, the function of an obfuscated program it to take an input value and use it to compute an output value in an indiscernible way (for example, through a cryptographic operation with a hidden key). In most scenarios, the adversaries goal would be to replicate the functionality of the program – i.e. computing the same output values on a system owned by the adversary. Why not simply copy and re-use whole implementation instead of painstakingly reverse engineering the code? Is there any reason why the adversary needs to look inside the black-box?

This kind of attack is known as code lifting and is commonly used for breaking DRM and white-box cryptographic implementations <sup>[18]</sup>. For example, an adversary aiming to bypass digital media usage could simply extract the encryption routine from a player and include it in a counterfeit player, which decrypts the digital media without enforcing the contained usage policies <sup>19</sup>. Designers of white-box implementations have to deal with another issue: one can convert an encryption routine into a decryption routine without actually extracting the key <sup>[20]</sup>.

Protected applications must include measures against code lifting to be useful. In practice, this means binding the obfuscated functionality to the specific environment (hardware, device or client/server infrastructure) in which the binary is executed. Preferably, the protected functionality should execute correctly only in the specific, legitimate computing environment. For example, an obfuscated encryption algorithm could generate its key (or part of the key) using data collected from the environment <sup>[21]</sup>. Techniques that tie the functionality of an app to specific hardware are known as device binding.

Even so, it is relatively easy (as opposed to fully reverse engineering the black-box) to monitor the interactions of an app with its environment. In practice, simple hardware properties such as the IMEI and MAC address of a device are often used to achieve device binding. The effort needed to spoof these environmental properties is certainly lower than the effort required for needed for fully understanding the obfuscated functionality.

What all this means is that, for most practical purposes, the security of an obfuscated application is only as good as the device binding it implements. For device binding to be effective, specific characteristics of the system or device must be deeply intertwined with the various obfuscation layers, and these characteristics must be determined in stealthy ways (ideally, by reading content directly from memory). Advanced device binding methods are often deployed in DRM and malware and some research has been published in this area <sup>[22]</sup>.

## 参考情報

- [1] OWASP Reverse Engineering and Code Modification Prevention - https://www.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project
- [2] Boaz Barak, Oded Goldreich, Rusell Impagliazzo, Steven Rudich, Amit Sahai, Salil Vadhan, Ke Yang - On the (Im)possibility of Obfuscating Programs - Lecture Notes in Computer Science, issue 2139, 2001
- [3] Mariano Ceccato, Massimiliano Di Penta, Jasvir Nagra, Paolo Falcarin, Filippo Ricca, Marco Torchiano, Paolo Tonella - Towards Experimental Evaluation of Code Obfuscation Techniques, 2008
- [4] OWASP MASVS Resilience Requirements - https://github.com/OWASP/owasp-masvs/blob/master/Document/0x15-V8-Resiliency_Against_Reverse_Engineering_Requirements.md
- [5] C. Collberg, C. Thomborson, and D. Low - A taxonomy of obfuscating transformations, Dept. of Computer Science, The Univ. of Auckland, Technical Report 148, 1997
- [6] Bertrand Anckaert, Matias Madou, Bjorn De Sutter, Bruno De Bus and Koen De Bosschere, Bart Preneel - Program Obfuscation: A Quantitative Approach. Proceedings of the 2007 ACM workshop on Quality of protection, ACM New York, NY, USA, 2007
- [7] Mariusz H. Jakubowski, Chit W. (Nick) Saw, Ramarathnam Venkatesan - ITERATED TRANSFORMATIONS AND QUANTITATIVE METRICS FOR SOFTWARE PROTECTION, 2009
- [8] Zuse, H. - Software Complexity: Measures and Methods. Walter de Gruyter & Co. Hawthorne, NJ, USA, 1991
- [9] Yongdong Wu, Hui Fang, Shuhong Wang, Zhifeng Qi - A Framework for Measuring the Security of Obfuscated Software. International Conference on Test and Measurement, 2010
- [10] Hsin-Yi Tsai, Yu-Lun Huang, and David Wagner - A Graph Approach to Quantitative Analysis of Control-Flow Obfuscating Transformations. IEEE TRANSACTIONS ON INFORMATION FORENSICS AND SECURITY, Volume 4, Issue 2, 2009
- [11] Haruaki Tamada, Kazumasa Fukuda, Tomoya Yoshioka - Program Incomprehensibility Evaluation for Obfuscation Methods with Queue-based Mental Simulation Model, ACIS International Conference on Software Engineering, Artificial Intelligence, Networking and Parallel Distributed Computing (SNPD), 2012
- [12] Masahide Nakamura, Akito Monden, Tomoaki Itoh, Ken-ichi Matsumoto, Yuichiro Kanzaki, Hirotsugu Satoh - Queue-based Cost Evaluation of Mental Simulation Process in Program Comprehension. Proceedings of the Ninth International Software Metrics Symposium (METRICS’03), IEEE, 2003
- [13] Rabih Mohsen, Alexandre Miranda Pinto - Algorithmic Information Theory for Obfuscation Security. International Conference on Security and Cryptography, SECRYPT 2015
- [14] Ceccato, Mariano - On the Need for More Human Studies to Assess Software Protection.
- [15] Iain Sutherland, George E. Kalb, Andrew Blyth, Gaius Mulley - An empirical examination of the reverse engineering process for binary files.
- [16] Mariano Ceccato, Massimiliano Di Penta, Jasvir Nagra, Paolo Falcarin, Filippo Ricca, Marco Torchiano, Paolo Tonella - The effectiveness of source code obfuscation: An experimental assessment
- [17] Mariano Ceccato, Massimiliano Di Penta, Jasvir Nagra, Paolo Falcarin, Filippo Ricca, Marco Torchiano, Paolo Tonella - Towards Experimental Evaluation of Code Obfuscation Techniques
- [18] Brecht Wyseur - WHITE-BOX CRYPTOGRAPHY: HIDING KEYS IN SOFTWARE.
- [19] Sebastian Schrittwieser, Stefan Katzenbeisser, Johannes Kinder, Geord Merzdovnik, Edgar Weippl - Protecting Software through Obfuscation: Can It Keep Pace with Progress in Code Analysis? ACM Computing Surveys, Volume 49, issue 1, 2016
- [20] Joppe W. Bos, Charles Hubain, Wil Michiels, and Philippe Teuwen - Differential Computation Analysis: Hiding your White-Box Designs is Not Enough.
- [21] James Riordan, Bruce Schneier - Environmental Key Generation towards Clueless Agents. Mobile Agents and Security, Springer Verlag, 1998
- [22] Royal, Chengyu Song and Paul - Flowers for Automated Malware Analysis. Blackhat USA 2012. https://media.blackhat.com/bh-us-12/Briefings/Song/BH_US_12_Song_Royal_Flowers_Automated_WP.pdf
