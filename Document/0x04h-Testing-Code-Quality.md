---
masvs_category: MASVS-CODE
platform: all
---

# モバイルアプリのコード品質

モバイルアプリ開発者はさまざまなプログラミング言語とフレームワークを使用しています。そのため、SQL インジェクション、バッファオーバーフロー、クロスサイトスクリプティング (XSS) などの一般的な脆弱性は、セキュアなプログラミングプラクティスを軽視した場合のアプリに現れることがあります。

同じプログラミングの欠陥が Android と iOS の両方のアプリにある程度の影響を与える可能性があるため、最も一般的な脆弱性クラスの概要をこのガイドの一般セクションで繰り返し説明します。後のセクションでは、OS 固有のインスタンスと悪用緩和機能について説明します。

## インジェクション欠陥

_インジェクション欠陥_ はユーザーの入力がバックエンドのクエリやコマンドに挿入されたときに発生するセキュリティ脆弱性のクラスを表します。メタ文字を注入することにより、攻撃者は誤ってコマンドやクエリの一部として解釈される悪質なコードを実行できます。例えば、SQL クエリを操作することにより、攻撃者は任意のデータベースレコードを取得したり、バックエンドデータベースの内容を操作する可能性があります。

このクラスの脆弱性はサーバー側のウェブサービスで最も一般的です。悪用可能なインスタンスもモバイルアプリ内に存在しますが、発生頻度は少なく、アタックサーフェスも小さくなります。

例えば、アプリはローカルの SQLite データベースをクエリすることがありますが、そのようなデータベースは通常、機密データを格納しません (開発者が基本的なセキュリティプラウティスに従うと仮定します) 。これにより SQL インジェクションは実用的ではない攻撃ベクトルになります。それにもかかわらず、悪用可能なインジェクション脆弱性が発生することがあります。これは適切な入力検証がプログラマにとって必要なベストプラクティスであることを意味しています。

### SQL インジェクション

_SQL インジェクション_ 攻撃は入力データに SQL コマンドを統合し、定義済みの SQL コマンドを模倣します。SQL インジェクション攻撃が成功すると、攻撃者はデータベースの読み取りや書き込みが可能になり、サーバーに付与されたアクセス許可に応じて管理コマンドを実行される可能性があります。

Android と iOS のアプリは両方ともローカルデータストレージを制御及び整理する手段として SQLite データベースを使用します。Android アプリはローカルデータベースにユーザー資格情報を格納することにより、ローカルユーザー認証を処理すると仮定します (この例のための意図的な悪いプログラミングプラクティスです) 。ログインすると、アプリはデータベースをクエリし、ユーザーが入力したユーザー名とパスワードでレコードを検索します。

```java
SQLiteDatabase db;

String sql = "SELECT * FROM users WHERE username = '" +  username + "' AND password = '" + password +"'";

Cursor c = db.rawQuery( sql, null );

return c.getCount() != 0;
```

ここで攻撃者が "username" と "password" のフィールドに以下の値を入力したとします。

```sql
username = 1' or '1' = '1
password = 1' or '1' = '1
```

これにより以下のクエリが生成されます。

```sql
SELECT * FROM users WHERE username='1' OR '1' = '1' AND Password='1' OR '1' = '1'
```

条件 `'1' = '1'` は常に true と評価されるため、このクエリはデータベース内のすべてのレコードを返し、有効なユーザーアカウントが入力されていなくてもログイン関数は `true` を返すようになります。

Ostorlab はこの SQL インジェクションペイロードを使用して、adb で [Yahoo 天気モバイルアプリケーション](https://blog.ostorlab.co/android-sql-contentProvider-sql-injections.html) のソートパラメータを悪用しました。

Mark Woods は QNAP NAS ストレージアプライアンス上で動作する "Qnotes" および "Qget" Android アプリ内にクライアントサイドの SQL インジェクションのリアルワールドのインスタンスの一つを発見しました。これらのアプリは SQL インジェクションに脆弱なコンテンツプロバイダをエクスポートし、攻撃者が NAS デバイスの資格情報を取得できるようにしました。この問題の詳細な説明は [Nettitude Blog](https://blog.nettitude.com/uk/qnap-android-dont-provide "Nettitude Blog - QNAP Android: Don\'t Over Provide") にあります。

### XML インジェクション

_XML インジェクション_ 攻撃では、攻撃者は XML メタキャラクタを注入して XML コンテンツを構造的に変更します。これは XML ベースのアプリケーションやサービスのロジックを侵害するために使用される可能性があり、攻撃者がコンテンツを処理する XML パーサーの操作を悪用する可能性もあります。

この攻撃の一般的な変種には [XML eXternal Entity (XXE)](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing "XML eXternal Entity attack (XXE)") があります。ここでは、攻撃者が URI を含む外部エンティティ定義を入力 XML に注入します。解析時に、XML パーサーは URI で指定されたリソースにアクセスして攻撃者が定義したエンティティを展開します。解析アプリケーションの完全性により最終的に攻撃者にもたらす能力を決定します。悪意のあるユーザーが次の一部 (または全て) を行う可能性があります。ローカルファイルにアクセスしたり、任意のホストおよびポートへの HTTP リクエストをトリガしたり、[クロスサイトリクエストフォージェリ (CSRF)](https://owasp.org/www-community/attacks/csrf "Cross-Site Request Forgery (CSRF)") 攻撃を実行したり、サービス拒否状態を引き起こしたりします。OWASP ウェブテストガイドには [XXE の以下の例](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection "Testing for XML Injection (OTG-INPVAL-008)") があります。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>
```

この例では、ローカルファイル `/dev/random` が開かれ、無限のバイトストリームが返され、潜在的にサービス拒否を引き起こします。

アプリ開発の現在の傾向では、ほとんどが REST/JSON ベースのサービスにフォーカスしており、XML はあまり一般的ではなくなっています。しかし、まれにユーザーが提供した、または信頼できないコンテンツが XML クエリを構築するために使用される場合、iOS の NSXMLParser などのローカル XML パーサーにより解釈される可能性があります。したがって、前記の入力は常に検証され、メタキャラクタはエスケープされる必要があります。

### インジェクション攻撃ベクトル

モバイルアプリのアタックサーフェスは一般的なウェブアプリケーションやネットワークアプリケーションとは大きく異なります。モバイルアプリはネットワーク上でサービスを公開することはあまりなく、アプリのユーザーインタフェース上で実行可能な攻撃ベクトルはまれです。アプリに対するインジェクション攻撃はプロセス間通信 (IPC) インタフェースを介して発生することがほとんどです。悪意のあるアプリがデバイス上で実行されている別のアプリを攻撃します。

潜在的な脆弱性を突きとめるには、以下を行います。

- 信頼できない入力について可能性のあるエントリポイントを特定し、それらのロケーションからトレースを行い、デスティネーションに潜在的な脆弱性をもつ機能が含まれているかどうかを確認します。
- 既知の危険なライブラリや API コール (SQL クエリなど) を特定し、チェックされていない入力がそれぞれのクエリとのインタフェースに成功するかどうかを確認します。

手動によるセキュリティレビューでは、両方の技法を組み合わせて使用する必要があります。一般に、信頼できない入力は以下のチャネルを通じてモバイルアプリに入ります。

- IPC コール
- カスタム URL スキーム
- QR コード
- Bluetooth, NFC, またはその他の方法で受信した入力ファイル
- ペーストボード
- ユーザーインタフェース

以下のベストプラクティスが実行されていることを確認します。

- 信頼できない入力を型チェックしたり、許容値のリストを使用して検証しています。
- データベースクエリを実行する際に変数バイディングでのプリペアードステートメント (つまり、パラメータ化されたクエリ) を使用しています。プリペアードステートメントが定義されている場合、ユーザー指定のデータと SQL コードは自動的に分離されています。
- XML データを解析する場合、パーサーアプリケーションが XXE 攻撃を防ぐために外部エンティティの解決を拒否するように構成されていることを確認しています。
- X.509 形式の証明書データを使用する場合、セキュアなパーサーが使用されていることを確認しています。例えばバージョン 1.6 以下の Bouncy Castle は安全でないリフレクションによりリモートコード実行を許します。

OS 固有のテストガイドでは各モバイル OS の入力ソースや潜在的に脆弱な API に関する詳細について説明します。

## クロスサイトスクリプティング欠陥

クロスサイトスクリプティング (XSS) の問題により、攻撃者はクライアント側のスクリプトをユーザーが閲覧したウェブページに注入できます。この種の脆弱性はウェブアプリケーションによく見られます。ユーザーがブラウザに注入されたスクリプトを閲覧すると、攻撃者は同一生成元ポリシーをバイパスすることができ、さまざまな攻撃 (例えば、セッションクッキーの盗難、キー押下の記録、任意のアクションの実行など) を可能にします。

_ネイティブアプリ_ のコンテキストでは、これらの種類のアプリケーションはウェブブラウザに依存していないという単純な理由により、XSS のリスクはあまりありません。但し、iOS の `WKWebView` や非推奨の `UIWebView` および Android の `WebView` などの WebView コンポーネントを使用するアプリではこのような攻撃について潜在的に脆弱です。

古いですがよく知られている例として [Phil Purviance により最初に特定された、iOS 向け Skype アプリのローカル XSS の問題](https://superevr.com/blog/2011/xss-in-skype-for-ios "XSS in Skype for iOS") があります。Skype アプリがメッセージ送信者の名前を正しくエンコードできなかったため、攻撃者は悪意のある JavsScript を注入でき、ユーザーがメッセージを表示したときに実行される可能性があります。この概念実証で、Phil はこの問題を悪用してユーザーのアドレス帳を盗む方法を示しました。

### 静的解析 - セキュリティテストに関する注意点

存在する WebView を注意深く見て、信頼できない入力についてアプリによる処理を調査します。

WebView で開かれる URL が部分的にユーザーの入力により決定される場合、XSS の問題が存在する可能性があります。以下の例は [Linus Särud により報告された Zoho Web Service](https://labs.detectify.com/2015/02/20/finding-an-xss-in-an-html-based-android-application/ "Finding an XSS in an HTML-based Android application") の XSS の問題です。

Java

```java
webView.loadUrl("javascript:initialize(" + myNumber + ");");
```

Kotlin

```kotlin
webView.loadUrl("javascript:initialize($myNumber);")
```

ユーザー入力により決定される XSS 問題のもう一つの例は public override メソッドです。

Java

```java
@Override
public boolean shouldOverrideUrlLoading(WebView view, String url) {
  if (url.substring(0,6).equalsIgnoreCase("yourscheme:")) {
    // parse the URL object and execute functions
  }
}
```

Kotlin

```kotlin
    fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
        if (url.substring(0, 6).equals("yourscheme:", ignoreCase = true)) {
            // parse the URL object and execute functions
        }
    }
```

Sergey Bobrov はこれを以下の [HackerOne report](https://hackerone.com/reports/189793 "HackerOne report - [Android] XSS via start ContentActivity") で使用しました。HTML パラメータへの任意の入力が Quora の ActionBarContentActivity で信頼されます。ペイロードは adb の使用、ModalContentActivity を介したクリップボードデータ、サードパーティアプリケーションからのインテントに成功しました。

- ADB

  ```bash
  $ adb shell
  $ am start -n com.quora.android/com.quora.android.ActionBarContentActivity \
  -e url 'http://test/test' -e html 'XSS<script>alert(123)</script>'
  ```

- クリップボードデータ

  ```bash
  $ am start -n com.quora.android/com.quora.android.ModalContentActivity  \
  -e url 'http://test/test' -e html \
  '<script>alert(QuoraAndroid.getClipboardData());</script>'
  ```

- Java や Kotlin でのサードパーティインテント:

  ```java
  Intent i = new Intent();
  i.setComponent(new ComponentName("com.quora.android",
  "com.quora.android.ActionBarContentActivity"));
  i.putExtra("url","http://test/test");
  i.putExtra("html","XSS PoC <script>alert(123)</script>");
  view.getContext().startActivity(i);
  ```

  ```kotlin
  val i = Intent()
  i.component = ComponentName("com.quora.android",
  "com.quora.android.ActionBarContentActivity")
  i.putExtra("url", "http://test/test")
  i.putExtra("html", "XSS PoC <script>alert(123)</script>")
  view.context.startActivity(i)
  ```

WebView を使用してリモートウェブサイトを表示する場合、HTML をエスケープする負担はサーバ側に移ります。XSS の欠陥がウェブサーバーに存在する場合、これを使用して WebView のコンテキストでスクリプトを実行できます。したがって、ウェブアプリケーションソースコードの静的解析を実行することが重要です。

以下のベストプラクティスに準じていることを確認します。

- 絶対に必要でない限り、信頼できないデータを HTML, JavaScript, 他の解釈されるコンテキストで処理していません。
- エスケープ文字には HTML エンティティエンコーディングなどの適切なエンコーディングが適用されています。注：エスケープのルールは HTML が他のコード内にネストされていると複雑になります。例えば、JavaScript ブロック内にある URL を処理するなどです。

レスポンスでのデータの処理方法を検討します。例えば、データが HTML コンテキストで処理される場合に、エスケープする必要がある六つの制御文字です。

| 文字 | エスケープ後 |
| :-------------: |:-------------:|
| & | &amp;amp;|
| < | &amp;lt; |
| > | &amp;gt;|
| " | &amp;quot;|
| ' | &amp;#x27;|
| / | &amp;#x2F;|

エスケープのルールや他の予防措置の包括的なリストについては、[OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html "OWASP XSS Prevention Cheat Sheet") を参照してください。

### 動的解析 - セキュリティテストに関する注意点

XSS の問題は手動や自動の入力ファジングを使用すると最も良く検出できます。すなわち、利用可能なすべての入力フィールドに HTML タグや特殊文字を注入して、ウェブアプリケーションが無効な入力を拒否するか、その出力に HTML メタキャラクタをエスケープすることを確認します。

[反射型 XSS 攻撃](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.html "Testing for Reflected Cross site scripting") は悪意のあるコードが悪意のあるリンクを介して注入される攻撃を指します。これらの攻撃をテストするためには、自動化された入力ファジングが効果的な方法であると考えられています。例えば、[BURP Scanner](https://portswigger.net/burp/ "Burp Suite") は反射型 XSS 脆弱性の特定に非常に効果的です。自動解析の常として、すべての入力ベクトルがテストパラメータの手動レビューでカバーされていることを確認します。

## メモリ破損バグ

メモリ破損バグはハッカーにとって一般的な頼みの綱です。このクラスのバグはプログラムが意図しないメモリ位置にアクセスするようなプログラミングエラーが原因です。適切な状況下では、攻撃者はこの動作を利用し、脆弱なプログラムの実行フローをハイジャックして任意のコードを実行できます。この種の脆弱性は様々な方法で発生します。

- **バッファオーバーフロー**: これはアプリが特定の操作のために割り当てられたメモリ範囲を越えて書き込みを行うプログラミングエラーを表します。攻撃者はこの欠陥を使用して関数ポインタなど隣接するメモリにある重要な制御データを上書きできます。バッファオーバーフローは以前は最も一般的な種類のメモリ破損の欠陥でしたが、さまざまな要因により長年にわたり流行してはいません。特に、安全でない C ライブラリ関数を使用するリスクの開発者の意識は現在の一般的なベストプラクティスであり、バッファオーバーフローバグを捕捉することは比較的簡単です。しかし、そのような欠陥をテストする価値はまだあります。

- **境界外アクセス**: バグのあるポインタ演算により、意図されたメモリ構造 (バッファやリストなど) の境界を超えた位置を参照するポインタやインデックスとなる可能性があります。アプリが境界外のアドレスに書き込もうとすると、クラッシュや意図しない動作が発生します。攻撃者がターゲットオフセットを制御し、コンテンツをある程度の範囲で書き込む操作ができる場合、[コード実行悪用の可能性があります](https://www.zerodayinitiative.com/advisories/ZDI-17-110/ "Adobe Flash Mediaplayer example") 。

- **ダングリングポインタ**: これらは、メモリ位置への参照を含むオブジェクトが削除または割り当て解除されますが、オブジェクトポインタがリセットされないときに発生します。プログラムがすでに割り当て解除されたオブジェクトの仮想関数をコールする _ダングリング_ ポインタを後で使用する場合、元の vtable ポインタを上書きすることにより実行をハイジャックすることが可能です。あるいは、ダングリングポインタにより参照されるオブジェクト変数や他のメモリ構造を読み書きすることが可能です。

- **Use After Free**: これは解放 (割り当て解除) されたメモリを参照するダングリングポインタの特殊なケースを指します。メモリアドレスがクリアされると、その位置を参照するすべてのポインタは無効になり、メモリマネージャはそのアドレスを使用可能なメモリのプールに戻します。このメモリ位置が後に再割り当てされるとき、元のポインタにアクセスすると、新たに割り当てられたメモリに含まれるデータを読み書きします。これは通常、データ破損や未定義の動作につながりますが、巧妙な攻撃者は適切なメモリ位置を設定して命令ポインタの制御に利用できます。

- **整数オーバーフロー**: 算術演算の結果がプログラマにより定義された整数型の最大値を超える場合、これは最大整数値を「ラップアラウンド」した値となり、必然的に小さい値が格納されます。逆に、算術演算の結果が整数型の最小値より小さい場合、結果が予想より大きくなる _整数アンダーフロー_ が発生します。特定の整数オーバーフローやアンダーフローのバグが悪用可能かどうかは整数がどのように使用されるかで異なります。例えば、整数型がバッファの長さを表す場合、バッファオーバーフローの脆弱性が生じる可能性があります。

- **書式文字列の脆弱性**: チェックされていないユーザー入力が C 関数の `printf` ファミリの書式文字列パラメータに渡されると、攻撃者は '%c' や '%n' などの書式トークンを注入してメモリにアクセスする可能性があります。書式文字列のバグはその柔軟性のため、悪用するのに便利です。プログラムが文字列書式操作の結果を出力すると、ASLR などの保護機能をバイパスして、攻撃者は任意のメモリに読み書きできます。

メモリ破損を悪用する主な目的は、通常、プログラマが _シェルコード_ と呼ばれるアセンブルされた機械命令を配置した場所にプログラムフローをリダイレクトすることです。iOS では、データ実行防止機能は (名前が示すように) データセグメントとして定義されたメモリからの実行を防ぎます。この保護をバイパスするために、攻撃者はリターン指向プログラミング (ROP) を活用します。このプロセスではテキストセグメント内の小さな、既存のコードチャンク (「ガジェット」) を繋いで実行します。これらのガジェットは攻撃者にとって有用な機能を実行したり、攻撃者が格納した _シェルコード_ の位置の `mprotect` と呼ばれるメモリ保護設定を変更する可能性があります。

Android アプリは大部分が Java で実装されています。これは設計上、本質的にメモリ破損問題から安全です。しかし、JNI ライブラリを利用するネイティブアプリはこの種のバグの影響を受ける可能性があります。まれに、XML/JSON パーサーを使用して Java オブジェクトをアンラップする Android アプリもメモリ破損バグの影響を受けることもあります。そのような脆弱性の [一例](https://blog.oversecured.com/Exploiting-memory-corruption-vulnerabilities-on-Android/#example-of-the-vulnerability-in-paypal%E2%80%99s-apps) が PayPal アプリで発見されました。

同様に、iOS アプリは Obj-C や Swift で C/C++ コールをラップできるため、これらの種類の攻撃を受けやすくなります。

**例:**

以下のコードスニペットはバッファオーバーフロー脆弱性をもたらす状態の簡単な例を示しています。

```c
 void copyData(char *userId) {
    char  smallBuffer[10]; // size of 10
    strcpy(smallBuffer, userId);
 }
```

潜在的なバッファオーバーフローを特定するには、限られたサイズのバッファにユーザー入力をコピーするなど、安全ではない文字列関数 (`strcpy`, `strcat`, その他の "str" 接頭辞で始まる関数など) や潜在的に脆弱なプログラミング構造の使用を探します。以下は安全でない文字列関数のため危険とみなすべきです。

- `strcat`
- `strcpy`
- `strncat`
- `strlcat`
- `strncpy`
- `strlcpy`
- `sprintf`
- `snprintf`
- `gets`

また、"for" や "while" ループとして実装されたコピー操作のインスタンスを探し、長さのチェックが正しく実行されていることを確認します。

以下のベストプラクティスに従っていることを確認します。

- 配列インデックス、バッファ長計算、その他セキュリティ上重要な操作に整数変数を使用する場合には、符号なしの整数型が使用されていること、および整数ラッピングの可能性を防ぐために前提条件テストを実行していることを確認しています。
- アプリは `strcpy` や他の "str" 接頭辞で始まる安全でない文字列関数や, `sprint`, `vsprintf`, `gets` などを使用していません。
- アプリに C++ コードを含む場合、ANSI C++ string クラスを使用しています。
- `memcpy` の場合、ターゲットバッファが少なくともソースと同じであること、および両方のバッファがオーバーラップしていないことを確認します。
- Objective-C で書かれた iOS アプリは NSString クラスを使用しています。iOS 上の C アプリは、文字列の Core Foundation 表現である CFString を使用する必要があります。
- 信用できないデータを書式文字列に連結していません。

### 静的解析セキュリティテストに関する注意点

低レベルコードの静的コード解析は、簡単に一冊の本を埋めることができる複雑なトピックです。[RATS](https://code.google.com/archive/p/rough-auditing-tool-for-security/downloads "RATS - Rough auditing tool for security") などの自動化ツールと限られた手作業によるインスペクションの労力の組み合わせが、通常、比較的簡単な問題を特定するには十分です。しかし、メモリ破損の状態はしばしば複雑な原因に起因します。例えば、Use After Free バグは実際に、入り組んで直感的ではない競合状態の結果かもしれません。見落とされたコードの欠陥の深刻な例から明らかなバグは、一般に動的解析やプログラムを深く理解することに時間を費やしたテスト担当者により発見されます。

### 動的解析セキュリティテストに関する注意点

メモリ破損のバグは入力ファジングで最もよく見つかります。自動化されたブラックボックスソフトウェアテスト技法であり、不正なデータを継続的にアプリに送信して、潜在的な脆弱性の状態を調査します。このプロセスの間、アプリケーションは誤動作やクラッシュを監視されます。クラッシュが発生した場合、(少なくともセキュリティテスト技術者にとっての) 希望はクラッシュを引き起こす条件が悪用可能なセキュリティ上の欠陥を明らかにすることです。

ファズテスト技法やスクリプト (しばしば「ファザー」と呼ばれる) は通常、構造化された入力の複数のインスタンスを完全には正しくない形式で生成します。基本的に、生成された値や引数は少なくとも部分的にターゲットアプリケーションにより受け入れられ、また無効な要素も含み、潜在的に入力処理上の欠陥や予期しないプログラム動作を引き起こします。よいファザーはかなりの量の可能なプログラム実行パス (すなわち、高いカバレッジ出力) をさらけ出します。入力はスクラッチで生成される (「生成ベース」) か、既知の有効な入力データの変異から導出 (「変異ベース」) します。

ファジングの詳細については、[OWASP ファジングガイド](https://owasp.org/www-community/Fuzzing "OWASP Fuzzing Guide") を参照してください。

## バイナリ保護メカニズム

### 位置独立コード (Position Independent Code)

[PIC (Position Independent Code)](https://en.wikipedia.org/wiki/Position-independent_code) は一次メモリのどこかに配置され、その絶対アドレスに関係なく適切に実行されるコードです。PIC は共有ライブラリによく使用されるため、同じライブラリコードを各プログラムアドレス空間の使用中の他のメモリ (例えば、他の共有ライブラリ) と重ならない場所にロードできます。

PIE (Position Independent Executable) はすべて PIC から作られた実行可能バイナリです。PIE バイナリは実行可能ファイルのベースやスタック、ヒープ、ライブラリの位置など、プロセスの重要なデータ領域のアドレス空間位置をランダムに配置する [ASLR (Address Space Layout Randomization)](https://en.wikipedia.org/wiki/Address_space_layout_randomization) を有効にするために使用されます。

### メモリ管理

#### 自動参照カウント (Automatic Reference Counting)

[ARC (Automatic Reference Counting)](https://en.wikipedia.org/wiki/Automatic_Reference_Counting) は [Objective-C](https://developer.apple.com/library/content/releasenotes/ObjectiveC/RN-TransitioningToARC/Introduction/Introduction.html) および [Swift](https://docs.swift.org/swift-book/LanguageGuide/AutomaticReferenceCounting.html) 専用の Clang コンパイラのメモリ管理機能です。ARC はクラスインスタンスが不要になると、そのインスタンスが使用していたメモリを自動的に解放します。ARC はトレーシングガベージコレクションとは異なり、実行時に非同期にオブジェクトを解放するバックグラウンドプロセスが存在しません。

トレーシングガベージコレクションとは異なり、ARC は参照サイクルを自動的には処理しません。つまり、あるオブジェクトへの「強い」参照がある限り、そのオブジェクトは解放されないということです。強い相互参照によりデッドロックやメモリリークが発生する可能性があります。弱い参照を使用してサイクルを断つかどうかは開発者次第です。ガベージコレクションとの違いについて詳しくは [こちら](https://fragmentedpodcast.com/episodes/064/) をご覧ください。

#### ガベージコレクション (Garbage Collection)

[Garbage Collection (GC)](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science)) は Java/Kotlin/Dart などの一部の言語の自動メモリ管理機能です。ガベージコレクタはプログラムによって割り当てられたがもはや参照されないメモリ (ガベージとも呼ばれます) を再利用しようとします。Android ランタイム (ART) は [改良版 GC](https://source.android.com/devices/tech/dalvik#Improved_GC) を使用しています。ARC との違いについて詳しくは [こちら](https://fragmentedpodcast.com/episodes/064/) をご覧ください。

#### 手動メモリ管理 (Manual Memory Management)

ARC や GC が適用されない C/C++ で書かれたネイティブライブラリでは一般的に [手動メモリ管理](https://en.wikipedia.org/wiki/Manual_memory_management) を必要とします。開発者は適切なメモリ管理を行う責任があります。手動メモリ管理は間違って使用された場合、プログラムに主要なクラスのバグ、特に [メモリセーフティ](https://en.wikipedia.org/wiki/Memory_safety) の違反や [メモリリーク](https://en.wikipedia.org/wiki/Memory_leak) を引き起こすことが知られています。

詳細については ["メモリ破損バグ"](#memory-corruption-bugs) をご覧ください。

### スタックスマッシュ保護 (Stack Smashing Protection)

[スタックカナリア](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries) はリターンポインタの直前のスタックに隠された整数値を格納することでバッファオーバーフロー攻撃を防ぐのに役立ちます。この値は関数の return 文が実行される前に検証されます。バッファオーバーフロー攻撃は多くの場合メモリ領域を上書きし、リターンポインタを上書きしてプログラムフローを乗っ取ります。スタックカナリアが有効な場合、それらも上書きされるため、CPU はメモリが改竄されたことを認識します。

スタックオーバーフローは [バッファオーバーフロー](https://en.wikipedia.org/wiki/Buffer_overflow) (またはバッファオーバーラン) として知られる、より一般的なプログラミング脆弱性の一種です。スタックにはすべてのアクティブな関数呼び出しのリターンアドレスが含まれているため、スタック上のバッファをオーバーフィルすると、ヒープ上のバッファをオーバーフィルするよりも **プログラムの実行に失敗する** 可能性が高くなります。
