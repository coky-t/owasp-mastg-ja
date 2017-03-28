## 認証とセッション管理のテスト

### ユーザーが正しく認証されていることの検証

#### 概要

-- TODO [Provide a general description of the issue "Verifying that Users Are Authenticated Properly".] --

-- TODO [One recommended best practice is that authentication must be enforced on the server. List other recommendations here.] --

一部のアプリケーションではクライアント側で認証を行います。つまり開発者はバックエンド API に資格情報を送信する代わりにクライアント側でユーザー名とパスワードを確認するメソッドを作成します。そのような状況では、いくつかのツールの助けを借りてログインフォームをバイパスし、アプリケーションにアクセスすることが可能です。

#### 静的解析

##### ソースコードあり

-- TODO [Add content on "Verifying that Users Are Authenticated Properly" with source code] --

##### ソースコードなし

-- TODO [Add content on "Verifying that Users Are Authenticated Properly" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Verifying that Users Are Authenticated Properly" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying that Users Are Authenticated Properly".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Verifying that Users Are Authenticated Properly"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Verifying that Users Are Authenticated Properly"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Verifying that Users Are Authenticated Properly"] --
* Enjarify - https://github.com/google/enjarify

### セッション管理のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Session Management".] --

##### 推奨されるベストプラクティス

-- TODO [Develop content for Recommended best Practices for "Testing Session Management".] --
- ユーザーがセッションを終了できる「ログアウト」機能が存在する必要があります。

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### ソースコードあり

-- TODO [Add content on "Testing Session Management" with source code] --

##### ソースコードなし

-- TODO [Add content on "Testing Session Management" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Session Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Session Management".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Session Management"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Session Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing Session Management"] --
* Enjarify - https://github.com/google/enjarify

### ログアウト機能のテスト

#### 概要

セッションの終了はセッションのライフサイクルの重要な部分です。セッショントークンの寿命を最小限にすることは、セッションハイジャック攻撃の成功の可能性を低下させます。
 
このテストケースのスコープはアプリケーションにログアウト機能があることと、クライアント側とサーバー側のセッションを効果的に終了することを検証することです。
 
#### テスト

ログアウト機能の正しい実装を確認するには、傍受プロキシを使用して動的解析を適用する必要があります。この技法は Android と iOS の両方のプラットフォームに適用できます。
静的解析

サーバーサイドコードが利用可能な場合は、ログアウト機能の一部としてセッションが終了していることを確認するためにレビューを行う必要があります。

ここで必要となるチェックは使用する技術によって異なります。サーバー側で適切なログアウトを実装するためにセッションを終了する方法の例を以下に示します。
- Spring (Java) - http://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html
-   Ruby on Rails -  http://guides.rubyonrails.org/security.html
- PHP - http://php.net/manual/en/function.session-destroy.php
-   JSF - http://jsfcentral.com/listings/A20158?link
-   ASP.Net - https://msdn.microsoft.com/en-us/library/ms524798(v=vs.90).aspx
-   Amazon AWS - http://docs.aws.amazon.com/appstream/latest/developerguide/rest-api-session-terminate.html

#### 動的解析

アプリケーションの動的解析には、傍受プロキシを使用する必要があります。設定方法についてはセクション XXX を参照ください。
ログアウトが適切に実装されているかどうかを確認するには以下の手順を実行します。
1.  アプリケーションにログインします。
2.  アプリケーション内で認証に必要な操作を行います。
3.  ログアウト操作を実行します。
4.  傍受プロキシを使用して、手順 2 で説明した操作を再送します。例えば、Burp Repeater を使用します。手順 3 で無効にされたトークンを使用してサーバーにリクエストを送信することが目的です。
 
セッションがサーバー側で正しく終了している場合は、エラーメッセージもしくはログインページへのリダイレクトがクライアントに返されます。一方、手順 2 で同じレスポンスがあった場合、このセッションはまだ有効でありサーバー側で正しく終了していません。

より多くのテストケースを含む詳細な説明は、OWASP Web テストガイド (OTG-SESS-006) [1] にも記載されています。

#### 改善方法 

開発者がログアウト機能に行う最も一般的なエラーのひとつは、単にサーバー側でセッションオブジェクトを破壊しないことです。これによりユーザーがアプリケーションからログアウトしても、まだセッションが生きている状態になります。セッションが生き残っており、攻撃者が有効なセッションを所有している場合でもそれを使用することができます。ユーザーはログアウトで自身を保護することはできません。セッションタイムアウトコントロールがない場合も同様です。
 
これを軽減するには、ログアウトした直後にサーバー側のログアウト機能がこのセッション識別子を無効にして、傍受した可能性のある攻撃者が再利用できないようにする必要があります。
 
これに関連して、有効期限が切れたトークンで操作を呼び出した後、アプリケーションは別の有効なトークンを生成しないことを確認する必要があります。これにより別の認証バイパスが発生する可能性があります。
 
お客様の利便性のため、多くのアプリは自動的にユーザーをログアウトしません。ユーザーは一度ログインすると、サーバー側でトークンが生成された後、アプリケーションの内部ストレージに格納され、アプリケーションの起動時にユーザー資格情報を再度要求する代わりに認証に使用されます。アプリケーション内には有効なログアウト機能が必要であり、ベストプラクティスに従ってサーバー側のセッションを破壊する必要があります。

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing the Logout Functionality"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing the Logout Functionality"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] https://www.owasp.org/index.php/Testing_for_logout_functionality_(OTG-SESS-006)
- [2] https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

##### ツール

-- TODO [Add relevant tools for "Testing the Logout Functionality"] --
* Enjarify - https://github.com/google/enjarify

### パスワードポリシーのテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing the Password Policy".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### ソースコードあり

-- TODO [Add content on "Testing the Password Policy" with source code] --

##### ソースコードなし

-- TODO [Add content on "Testing the Password Policy" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing the Password Policy" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing the Password Policy".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing the Password Policy"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing the Password Policy"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing the Password Policy"] --
* Enjarify - https://github.com/google/enjarify

### 過度なログイン試行のテスト

#### 概要

ブルートフォース攻撃について聞いたことはありますか？これは最も簡単な攻撃タイプのひとつで、すでに多くのツールが用意されており、すぐに使用できます。また、ターゲットの深い技術的な理解は必要ではなく、ユーザー名とパスワードの組み合わせのリストだけで十分に攻撃を実行できます。有効な資格情報の組み合わせが特定されると、アプリケーションへのアクセスが可能になり、アカウントが侵害される可能性があります。
 
この種の攻撃から保護されるために、アプリケーションは定義された数の不正なログイン試行後にアクセスをブロックするコントロールを実装する必要があります。
 
保護したいアプリケーションによっては、許可されている不正な試行回数が異なる場合があります。例えば、銀行アプリケーションでは3回から5回くらいですが、一般公開のフォーラムではもっと大きい数字になる可能性があります。この閾値に達したとき、アカウントが永続的にもしくは一時的にロックされるかどうかを決定する必要があります。アカウントを一時的にロックすることはログイン抑制とも呼ばれます。
 
#### テスト

このコントロールはサーバー側であることを明確にすることが重要です。そのため、テストは iOS と Android アプリケーションで同じになります。
さらに、テストは定義された回数の試行のためにパスワードを誤って入力することによりアカウントロックアウトを発動することで成り立ちます。その時点で、耐ブルートフォースコントロールが活性化され、正しい資格情報が入力されてもログオンが拒否される必要があります。
  
#### 静的解析

サーバー側のコードが利用可能である場合、ロックアウト機能の一部としてセッションが終了していることを確認するためにコードをレビューすべきです。
ここでは、ログオンメソッドに資格情報の試行回数が設定された試行の最大回数と等しいことをチェックする validation があることを確認する必要があります。その場合、ログオンは許可されません。
正しい試行の後、エラーカウンターをゼロに設定する仕組みがあることもレビューする価値があります。
 
#### 動的解析

アプリケーションの動的解析には傍受プロキシを使用する必要があります。設定方法についてはセクション XXX を参照ください。
ロックアウト機能が適切に実装されているかどうかをチェックするには以下の手順を実行します。
1.  ログアウトコントロールを発動するために何度も間違ったログインを行います(一般的に3回から15回の間違った試行です)。
2.  アカウントをロックアウトしたら、正しいログオン情報を入力してログインができないかどうかを確認します。
これが正しく実装されている場合、正しいパスワードが入力された場合でも、資格情報はすでにブロックされているため、ログオンは拒否されます。

#### 改善方法

ブルートフォース攻撃を防ぐためにロックアウトコントロールを実装する必要があります。さらなる軽減技法については [3] を参照ください。
不正なログオン試行が累積的でありセッションにリンクされていないことを明確にすることは注意を引き付けます。同じセッションで3回目の試行で資格情報をブロックするコントロールを実装すると、間違った情報を2回入力してから新しいセッションを取得することで簡単にバイパスできてしまいます。これは別の自由な試行を与えることになります。

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Excessive Login Attempts"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Excessive Login Attempts"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] https://www.owasp.org/index.php/Testing_for_Weak_lock_out_mechanism_(OTG-AUTHN-003)
- [2] https://www.owasp.org/index.php/Brute_force_attack
- [3] https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks

##### ツール

-- TODO [Add relevant tools for "Testing Excessive Login Attempts"] --
* Enjarify - https://github.com/google/enjarify

### 生体認証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Biometric Authentication".]

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### ソースコードあり

-- TODO [Add content for "Testing Biometric Authentication" with source code] --

##### ソースコードなし

-- TODO [Add content for "Testing Biometric Authentication" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Biometric Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Biometric Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Biometric Authentication"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Biometric Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing Biometric Authentication"] --
* Enjarify - https://github.com/google/enjarify

### セッションタイムアウトのテスト

#### 概要

Web アプリケーションと比較して、ほとんどのモバイルアプリケーションには不活性な期間の後にセッションを終了してユーザーに再度ログインさせるセッションタイムアウト機能がありません。ほとんどのモバイルアプリケーションでは、ユーザーは一度だけ資格情報を入力する必要があります。サーバー側で認証された後、アクセストークンが認証に使用されるデバイスに格納されます。トークンが期限切れになると、資格情報を再度入力することなくトークンが更新されます。患者データのような機密データや金融取引のような重要な機能を扱うアプリケーションは多層セキュリティ施策として定義された期間後にユーザーに再ログインさせるセッションタイムアウトを実装する必要があります。
 
ここではこのコントロールがクライアント側とサーバー側の両方で正しく実装されていることを確認する方法を説明します。

#### テスト

これをテストするには、動的解析が効率的な選択肢であり、傍受プロキシを使用して実行時にこの機能が動作しているかどうかを簡単に検証できます。これはテストケース OMTG-AUTH-002 (ログアウト機能のテスト) に似ていますが、タイムアウト機能を発動するために必要な時間分、アプリケーションをアイドル状態のままにする必要があります。この条件が整ったとき、セッションがクライアント側とサーバー側で実際に終了することを確認する必要があります。
この技法は Android と iOS プラットフォームの両方に適用できます。

#### 静的解析

サーバー側コードが利用可能である場合、セッションタイムアウト機能が正しく構成され、定義された時間が経過するとタイムアウトが発生することをレビューすべきです。
ここで必要なチェックは使用される技術によって異なります。セッションタイムアウトを設定する方法のさまざまな例を以下に示します。
- Spring (Java) - http://docs.spring.io/spring-session/docs/current/reference/html5/
-   Ruby on Rails -  https://github.com/rails/rails/blob/318a20c140de57a7d5f820753c82258a3696c465/railties/lib/rails/application/configuration.rb#L130
- PHP - http://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime
- ASP.Net - https://msdn.microsoft.com/en-GB/library/system.web.sessionstate.httpsessionstate.timeout(v=vs.110).aspx
-   Amazon AWS - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/config-idle-timeout.html
 
一部もアプリケーションではクライアント側での自動ログオフ機能もあります。これは必須の機能ではありませんが、セッションタイムアウトを強制するのに役立ちます。これを実装するには、クライアント側では画面が表示されたときにタイムスタンプをコントロールし、経過した時間が定義されたタイムアウトよりも小さいかどうかを継続的にチェックする必要があります。その時間がタイムアウトに一致または超過すると、ログオフメソッドが呼び出され、サーバー側にセッションを終了するシグナルを送信し、顧客を情報提供画面にリダイレクトします。

-- TODO [Change code below from Android code to iOS code + format it as code "Testing the Session Timeout"] --
Android の場合、以下のコードを使用して実装することができます。 [3]

public class TestActivity extends TimeoutActivity {<br>
 @Override protected void onTimeout() {<br>
  // logout<br>
}<br>
 @Override protected long getTimeoutInSeconds() {<br>
  return 15 * 60; // 15 minutes<br>
}<br>

#### 動的解析

アプリケーションの動的解析には傍受プロキシを使用する必要があります。設定方法についてはセクション XXX を参照ください。
セッションタイムアウトが適切に実装されているかどうかをチェックするには以下の手順を実行します。
-   アプリケーションにログインする。
-   アプリケーション内で認証に必要な操作を行う。
-   セッションが期限切れになるまでアプリケーションをアイドル状態のままにしておきます(テスト目的では、合理的なタイムアウトを設定し、最終バージョンで修正します)。
 
傍受プロキシを使用して手順2で実行された操作を再送します。例えば、Burp Repeater を使用します。セッションが期限切れになったときに無効にされたセッション ID を持つリクエストをサーバーに送信することが目的です。
セッションタイムアウトがサーバー側で正しく構成されている場合は、エラーメッセージもしくはログインページへのリダイレクトがクライアントに返されます。一方、手順 2 で同じレスポンスがあった場合、このセッションはまだ有効でありセッションタイムアウトコントロールは正しく構成されていません。
より多くのテストケースを含む詳細な説明は、OWASP Web テストガイド (OTG-SESS-007) [1] にも記載されています。

#### 改善方法

ほとんどのフレームワークはセッションタイムアウトを設定するパラメータを持っています。このパラメータはフレームワークのドキュメントで指定されているベストプラクティスに応じて設定する必要があります。アプリケーションの機密性とそのユースケースに応じて、ベストプラクティスのタイムアウト設定は5分から30分の間で変更できます。
自動ログオフに関して、疑似コードの実装は以下のようになります。

Function autologoff<br>
    Get timestamp_start<br>
    While application_is_running<br>
        time=timestamp-timestamp_start<br>
        If time=logoff_condition<br>
            Call logoff<br>
        EndIf<br>
    EndWhile<br>
End<br>

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing the Session Timeout"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing the Session Timeout"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] OWASP web application test guide https://www.owasp.org/index.php/Test_Session_Timeout_(OTG-SESS-007)
- [2] OWASP Session management cheatsheet https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

##### ツール

-- TODO [Add relevant tools for "Testing the Session Timeout"] --
* Enjarify - https://github.com/google/enjarify


### 二要素認証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing 2-Factor Authentication".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### ソースコードあり

-- TODO [Add content on "Testing 2-Factor Authentication" with source code] --

##### ソースコードなし

-- TODO [Add content on "Testing 2-Factor Authentication" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing 2-Factor Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing 2-Factor Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" in "Testing 2-Factor Authentication"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing 2-Factor Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing 2-Factor Authentication"] --
* Enjarify - https://github.com/google/enjarify

### ステップアップ認証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Step-up Authentication".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### ソースコードあり

-- TODO [Add content on "Testing Step-up Authentication" with source code] --

##### ソースコードなし

-- TODO [Add content on "Testing Step-up Authentication" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Step-up Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Step-up Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Step-up Authentication"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Step-up Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing Step-up Authentication"] --
* Enjarify - https://github.com/google/enjarify

### ユーザーデバイス管理のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing User Device Management".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### ソースコードあり

-- TODO [Add content for "Testing User Device Management" with source code] --

##### ソースコードなし

-- TODO [Add content for "Testing User Device Management" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing User Device Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing User Device Management".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing User Device Management"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing User Device Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing User Device Management"] --
* Enjarify - https://github.com/google/enjarify


