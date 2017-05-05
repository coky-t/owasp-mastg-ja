## 認証とセッション管理のテスト

### ユーザーが正しく認証されていることの検証

#### 概要

-- TODO [Provide a general description of the issue.] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on Verifying that Users Are Properly Authenticated with source code] --


#### 動的解析

-- TODO [Describe how to test for this issue "Verifying that Users Are Properly Authenticated" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue.] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
- 4.1: "アプリがリモートサービスへのアクセスを提供する場合、ユーザー名/パスワード認証など許容される形態の認証がリモートエンドポイントで実行されている。"

##### CWE

-- TODO [Add relevant CWE for "Verifying that Users Are Properly Authenticated"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Verifying that Users Are Properly Authenticated"] --
* Enjarify - https://github.com/google/enjarify


### セッション管理のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Session Management".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on "Testing Session Management" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Session Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Session Management".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.2: "リモートエンドポイントはランダムに生成されたアクセストークンを使用し、ユーザーの資格情報を送信せずにクライアント要求を認証している。"

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

セッションの終了はセッションのライフサイクルの重要な部分です。セッショントークンの寿命を最小限にすることはセッションハイジャック攻撃の成功の可能性を低下させます。

このテストケースのスコープはアプリケーションにログアウト機能があることおよびクライアント側とサーバー側でセッションを実際に終了させることを検証することです。

##### 静的解析

サーバー側コードが利用可能な場合、ログアウト機能の一部としてセッションが終了していることを検証するために、サーバー側コードをレビューします。
ここで必要なチェックは使用される技術により異なります。サーバー側で適切なログアウトを実装するためにセッションを終了する方法の例を以下の示します。
- Spring (Java) - http://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html
- Ruby on Rails -  http://guides.rubyonrails.org/security.html
- PHP - http://php.net/manual/en/function.session-destroy.php
- JSF - http://jsfcentral.com/listings/A20158?link
- ASP.Net - https://msdn.microsoft.com/en-us/library/ms524798(v=vs.90).aspx
- Amazon AWS - http://docs.aws.amazon.com/appstream/latest/developerguide/rest-api-session-terminate.html

#### 動的解析

アプリケーションを動的に解析するには、傍受プロキシを使用する必要があります。ログアウトが適切に実装されているかどうかを確認するには、以下の手順を実行します。
1.  アプリケーションにログインします。
2.  アプリケーション内で認証に必要な操作を行います。
3.  ログアウト操作を行います。
4.  傍受プロキシを使用して手順2で説明した操作の一つを再送信します。例えば、Burp Repeater を使用します。この目的は手順3で無効にされたトークンを使用してサーバーにリクエストを送信することです。

セッションがサーバー側で正しく終了している場合は、エラーメッセージまたはログインページへのリダイレクトがクライアントに戻されます。そうではなく、手順2で同じレスポンスがある場合、このセッションはまだ有効でありサーバー側で正しく終了していません。
より多くのテストケースを含む詳細な説明は、OWASP Web Testing Guide (OTG-SESS-006) <sup>[1]</sup> にあります。

#### 改善方法

ログアウト機能を実装する際に最もよくあるエラーの一つはサーバー側でセッションオブジェクトを破棄しないことです。これによりユーザーがアプリケーションからログアウトしても、セッションがまだ生きている状態になります。セッションが生き残っていて、攻撃者が有効なセッションを所有していれば、それを引き続き使用することができます。セッションタイムアウトコントロールがなければ、ユーザーはログアウトにより自分自身を保護することさえできません。

これを軽減するには、ログアウトした直後にサーバー側のログアウト機能でこのセッション識別子を無効にして、傍受した可能性のある攻撃者が再利用できないようにする必要があります。

これに関連して、有効期限が切れたトークンで操作を呼び出した後、アプリケーションが別の有効なトークンを生成しないことを確認する必要があります。これにより別の認証バイパスが発生する可能性があります。

多くのアプリはお客様の利便性のために自動的にはユーザーをログアウトしません。ユーザーは一度ログインすると、サーバー側でトークンが生成され、アプリケーションの内部ストレージに格納されます。アプリケーションの起動時にユーザー資格情報を再度要求することなく、認証に使用されます。トークンが期限切れになるとリフレッシュトークンを使用して (OAuth2)、ユーザーのセッションを透過的に再開することができます。アプリケーション内にログアウト機能が必要であり、ベストプラクティスに従ってサーバー側のセッションを破棄することで機能します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
-- TODO [Update reference "VX.Y" below for "Testing the Logout Functionality"] --
- 4.3: "ユーザーがログアウトする場合に、リモートエンドポイントは既存のセッションを終了している。"

##### CWE

-- TODO [Add relevant CWE for "Testing the Logout Functionality"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* [1] OTG-SESS-006 - https://www.owasp.org/index.php/Testing_for_logout_functionality
* [2] Session Management Cheat Sheet - https://www.owasp.org/index.php/Session_Management_Cheat_Sheet


### パスワードポリシーのテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing the Password Policy".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

-- TODO [Develop content on Testing the Password Policy with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing the Password Policy" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing the Password Policy".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.4: "パスワードポリシーが存在し、リモートエンドポイントで実施されている。"

##### CWE

-- TODO [Add relevant CWE for "Testing the Password Policy"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing the Password Policy"] --
* Enjarify - https://github.com/google/enjarify




### 過度なログイン試行のテスト

#### 概要

私たちは皆ブルートフォース攻撃について聞いたことがあります。これは最もシンプルな攻撃タイプの一つです。すでに多くのツールが用意されており、すぐに使用できます。また、ターゲットの深い技術的な理解は必要ありません。ユーザー名とパスワードの組み合わせのリストだけで十分に攻撃を実行できます。有効な資格情報の組み合わせが特定されるとアプリケーションへのアクセスが可能となり、アカウントが侵害される可能性があります。

この種の攻撃から保護するために、アプリケーションは定義された数の不正なログイン試行後にアクセスをブロックするコントロールを実装する必要があります。

保護したいアプリケーションによって、許可される不正な試行回数が異なります。例えば、銀行業務アプリケーションでは3回から5回程度の試行ですが、一般公開のフォーラムではもっと多くの回数となります。この閾値に達するとき、アカウントがロックされるのは永続的か一時的かを決定する必要もあります。アカウントを一時的にロックすることをログイン抑制とも呼びます。

このコントロールはサーバー側にあることを明確にすることが重要です。そのため、テストは iOS と Android アプリケーションで同じになります。
さらに、テストはアカウントロックアウトを引き起こす定義された試行回数だけパスワードを誤って入力することにより行われます。その時点で、アンチブルートフォースコントロールが有効になり、正しい資格情報が入力されてもログインは拒否される必要があります。

#### 静的解析

ユーザー名に対する試行回数が設定された試行の最大数に等しいかどうかを確認する検証メソッドがログイン時に存在することを確認する必要があります。この場合、一度この閾値を満たしたら、ログインを許可してはいけません。
正しい試行の後、エラーカウンタをゼロに設置する仕組みも必要です。


#### 動的解析

アプリケーションを動的に解析するには傍受プロキシを使用する必要があります。ロックアウトメカニズムが適切に実装されているかどうかを確認するには以下の手順を実行します。
1.  ロックアウトコントロールを引き起こす回数分の間違ったログインをします(一般に3回から15回の間違った試行です)
2.  アカウントをロックアウトしたら、正しいログイン詳細を入力してログインが可能ではないかどうかを確認します。
正しく実装されている場合、正しいパスワードが入力されても資格情報はすでにブロックされているため、ログオンを拒否する必要があります。

#### 改善方法

ブルートフォース攻撃を防ぐためにロックアウトコントロールをサーバー側で実装する必要があります。さらなる軽減技術について OWASP により Blocking Brute Force Attacks <sup>[3]</sup> に記されています。
不正なログオン試行が累積され、セッションにリンクされないことを明確にすることは重要です。同じセッションでの3回目の試行で資格情報をブロックするコントロールを実装すると、間違った情報を2回入力してから新しいセッションを取得することで簡単にバイパスできます。これによりさらに2回のフリーな試行が可能です。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.5: "不正な認証資格情報が過度に送信される場合、リモートエンドポイントはExponential Backoffを実装しているか一時的にユーザーアカウントをロックしている。"

##### CWE

-- TODO [Add relevant CWE for "Testing Excessive Login Attempts"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他
* [1] OTG-AUTHN-003 - https://www.owasp.org/index.php/Testing_for_Weak_lock_out_mechanism
* [2] Brute Force Attacks - https://www.owasp.org/index.php/Brute_force_attack
* [3] Blocking Brute Force Attacks - https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks

##### ツール

* Burp Suite Professional - https://portswigger.net/burp/
* OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project


### 生体認証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Biometric Authentication".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on "Testing Biometric Authentication" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Biometric Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Biometric Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.6: "生体認証が使用される場合は（単に「true」や「false」を返すAPIを使うなどの）イベントバインディングは使用しない。代わりに、キーチェーンやキーストアのアンロックに基づくものとする。"

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

Web アプリケーションと比較すると、ほとんどのモバイルアプリケーションには一定時間の非アクティブの後セッションを終了してユーザーに再度ログインを強制するセッションタイムアウトメカニズムがありません。ほとんどのモバイルアプリケーションではユーザーは一度だけ資格情報を入力する必要があります。サーバー側で認証された後、アクセストークンはデバイスに格納され、認証に使用されます。トークンが期限切れになると資格情報を再度入力することなしにトークンは更新されます。診療データのような機密情報や金融取引のような重要な機能を扱うアプリケーションではセッションタイムアウトを実装する必要があります。セキュリティ多層対策として定義された時間後にユーザーに再ログインを強制します。

ここではこのコントロールがクライアント側とサーバー側の両方で正しく実装されていることを確認する方法を説明します。

これをテストするには動的解析が効率的な選択肢です。傍受プロキシを使用して実行時にこの機能が動作しているかどうかを簡単に検証できるためです。これはテストケース「ログアウト機能のテスト」に似ていますが、タイムアウト機能を引き起こすのに必要な時間に対してアプリケーションをアイドル状態のままにする必要があります。この条件を満たしたとき、クライアント側とサーバー側で実際にセッションが終了することを検証する必要があります。

#### 静的解析

サーバー側コードが使用可能な場合、セッションタイムアウト機能が正しく構成され、定義された時間が経過するとタイムアウトが発生することをレビューすべきです。
ここで必要なチェックは使用する技術により異なります。セッションタイムアウトを構成する方法の例を以下に示します。
- Spring (Java) - http://docs.spring.io/spring-session/docs/current/reference/html5/
- Ruby on Rails -  https://github.com/rails/rails/blob/318a20c140de57a7d5f820753c82258a3696c465/railties/lib/rails/application/configuration.rb#L130
- PHP - http://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime
- ASP.Net - https://msdn.microsoft.com/en-GB/library/system.web.sessionstate.httpsessionstate.timeout(v=vs.110).aspx
- Amazon AWS - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/config-idle-timeout.html

一部のアプリケーションではクライアント側にも自動ログオフ機能があります。これは必須の機能ではありませんが、セッションタイムアウトを強化するのに役立ちます。これを実装するには、クライアント側は画面が表示されているときにタイムスタンプをコントロールし、経過した時間が定義されたタイムアウトよりも小さいかどうかを継続的にチェックする必要があります。その時間がタイムアウトに一致または超過すると、ログオフメソッドが呼び出され、サーバー側にセッションを終了するためのシグナルを送信し、顧客を情報を与える画面にリダイレクトします。
Android では以下のコードを使用して実装できます <sup>[3]</sup>。

```
public class TestActivity extends TimeoutActivity {
@Override protected void onTimeout() {
// logout
}
@Override protected long getTimeoutInSeconds() {
return 15 * 60; // 15 minutes
}
```

#### 動的解析

アプリケーションを動的に解析するには傍受プロキシを使用する必要があります。セッションタイムアウトが適切に実装されているかどうかを確認するには以下の手順を実行します。
-   アプリケーションにログインします。
-   アプリケーション内で認証に必要な操作を行います。
-   セッションが期限切れになるまでアプリケーションをアイドル状態のままにします(テスト目的では、合理的なタイムアウトを設定し、後の最終バージョンで修正します)

傍受プロキシを使用して手順2で実行した操作の一つを再送信します。例えば、Burp Repeater を使用します。この目的はセッションが期限切れになったときに無効にされたセッション ID でサーバーにリクエストを送信することです。
セッションタイムアウトがサーバー側で正しく構成されている場合には、エラーメッセージまたはログインページへのリダイレクトがクライアントに戻されます。そうではなく、手順2で同じレスポンスがあった場合、このセッションはまだ有効であり、セッションタイムアウトが正しく構成されていないことを意味します。
詳細については OWASP Web Testing Guide (OTG-SESS-007) <sup>[1]</sup> にもあります。

#### 改善方法

ほとんどのフレームワークにはセッションタイムアウトを構成するパラメータがあります。このパラメータはフレームワークのドキュメントで指定されているベストプラクティスに応じて設定する必要があります。ストプラクティスのタイムアウトは10分から2時間までさまざまで、アプリケーションの機密性やそのユースケースによって変化します。
自動ログオフに関して、実装の疑似コードは以下のようになります。

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

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.7: "非アクティブな状態で所定の期間経過後、リモートエンドポイントでセッションを終了している。"

##### CWE

-- TODO [Add relevant CWE for "Testing the Session Timeout"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* [1] OWASP web application test guide https://www.owasp.org/index.php/Test_Session_Timeout_(OTG-SESS-007)
* [2] OWASP Session management cheatsheet https://www.owasp.org/index.php/Session_Management_Cheat_Sheet
* [3] Logout triggered by Client - https://github.com/zoltanersek/android-timeout-activity

##### ツール

-- TODO [Add relevant tools for "Testing the Session Timeout"] --
* Enjarify - https://github.com/google/enjarify



### 二要素認証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing 2-Factor Authentication".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on Testing 2-Factor Authentication with source code] --


#### 動的解析

-- TODO [Describe how to test for this issue "Testing 2-Factor Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing 2-Factor Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.8: "リモートエンドポイントに二要素認証が存在し、リモートエンドポイントで二要素認証要件が一貫して適用されている。"

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

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

-- TODO [Develop content on Testing Step-up Authentication with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Step-up Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Step-up Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.9: "機密データやトランザクションを処理するアクションを有効にするには、ステップアップ認証が必要とされている。"

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

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

--TODO [Develop content on Testing User Device Management with source code] --


#### 動的解析

-- TODO [Describe how to test for this issue "Testing User Device Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing User Device Management".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.10: "アプリはユーザーのアカウントでのすべてのログインアクティビティをユーザーに通知している。ユーザーはアカウントへのアクセスに使用されるデバイスの一覧を表示し、特定のデバイスをブロックすることができる。"

##### CWE

-- TODO [Add relevant CWE for "Testing User Device Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing User Device Management"] --
* Enjarify - https://github.com/google/enjarify
