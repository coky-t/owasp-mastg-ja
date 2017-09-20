## プラットフォームインタラクションのテスト (Android)

### アプリパーミッションのテスト

#### 概要

Androi はインストールされたすべてのアプリに異なるシステム識別子 (Linux ユーザー ID とグループ ID) を割り当てます。各 Android アプリはプロセスサンドボックス内で動作するため、アプリはサンドボックス外のリソースやデータへのアクセスを明示的に要求する必要があります。特定のシステムデータや機能を使用するために必要なパーミッションを宣言することにより、このアクセスを要求します。データや機能の機密性や重要性に応じて、Android システムは自動的にパーミッションを与えたり、ユーザーに要求を承認するよう求めます。

Android のパーミッションは提供する保護レベルに基づいて四つの異なるカテゴリに分類されます。

* **Normal**: このパーミッションは、他のアプリ、ユーザー、システムへのリスクを最小限に抑えながら、アプリが独立したアプリケーションレベルの機能にアクセスできるようにします。これはアプリのインストール時に付与されます。保護レベルが指定されていない場合、normal がデフォルト値です。例： `android.permission.INTERNET`
* **Dangerous**: このパーミッションはアプリにユーザーデータの制御やデバイスの制御を与え、ユーザーに影響を与えます。このタイプのパーミッションはインストール時には付与されないかもしれません。アプリにパーミッションを与えるかどうかをユーザーに委ねます。例： `android.permission.RECORD_AUDIO`
* **Signature**: このパーミッションは、要求しているアプリがパーミッションを宣言したアプリと同じ証明書で署名されている場合にのみ付与されます。署名が一致する場合、パーミッションは自動的に付与されます。例： `android.permission.ACCESS_MOCK_LOCATION`
* **SystemOrSignature**: このパーミッションはシステムイメージに組み込まれたアプリケーション、もしくはそのパーミッションを宣言したアプリケーションと同じ証明書を使用して署名されたアプリケーションにのみ付与されます。例： `android.permission.ACCESS_DOWNLOAD_MANAGER`

すべての Android パーミッションの完全なリストは、開発者ドキュメント <sup>[1]</sup> にあります。

**カスタムパーミッション**

Android ではアプリのサービスやコンポーネントを他のアプリに公開できます。公開されているコンポーネントにアクセスできるアプリを制限するには、カスタムパーミッションが必要です。カスタムパーミッションは `AndroidManifest.xml` で定義でき、二つの必須の属性を持つ permission タグを作成します。
* `android:name`
* `android:protectionLevel`

_最小限の権限の原則_ に準拠したカスタムパーミッションを作成することは重要です。パーミッションはその目的のために意味のある正確なラベルと説明で明示的に定義する必要があります。

以下は `TEST_ACTIVITY` アクティビティを起動する際に必要となる `START_MAIN_ACTIVITY` というカスタムパーミッションの例です。

最初のコードブロックは自明である新しいパーミッションを定義しています。label タグはパーミッションの要約であり、description は要約より詳細な説明です。protection level は付与しているパーミッションの種類に基づいて設定できます。
パーミッションを定義したら、アプリケーションのマニフェストでそれを指定することにより、コンポーネントに適用できます。この例では、二つ目のブロックが作成したパーミッションで制限するコンポーネントです。これは `android:permission` 属性を加えることで適用できます。

```xml
<permission android:name="com.example.myapp.permission.START_MAIN_ACTIVITY"
        android:label="Start Activity in myapp"
        android:description="Allow the app to launch the activity of myapp app, any app you grant this permission will be able to launch main activity by myapp app."
        android:protectionLevel="normal" />

<activity android:name="TEST_ACTIVITY"
    android:permission="com.example.myapp.permission.START_MAIN_ACTIVITY">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER"/>
     </intent-filter>
</activity>
```

新しいパーミッション `START_MAIN_ACTIVTY` が作成されたので、アプリは `AndroidManifest.xml` ファイルで `uses-permission` タグを使用して、それを要求できます。カスタムパーミッション `START_MAIN_ACTIVITY` を付与された場合、任意のアプリケーションが `TEST_ACTIVITY` を起動できます。Any application can now launch the `TEST_ACTIVITY` if it is granted with the custom permission `START_MAIN_ACTIVITY`.

```xml
<uses-permission android:name=“com.example.myapp.permission.START_MAIN_ACTIVITY”/>
```

#### 静的解析

**Android パーミッション**

パーミッションがアプリ内で本当に必要かどうかチェックする必要があります。例えば、アクティビティがウェブページを WebView にロードするには、Android マニフェストファイルに `INTERNET` パーミッションが必要です。

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

すべてのパーミッションセットのインテントを識別し、必要のないものを削除するには、開発者と共にパーミッションを調べることを常にお勧めします。

また、Android Asset Packaging ツールを使用して、パーミッションを調べることもできます。

```bash
$ aapt d permissions com.owasp.mstg.myapp
uses-permission: android.permission.WRITE_CONTACTS
uses-permission: android.permission.CHANGE_CONFIGURATION
uses-permission: android.permission.SYSTEM_ALERT_WINDOW
uses-permission: android.permission.INTERNAL_SYSTEM_WINDOW
```

**カスタムパーミッション**

アプリケーションマニフェストファイルを使用してカスタムパーミッションを適用するのではなく、プログラムで適用することもできます。これはパーミッションのリークを引き起こし、認証されない操作を実行する可能性があるため、お勧めしません。これは定義されたすべてのカスタムパーミッションが Android マニフェストファイルに適用されているかどうかを調べることにより検証できます。

```java
int canProcess = checkCallingOrSelfPermission(“com.example.perm.READ_INCOMING_MSG”);
if (canProcess != PERMISSION_GRANTED)
throw new SecurityException();
```

#### 動的解析

デバイスにインストールされているアプリケーションのパーミッションは Android セキュリティ評価フレームワーク Drozer を使用して取得できます。以下の抜粋はアプリケーションで使用されるパーミッションに加えてアプリで呈されたカスタムパーミッションを調べる方法を示しています。

```bash
dz> run app.package.info  -a com.android.mms.service
Package: com.android.mms.service
  Application Label: MmsService
  Process Name: com.android.phone
  Version: 6.0.1
  Data Directory: /data/user/0/com.android.mms.service
  APK Path: /system/priv-app/MmsService/MmsService.apk
  UID: 1001
  GID: [2001, 3002, 3003, 3001]
  Shared Libraries: null
  Shared User ID: android.uid.phone
  Uses Permissions:
  - android.permission.RECEIVE_BOOT_COMPLETED
  - android.permission.READ_SMS
  - android.permission.WRITE_SMS
  - android.permission.BROADCAST_WAP_PUSH
  - android.permission.BIND_CARRIER_SERVICES
  - android.permission.BIND_CARRIER_MESSAGING_SERVICE
  - android.permission.INTERACT_ACROSS_USERS
  Defines Permissions:
  - None
```

Android アプリケーションが IPC コンポーネントを他のアプリケーションに公開する場合、特定のアプリケーションに対するコンポーネントにアクセスを制限するパーミッションを定義できます。`normal` または `dangerous` パーミッションで保護されたコンポーネントと通信するために、Drozer は必要なパーミッションを含むように再ビルドできます。

```
$ drozer agent build  --permission android.permission.REQUIRED_PERMISSION
```

この手法は `signature` レベルのパーミッションには使用できないことに注意します。Drozer をターゲットアプリケーションと同じ証明書で署名する必要があるためです。

#### 改善方法

Android マニフェストファイルではアプリ内で必要となるパーミッションのみを要求し、他のパーミッションはすべて削除すべきです。

開発者は `signature` 保護レベルの機密性の高い IPC コンポーネントをセキュアにするよう注意する必要があります。同じ証明書で署名されたアプリケーションのみコンポーネントにアクセスできるようにします。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage

##### OWASP MASVS
* V6.1: "アプリは必要となる最低限の権限のみを要求している。"

##### CWE
* CWE-250 - Execution with Unnecessary Privileges

##### その他
* [1] Android Permissions - https://developer.android.com/guide/topics/permissions/requesting.html
* [2] Custom Permissions - https://developer.android.com/guide/topics/permissions/defining.html
* [3] An In-Depth Introduction to the Android Permission Model - https://www.owasp.org/images/c/ca/ASDC12-An_InDepth_Introduction_to_the_Android_Permissions_Modeland_How_to_Secure_MultiComponent_Applications.pdf
* [4] Android Permissions - https://developer.android.com/reference/android/Manifest.permission.html#ACCESS_LOCATION_EXTRA_COMMANDS

##### ツール
* AAPT - http://elinux.org/Android_aapt
* Drozer - https://github.com/mwrlabs/drozer


### 入力の妥当性確認とサニタイズのテスト

#### 概要

-- TODO [Provide a general description of the issue.] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Clarify the purpose of "[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]" ] --

-- TODO [Develop content for "Testing Input Validation and Sanitization" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue.] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M7 - 脆弱なコード品質 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V6.2: "外部ソースおよびユーザーからの入力がすべて検証されており、必要に応じてサニタイズされている。これにはUI、インテントやカスタムURLなどのIPCメカニズム、ネットワークソースを介して受信したデータを含んでいる。"

##### CWE
* CWE-20 - Improper Input Validation

##### その他
* [1] xyz

##### ツール
* Enjarify - https://github.com/google/enjarify


### カスタム URL スキームのテスト

#### 概要

Android と iOS の両者はカスタム URL スキームを使用してアプリ間通信が可能です。これらのカスタム URL により、他のアプリケーションはカスタム URL スキームをホストするアプリケーション内で特定のアクションを実行できます。`https://` で始まる標準のウェブ URL と同様に、カスタム URI は任意のスキーム接頭辞で始まり、一般的にアプリケーション内で実行するアクションとそのアクションのパラメータを定義します。

事例として、`sms://compose/to=your.boss@company.com&message=I%20QUIT!&sendImmediately=true` を考えます。このようなものをリンクとしてウェブページに埋め込み、モバイルデバイス上で被害者がクリックした場合、悪意を持って作成されたパラメータでカスタム URI を呼び出し、攻撃者が定義したコンテンツを持つ脆弱な SMS アプリケーションにより SMS が送信される可能性があります。

どのアプリケーションでも、これらのカスタム URL スキームのそれぞれを列挙する必要があり、それらが実行するアクションをテストする必要があります。

#### 静的解析

カスタム URL スキームが定義されているかどうかを調査する必要があります。これは AndroidManifest ファイル内の intent-filter 要素でできます <sup>[1]</sup> 。

```xml
<data android:scheme="myapp" android:host="path" />
```
上記の例では `myapp://` という新しい URL を指定しています。

#### 動的解析

ウェブブラウザで呼び出すことができるアプリケーション内の URL スキームを列挙するには、Drozer モジュール `scanner.activity.browsable` を使用する必要があります。

```
dz> run scanner.activity.browsable -a com.google.android.apps.messaging
Package: com.google.android.apps.messaging
  Invocable URIs:
    sms://
    mms://
  Classes:
    com.google.android.apps.messaging.ui.conversation.LaunchConversationActivity
```

カスタム URL スキームは Drozer モジュール `app.activity.start` を使用して呼び出すことができます。

```
dz> run app.activity.start  --action android.intent.action.VIEW --data-uri "sms://0123456789"
```

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue.] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M1 - 不適切なプラットフォームの利用 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage

##### OWASP MASVS
* V6.3: "アプリはメカニズムが適切に保護されていない限り、カスタムURLスキームを介して機密な機能をエクスポートしていない。"

##### CWE
N/A

##### その他
- [1] Custom URL scheme - https://developer.android.com/guide/components/intents-filters.html#DataTest

##### ツール
* Drozer - https://github.com/mwrlabs/drozer



### IPC による機密性の高い機能の開示のテスト

#### 概要

-- TODO [Provide a general description of the issue.] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Clarify purpose of "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content for "Testing For Sensitive Functionality Exposure Through IPC" with source code] --

#### 動的解析

IPC コンポーネントは Drozer を使用して列挙できます。エクスポートされたすべての IPC コンポーネントを一覧表示するには、モジュール `app.package.attacksurface` を使用する必要があります。

```
dz> run app.package.attacksurface com.mwr.example.sieve
Attack Surface:
  3 activities exported
  0 broadcast receivers exported
  2 content providers exported
  2 services exported
    is debuggable
```

##### アクティビティ

アプリケーションによりエクスポートされたアクティビティを一覧表示するには、モジュール `app.activity.info` を使用する必要があります。`-a` でターゲットパッケージを指定するか、ブランクのままにしてデバイス上のすべてのアプリケーションを対象にします。

```
dz> run app.activity.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
  com.mwr.example.sieve.FileSelectActivity
    Permission: null
  com.mwr.example.sieve.MainLoginActivity
    Permission: null
  com.mwr.example.sieve.PWList
    Permission: null  
```

脆弱なパスワードマネージャ "Sieve" <sup>[1]</sup> のアクティビティを列挙することにより、アクティビティ `com.mwr.example.sieve.PWList` は必要なパーミッションなしでエクスポートされていることがわかります。このアクティビティを起動するには、モジュール `app.activity.start` を使用できます。

```
dz> run app.activity.start --component com.mwr.example.sieve com.mwr.example.sieve.PWList
```

アクティビティが直接呼び出されたため、パスワードマネージャを保護するログインフォームはバイパスされ、パスワードマネージャに含まれるデータにアクセスすることができます。

##### サービス

サービスは Drozer モジュール `app.service.info` を使用して列挙できます。

```
dz> run app.service.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
  com.mwr.example.sieve.AuthService
    Permission: null
  com.mwr.example.sieve.CryptoService
    Permission: null
```

サービスと通信するには、静的解析を最初に使用して必要な入力を特定する必要があります。ターゲットアプリケーションをリバースすることで、サービス `AuthService` がターゲットアプリを保護するパスワードと PIN を変更する機能を提供することが分かります。

```
   public void handleMessage(Message msg) {
            AuthService.this.responseHandler = msg.replyTo;
            Bundle returnBundle = msg.obj;
            int responseCode;
            int returnVal;
            switch (msg.what) {
                ...
                case AuthService.MSG_SET /*6345*/:
                    if (msg.arg1 == AuthService.TYPE_KEY) /*7452*/ {
                        responseCode = 42;
                        if (AuthService.this.setKey(returnBundle.getString("com.mwr.example.sieve.PASSWORD"))) {
                            returnVal = 0;
                        } else {
                            returnVal = 1;
                        }
                    } else if (msg.arg1 == AuthService.TYPE_PIN) {
                        responseCode = 41;
                        if (AuthService.this.setPin(returnBundle.getString("com.mwr.example.sieve.PIN"))) {
                            returnVal = 0;
                        } else {
                            returnVal = 1;
                        }
                    } else {
                        sendUnrecognisedMessage();
                        return;
                    }
```

このサービスはエクスポートされるため、モジュール `app.service.send` を使用してサービスと通信し、ターゲットアプリケーションに格納されているパスワードを変更することが可能です。

```
dz> run app.service.send com.mwr.example.sieve com.mwr.example.sieve.AuthService --msg  6345 7452 1 --extra string com.mwr.example.sieve.PASSWORD "abcdabcdabcdabcd" --bundle-as-obj
Got a reply from com.mwr.example.sieve/com.mwr.example.sieve.AuthService:
  what: 4
  arg1: 42
  arg2: 0
  Empty
```

##### ブロードキャスト

ブロードキャストは Drozer モジュール `app.broadcast.info` を使用して列挙できます。ターゲットパッケージは `-a` パラメータを使用して指定する必要があります。

```
dz> run app.broadcast.info -a com.android.insecurebankv2
Package: com.android.insecurebankv2
  com.android.insecurebankv2.MyBroadCastReceiver
    Permission: null
```

例題アプリ "Android Insecure Bank" <sup>2</sup> では、ひとつのブロードキャストレシーバがエクスポートされており、パーミッションを必要とせず、ブロードキャストレシーバをトリガするインテントを記述できることを示しています。ブロードキャストレシーバをテストする際、静的解析を使用してブロードキャストレシーバの機能を理解する必要もあります。

以下の抜粋は、ターゲットアプリケーションのソースコードから取得したもので、ブロードキャストレシーバが SMS メッセージをトリガし、復号されたユーザーのパスワードを含むものを送信することが分かります。

```
public class MyBroadCastReceiver extends BroadcastReceiver {
  String usernameBase64ByteString;
  public static final String MYPREFS = "mySharedPreferences";

  @Override
  public void onReceive(Context context, Intent intent) {
    // TODO Auto-generated method stub

        String phn = intent.getStringExtra("phonenumber");
        String newpass = intent.getStringExtra("newpass");

    if (phn != null) {
      try {
                SharedPreferences settings = context.getSharedPreferences(MYPREFS, Context.MODE_WORLD_READABLE);
                final String username = settings.getString("EncryptedUsername", null);
                byte[] usernameBase64Byte = Base64.decode(username, Base64.DEFAULT);
                usernameBase64ByteString = new String(usernameBase64Byte, "UTF-8");
                final String password = settings.getString("superSecurePassword", null);
                CryptoClass crypt = new CryptoClass();
                String decryptedPassword = crypt.aesDeccryptedString(password);
                String textPhoneno = phn.toString();
                String textMessage = "Updated Password from: "+decryptedPassword+" to: "+newpass;
                SmsManager smsManager = SmsManager.getDefault();
                System.out.println("For the changepassword - phonenumber: "+textPhoneno+" password is: "+textMessage);
smsManager.sendTextMessage(textPhoneno, null, textMessage, null, null);
```

Drozer モジュール `app.broadcast.send` を使用して、ブロードキャストをトリガするインテントを記述し、コントロール内の電話番号にパスワードを送信できます。

```
dz>  run app.broadcast.send --action theBroadcast --extra string phonenumber 07123456789 --extra string newpass 12345
```

これにより以下の SMS が生成されます。

```
Updated Password from: SecretPassword@ to: 12345
```

###### Sniffing Intents

If an Android application broadcasts intents without setting a required permission or specifying the destination package, the intents are susceptible to monitoring by any application on the device.

To register a broadcast receiver to sniff intents, the Drozer module `app.broadcast.sniff` should be used, specifying the action to monitor with the `--action` parameter:

```
dz> run app.broadcast.sniff  --action theBroadcast
[*] Broadcast receiver registered to sniff matching intents
[*] Output is updated once a second. Press Control+C to exit.

Action: theBroadcast
Raw: Intent { act=theBroadcast flg=0x10 (has extras) }
Extra: phonenumber=07123456789 (java.lang.String)
Extra: newpass=12345 (java.lang.String)
```

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue.] --

#### References

##### OWASP Mobile Top 10 2016
* M1 - Improper Platform Usage - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage

##### OWASP MASVS
- V6.4: "The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected."

##### CWE
-- TODO [Add links and titles for CWE related to the "Testing For Sensitive Functionality Exposure Through IPC" topic] --

##### Info
- [1] Sieve: Vulnerable Password Manager - https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk
- [2] Android Insecure Bank V2 - https://github.com/dineshshetty/Android-InsecureBankv2

##### Tools
* Drozer - https://github.com/mwrlabs/drozer


### Testing JavaScript Execution in WebViews

#### Overview

In Web applications, JavaScript can be injected in many ways by leveraging reflected, stored or DOM based Cross-Site Scripting (XSS). Mobile Apps are executed in a sandboxed environment and when implemented natively do not possess this attack vector. Nevertheless, WebViews can be part of a native App to allow viewing of web pages. Every App has it's own cache for WebViews and doesn't share it with the native Browser or other Apps. WebViews in Android are using the WebKit rendering engine to display web pages but are stripped down to a minimum of functions, as for example no address bar is available. If the WebView is implemented too lax and allows the usage of JavaScript it can be used to to attack the App and gain access to it's data.

#### Static Analysis

To create and use a WebView, an instance of the class WebView need to be created.

```Java
WebView webview = new WebView(this);
setContentView(webview);
webview.loadUrl("http://slashdot.org/");
```

Different settings can be applied to the WebView of which one is able to activate and deactivate JavaScript. By default JavaScript is disabled in a WebView, so it need to be explicitly enabled. Look for the method `setJavaScriptEnabled` to check if JavaScript is activated.

```Java
webview.getSettings().setJavaScriptEnabled(true);
```

This allows the WebView to interpret JavaScript and execute it's command.


#### Dynamic Analysis

A Dynamic Analysis depends on different surrounding conditions, as there are different possibilities to inject JavaScript into a WebView of an App:
* Stored Cross-Site Scripting (XSS) vulnerability in an endpoint, where the exploit will be sent to the WebView of the Mobile App when navigating to the vulnerable function.
* Man-in-the-middle (MITM) position by an attacker where he is able to tamper the response by injecting JavaScript.
* Malware tampering local files that are loaded by the WebView.

In order to address these attack vectors, the outcome of the following checks should be verified:
* All functions offered by the endpoint need to be free of stored XSS<sup>[4]</sup>.
* The HTTPS communication need to be implemented according to best practices to avoid MITM attacks. This means:
  * whole communication is encrypted via TLS (see OMTG-NET-001),
  * the certificate is checked properly (see OMTG-NET-002) and/or
  * the certificate is even pinned (see OMTG-NET-004)
* Only files within the App data directory should be rendered in a WebView (see OMTG-ENV-007).

#### Remediation

JavaScript is disabled by default in a WebView and if not needed shouldn't be enabled. This reduces the attack surface and potential threats to the App. If JavaScript is needed it should be ensured:
* that the communication relies consistently on HTTPS (see also OMTG-NET-001) to protect the HTML and JavaScript from tampering while in transit.
* that JavaScript and HTML is only loaded locally from within the App data directory or from trusted web servers.

The cache of the WebView should also be cleared in order to remove all JavaScript and locally stored data, by using `clearCache()`<sup>[2]</sup> when closing the App.

Devices running platforms older than Android 4.4 (API level 19) use a version of Webkit that has a number of security issues. As a workaround, if your app is running on these devices, it must confirm that WebView objects display only trusted content<sup>[3]</sup>.

#### References

##### OWASP Mobile Top 10 2016
* M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V6.5: "JavaScript is disabled in WebViews unless explicitly required."

##### CWE
- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html

##### Info
- [1] setJavaScriptEnabled in WebViews  - https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled(boolean)
- [2] clearCache() in WebViews - https://developer.android.com/reference/android/webkit/WebView.html#clearCache(boolean)
- [3] WebView Best Practices - https://developer.android.com/training/articles/security-tips.html#WebView
- [4] Stored Cross-Site Scripting - https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002)


### Testing WebView Protocol Handlers

#### Overview

Several schemas are available by default in an URI on Android and can be triggered within a WebView<sup>[3]</sup>, e.g:

* http(s):
* file:
* tel:
* geo:

When using them in a link the App can be triggered for example to access a local file when using `file:///storage/emulated/0/private.xml`. This can be exploited by an attacker if he is able to inject JavaScript into the Webview to access local resources via the file schema.

-- TODO [Further develop content on "Testing WebView Protocol Handlers"] --

#### Static Analysis

The following methods are available for WebViews to control access to different resources<sup>[4]</sup>:

* `setAllowContentAccess()`: Content URL access allows WebView to load content from a content provider installed in the system. The default is enabled.
* `setAllowFileAccess()`: Enables or disables file access within WebView. File access is enabled by default.
* `setAllowFileAccessFromFileURLs()`: Sets whether JavaScript running in the context of a file scheme URL should be allowed to access content from other file scheme URLs. The default value is true for API level _ICE_CREAM_SANDWICH_MR1_ and below, and false for API level _JELLY_BEAN_ and above.
* `setAllowUniversalAccessFromFileURLs()`: Sets whether JavaScript running in the context of a file scheme URL should be allowed to access content from any origin. The default value is true for API level ICE_CREAM_SANDWICH_MR1 and below, and false for API level JELLY_BEAN and above.

If one or all of the methods above can be identified and they are activated it should be verified if it is really needed for the App to work properly.

#### Dynamic Analysis

While using the App look for ways to trigger phone calls or accessing files from the file system to identify usage of protocol handlers.

-- TODO [Further develop content on dynamic analysis for "Testing WebView Protocol Handlers" ] --

#### Remediation

Set the following best practices in order to deactivate protocol handlers, if applicable<sup>[2]</sup>:

```java
//Should an attacker somehow find themselves in a position to inject script into a WebView, then they could exploit the opportunity to access local resources. This can be somewhat prevented by disabling local file system access. It is enabled by default. The Android WebSettings class can be used to disable local file system access via the public method setAllowFileAccess.
webView.getSettings().setAllowFileAccess(false);

webView.getSettings().setAllowFileAccessFromFileURLs(false);

webView.getSettings().setAllowUniversalAccessFromFileURLs(false);

webView.getSettings().setAllowContentAccess(false);
```

Access to files in the file system can be enabled and disabled for a WebView with `setAllowFileAccess()`. File access is enabled by default and should be deactivated if not needed. Note that this enables or disables file system access only. Assets and resources are still accessible using `file:///android_asset` and `file:///android_res`<sup>[1]</sup>.

-- TODO [How to disable tel and geo schema?] --

#### References

##### OWASP Mobile Top 10 2016
* M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V6.6: "WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled."

##### CWE
N/A

##### Info
- [1] File Access in WebView - https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess%28boolean%29
- [2] WebView best practices - https://github.com/nowsecure/secure-mobile-development/blob/master/en/android/webview-best-practices.md#remediation
- [3] Intent List - https://developer.android.com/guide/appendix/g-app-intents.html
- [4] WebView Settings - https://developer.android.com/reference/android/webkit/WebSettings.html



### Testing for Local File Inclusion in WebViews

#### Overview

WebViews can load content remotely, but can also load it locally from the App data directory or external storage. If the content is loaded locally it should not be possible by the user to influence the filename or path where the file is loaded from or should be able to edit the loaded file.

-- TODO [Further develop content on the overview for "Testing for Local File Inclusion in WebViews"] --

#### Static Analysis

Check the source code for the usage of WebViews. If a WebView instance can be identified check if local files are loaded through the method `loadURL()`<sup>[1]</sup>.

```Java
WebView webview = new WebView(this);
webView.loadUrl("file:///android_asset/filename.html");
```

It needs to be verified where the HTML file is loaded from. For example if it's loaded from the external storage the file is read and writable by everybody and considered a bad practice.

```java
webview.loadUrl("file:///" +
Environment.getExternalStorageDirectory().getPath() +
"filename.html");
```

The URL specified in `loadURL()` should be checked, if any dynamic parameters are used that can be manipulated, which may lead to local file inclusion.

#### Dynamic Analysis

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

Create a white-list that defines the web pages and it's protocols (HTTP or HTTPS) that are allowed to be loaded locally and remotely. Loading web pages from the external storage should be avoided as they are read and writable for all users in Android. Instead they should be placed in the assets directory of the App.

Create checksums of the local HTML/JavaScript files and check it during start up of the App. Minify JavaScript files in order to make it harder to read them.

#### References

##### OWASP Mobile Top 10 2016
* M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V6.7: "The app does not load user-supplied local resources into WebViews."

##### CWE
N/A

##### Info
- [1] loadURL() in WebView - https://developer.android.com/reference/android/webkit/WebView.html#loadUrl(java.lang.String)



### Testing Whether Java Objects Are Exposed Through WebViews

#### Overview

Android offers two different ways that enables JavaScript executed in a WebView to call and use native functions within an Android App:

* `shouldOverrideUrlLoading()`<sup>[4]</sup>
* `addJavascriptInterface()`<sup>[5]</sup>

**shouldOverrideUrlLoading**

This method gives the host application a chance to take over the control when a new URL is about to be loaded in the current WebView.  The method `shouldOverrideUrlLoading()` is available with two different method signatures:

* `boolean shouldOverrideUrlLoading` (WebView view, String url)
  * This method was deprecated in API level 24.
* `boolean shouldOverrideUrlLoading` (WebView view, WebResourceRequest request)
  * This method was added in API level 24

**addJavascriptInterface**

The `addJavascriptInterface()` method allows to expose Java Objects to WebViews. When using this method in an Android App it is possible for JavaScript code in a WebView to invoke native methods of the Android App.

Before Android 4.2 JELLY_BEAN (API Level 17) a vulnerability was discovered in the implementation of `addJavascriptInterface()`, by using reflection that leads to remote code execution when injecting malicious JavaScript in a WebView<sup>[2]</sup>.

With API Level 17 this vulnerability was fixed and the access granted to methods of a Java Object for JavaScript was changed. When using `addJavascriptInterface()`, methods of a Java Object are only accessible for JavaScript when the annotation `@JavascriptInterface` is explicitly added. Before API Level 17 all methods of the Java Object were accessible by default.

An App that is targeting an Android version before Android 4.2 is still vulnerable to the identified flaw in `addJavascriptInterface()` and should only be used with extreme care. Therefore several best practices should be applied in case this method is needed.


#### Static Analysis

**shouldOverrideUrlLoading**

It needs to be verified if and how the method `shouldOverrideUrlLoading()` is used and if it's possible for an attacker to inject malicious JavaScript.

The following example illustrates how the method can be used.

```Java
@Override
public boolean shouldOverrideUrlLoading (WebView view, WebResourceRequest request) {
    URL url = new URL(request.getUrl().toString());
    // execute functions according to values in URL
  }
}
```

If an attacker has access to the JavaScript code, for example through stored XSS or MITM, he can directly trigger native functions if the exposed Java methods are implemented in an insecure way.

```javascript
window.location = http://example.com/method?parameter=value
```

**addJavascriptInterface**

It need to be verified if and how the method `addJavascriptInterface()` is used and if it's possible for an attacker to inject malicious JavaScript.

The following example shows how `addJavascriptInterface` is used in a WebView to bridge a Java Object to JavaScript:

```Java
WebView webview = new WebView(this);
WebSettings webSettings = webview.getSettings();
webSettings.setJavaScriptEnabled(true);

MSTG_ENV_008_JS_Interface jsInterface = new MSTG_ENV_008_JS_Interface(this);

myWebView.addJavascriptInterface(jsInterface, "Android");
myWebView.loadURL("http://example.com/file.html");
setContentView(myWebView);
```

In Android API level 17 and above, a special annotation is used to explicitly allow the access from JavaScript to a Java method.


```Java
public class MSTG_ENV_008_JS_Interface {

        Context mContext;

        /** Instantiate the interface and set the context */
        MSTG_ENV_005_JS_Interface(Context c) {
            mContext = c;
        }

        @JavascriptInterface
        public String returnString () {
            return "Secret String";
        }

        /** Show a toast from the web page */
        @JavascriptInterface
        public void showToast(String toast) {
            Toast.makeText(mContext, toast, Toast.LENGTH_SHORT).show();
        }
}
```

If the annotation `@JavascriptInterface` is used, this method can be called from JavaScript. If the App is targeting API level < 17, all methods of the Java Object are exposed to JavaScript and can be called.

In JavaScript the method `returnString()` can now be called and the return value can be stored in the parameter `result`.

```Javascript
var result = window.Android.returnString();
```

If an attacker has access to the JavaScript code, for example through stored XSS or MITM, he can directly call the exposed Java methods in order to exploit them.

#### Dynamic Analysis

-- TODO [Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

If `shouldOverrideUrlLoading()` is needed, it should be verified how the input is processed and if it's possible to execute native functions through malicious JavaScript.

If `addJavascriptInterface()` is needed, only JavaScript provided with the APK should be allowed to call it but no JavaScript loaded from remote endpoints.

Another compliant solution is to define the API level to 17 (JELLY_BEAN_MR1) and above in the manifest file of the App. For these API levels, only public methods that are annotated with `JavascriptInterface` can be accessed from JavaScript<sup>[1]</sup>.

```xml
<uses-sdk android:minSdkVersion="17" />
...

</manifest>
```

#### References

##### OWASP Mobile Top 10 2016
* M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
- V6.8: "If Java objects are exposed in a WebView, verify that the WebView only renders JavaScript contained within the app package."

##### CWE
* CWE-502 - Deserialization of Untrusted Data

##### Info
- [1] DRD13 addJavascriptInterface()  - https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=129859614
- [2] WebView addJavascriptInterface Remote Code Execution - https://labs.mwrinfosecurity.com/blog/webview-addjavascriptinterface-remote-code-execution/
- [3] Method shouldOverrideUrlLoading() - https://developer.android.com/reference/android/webkit/WebViewClient.html#shouldOverrideUrlLoading(android.webkit.WebView,%20java.lang.String)
- [4] Method addJavascriptInterface() - https://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object, java.lang.String)



### Testing Object (De-)Serialization

#### Overview

An object and it's data can be represented as a sequence of bytes. In Java, this is possible using object serialization. Serialization is not secure by default and is just a binary format or representation that can be used to store data locally as .ser file. It is possible to sign and encrypt serialized data but, if the source code is available, this is always reversible.  

#### Static Analysis

Search the source code for the following keywords:

* `import java.io.Serializable`
* `implements Serializable`

Check if serialized data is stored temporarily or permanently within the app's data directory or external storage and if it contains sensitive data.

**https://www.securecoding.cert.org/confluence/display/java/SER04-J.+Do+not+allow+serialization+and+deserialization+to+bypass+the+security+manager**


#### Dynamic Analysis

-- TODO [Create content for dynamic analysis of "Testing Object (De-)Serialization" ] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Object (De-)Serialization".] --

#### References

##### OWASP Mobile Top 10 2016
* M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS
* V6.9: "Object serialization, if any, is implemented using safe serialization APIs."

##### CWE
N/A

##### Info
* [1] Update Security Provider - https://developer.android.com/training/articles/security-gms-provider.html



### Testing Root Detection

#### Overview

Checking the integrity of the environment where the app is running is getting more and more common on the Android platform. Due to the usage of rooted devices several fundamental security mechanisms of Android are deactivated or can easily be bypassed by any app. Apps that process sensitive information or have built in largely intellectual property (IP), like gaming apps, might want to avoid to run on a rooted phone to protect data or their IP.

Keep in mind that root detection is not protecting an app from attackers, but can slow down an attacker dramatically and higher the bar for successful local attacks. Root detection should be considered as part of a broad security-in-depth strategy, to be more resilient against attackers and make analysis harder.

#### Static Analysis

Root detection can either be implemented by leveraging existing root detection libraries, such as `Rootbeer`<sup>[1]</sup>, or by implementing manually checks.

Check the source code for the string `rootbeer` and also the `gradle` file, if a dependency is defined for Rootbeer:

```java
dependencies {
    compile 'com.scottyab:rootbeer-lib:0.0.4'
}
```

If this library is used, code like the following might be used for root detection.

```java
        RootBeer rootBeer = new RootBeer(context);
        if(rootBeer.isRooted()){
            //we found indication of root
        }else{
            //we didn't find indication of root
        }
```

If the root detection is implemented from scratch, the following should be checked to identify functions that contain the root detection logic. The following checks are the most common ones for root detection:
* Checking for settings/files that are available on a rooted device, like verifying the BUILD properties for test-keys in the parameter `android.os.build.tags`.
* Checking permissions of certain directories that should be read-only on a non-rooted device, but are read/write on a rooted device.
* Checking for installed Apps that allow or support rooting of a device, like verifying the presence of _Superuser.apk_.
* Checking available commands, like is it possible to execute `su` and being root afterwards.


#### Dynamic Analysis

A debug build with deactivated root detection should be provided in a white box test to be able to apply all test cases to the app.

In case of a black box test, an implemented root detection can be challenging if for example the app is immediately terminated because of a rooted phone. Ideally, a rooted phone is used for black box testing and might also be needed to disable SSL Pinning. To deactivate SSL Pinning and allow the usage of an interception proxy, the root detection needs to be defeated first in that case. Identifying the implemented root detection logic without source code in a dynamic scan can be fairly hard.

By using the Xposed module `RootCloak` it is possible to run apps that detect root without disabling root. Nevertheless, if a root detection mechanism is used within the app that is not covered in RootCloak, this mechanism needs to be identified and added to RootCloak in order to disable it.

Other options are dynamically patching the app with Friday or repackaging the app. This can be as easy as deleting the function in the smali code and repackage it, but can become difficult if several different checks are part of the root detection mechanism. Dynamically patching the app can also become difficult if countermeasures are implemented that prevent runtime manipulation/tampering.

Otherwise it should be switched to a non-rooted device in order to use the testing time wisely and to execute all other test cases that can be applied on a non-rooted setup. This is of course only possible if the SSL Pinning can be deactivated for example in smali and repackaging the app.

#### Remediation

To implement root detection within an Android app, libraries can be used like `RootBeer`<sup>[1]</sup>. The root detection should either trigger a warning to the user after start, to remind him that the device is rooted and that the user can only proceed on his own risk. Alternatively, the app can terminate itself in case a rooted environment is detected. This decision is depending on the business requirements and the risk appetite of the stakeholders.

#### References

##### OWASP Mobile Top 10 2016
* M8 - Code Tampering - https://www.owasp.org/index.php/Mobile_Top_10_2016-M8-Code_Tampering
* M9 - Reverse Engineering - https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering

##### OWASP MASVS

- V6.10: "The app detects whether it is being executed on a rooted or jailbroken device. Depending on the business requirement, users are warned, or the app is terminated if the device is rooted or jailbroken."

##### CWE
N/A

##### Info
- [1] RootBeer - https://github.com/scottyab/rootbeer

##### Tools

* RootCloak - http://repo.xposed.info/module/com.devadvance.rootcloak2
