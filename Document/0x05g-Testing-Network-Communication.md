## ネットワーク通信のテスト (Android アプリ)

### エンドポイント同一性検証のテスト

#### 概要

ネットワーク上で機密情報を転送するために TLS を使用することは、セキュリティの観点から不可欠です。しかし、モバイルアプリケーションとバックエンド API との間の暗号化通信の仕組みを実装することは簡単な作業ではありません。開発者はしばしば、開発プロセスを楽にするために、より簡単ではあるものの安全ではない(任意の証明書を受け入れるなどの)ソリューションを選びます。往々にして製造後に修正されず <sup>[1]</sup>、同時にアプリケーションを中間者攻撃に晒します <sup>[2]</sup>。

#### 静的解析

The static analysis approach is to decompile an application, if the source code was not provided. There are 2 main issues related with validating TLS connection that should be verified in the code:
* 一つ目は証明書が信頼できるソースから取得されたかどうかの検証
* 二つ目はエンドポイントサーバーが正しい証明書を提示しているかどうかを確認すること <sup>[3]</sup> 。

Simply look in the code for TrustManager and HostnameVerifier usage. You can find insecure usage examples in the sections below.

Such checks of improper certificate verification, may be done automatically, using a tool called MalloDroid<sup>[4]</sup>. It simply decompiles an application and warns you if it finds something suspicious. To run it, simply type this command:

```bash
$ ./mallodroid.py -f ExampleApp.apk -d ./outputDir
```

Now, you should be warned if any suspicious code was found by MalloDroid and in `./outputDir` you will find decompiled application for further manual analysis.

##### サーバー証明書の検証

Android で信頼できる接続を確立するための条件を検証するためのメカニズムは `TrustManager` と呼ばれます。ここで確認される条件は、以下の通りです。

* 「信頼できる」CA が署名した証明書であるか
* 証明書は期限切れではないか
* 証明書は自己署名されていないか

前述の条件のコントロールチェックがあるかどうかコードを参照します。例えば、以下のコードは任意の証明書を受け入れます。

```java
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }
    }
};

// SSLContext context
context.init(null, trustAllCerts, new SecureRandom());
```

##### ホスト名検証

TLS 実装のもう一つのセキュリティ違反はホスト名検証の欠如です。開発環境では通常、有効なドメイン名の代わりに内部アドレスを使用するため、開発者はホスト名の検証を無効にする(もしくはアプリケーションに任意のホスト名を許可する)ことがあり、アプリケーションが実稼働に移行する際に変更することを忘れてしまいます。以下のコードはホスト名の検証を無効にする役割を果たします。

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

ビルトインの `HostnameVerifier` を使用して任意のホスト名を受け入れることも可能です。

```
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

信頼できる接続を設定する前にアプリケーションがホスト名を検証することを確認します。


#### 動的解析

動的解析のアプローチは傍受プロキシの使用を必要とします。不適切な証明書の検証をテストするには、以下のコントロールチェックを実行する必要があります。

 1) 自己署名証明書

  Burp で `Proxy -> Options` タブに移動し、`Proxy Listeners` セクションに移動し、リスナを強調表示にしてから `Edit` をクリックします。それから `Certificate` タブに移動し `Use a self-signed certificate` をチェックして `Ok` をクリックします。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが自己署名証明書を受け入れていることを意味します。

 2) 無効な証明書の受け入れ

  Burp で `Proxy -> Options` タブに移動し、`Proxy Listeners` セクションに移動し、リスナを強調表示にしてから `Edit` をクリックします。それから `Certificate` タブに移動し `Generate a CA-signed certificate with a specific hostname` をチェックしてバックエンドサーバーのホスト名を入力します。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが任意の証明書を受け入れていることを意味します。

 3) 間違ったホスト名の受け入れ

  Burp で `Proxy -> Options` タブに移動し、`Proxy Listeners` セクションに移動し、リスナを強調表示にしてから `Edit` をクリックします。それから `Certificate` タブに移動し `Generate a CA-signed certificate with a specific hostname` をチェックして example.org などの無効なホスト名を入力します。ここで、アプリケーションを実行します。HTTPS トラフィックを見ることができれば、アプリケーションが任意のホスト名を受け入れていることを意味します。

> **注意** さらに MITM 分析を行う場合や傍受プロキシの設定に問題がある場合には、Tapioca <sup>[6]</sup> の使用を検討します。これはソフトウェアの MITM 分析を実行するために CERT が事前設定した VM アプライアンス <sup>[7]</sup> です。行うべきことはテストされるアプリケーションをエミュレータにデプロイしてトラフィックのキャプチャを開始するだけです <sup>[8]</sup> 。

#### 改善方法

ホスト名と証明書が正しく検証されていることを確認します。事例や一般的な落とし穴は公式の Android ドキュメント <sup>[3]</sup> を参照ください。


#### 参考情報

#### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

#### OWASP MASVS
* V5.3: "セキュアチャネルが確立されたときに、アプリはリモートエンドポイントのX.509証明書を確認している。有効なCAにより署名された証明書のみが受け入れられている。"

#### CWE
* CWE-296 - Improper Following of a Certificate's Chain of Trust - https://cwe.mitre.org/data/definitions/296.html
* CWE-297 - Improper Validation of Certificate with Host Mismatch - https://cwe.mitre.org/data/definitions/297.html
* CWE-298 - Improper Validation of Certificate Expiration - https://cwe.mitre.org/data/definitions/298.html

#### その他
* [1] Hunting Down Broken SSL in Android Apps -  https://www.owasp.org/images/7/77/Hunting_Down_Broken_SSL_in_Android_Apps_-_Sascha_Fahl%2BMarian_Harbach%2BMathew_Smith.pdf
* [2] CWE-295 - https://cwe.mitre.org/data/definitions/295.html
* [3] Android Official Documentation SSL - https://developer.android.com/training/articles/security-ssl.html
* [4] MalloDroid - https://github.com/sfahl/mallodroid
* [5] Configuring an Android device to work with Burp -  https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
* [6] Announcing CERT Tapioca for MITM Analysis - https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html
* [7] Downloading the CERT Tapioca Virtual Machine - http://www.cert.org/download/mitm/CERT_Tapioca.ova
* [8] Finding Android SSL vulnerabilites with CERT Tapioca - https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html


### カスタム証明書ストアおよび SSL ピンニングのテスト

#### 概要

証明書ピンニングはサーバーで使用されることが既知である証明書やその要素をアプリにハードコードするものです。この技法は不正な CA や CA の危殆化の脅威を軽減するために使用されます。サーバー証明書のピンニングは CA のゲームを終わらせます。証明書ピンニングを実装するモバイルアプリは限られた数のサーバーにのみ接続できます。信頼できる CA やサーバー証明書の小さなリストをアプリケーションにハードコードされるためです。

#### 静的解析

SSL ピンニングを実装するプロセスには以下で示す3つの主要な手順があります。

1. 目的のホストの証明書を取得します
1. 証明書が .bks 形式であることを確認します
1. 証明書をデフォルトの Apache Httpclient のインスタンスにピン留めします

SSL ピンニングの正しい実装を分析するには、HTTP クライアントを以下のようにします。

1. キーストアをロードする

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

キーストアがロードされると KeyStore の CA を信頼する TrustManager を使用できます。

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

The specific implementation in the app might be different, as it might be pinning against only the public key of the certificate, the whole certificate or a whole certificate chain. 

Applications that use third-party networking libraries may utilize the certificate pinning functionality in those libraries. For example, okhttp<sup>[3]</sup> can be set up with the `CertificatePinner` as follows:

```java
OkHttpClient client = new OkHttpClient.Builder()
        .certificatePinner(new CertificatePinner.Builder()
            .add("bignerdranch.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
            .build())
        .build();
```

#### 動的解析

動的解析は好みの傍受プロキシ <sup>[1]</sup> を使用して MITM 攻撃を開始することで実行できます。これによりクライアント(モバイルアプリケーション)とバックエンドサーバーとの間で交換されるトラフィックを監視することができます。プロキシが HTTP リクエストやレスポンスを傍受できない場合、SSL ピンニングは正しく実装されています。

#### 改善方法

SSL ピンニングプロセスは静的解析セクションで説明したように実装する必要があります。詳細については OWASP certificate pinning guide [2] を参照ください。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M3 - 安全でない通信 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
* V5.4 "アプリは独自の証明書ストアを使用するか、エンドポイント証明書もしくは公開鍵を固定化しており、信頼できるCAにより署名された場合でも、別の証明書や鍵を提供するエンドポイントとの接続を確立していない。"

##### CWE
* CWE-295 - Improper Certificate Validation

##### その他

* [1] Setting Burp Suite as a proxy for Android Devices -  https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
* [2] OWASP Certificate Pinning for Android - https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android
* [3] okhttp library - https://github.com/square/okhttp/wiki/HTTPS


### Testing used connectivity and communication libraries

#### Overview 
Android relies on a security provider to provide SSL/TLS based connections. The problem with this security provider (for instance OpenSSL) which is packed with the device, is that it often has bugs and/or vulnerabilities<sup>[1]</sup>.
Developers need to make sure that the application will install a proper security provider to make sure that there will be lesser bugs and vulnerabilities.
Since July 11, 2016, Google rejects Play Store application submissions (both new applications and updates) if they are using vulnerable versions of OpenSSL<sup>[3]</sup>.

#### Static Analysis
In case of an Android SDK based application. The application should have a dependency on the GooglePlayServices. (e.g. in a. gradle build file, you will find `compile 'com.google.android.gms:play-services-gcm:x.x.x'` in the dependencies block). Next you need to make sure that the `ProviderInstaller` class is called with either `installIfNeeded()` or with `installIfNeededAsync()` is called as soon as possible. Exceptions that are thrown by these methods should be caught and handled correctly.
If the application cannot patch its securityprovider then it can either inform the API on his lesser secure state or it can restrict the user in its possible actions as all https-traffic should now be deemed more risky. 
See remediation for possible examples.

In case of an NDK based application: make sure that the application does only bind to a recent and properly patched library that provides SSL/TLS functionality.


#### Dynamic Analysis
When you have the source-code: 

- Run the application in debug mode, then make a breakpoint right where the app will make its first contact with the backend (e.g. do a call to the backend-services/server).
- Right click at the code that is highlighted and select `Evaluate Expression`
- Type `Security.getProviders()` and press enter
- Check the providers and see if you can find `GmsCore_OpenSSL` which should be the new toplisted provider.

When you do not have the source-code:
- Use Xposed to hook into `java.security` package, then hook into `java.security.Security` with the method `getProviders` with no arguments. The return value is an Array of `Provider`. 
- Check if the first provider is `GmsCore_OpenSSL`.


#### Remediation
To make sure that the application is using a patched security provider, the application needs to use the `ProviderInstaller` class which comes with the Google Play services. The Google Play Services can be installed as a dependency in the build.gradle file by adding `compile 'com.google.android.gms:play-services-gcm:x.y.z'` (where x.y.z is a version number) in the dependencies block.
Next, the `ProviderInstaller` needs to be called as early as possible by a component of the application. Here are two adjusted examples from Google on how this could work. In both cases, the developer needs to handle the exceptions properly and it might be wise to report to the backend when the application is working with an unpatched security provider. The first example shows how to do the installation synchronously, the second example shows how to do it asynchronously.

```java
//this is a syncadapter that runs in the background, so you can run the synchronous patching.
public class SyncAdapter extends AbstractThreadedSyncAdapter {

  ...

  // This is called each time a sync is attempted; this is okay, since the
  // overhead is negligible if the security provider is up-to-date.
  @Override
  public void onPerformSync(Account account, Bundle extras, String authority,
      ContentProviderClient provider, SyncResult syncResult) {
    try {
      ProviderInstaller.installIfNeeded(getContext());
    } catch (GooglePlayServicesRepairableException e) {

      // Indicates that Google Play services is out of date, disabled, etc.

      // Prompt the user to install/update/enable Google Play services.
      GooglePlayServicesUtil.showErrorNotification(
          e.getConnectionStatusCode(), getContext());

      // Notify the SyncManager that a soft error occurred.
      syncResult.stats.numIOExceptions++;
      return;

    } catch (GooglePlayServicesNotAvailableException e) {
      // Indicates a non-recoverable error; the ProviderInstaller is not able
      // to install an up-to-date Provider.

      // Notify the SyncManager that a hard error occurred.
      //in this case: make sure that you inform your API of it.
      syncResult.stats.numAuthExceptions++;
      return;
    }

    // If this is reached, you know that the provider was already up-to-date,
    // or was successfully updated.
  }
}



```

```java
//This is the mainactivity/first activity of the application that is there long enough to make the async installing of the securityprovider work.
public class MainActivity extends Activity
    implements ProviderInstaller.ProviderInstallListener {

  private static final int ERROR_DIALOG_REQUEST_CODE = 1;

  private boolean mRetryProviderInstall;

  //Update the security provider when the activity is created.
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    ProviderInstaller.installIfNeededAsync(this, this);
  }

  /**
   * This method is only called if the provider is successfully updated
   * (or is already up-to-date).
   */
  @Override
  protected void onProviderInstalled() {
    // Provider is up-to-date, app can make secure network calls.
  }

  /**
   * This method is called if updating fails; the error code indicates
   * whether the error is recoverable.
   */
  @Override
  protected void onProviderInstallFailed(int errorCode, Intent recoveryIntent) {
    if (GooglePlayServicesUtil.isUserRecoverableError(errorCode)) {
      // Recoverable error. Show a dialog prompting the user to
      // install/update/enable Google Play services.
      GooglePlayServicesUtil.showErrorDialogFragment(
          errorCode,
          this,
          ERROR_DIALOG_REQUEST_CODE,
          new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
              // The user chose not to take the recovery action
              onProviderInstallerNotAvailable();
            }
          });
    } else {
      // Google Play services is not available.
      onProviderInstallerNotAvailable();
    }
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode,
      Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == ERROR_DIALOG_REQUEST_CODE) {
      // Adding a fragment via GooglePlayServicesUtil.showErrorDialogFragment
      // before the instance state is restored throws an error. So instead,
      // set a flag here, which will cause the fragment to delay until
      // onPostResume.
      mRetryProviderInstall = true;
    }
  }

  /**
   * On resume, check to see if we flagged that we need to reinstall the
   * provider.
   */
  @Override
  protected void onPostResume() {
    super.onPostResult();
    if (mRetryProviderInstall) {
      // We can now safely retry installation.
      ProviderInstall.installIfNeededAsync(this, this);
    }
    mRetryProviderInstall = false;
  }

  private void onProviderInstallerNotAvailable() {
    // This is reached if the provider cannot be updated for some reason.
    // App should consider all HTTP communication to be vulnerable, and take
    // appropriate action (e.g. inform backend, block certain high-risk actions, etc.).
  }
}

```

---TODO: {What to do in case of the NDK?}
#### References
##### OWASP Mobile Top 10 2016
##### OWASP MASVS

* V5.6 "The app only depends on up-to-date connectivity and security libraries."

##### CWE

-- {TODO: add CWE references }

##### Info

- [1] OpenSSL Vulnerabilities - https://www.openssl.org/news/vulnerabilities.html
- [2] Updating Your Security Provider to Protect Against SSL Exploits - https://developer.android.com/training/articles/security-gms-provider.html
- [3] How to address OpenSSL vulnerabilities in your apps - https://support.google.com/faqs/answer/6376725?hl=en
