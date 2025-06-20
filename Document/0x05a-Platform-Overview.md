# Android プラットフォーム概要

この章ではアーキテクチャの観点から Android プラットフォームを紹介します。以下の五つの主要な領域について説明します。

1. Android アーキテクチャ
2. Android セキュリティ: 多層防御アプローチ
3. Android アプリケーション構造
4. Android アプリケーションの公開
5. Android アプリケーションのアタックサーフェイス

Android プラットフォームの詳細については [Android 開発者ドキュメントウェブサイト](https://developer.android.com/index.html "Android Developer Guide") をご覧ください。

## Android アーキテクチャ

[Android](https://en.wikipedia.org/wiki/Android_(operating_system) "Android (Operating System)") は [Open Handset Alliance](https://www.openhandsetalliance.com/) (Google を中心としたコンソーシアム) が開発した Linux ベースのオープンソースプラットフォームであり、モバイルオペレーティングシステム (OS) として機能します。現在、このプラットフォームはモバイルフォン、タブレット、ウェアラブル技術、テレビ、その他の「スマート」デバイスなど、さまざまな最新テクノロジの基盤となっています。典型的な Android ビルドにはさまざまなプリインストール (「ストック」) アプリが付属しており、 Google Play ストアや他のマーケットプレイスを通じてサードパーティアプリのインストールをサポートしています。

Android のソフトウェアスタックはいくつかの異なるレイヤで構成されています。各レイヤはインタフェースを定義し、特定のサービスを提供します。

<img src="Images/Chapters/0x05a/android_software_stack.png" width="400px" />

**カーネル:** 最下層では、Android は [Low Memory Killer](https://source.android.com/devices/tech/perf/lmkd) 、ウェイクロック、 [Binder IPC](https://source.android.com/devices/architecture/hidl/binder-ipc) ドライバなどの重要な追加機能を含む [Linux カーネルのバリエーション](https://source.android.com/devices/architecture/kernel) をベースにしています。 MASTG では、Android が一般的な Linux ディストリビューションと大きく異なる、OS のユーザーモード部分に焦点を当てます。私たちにとって最も重要なコンポーネントはアプリケーションで使用されるマネージドランタイム (ART/Dalvik) と、glibc (GNU C ライブラリ) の Android 版である [Bionic](https://en.wikipedia.org/wiki/Bionic_(software) "Android (Bionic)") の二つです。

**HAL:** カーネルの上には、ハードウェア抽象化レイヤ (Hardware Abstraction Layer, HAL) がビルトインのハードウェアコンポーネントと対話するための標準インタフェースを定義します。いくつかの HAL 実装では Android システムが必要に応じて呼び出す共有ライブラリモジュールにパッケージ化されています。これはアプリケーションがデバイスのハードウェアと対話できるようにするための基礎となります。たとえば、純正の電話アプリケーションがデバイスのマイクとスピーカーを使用できるようにします。

**ランタイム環境:** Android アプリは Java や Kotlin で書かれて [Dalvik バイトコード](https://source.android.com/devices/tech/dalvik/dalvik-bytecode) にコンパイルされます。バイトコード命令を解釈してターゲットデバイス上で実行するランタイムを使用して実行できます。Android では、これは [Android Runtime (ART)](https://source.android.com/devices/tech/dalvik/configure#how_art_works) です。これは Java アプリケーションの [JVM (Java Virtual Machine)](https://en.wikipedia.org/wiki/Java_virtual_machine) や .NET アプリケーションの Mono ランタイムに似ています。

Dalvik バイトコードは Java バイトコードの最適化バージョンです。作成にはまず Java または Kotlin コードをそれぞれ javac や kotlinc コンパイラを使用して Java バイトコードにコンパイルし .class ファイルを生成します。最後に、Java バイトコードは d8 ツールを使用して Dalvik バイトコードに変換されます。 Dalvik バイトコードは .dex ファイルの形で APK や AAB ファイルにパックされ、Android のマネージドランタイムによってデバイス上で実行されます。

<img src="Images/Chapters/0x05a/java_vs_dalvik.png" width="400px" />

Android 5.0 (API レベル 21) 以前は、Android は Dalvik Virtual Machine (DVM) 上でバイトコードを実行し、実行時にマシンコードに変換していました。 ジャストインタイム (_just-in-time_, JIT) コンパイルと呼ばれる処理です。これによりランタイムはコード解釈の柔軟性を維持しながら、コンパイルされたコードの速度の恩恵を受けられます。

Android 5.0 (API レベル 21) 以降、Android は DVM の後継である Android Runtime (ART) 上でバイトコードを実行するようになりました。ART は Java とネイティブスタック情報の両方を含めることで、パフォーマンスを向上させ、アプリのネイティブクラッシュレポートのコンテキスト情報を提供します。後方互換性を維持するために同じ Dalvik バイトコードを入力に使用します。しかし、ART は Dalvik バイトコードを異なる方法で実行します。 事前 (_ahead-of-time_, AOT) コンパイル、 ジャストインタイム (_just-in-time_, JIT) コンパイル、プロファイルガイドに基づくコンパイルを組み合わせたハイブリッドコンパイルを使用します。

- **AOT** は Dalvik バイトコードをネイティブコードにプリコンパイルし、生成されたコードはディスク上に .oat 拡張子 (ELF バイナリ) で保存されます。 dex2oat ツールはコンパイルの実行に使用され、Android デバイスの /system/bin/dex2oat にあります。 AOT コンパイルはアプリのインストール時に実行されます。これによりコンパイルが不要になるため、アプリケーションの起動が速くなります。しかし、これは JIT コンパイルに比べてインストール時間が長くなることも意味します。さらに、アプリケーションは常に OS の現行バージョンに対して最適化されているため、ソフトウェアのアップデートによって以前にコンパイルされたアプリケーションはすべて再コンパイルすることになり、システムアップデート時間が大幅に増加することを意味します。最後に、AOT コンパイルはユーザーが使用しない部分があってもアプリケーション全体をコンパイルします。
- **JIT** は実行時に発生します。
- **プロファイルガイドに基づくコンパイル** は AOT の欠点に対処するために Android 7 (API レベル 24) で導入されたハイブリッドアプローチです。最初に、アプリケーションは JIT コンパイルを使用し、Android はアプリケーションで頻繁に使用される部分すべてを追跡します。この情報はアプリケーションプロファイルに保存され、デバイスがアイドル状態のときにコンパイル (dex2oat) デーモンが実行され、プロファイルから特定された頻繁に使用されるコードパスを AOT コンパイルします。

<img src="Images/Chapters/0x05a/java2oat.png" width="100%" />

入手元: <https://lief-project.github.io/doc/latest/tutorials/10_android_formats.html>

**サンドボックス化:** Android アプリはハードウェアリソースに直接アクセスできず、各アプリはそれ自身の仮想マシンまたはサンドボックス内で動作します。これにより OS はデバイス上のリソースとメモリアクセスを正確に制御できます。例えば、アプリがクラッシュしてもその同じデバイス上で実行中の他のアプリには影響しません。 Android はアプリに割り当てられるシステムリソースの最大数を制御し、一つのアプリが多すぎるリソースを独占することを防ぎます。同時に、このサンドボックス設計は Android のグローバルな多層防御戦略における多くの原則の一つとみなすことができます。権限の低い悪意のあるサードパーティアプリケーションは自身のランタイムを抜け出して、同じデバイス上で狙ったアプリケーションのメモリを読み取ることはできないはずです。次のセクションでは Android オペレーティングシステムのさまざまな防御層について詳しく見ていきます。 ["ソフトウェアの分離"](#software-isolation) セクションで詳しく説明します。

より詳しい情報については Google Source 記事 ["Android Runtime (ART)"](https://source.android.com/devices/tech/dalvik/configure#how_art_works) 、 [Jonathan Levin による書籍 "Android Internals"](http://newandroidbook.com/) 、 [@_qaz_qaz によるブログ投稿 "Android 101"](https://secrary.com/android-reversing/android101/) をご覧ください。

## Android セキュリティ: 多層防御アプローチ

Android アーキテクチャは多層防御アプローチを可能にするさまざまなセキュリティ層を実装しています。これは機密性の高いユーザーデータやアプリケーションの機密性、完全性、可用性が単一のセキュリティ対策に依存していないことを意味します。このセクションでは Android システムが提供するさまざまな防御層の概要を説明します。セキュリティ戦略は大きく四つの異なるドメインに分類でき、それぞれが特定の攻撃モデルに対する保護に重点を置いています。

- システム全体のセキュリティ
- ソフトウェアの分離
- ネットワークセキュリティ
- エクスプロイト防止

### システム全体のセキュリティ

#### デバイス暗号化

Android は Android 2.3.4 (API レベル 10) からデバイス暗号化をサポートしており、それ以降いくつかの大きな変更が加えられています。 Google は Android 6.0 (API レベル 23) 以降を実行するすべてのデバイスがストレージ暗号化をサポートすることを課しています。ただし一部のローエンドデバイスではパフォーマンスに大きな影響を与えるため免除されています。

- [フルディスク暗号化 (Full-Disk Encryption, FDE)](https://source.android.com/security/encryption/full-disk "Full-Disk Encryption"): Android 5.0 (API レベル 21) 以降はフルディスク暗号化をサポートしています。この暗号化ではユーザーのデバイスパスワードで保護された単一の鍵を使用してユーザーデータパーティションを暗号化および復号化します。この種の暗号化は現在では非推奨とされており、可能な限りファイルベース暗号化を使用すべきです。フルディスク暗号化には、ユーザーがパスワードを入力してロック解除しないと、通話を受けられないことや再起動後にアラームが作動しないことなどの欠点があります。

- [ファイルベース暗号化 (File-Based Encryption, FBE)](https://source.android.com/security/encryption/file-based "File-Based Encryption"): Android 7.0 (API レベル 24) ではファイルベースの暗号化をサポートしています。ファイルベース暗号化はさまざまなファイルを異なる鍵で暗号化できるため、ファイルを個別に解読できます。このタイプの暗号化をサポートするデバイスは Direct Boot もサポートします。 Direct Boot により、ユーザーがデバイスをロック解除していなくても、デバイスはアラームやアクセシビリティサービスなどの機能にアクセスできます。

> 注意: [Adiantum](https://github.com/google/adiantum "Adiantum") について耳にしたことがあるかもしれません。これは Android 9 (API レベル 28) 以降を実行している  CPU に AES 命令がないデバイス用に設計された暗号化方式です。 **Adiantum は ROM 開発者やデバイスベンダーにのみ関係します**。 Android は開発者がアプリケーションから Adiantum を使用するための API を提供していません。 Google が推奨しているように、 ARMv8 Cryptography Extensions を搭載した ARM ベースのデバイスや、 AES-NI を搭載した x86 ベースのデバイスを出荷する際に Adiantum を使用すべきではありません。これらのプラットフォームでは AES の方が高速です。
>
> 詳細については [Android ドキュメント](https://source.android.com/security/encryption/adiantum "Adiantum") を参照してください。

#### Trusted Execution Environment (TEE)

Android システムが暗号化を実行するには暗号化鍵をセキュアに生成、インポート、保存する方法が必要です。私たちは本質的に機密データをセキュアに保つという本題を暗号化鍵をセキュアに保つことにシフトしています。攻撃者が暗号化鍵をダンプまたは推測できる場合、暗号化された機密データを取り出すことができます。

Android は暗号化鍵をセキュアに生成および保護する問題を解決するために Trusted Execution Environment を提供します。これは Android システムの専用ハードウェアコンポーネントが暗号化鍵マテリアルの処理を担うことを意味します。これには三つの主要モジュールが関与します。

- [ハードウェア支援 KeyStore](https://source.android.com/security/keystore): このモジュールは Android OS およびサードパーティアプリに暗号化サービスを提供します。これによりアプリは暗号化鍵マテリアルを公開することなく TEE で暗号化にかかわる機密性の高い操作を実行できます。

- [StrongBox](https://developer.android.com/training/articles/keystore#HardwareSecurityModule): Android 9 (Pie) では、ハードウェア支援 KeyStore を実装するためのもう一つのアプローチとして StrongBox が導入されました。 Android 9 Pie までは、 Android OS カーネルの外部にある TEE 実装がハードウェア支援 KeyStore とされていました。 StrongBox は KeyStore が実装されるデバイスに追加される実際には完全に別のハードウェアチップで、 Android ドキュメントにも明確に定義されています。鍵が StrongBox にあるかどうかをプログラムで確認できます。ある場合、独自の CPU 、セキュアストレージ、 True Random Number Generator (TRNG) を備えたハードウェアセキュリティモジュールにより鍵が保護されていることを確認できます。すべての機密性の高い暗号化操作は StrongBox のセキュアな境界内にあるこのチップ上で行われます。

- [GateKeeper](https://source.android.com/security/authentication/gatekeeper): GateKeeper モジュールはデバイスパターンおよびパスワード認証を有効にします。認証プロセス時のセキュリティ上機密性の高い操作はデバイス上で利用可能な TEE の内部で行われます。 GateKeeper は三つの主要コンポーネントで構成されています。 (1) GateKeeper を公開するサービス `gatekeeperd` 、(2) ハードウェアインタフェースである GateKeeper HAL 、(3) TEE の GateKeeper 機能を実装する実際のソフトウェアである TEE 実装。

#### 検証済みブート (Verified Boot)

Android デバイスで実行されているコードが信頼できるソースからのものであり、その完全性が損なわれていないことを確認する方法が必要です。これを実現するために、 Android は検証済みブートの概念を導入しました。検証済みブートの目的はハードウェアとそのハードウェア上で実行される実際のコードとの間に信頼関係を確立することです。検証済みブートシーケンスでは、ハードウェア保護された Root-of-Trust (RoT) から最終的に実行されるシステムまで完全な信頼の連鎖が確立され、必要なすべてのブートフェーズを通して検証されます。 Android システムが最終的にブートした際、そのシステムが改竄されていないことが保証されます。実行されているコードが OEM により意図されたものであり、悪意を持ってあるいは偶発的に改変されたものではないことを暗号学的に証明できます。

詳細については [Android ドキュメント](https://source.android.com/security/verifiedboot) を参照してください。

### ソフトウェアの分離

#### Android ユーザーとグループ

Android オペレーティングシステムは Linux をベースにしていますが、他の Unix ライクなシステムと同じようにユーザーアカウントを実装してはいません。 Android では Linux カーネルのマルチユーザーサポートを使用してアプリをサンドボックス化しています。一部の例外を除いて、各アプリは別々の Linux ユーザーの下で実行しており、他のアプリやオペレーティングシステムの他の部分から実質的に分離されています。

ファイル [android_filesystem_config.h](https://android.googlesource.com/platform/system/core/+/master/libcutils/include/private/android_filesystem_config.h) には、システムプロセスに割り当てられる定義済みユーザーおよびグループのリストがあります。他のアプリケーション用の UID (userID) は後者がインストールされたときに追加されます。

例えば、 Android 9.0 (API レベル 28) では以下のシステムユーザーが定義されています。

```c
    #define AID_ROOT             0  /* traditional unix root user */
    #...
    #define AID_SYSTEM        1000  /* system server */
    #...
    #define AID_SHELL         2000  /* adb and debug shell user */
    #...
    #define AID_APP_START          10000  /* first app user */
    ...
```

#### SELinux

Security-Enhanced Linux (SELinux) は 強制アクセス制御 (Mandatory Access Control, MAC) システムを使用して、どのプロセスがどのリソースにアクセスする必要があるかをさらにロックダウンします。各リソースにはどのユーザーがどのタイプのアクションを実行できるかを定義する `user:role:type:mls_level` の形式でラベルが付けられます。例えば、あるプロセスはファイルを読むことしかできず、別のプロセスはそのファイルを編集または削除できることがあります。このように、最小特権の原則に取り組むことにより、脆弱なプロセスは特権昇格やラテラルムーブメントにより悪用することがより困難になります。

詳細については [Android ドキュメント](https://source.android.com/security/selinux "Security-Enhanced Linux in Android") を参照してください。

#### パーミッション

Android はアクセス制御メカニズムとして使用される広範なパーミッションシステムを実装しています。これにより機密性の高いユーザーデータやデバイスリソースへの制御されたアクセスを保証します。 Android はパーミッションをさまざまな保護レベルを提供する異なる [タイプ](https://developer.android.com/guide/topics/permissions/overview#types) に分類しています。

> Android 6.0 (API レベル 23) より前では、アプリが要求したすべてのパーミッションはインストール時に付与されていました (インストール時パーミッション) 。 API レベル 23 以降、実行時に一部のパーミッション要求をユーザーが承認する必要があります (ランタイムパーンミッション) 。

詳細については [Android ドキュメント](https://developer.android.com/guide/topics/permissions/overview) を参照してください。いくつかの [考慮事項](https://developer.android.com/training/permissions/evaluating) や [ベストプラクティス](https://developer.android.com/training/permissions/usage-notes) もあります。

アプリパーミッションをテストする方法については "Android のプラットフォーム API" の章の [アプリパーミッションのテスト](0x05h-Testing-Platform-Interaction.md#app-permissions) セクションを参照してください。

### ネットワークセキュリティ

#### TLS by Default

デフォルトでは、 Android 9 (API レベル 28) 以降、すべてのネットワークアクティビティは敵対的環境で実行されているものとして扱われます。これは Android システムが Transport Layer Security (TLS) プロトコルを使用して確立されたネットワークチャネルを介してのみアプリが通信できることを意味します。このプロトコルはすべてのネットワークトラフィックを効果的に暗号化し、サーバーへのセキュアなチャネルを構築します。過去資産の理由のため、クリアなトラフィック接続を使用したい場合があります。このような場合にはアプリケーション内の `res/xml/network_security_config.xml` ファイルを適応させることで実現できます。

詳細については [Android ドキュメント](https://developer.android.com/training/articles/security-config.html) を参照してください。

#### DNS over TLS

システムワイドの DNS over TLS サポートは Android 9 (API レベル 28) から導入されました。これにより TLS プロトコルを使用して DNS サーバーへのクエリを実行できます。 DNS サーバーとの間にセキュアなチャネルが確立され、そのチャネルを通じて DNS クエリが送信されます。これにより DNS ルックアップ時に機密データが漏洩しないことが保証されます。

詳細については [Android 開発者ブログ](https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html) を参照してください。

### エクスプロイト防止

#### ASLR, KASLR, PIE, DEP

アドレス空間配置のランダム化 (Address Space Layout Randomization, ASLR) は Android 4.1 (API レベル 15) 以降 Android の一部となっており、バッファオーバーフロー攻撃に対する標準的な保護です。アプリケーションと OS の両方がランダムなメモリアドレスにロードされるようにします。特定のメモリ領域やライブラリの正しいアドレスを取得することは困難になります。 Android 8.0 (API レベル 26) で、この保護はカーネルにも実装されました (KASLR) 。 ASLR 保護はアプリケーションがメモリ内のランダムな場所にロードできる場合にのみ可能です。これはアプリケーションの位置独立実行可能  (Position Independent Executable, PIE) フラグにより示されます。 Android 5.0 (API レベル 21) 以降、 PIE 非対応のネイティブライブラリのサポートは終了しました。最後に、データ実行防止 (Data Execution Prevention, DEP) はスタックおよびヒープのコード実行を防止します。これもバッファオーバーフローの悪用を阻止するために使用されます。

詳細については [Android Developers ブログ](https://android-developers.googleblog.com/2016/07/protecting-android-with-more-linux.html "Protecting Android with more Linux kernel defenses") を参照してください。

#### SECCOMP フィルタ

Android アプリケーションには C または C++ で記述されたネイティブコードを含めることができます。これらのコンパイル済みバイナリは Java Native Interface (JNI) バインディングを介して Android Runtime と通信することも、システムコールを介して OS と通信することもできます。一部のシステムコールは実装されていないか、通常のアプリケーションにより呼び出されることが想定されていません。これらのシステムコールはカーネルと直接通信するため、エクスプロイト開発者にとって最も重要なターゲットです。 Android 8 (API レベル 26) では、 Android はすべての Zygote ベースのプロセス (つまりユーザーアプリケーション) に対して Secure Computing (SECCOMP) フィルタのサポートが導入されています。このフィルタは利用可能な syscall を bionic を通じて公開されたものに制限します。

詳細については [Android Developers ブログ](https://android-developers.googleblog.com/2017/07/seccomp-filter-in-android-o.html "Seccomp filter in Android O") を参照してください。

## Android アプリケーション構造

### オペレーティングシステムとの通信

Android アプリは Android Framework を介してシステムサービスとやり取りします。 Android Framework は高レベル Java API を提供する抽象化レイヤです。これらのサービスの大部分は通常の Java メソッドコールを介して呼び出され、バックグラウンドで実行されているシステムサービスへの IPC コールに変換されます。システムサービスの例は以下のとおりです。

- コネクティビティ (Wi-Fi, Bluetooth, NFC, など)
- ファイル
- カメラ
- 位置情報 (GPS)
- マイク

このフレームワークは暗号化などの一般的なセキュリティ機能も提供しています。

API 仕様は Android の新しいリリースごとに変更されます。重要なバグ修正とセキュリティパッチは通常、以前のバージョンにも適用されます。

注目すべき [API バージョン](https://developer.android.com/guide/topics/manifest/uses-sdk-element#ApiLevels "What is API level?")。Android バージョンごとに導入されたセキュリティとプライバシー機能の詳細については [最新の minSdkVersion を使用する (Use Up-to-Date minSdkVersion)](../best-practices/MASTG-BEST-0010.md) を参照してください。

Android 開発リリースはユニークな構造になっています。それらはファミリーに編成され、おいしいお菓子にインスパイアされたアルファベット順のコードネームが付けられています。これらはすべて [こちら](https://source.android.com/docs/setup/about/build-numbers "Codenames, tags, and build numbers") で見ることができます。

### アプリサンドボックス

アプリは Android アプリケーションサンドボックス内で実行され、デバイス上の他のアプリからアプリデータとコードの実行を分離します。前述したように、この分離は第一の防御層を追加するものです。

新しいアプリをインストールすると、アプリパッケージから名付けられた新しいディレクトリが作成され、次のパス `/data/data/[package-name]` になります。このディレクトリはアプリのデータを保持します。 Linux ディレクトリパーミッションはディレクトリがアプリの一意の UID でのみ読み書きできるように設定されています。

<img src="Images/Chapters/0x05a/Selection_003.png" width="400px" />

これは `/data/data` フォルダのファイルシステムパーミッションを見ることで確認できます。例えば、 Google Chrome と Calendar にはそれぞれ一つのディレクトリが割り当てられており、異なるユーザーアカウントの下で実行されていることがわかります。

```bash
drwx------  4 u0_a97              u0_a97              4096 2017-01-18 14:27 com.android.calendar
drwx------  6 u0_a120             u0_a120             4096 2017-01-19 12:54 com.android.chrome
```

アプリに共通のサンドボックスを共有させたい開発者はサンドボックス化を回避できます。二つのアプリが同じ証明書で署名され、同じユーザー ID を明示的に共有している (_AndroidManifest.xml_ ファイルに _sharedUserId_ がある) 場合、それぞれが他方のデータディレクトリにアクセスできます。NFC アプリでこれを実現するには以下の例を参照してください。

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="com.android.nfc"
  android:sharedUserId="android.uid.nfc">
```

#### Linux ユーザー管理

Android は Linux ユーザー管理を利用してアプリを分離しています。このアプローチは従来の Linux 環境でのユーザー管理の使用方法とは異なります。従来は複数のアプリが同じユーザーにより実行されることがよくあります。 Android は Android アプリごとに一意の UID を作成し、別のプロセスでアプリを実行します。したがって、各アプリは自身のリソースにのみアクセスできます。この保護は Linux カーネルにより実施されます。

一般的に、アプリには 10000 から 99999 の範囲の UID が割り当てられます。 Android アプリはその UID に基づくユーザー名も受け取ります。例えば、 UID 10188 のアプリはユーザー名 `u0_a188` を受け取ります。アプリが要求したパーミッションが許可された場合、対応するグループ ID がアプリのプロセスに追加されます。例えば、以下のアプリのユーザー ID は 10188 です。グループ ID 3003 (inet) に属しています。そのグループは android.permission.INTERNET パーミッションに関連付けられています。 `id` コマンドの出力は以下のようになります。

```bash
$ id
uid=10188(u0_a188) gid=10188(u0_a188) groups=10188(u0_a188),3003(inet),
9997(everybody),50188(all_a188) context=u:r:untrusted_app:s0:c512,c768
```

グループ ID とパーミッションの関係は以下のファイルで定義されています。

[platform.xml](https://android.googlesource.com/platform/frameworks/base/+/master/data/etc/platform.xml)

```xml
<permission name="android.permission.INTERNET" >
    <group gid="inet" />
</permission>

<permission name="android.permission.READ_LOGS" >
    <group gid="log" />
</permission>

<permission name="android.permission.WRITE_MEDIA_STORAGE" >
    <group gid="media_rw" />
    <group gid="sdcard_rw" />
</permission>
```

#### Zygote

`Zygote` プロセスは [Android の初期化](https://github.com/dogriffiths/HeadFirstAndroid/wiki/How-Android-Apps-are-Built-and-Run "How Android Apps are run") 時に起動します。 Zygote はアプリを起動するためのシステムサービスです。 Zygote プロセスはアプリが必要とするすべてのコアライブラリを含む "ベース" プロセスです。起動時に Zygote は `/dev/socket/zygote` ソケットを開き、ローカルクライアントからの接続を待ち受けます。接続を受信すると、新しいプロセスをフォークし、アプリ固有のコードをロードおよび実行します。

#### アプリライフサイクル

Android では、アプリプロセスの存続期間はオペレーティングシステムにより制御されます。アプリコンポーネントが起動されるとき、同じアプリがまだ他のコンポーネントを実行していない場合、新しい Linux プロセスが作成されます。後者がもはや必要ではない場合やより重要なアプリを実行するためにメモリの再利用が必要である場合に、 Android はこのプロセスを強制終了することがあります。プロセスを強制終了する判断は主にユーザーとプロセスの対話の状態に関連しています。一般に、プロセスは四つの状態のいずれかになります。

- フォアグラウンドプロセス (画面上部で実行中のアクティビティや実行中の BroadcastReceiver など)
- 表示プロセスはユーザーが認識しているプロセスであるため、強制終了するとユーザーエクスペリエンスが大きく損なわれます。一例として画面上ではユーザーに見えているがフォアグラウンドではないアクティビティを実行していることが挙げられます。

- サービスプロセスは `startService` メソッドで開始されるサービスをホストするプロセスです。これらのプロセスはユーザーには直接見えるものではありませんが、一般的にユーザーが気にすること (バックグラウンドでのネットワークデータのアップロードやダウンロードなど) であるため、フォアグラウンドプロセスと表示プロセスをすべて保持するメモリが不足しない限り、システムは常にこのようなプロセスを実行し続けます。
- キャッシュ済みプロセスは現在必要ではないプロセスであるため、メモリが必要な場合にシステムは自由にプロセスを強制終了できます。
アプリはいくつかのイベントに反応するコールバックメソッドを実装する必要があります。例えば、アプリプロセスが最初に作成されたときに `onCreate` ハンドラが呼び出されます。他のコールバックメソッドには `onLowMemory`, `onTrimMemory`, `onConfigurationChanged` があります。

### App Bundle

Android アプリケーションは Android Package Kit (APK) または [Android App Bundle](https://developer.android.com/guide/app-bundle "Android App Bundle") (.aab) の二つの形式で出荷できます。Android App Bundle はアプリに必要なすべてのリソースを提供しますが、 APK の生成とその署名を Google Play に任せます。App Bundle はいくつかのモジュールにアプリのコードを含む署名付きバイナリです。ベースモジュールにはアプリケーションのコアが含まれています。ベースモジュールは [アプリバンドルに関する開発者ドキュメント](https://developer.android.com/guide/app-bundle "Documentation on App Bundle") で詳しく説明されているように、アプリの新しい拡張機能を含むさまざまなモジュールで拡張できます。
Android App Bundle がある場合は、 Google の [bundletool](https://developer.android.com/studio/command-line/bundletool "bundletool") コマンドラインツールを使用して、APK の既存ツールを使用して署名なしの APK をビルドするのがベストです。以下のコマンドを実行して AAB ファイルから APK を作成できます。

```bash
bundletool build-apks --bundle=/MyApp/my_app.aab --output=/MyApp/my_app.apks
```

テストデバイスにデプロイできるように署名付き APK を作成したい場合には、以下を使用します。

```bash
$ bundletool build-apks --bundle=/MyApp/my_app.aab --output=/MyApp/my_app.apks
--ks=/MyApp/keystore.jks
--ks-pass=file:/MyApp/keystore.pwd
--ks-key-alias=MyKeyAlias
--key-pass=file:/MyApp/key.pwd
```

追加モジュールがある場合とない場合の両方で APK をテストすることをお勧めします。これにより追加モジュールがベースモジュールに対してセキュリティ問題を導入もしくは修正するかどうかが明確になります。

### Android Manifest

すべての Android アプリには APK のルートにバイナリ XML 形式で保存された `AndroidManifest.xml` ファイルを含みます。このファイルはインストール時および実行時に Android オペレーティングシステムによって使用されるアプリの構造と主要なプロパティを定義します。

セキュリティ関連の要素には以下のものがあります。

- **パーミッション:** インターネット、カメラ、ストレージ、位置情報、連絡先へのアクセスなど、必要なパーミッションを `<uses-permission>` を使用して宣言します。これらはアプリのアクセス境界を定義し、最小権限の原則に従う必要があります。カスタムパーミッションは `<permission>` を使用して定義でき、他のアプリによる悪用を防ぐために `signature` や `dangerous` などの適切な `protectionLevel` を含む必要があります。
- **コンポーネント:** マニフェストには、アプリ内で宣言され、エントリポイントとして機能するすべての [アプリコンポーネント](#app-components) をリストします。これらは他のアプリに (インテントフィルタまたは `exported` 属性を介して) 公開される可能性があるため、攻撃者がアプリとどのようにやり取りするかを判断する上で非常に重要です。主なコンポーネントの種類は以下のとおりです。
    - **アクティビティ:** ユーザーインタフェース画面を定義します。
    - **サービス:** バックグラウンドタスクを実行します。
    - **ブロードキャストレシーバ:** 外部メッセージを処理します。
    - **コンテンツプロバイダ:** 構造化データを公開します。
- **ディープリンク:** [ディープリンク](0x05h-Testing-Platform-Interaction.md#deep-links) は `VIEW` アクション、`BROWSABLE` カテゴリ、URI パターンを指定する `data` 要素でのインテントフィルタを介して設定されます。これらはウェブまたはアプリリンクにアクティビティを公開する可能性があり、インジェクションやスプーフィングのリスクを回避するために慎重に検証する必要があります。`android:autoVerify="true"` を追加すると、アプリリンクが有効になり、検証済みリンクの処理は宣言されたアプリに制限されるため、リンクハイジャックのリスクを軽減します。
- **クリアテキストトラフィックの使用:** `android:usesCleartextTraffic` 属性はアプリが暗号化されていない HTTP トラフィックを許可するかどうかを制御します。Android 9 (API 28) 以降では、明示的に許可されない限り、クリアテキストトラフィックはデフォルトで無効になっています。この属性は `networkSecurityConfig` でオーバーライドすることもできます。
- **ネットワークセキュリティ設定:** Android 7.0 (API レベル 24) 以降で利用可能な `android:networkSecurityConfig` で定義されるオプションの XML ファイルです。[ネットワークセキュリティの動作](0x05g-Testing-Network-Communication.md#android-network-security-configuration) をきめ細かく制御できます。信頼できる証明機関、ドメインごとの TLS 要件、クリアテキストトラフィックの例外を指定でき、`android:usesCleartextTraffic` で定義されたグローバル設定をオーバーライドできます。
- **バックアップの動作:** `android:allowBackup` 属性はアプリデータの [バックアップ](0x05d-Testing-Data-Storage.md#backups) を許可または禁止します。
- **タスクの親和性と起動モード:** これらの設定はアクティビティのグループ化と起動方法に影響します。不適切な設定により、攻撃者のアプリが正規のコンポーネントを模倣した場合、タスクのハイジャックやフィッシングのような攻撃が発生する可能性があります。

利用可能なマニフェストオプションの完全なリストについては、公式の [Android Manifest ファイルのドキュメント](https://developer.android.com/guide/topics/manifest/manifest-intro.html "Android Developer Guide for Manifest") をご覧ください。

ビルド時に、マニフェストは、含まれているライブラリと依存関係のマニフェストとマージされます。最終的にマージされたマニフェストには、開発者が明示的に宣言していない追加のパーミッション、コンポーネント、設定が含まれることがあります。セキュリティレビューでは、アプリの実際の露出を把握するために、マージされた出力を分析する必要があります。

以下は開発者が定義したマニフェストファイルの例です。いくつかのパーミッションを宣言し、バックアップを許可し、アプリのメインアクティビティを定義しています。

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.MASTestApp"
        tools:targetApi="31">
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:theme="@style/Theme.MASTestApp">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
```

APK から AndroidManifest.xml ファイルを取得 ([AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../techniques/android/MASTG-TECH-0117.md)) すると、アプリの一意の識別子を定義する `package` 属性、`android:minSdkVersion` と `android:targetSdkVersion` を指定する `<uses-sdk>` 要素、新しいアクティビティ、プロバイダ、レシーバ、アプリがデバッグモードであることを示す `android:debuggable="true"` などのその他の属性などの追加要素を含むことがわかります。

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0"
    android:compileSdkVersion="35"
    android:compileSdkVersionCodename="15"
    package="org.owasp.mastestapp"
    platformBuildVersionCode="35"
    platformBuildVersionName="15">
    <uses-sdk
        android:minSdkVersion="29"
        android:targetSdkVersion="35"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <permission
        android:name="org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
        android:protectionLevel="signature"/>
    <uses-permission android:name="org.owasp.mastestapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application
        android:theme="@style/Theme.MASTestApp"
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        android:debuggable="true"
        android:testOnly="true"
        android:allowBackup="true"
        android:supportsRtl="true"
        android:extractNativeLibs="false"
        android:fullBackupContent="@xml/backup_rules"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:appComponentFactory="androidx.core.app.CoreComponentFactory"
        android:dataExtractionRules="@xml/data_extraction_rules">
        <activity
            android:theme="@style/Theme.MASTestApp"
            android:name="org.owasp.mastestapp.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity
            android:name="androidx.compose.ui.tooling.PreviewActivity"
            android:exported="true"/>
        <activity
            android:name="androidx.activity.ComponentActivity"
            android:exported="true"/>
        <provider
            android:name="androidx.startup.InitializationProvider"
            android:exported="false"
            android:authorities="org.owasp.mastestapp.androidx-startup">
            <meta-data
                android:name="androidx.emoji2.text.EmojiCompatInitializer"
                android:value="androidx.startup"/>
            ...
        </provider>
        <receiver
            android:name="androidx.profileinstaller.ProfileInstallReceiver"
            android:permission="android.permission.DUMP"
            android:enabled="true"
            android:exported="true"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.INSTALL_PROFILE"/>
            </intent-filter>
            ...
        </receiver>
    </application>
</manifest>
```

### アプリコンポーネント

Android アプリは複数の上位コンポーネントで構成されています。主なコンポーネントは以下のとおりです。

- アクティビティ
- フラグメント
- インテント
- ブロードキャストレシーバ
- コンテンツプロバイダおよびサービス

これらの要素はすべて、API を介して利用可能な定義済みクラスの形式で、 Android オペレーティングシステムにより提供されています。

#### アクティビティ

アクティビティはアプリの表示部分を構成します。画面ごとにひとつのアクティビティがあるため、三つの異なる画面を持つアプリは三つの異なるアクティビティを実装します。アクティビティは Activity クラスを拡張することにより宣言されます。これらにはフラグメント、ビュー、レイアウトのすべてのユーザーインタフェース要素が含まれています。

各アクティビティは以下の構文で Android Manifest に宣言する必要があります。

```xml
<activity android:name="ActivityName">
</activity>
```

マニフェストに宣言されていないアクティビティは表示できず、それらを実行しようとすると例外が発生します。

アプリと同様に、アクティビティも独自のライフサイクルを持ち、システムの変化を監視してそれらを処理する必要があります。アクティビティには active, paused, stopped, inactive の状態があります。これらの状態は Android オペレーティングシステムにより管理されます。したがって、アクティビティは以下のイベントマネージャを実装します。

- onCreate
- onSaveInstanceState
- onStart
- onResume
- onRestoreInstanceState
- onPause
- onStop
- onRestart
- onDestroy

アプリは明示的にすべてのイベントマネージャを実装していないことがあり、その場合にはデフォルトアクションがとられます。一般的には、少なくとも `onCreate` マネージャはアプリ開発者によりオーバーライドされます。これはほとんどのユーザーインタフェースコンポーネントを宣言および初期化する方法です。リソース (ネットワーク接続やデータベースへの接続など) を明示的に解放しなければならない場合や、アプリのシャットダウン時に特定のアクションを実行しなければならない場合、 `onDestroy` がオーバーライドされることがあります。

#### フラグメント

フラグメントはアクティビティ内の動作やユーザーインタフェースの一部を表します。フラグメントは Honeycomb 3.0 (API レベル 11) バージョンで Android に導入されました。

フラグメントはインタフェースの一部をカプセル化して、再利用性とさまざまな画面サイズへの適応を容易にすることを目的としています。フラグメントは必要なコンポーネント (独自のレイアウト、ボタン、などがあります) をすべて含むという点で自律的なエンティティです。しかし、それらを役立たせるにはアクティビティと統合する必要があります。フラグメントはそれ自体では存在できません。それらには独自のライフサイクルがあり、それを実装するアクティビティのライフサイクルと結びついています。

フラグメントは独自のライフサイクルを持つため、 Fragment クラスにはイベントマネージャが含まれており、再定義および拡張できます。そのようなイベントマネージャには onAttach, onCreate, onStart, onDestroy, onDetach があります。他にもいくつか存在します。詳細については [Android Fragment 仕様](https://developer.android.com/guide/components/fragments "Fragment Class") を参照してください。

フラグメントは Android により提供される Fragment クラスを拡張することにより簡単に実装できます。

Java の例:

```java
public class MyFragment extends Fragment {
    ...
}
```

Kotlin の例:

```kotlin
class MyFragment : Fragment() {
    ...
}
```

フラグメントはアクティビティに依存するため、マニフェストファイルに宣言する必要はありません。

フラグメントを管理するために、アクティビティはフラグメントマネージャ (FragmentManager クラス) を使用できます。このクラスは関連するフラグメントの検索、追加、削除、置換を容易にします。

フラグメントマネージャは以下のようにして作成できます。

Java の例:

```java
FragmentManager fm = getFragmentManager();
```

Kotlin の例:

```kotlin
var fm = fragmentManager
```

フラグメントは必ずしもユーザーインタフェースを持つとは限りません。それらはアプリのユーザーインタフェースに関連するバックグラウンド操作を管理するための便利で効率的な方法です。アクティビティ破棄された際、システムがその状態を維持できるように、フラグメントが永続的であると宣言することができます。

#### コンテンツプロバイダ

Android は SQLite を使用して、データを永続的に格納しています。 Linux の場合と同様に、データはファイルに格納されます。 SQLite は軽量で効率的なオープンソースのリレーショナルデータストレージテクノロジであり、処理能力をあまり必要としないため、モバイルでの使用に理想的です。特定のクラス (Cursor, ContentValues, SQLiteOpenHelper, ContentProvider, ContentResolver, など) を使用して API 全体を利用できます。
SQLite は別のプロセスとして実行されるのではなく、アプリの一部となります。
デフォルトでは、特定のアプリに属するデータベースはこのアプリからのみアクセスできます。しかし、コンテンツプロバイダはデータソース (データベースやフラットファイルを含む) を抽象化する優れたメカニズムを提供します。また、ネイティブアプリを含むアプリ間でデータを共有するための標準的で効率的なメカニズムも提供します。他のアプリからアクセスできるようにするには、コンテンツプロバイダは共有するアプリのマニフェストファイルで明示的に宣言する必要があります。コンテンツプロバイダが宣言されない限り、それらはエクスポートされず、それらを作成するアプリによってのみ呼び出すことができます。

コンテンツプロバイダは URI アドレッシングスキームを通じて実装されます。それらはすべて content:// モデルを使用します。ソースのタイプ (SQLite データベース、フラットファイル、など) に関係なく、アドレッシングスキームは常に同じであるため、ソースを抽象化し、開発者に一意のスキームを提供します。コンテンツプロバイダはすべての通常のデータベース操作 (作成、読取、更新、削除) を提供します。つまり、マニフェストファイルに適切な権限を持つアプリは他のアプリからデータを操作できます。

#### サービス

サービスはユーザーインタフェースを表示せずにバックグラウンドでタスク (データ処理、インテント起動、通知など) を実行する (Service クラスをベースとした) Android OS コンポーネントです。サービスはプロセスを長期的に実行することを目的としています。それらのシステム優先度はアクティブアプリのものより低くなりますが、非アクティブなアプリのものよりも高くなります。したがって、システムがリソースを必要とする場合にそれらが強制終了される可能性は低く、十分なリソースが利用可能になった際には自動的に再起動するように設定することも可能です。このため、サービスはバックグラウンドタスクを実行するのに最適な候補となります。アクティビティと同様に、サービスはメインアプリスレッドで実行されることに注意してください。特に指定しない限り、サービスは独自のスレッドを作成せず、別のプロセスで実行しません。

### プロセス間通信

すでに学んだように、すべての Android プロセスには独自のサンドボックス化されたアドレス空間があります。プロセス間通信機能によりアプリが信号とデータをセキュアに交換できます。デフォルトの Linux IPC 機能に依存する代わりに、 Android の IPC では OpenBinder のカスタム実装である Binder をベースとしています。 Android システムサービスの多くとすべての高レベル IPC サービスが Binder に依存しています。

_Binder_ という用語は以下のようなさまざまなことを表しています。

- Binder ドライバ: カーネルレベルドライバ
- Binder プロトコル: binder ドライバとの通信に使用される低レベル ioctl ベースのプロトコル
- IBinder インタフェース: Binder オブジェクトが実装する定義済みの動作
- Binder オブジェクト: IBinder インタフェースの一般的な実装
- Binder サービス: Binder オブジェクトの実装、例えば、位置情報サービスやセンサーサービス
- Binder クライアント: Binder サービスを使用するオブジェクト

Binder フレームワークではクライアント・サーバー通信モデルが含まれています。 IPC を使用するには、アプリがプロキシオブジェクトの IPC メソッドを呼び出します。プロキシオブジェクトは呼び出しパラメータを透過的に _parcel_ に _marshall_ し、 Binder サーバーにトランザクションを送信します。これはキャラクタードライバ (/dev/binder) として実装されています。サーバーは着信要求を処理するためのスレッドプールを保持し、宛先オブジェクトにメッセージを配信します。クライアントアプリの視点から見ると、これらはすべて通常のメソッド呼び出しのように見えますが、すべての重い作業は Binder フレームワークにより行われています。

<img src="Images/Chapters/0x05a/binder.jpg" width="400px" />

- _Binder Overview - Image source: [Android Binder by Thorsten Schreiber](https://1library.net/document/z33dd47z-android-android-interprocess-communication-thorsten-schreiber-somorovsky-bussmeyer.html "Android Binder")_

他のアプリケーションがそれらにバインドできるようにするサービスは _バインドされたサービス_ と呼ばれます。これらのサービスはクライアントに IBinder インタフェースを提供する必要があります。開発者は Android Interface Descriptor Language (AIDL) を使用して、リモートサービスのインタフェースを記述します。

ServiceManager はシステムサービスの登録と検索を管理するシステムデーモンです。すべての登録済みサービスの名前と Binder のペアのリストを維持します。サービスは `android.os.ServiceManager` の `addService` メソッドで追加され、静的な `getService` メソッドで名前により取得されます。

Java の例:

```java
public static IBinder getService(String name) {
        try {
            IBinder service = sCache.get(name);
            if (service != null) {
                return service;
            } else {
                return getIServiceManager().getService(name);
            }
        } catch (RemoteException e) {
            Log.e(TAG, "error in getService", e);
        }
        return null;
    }
```

Kotlin の例:

```kotlin
companion object {
        private val sCache: Map<String, IBinder> = ArrayMap()
        fun getService(name: String): IBinder? {
            try {
                val service = sCache[name]
                return service ?: getIServiceManager().getService(name)
            } catch (e: RemoteException) {
                Log.e(FragmentActivity.TAG, "error in getService", e)
            }
            return null
        }
    }
```

`service list` コマンドでシステムサービスのリストをクエリできます。

```bash
$ adb shell service list
Found 99 services:
0 carrier_config: [com.android.internal.telephony.ICarrierConfigLoader]
1 phone: [com.android.internal.telephony.ITelephony]
2 isms: [com.android.internal.telephony.ISms]
3 iphonesubinfo: [com.android.internal.telephony.IPhoneSubInfo]
```

#### インテント

_インテントメッセージング_ は Binder の上に構築された非同期通信フレームワークです。このフレームワークではポイントツーポイントとパブリッシュ・サブスクライブの両方のメッセージングが可能です。 _インテント_ は別のアプリコンポーネントからアクションをリクエストするために使用できるメッセージオブジェクトです。インテントはいくつかの方法でコンポーネント間通信を手助けしますが、三つの基本的なユースケースがあります。

- アクティビティの開始
    - アクティビティはアプリ内の単一の画面を表します。 `startActivity` にインテントを渡すことによりアクティビティの新しいインスタンスを開始できます。インテントはアクティビティを記述し、必要なデータを伝えます。
- サービスの開始
    - サービスはユーザーインタフェースなしでバックグラウンドd操作を実行するコンポーネントです。 Android 5.0 (API レベル 21) 以降では、 JobScheduler でサービスを開始できます。
- ブロードキャストの配信
    - ブロードキャストはどのアプリでも受信できるメッセージです。システムはシステムの起動や充電の初期化など、システムイベントについてのブロードキャストを配信します。 `sendBroadcast` または `sendOrderedBroadcast` にインテントを渡すことにより、他のアプリにブロードキャストを配信できます。

インテントには二つのタイプがあります。明示的インテントは開始されるコンポーネントに名前を付けます (完全修飾クラス名) 。以下に例を示します。

Java の例:

```java
Intent intent = new Intent(this, myActivity.myClass);
```

Kotlin の例:

```kotlin
var intent = Intent(this, myActivity.myClass)
```

暗黙的インテントは OS に送信され、特定のデータセット (以下の例では OWASP ウェブサイトの URL) に対して特定のアクションを実行します。どのアプリまたはクラスが対応するサービスを実行するかを決定するのはシステム次第です。以下に例を示します。

Java の例:

```java
Intent intent = new Intent(Intent.MY_ACTION, Uri.parse("https://www.owasp.org"));
```

Kotlin の例:

```kotlin
var intent = Intent(Intent.MY_ACTION, Uri.parse("https://www.owasp.org"))
```

_インテントフィルタ_ はコンポーネントが受け取りたいインテントのタイプを指定する Android Manifest ファイル内の式です。例えば、アクティビティに対するインテントフィルタを宣言することにより、他のアプリが特定の種類のインテントで直接アクティビティを開始できるようになります。同様に、アクティビティのインテントフィルタを宣言しない場合には、明示的インテントでのみアクティビティを開始できます。

Android はインテントを使用して、アプリへのメッセージ (着信や SMS など) 、重要な電源情報 (バッテリ低下など) 、ネットワーク変更 (接続喪失など) をブロードキャストします。インテントには Extra データを追加できます (`putExtra`/`getExtras` を介して) 。

以下はオペレーティングシステムにより送信されるインテントの短いリストです。すべての定数は Intent クラスで定義されており、リスト全体は公式の Android ドキュメントにあります。

- ACTION_CAMERA_BUTTON
- ACTION_MEDIA_EJECT
- ACTION_NEW_OUTGOING_CALL
- ACTION_TIMEZONE_CHANGED

セキュリティとプライバシーを向上させるために、 Local Broadcast Manager を使用してアプリ内でインテントの送受信し、オペレーティングシステムの他の部分にインテントを送信しません。これは機密データやプライベートデータ (位置情報データなど) がアプリ境界線から外に出ないようにするために非常に役立ちます。

#### ブロードキャストレシーバ

ブロードキャストレシーバはアプリが他のアプリやシステム自体からの通知を受信できるようにするコンポーネントです。これにより、アプリはイベント (内部的なもの、他のアプリにより開始されたもの、オペレーティングシステムにより開始されたもの) に反応できます。これらは一般的に、ユーザーインタフェースの更新、サービスの開始、コンテンツの更新、ユーザー通知の作成に使用されます。

ブロードキャストレシーバをシステムに認識させる方法は二つあります。一つの方法は Android Manifest ファイルで宣言することです。マニフェストではブロードキャストレシーバとインテントフィルタの間の関連付けを指定して、レシーバが受け付けるアクションを示す必要があります。

マニフェストにインテントフィルタを持つブロードキャストレシーバ宣言の例です。

```xml
<receiver android:name=".MyReceiver" >
    <intent-filter>
        <action android:name="com.owasp.myapplication.MY_ACTION" />
    </intent-filter>
</receiver>
```

この例では、ブロードキャストレシーバに [`android:exported`](https://developer.android.com/guide/topics/manifest/receiver-element "receiver element") 属性が含まれていないことに注意します。少なくとも一つのフィルタが定義されているため、デフォルト値は "true" に設定されます。フィルタがない場合、 "false" に設定されます。

もう一つの方法はコード内で動的にレシーバを作成することです。レシーバは [`Context.registerReceiver`](https://developer.android.com/reference/android/content/Context.html#registerReceiver%28android.content.BroadcastReceiver,%2520android.content.IntentFilter%29 "Context.registerReceiver") メソッドで登録することができます。

ブロードキャストレシーバを動的に登録する例です。

Java の例:

```java
// Define a broadcast receiver
BroadcastReceiver myReceiver = new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(TAG, "Intent received by myReceiver");
    }
};
// Define an intent filter with actions that the broadcast receiver listens for
IntentFilter intentFilter = new IntentFilter();
intentFilter.addAction("com.owasp.myapplication.MY_ACTION");
// To register the broadcast receiver
registerReceiver(myReceiver, intentFilter);
// To un-register the broadcast receiver
unregisterReceiver(myReceiver);
```

Kotlin の例:

```kotlin
// Define a broadcast receiver
val myReceiver: BroadcastReceiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        Log.d(FragmentActivity.TAG, "Intent received by myReceiver")
    }
}
// Define an intent filter with actions that the broadcast receiver listens for
val intentFilter = IntentFilter()
intentFilter.addAction("com.owasp.myapplication.MY_ACTION")
// To register the broadcast receiver
registerReceiver(myReceiver, intentFilter)
// To un-register the broadcast receiver
unregisterReceiver(myReceiver)
```

関連したインテントが発生すると、システムは登録されたレシーバでアプリを自動的に起動することに注意します。

[ブロードキャストの概要](https://developer.android.com/guide/components/broadcasts "Broadcasts Overview") によると、ブロードキャストがアプリを具体的に対象としていない場合には、 "暗黙的" とみなされます。暗黙的ブロードキャストを受信した後、 Android はフィルタに特定のアクションを登録したすべてのアプリをリストします。同じアクションに対して複数のアプリが登録されている場合、 Android はユーザーに利用可能なアプリのリストから選択するように求めます。

ブロードキャストレシーバの興味深い機能は優先度付けできることです。このようにして、インテントは優先度に従ってすべての認可されたレシーバに配信されます。優先度は `android:priority` 属性を介してマニフェストのインテントフィルタに割り当てることができますし、 [`IntentFilter.setPriority`](https://developer.android.com/reference/android/content/IntentFilter#setPriority%28int%29 "IntentFilter.setPriority") メソッドを介してプログラム的にもできます。ただし、同じ優先度のレシーバは [任意の順序で実行](https://developer.android.com/guide/components/broadcasts.html#sending-broadcasts "Sending Broadcasts") されることに注意します。

アプリがアプリ間でブロードキャストを送信することを想定していない場合には、 Local Broadcast Manager ([`LocalBroadcastManager`](https://developer.android.com/reference/androidx/localbroadcastmanager/content/LocalBroadcastManager.html "LocalBroadcastManager")) を使用します。これらは内部アプリからのみインテントを受信することを確保するために使用でき、他のアプリからのインテントは破棄されます。これはプロセス間通信が関与しないため、アプリのセキュリティと効率を向上させるために非常に役に立ちます。ただし、 `LocalBroadcastManager` クラスは [非推奨](https://developer.android.com/reference/androidx/localbroadcastmanager/content/LocalBroadcastManager.html "LocalBroadcastManager") であり、 Google は [`LiveData`](https://developer.android.com/reference/androidx/lifecycle/LiveData.html "LiveData") などの代替手段を推奨しています。

ブロードキャストレシーバに関するセキュリティ上の考慮事項については、 [セキュリティに関する考慮事項とお勧めの方法](https://developer.android.com/guide/components/broadcasts.html#security-and-best-practices "Security Considerations and Best Practices") を参照してください。

#### 暗黙的ブロードキャストレシーバの制限

[バックグラウンドの処理の最適化](https://developer.android.com/topic/performance/background-optimization "Background Optimizations") によると、 Android 7.0 (API レベル 24) 以降をターゲットとするアプリはブロードキャストレシーバを `Context.registerReceiver()` で登録しない限り `CONNECTIVITY_ACTION` ブロードキャストを受信しなくなりました。システムは `ACTION_NEW_PICTURE` および `ACTION_NEW_VIDEO` ブロードキャストも送信しません。

[バックグラウンドでの実行の制限](https://developer.android.com/about/versions/oreo/background.html#broadcasts "Background Execution Limits") によると、Android 8.0 (API レベル 26) 以降をターゲットとするアプリは [暗黙的なブロードキャストの例外](https://developer.android.com/guide/components/broadcast-exceptions "Implicit Broadcast Exceptions") にリストされているものを除き、マニフェストに暗黙的ブロードキャストのブロードキャストレシーバを登録できなくなりました。実行時に `Context.registerReceiver` を呼び出して作成されたブロードキャストレシーバはこの制限の影響を受けません。

[システムブロードキャストの変更](https://developer.android.com/guide/components/broadcasts#changes-system-broadcasts "Changes to System Broadcasts") によると、 Android 9 (API レベル 28) 以降、 `NETWORK_STATE_CHANGED_ACTION` ブロードキャストはユーザーの位置情報や個人を識別できるデータに関する情報を受信しません。

## Android アプリケーションの公開

アプリの開発が成功したら、次のステップはそれを公開して他の人と共有することです。しかし、アプリを単にストアに追加して共有することはできません。最初に署名する必要があります。暗号署名はアプリの開発者により置かれた検証可能なマークとして機能します。アプリの作成者を識別し、アプリが当初の配布以降改変されていないことを保証します。

### 署名のプロセス

開発時には、アプリは自動的に生成された証明書で署名されます。この証明書は本質的にセキュアではなく、デバッグ用です。ほとんどのストアは公開用にこの種の証明書を受け入れていません。そのため、よりセキュアな特性を持つ証明書を作成する必要があります。
アプリケーションが Android デバイスにインストールされる際、パッケージマネージャは当該 APK に含まれている証明書で署名されていることを確認します。証明書の公開鍵がデバイス上の他の APK を署名するために使用された鍵と一致する場合、新しい APK は既存の APK と UID を共有する可能性があります。これにより単一ベンダのアプリケーション間のやり取りが容易になります。あるいは、 Signature 保護レベルのセキュリティパーミッションを指定することもできます。これにより同じ鍵で署名されたアプリケーションにアクセスを制限します。

### APK 署名スキーム

Android は複数のアプリケーション署名スキームをサポートしています。

- **Android 7.0 (API レベル 24) 以前**: アプリケーションは JAR 署名 (v1) スキームのみを使用できますが、APK のすべての部分を保護しません。このスキームは安全でないと考えられています。
- **Android 7.0 (API レベル 24) および以降**: アプリケーションは **v2 署名スキーム** を使用できます。APK 全体に署名するため、古い v1 (JAR) 署名方法と比較してより強力な保護を提供します。
- **Android 9 (API レベル 28) および以降**: **v2 と v3 署名スキーム** の両方を使用することをお勧めします。v3 スキームは **鍵ローテーション** をサポートしており、開発者は古い署名を無効にすることなく、侵害時に鍵を置換できます。
- **Android 11 (API レベル 30) および以降**: アプリケーションはオプションで **v4 署名スキーム** を含めて、高速な増分アップデートを可能にできます。

後方互換のため、アプリを新旧両方の SDK バージョンで実行できるようにするために APK には複数の署名スキームで署名できます。たとえば、[古いプラットフォームは v2 署名を無視し v1 署名のみを検証します](https://source.android.com/security/apksigning/ "APK Signing")。

#### JAR 署名 (v1 スキーム)

アプリ署名のオリジナルバージョンでは、署名済み APK は標準の署名済み JAR として実装しており、 `META-INF/MANIFEST.MF` にすべてのエントリを含む必要があります。すべてのファイルは共通の証明書で署名する必要があります。このスキームは ZIP メタデータなど APK の一部を保護しません。このスキームの欠点は APK verifier が署名を適用する前に信頼できないデータ構造を処理する必要があり、 verifier はデータ構造がカバーしないデータを破棄することです。また、 APK verifier はすべての圧縮ファイルを展開する必要があり、かなりの時間とメモリを要します。

この署名スキームは安全でないと考えられており、たとえば **Janus 脆弱性 (CVE-2017-13156)** の影響を受け、悪意のあるアクターが v1 署名を無効にすることなく APK ファイルを変更できる可能性があります。そのため、**v1 は Android 7.0 および以降を実行しているデバイスでは決して信頼すべきではありません**。

#### APK 署名スキーム (v2 スキーム)

APK 署名スキームでは、完全な APK がハッシュおよび署名され、 APK 署名ブロックが作成されて APK に挿入されます。検証時には、 v2 スキームは APK ファイル全体の署名をチェックします。この形式の APK 検証はより高速で、改変に対するより包括的な保護を提供します。以下の [v2 スキームの APK 署名検証プロセス](https://source.android.com/security/apksigning/v2#verification "APK Signature verification process") をご覧ください。

<img src="Images/Chapters/0x05a/apk-validation-process.png" width="400px" />

#### APK 署名スキーム (v3 スキーム)

v3 APK 署名ブロックフォーマットは v2 と同じです。 v3 はサポートされている SDK バージョンと proof-of-rotation 構造に関する情報を APK 署名ブロックに追加します。 Android 9 (API レベル 28) 以降では、 APK は APK 署名スキーム v3, v2 または v1 にしたがって検証できます。古いプラットフォームでは v3 署名を無視し、 v2 それから v1 署名を検証しようと試みます。

署名ブロックの signed-data 内の proof-of-rotation 属性は単一リンクリストで構成され、各ノードにはアプリの以前のバージョンを署名するために使用された署名証明書を含んでいます。後方互換を機能させるために、古い署名証明書は新しい証明書のセットに署名するため、新しい鍵ごとに古い鍵と同じくらい信頼できるはすであるという証跡を提供します。
proof-of-rotation 構造には、一つずつ署名するのではなく、古い署名証明書が新しい証明書のセットに署名する必要があるため、 APK に個別に署名することができなくなりました。以下の [APK 署名 v3 スキーム検証プロセス](https://source.android.com/security/apksigning/v3 "APK Signature v3 scheme verification process") をご覧ください。

<img src="Images/Chapters/0x05a/apk-validation-process-v3-scheme.png" width="400px" />

#### APK 署名スキーム (v4 スキーム)

APK 署名スキーム v4 は Android 11 (API レベル 30) で導入され、Android 11 以上で起動するすべてのデバイスではデフォルトで [fs-verity](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html) が有効になっている必要があります。 fs-verity は Linux カーネル機能で、ファイルのハッシュ計算を非常に効率的に行うことができるため、主にファイル認証 (悪意のある改変の検出) に使用されています。読み取り要求はブート時にカーネルキーリングにロードされた信頼できるデジタル証明書に対してコンテンツが検証された場合にのみ成功します。

v4 署名は補完する v2 または v3 署名が必要であり、以前の署名スキームとは対照的に、 v4 署名では別のファイル `<apk name>.apk.idsig` に保存されます。 v4 署名された APK を `apksigner verify` で検証する際には `--v4-signature-file` フラグを使用してこのファイルを指定することを忘れないでください。

詳細については [Android 開発者ドキュメント](https://source.android.com/security/apksigning/v4) をご覧ください。

#### 証明書の作成

Android はパブリック/プライベート証明書を使用して Android アプリ (.apk ファイル) に署名します。証明書は情報の集合体であり、セキュリティの観点から鍵がその集合体の中で最も重要な部分です。パブリック証明書はユーザーの公開鍵を含み、プライベート証明書はユーザーの秘密鍵を含みます。パブリック証明書とプライベート証明書はリンクされています。証明書は一意であり、再生成することはできません。証明書が失われた場合、それを復元することはできないため、その証明書で署名されていたアプリを更新することは不可能になることに注意してください。
アプリの作成者は、利用可能な KeyStore にある既存の秘密鍵と公開鍵のペアを再利用するか、新しいペアを生成することができます。
Android SDK では、新しい鍵ペアは `keytool` コマンドで生成されます。以下のコマンドは鍵長 2048 ビットおよび有効期限 7300 日 = 20 年の RSA 鍵ペアを作成します。生成された鍵はカレントディレクトリのファイル 'myKeyStore.jks' に保存されます。

```bash
keytool -genkey -alias myDomain -keyalg RSA -keysize 2048 -validity 7300 -keystore myKeyStore.jks -storepass myStrongPassword
```

秘密鍵を安全に保管し、ライフサイクル全体にわたって機密を維持することが非常に重要です。鍵にアクセスできる人は誰でも、あなたがコントロールしていないコンテンツを持つアプリの更新を公開できます (これによりセキュアでない機能を追加したり、署名ベースのパーミッションを使用して共有されたコンテンツにアクセスします) 。ユーザーがアプリとその開発者に寄せる信頼は完全にそのような証明書に基づいています。したがって、証明書の保護やセキュアマネジメントは評判や顧客維持に不可欠であり、秘密鍵は他の個人と決して共有してはいけません。鍵はパスワードで保護できるバイナリファイルに格納されています。そのようなファイルは _KeyStores_ と呼ばれます。 KeyStore のパスワードは強力で、鍵作成者にのみ知られている必要があります。このため、鍵は一般的に開発者がアクセスを制限された専用のビルドマシンに保存されます。
Android 証明書の有効期間は関連するアプリ (その更新情報を含む) のものより長くする必要があります。例えば、 Google Play では少なくとも 2033 年 10 月 22 日まで有効である証明書が必要です。

#### アプリケーションへの署名

署名プロセスの目的はアプリファイル (.apk) を開発者の公開鍵に関連付けることです。これを実現するために、開発者は APK ファイルのハッシュを計算し、自身の秘密鍵で暗号化します。作成者の公開鍵で暗号化されたハッシュを復号化し、 APK ファイルの実際のハッシュと一致することを確認することで、第三者はアプリの真正性 (アプリが本当に作成者であると主張するユーザーからのものであるなど) を検証できます。

多くの統合開発環境 (IDE) はアプリの署名プロセスを統合して、ユーザーにとってより使いやすくしています。一部の IDE では秘密鍵を平文で設定ファイルに格納することに注意します。他の人がこのようなファイルにアクセスできるかどうかという点を再度確認し、必要に応じてその情報を削除します。
アプリは Android SDK (API レベル 24 以降) で提供される 'apksigner' ツールを使用してコマンドラインから署名できます。そのツールは `[SDK-Path]/build-tools/[version]` にあります。 API 24.0.2 以前の場合には Java JDK の一部である 'jarsigner' を使用できます。プロセス全体についての詳細は Android 公式ドキュメントにありますが、その要点を説明するために例を以下に示します。

```bash
apksigner sign --out mySignedApp.apk --ks myKeyStore.jks myUnsignedApp.apk
```

この例では、未署名のアプリ ('myUnsignedApp.apk') は (カレントディレクトリにある) 開発者 KeyStore 'myKeyStore.jks' の秘密鍵で署名されます。アプリは 'mySignedApp.apk' という署名付きのアプリになり、ストアにリリースする準備が整います。

##### Zipalign

配布前に APK ファイルを調整するには `zipalign` ツールを常に使用する必要があります。このツールは APK 内の圧縮されていないすべてのデータ (画像、 RAW ファイルなど) を4バイト境界に調整し、アプリ実行時のメモリ管理を改善します。

> apksigner で APK ファイルに署名する前に zipalign を使用する必要があります。

### 公開プロセス

Android エコシステムはオープンであるため、どこから (自身のサイト、任意のストア、など) でもアプリを配布することができます。しかし、 Google Play は最も有名で信頼できる人気のあるストアで、 Google 自体が提供しています。Amazon Appstore は Kindle デバイス向けの信頼できるデフォルトストアです。ユーザーが信頼できないソースからサードパーティアプリをインストールしたい場合には、デバイスのセキュリティ設定で明示的に許可する必要があります。

アプリはさまざまなソースから Android デバイスにインストールできます。ソースにはローカルの USB 経由、 Goole の公式アプリストア (Google Play Store) 、または別のストアがあります。

他のベンダーでは実際に公開する前にアプリのレビューおよび承認をする可能性がありますが、 Google では既知のマルウェアシグネチャをスキャンするだけです。これにより、公開プロセスを開始してからアプリが公に利用できるまでの時間を最小限に抑えます。

アプリの公開は非常に簡単であり、主な操作は署名付き APK ファイル自体をダウンロード可能にすることです。 Google Play では、公開はアカウントの作成から始まり、専用のインタフェースを通じてアプリを配信します。詳細は [Android 公式ドキュメント](https://play.google.com/console/about/guides/releasewithconfidence/ "Review the checklists to plan your launch") でご覧いただけます。
