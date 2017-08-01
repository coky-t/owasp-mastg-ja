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

- Programmatic defense is a fancy word for "anti-reversing-trick".  for  are For a protection scheme to be considered effective, it must incorporate many of these defenses. "Programmatic" refers to the fact that these kinds of defenses *do* things - they are functions that prevent, or react to, actions of the reverse engineer. In this, they differ from obfuscation, which changes the way the program looks. 

- Obfuscation is the process of transforming code and data in ways that make it more difficult to comprehend, while preserving its original meaning or function. Think about translating an English sentence into an French one that says the same thing (or pick a different language if you speak French - you get the point).

Note that these two categories sometimes overlap - for example, self-compiling or self-modifiying code, while most would refer to as a means of obfuscation, could also be said to "do something". In general however it is a useful distincton.

Programmatic defenses can be further categorized into two modi operandi:

1. Preventive: Functions that aim to *prevent* anticipated actions of the reverse engineer. As an example, an app may use an operating system API to prevent debuggers from attaching.

2. Reactive: Features that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way if a debugger is detected.

You'll usually find a mix of all the above in a given software protection scheme.

## Overall Effectiveness of Programmatic Defenses

The main motto in anti-reversing is **the sum is greater than its parts.** The defender wants to make it as difficult as possible to get a first foothold for an analysis. They want the adversary to throw the towel before they even get started! Because once the adversary does get started, it's usually only a matter of time before the house of card collapses.

To achieve this deterrant effect, one needs to combine a multitude of defenses, preferably including some original ones. The defenses need to be scattered throughout the app, but also work together in unison to create a greater whole. In the following sections, we'll describe the main criteria that contribute to the effectiveness of programmatic defenses.

#### Coverage

--[ TODO ] --

<img src="Images/Chapters/0x07b/reversing-processes.png" width="600px" />


```
8.1 The app detects, and responds to, the presence of a rooted or jailbroken device either by alerting the user or terminating the app.
```


```
8.2: The app implements prevents debugging and/or detects, and responds to, a debugger being attached. All available debugging protocols must be covered (Android: JDWP and ptrace, iOS: Mach IPC and ptrace).
```


```
8.3: The app detects, and responds to, tampering with executable files and critical data within its own container.
```


```
8.4: The app detects the presence of widely used reverse engineering tools and frameworks that support code injection, hooking, instrumentation and debugging.
```


```
8.5: The app detects, and responds to, being run in an emulator.
```

```
8.6: The app continually verifies the integrity of critical code and data structures within its own memory space.
```


#### Amount and Diversity

--[ TODO ] --

As a general rule of thumb, at least two to three defensive controls should be implemented for each category. These controls should operate independently of each other, i.e. use different techniques and APIs.

```
8.7 The app implements multiple mechanisms to fulfil requirements 8.1 to 8.6. Note that resilience scales with the amount, diversity of the originality of the mechanisms used.
```

```
8.8 The detection mechanisms trigger different responses, including stealthy ones that don't simply terminate the app.
```

```
8.10: Obfuscating transformations and functional defenses are interdependent and well-integrated throughout the app.
```

##### Originality

The effort required to reverse engineer an application highly depends on how much information is initially available to the adversary. This includes information about the functionality being reversed as well as knowledge about the obfuscation and anti-tampering techniques used by the target application. Therefore, the level of innovation that went into designing anti-reversing tricks is an important factor.

Adversaries are more likely to be familiar with ubiquituous techniques that are repeatedly documented in reverse engineering books, papers, presentations and tutorials. Such tricks can either be bypassed using generic tools or with little innovation. In contrast, a secret trick that hasn't been presented anywhere can only be bypassed by a reverser who truly understands the subject, and may force them to do additional research and/or scripting/coding.

Defenses can be roughly categorized into the following categories in terms of originality:

- Standard API: The feature relies on APIs that are specifically meant to prevent reverse engineering. It can be bypassed easily using generic tools.
- Widely known: A well-documented and commonly used technique is used. It can be bypassed using commonly available tools with a moderate amount of customization.
- Proprietary: The feature is not commonly found in reversing resources and research papers, or a known technique has been sufficiently extended / customized to cause significant effort for the reverse engineer.

##### API Layer

Generally speaking, the less your mechanisms relies on operating operating system APIs to work, the more difficult it is to discover and bypass. Also, lower-level calls are more difficult to defeat than higher level calls. To illustrate this, let's have a look at a few examples.

As you have learned in the 


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

- System library: The feature relies on public library functions or methods.
- System call: The anti-reversing feature calls directly into the kernel. 
- Self-contained: The feature does not require any library or system calls to work.


##### Parallelism

Debugging and disabling a mechanism becomes more difficult when multiple threats or processes are involved.

- Single thread 
- Multiple threads or processes

--[ TODO - description and examples ] --

<img src="Images/Chapters/0x07b/multiprocess-fork-ptrace.png" width="500px" />


##### Response

Less is better in terms of information given to the adversary. This principle also applies to anti-tampering controls: A control that reacts to tampering immediately in a visible way is more easily discovered than a control that triggers some kind of hidden response with no apparent immediate consequences. For example, imagine a debugger detection mechanism that displays a message box saying "DEBUGGER DETECTED!" in big, red, all-caps letters. This gives away exactly what has happened, plus it gives the reverse engineer something to look for (the code displaying the messagebox). Now imagine a mechanism that quietly changes modifies function pointer when it detects a debugger, triggering a sequence of events that leads to a crash later on. This makes the reverse engineering process much more painful.

The most effective defensive features are designed to respond in stealth mode: The attacker is left completely unaware that a defensive mechanism has been triggered. For maximum effectiveness, we recommend mixing different types of responses including the following:

- Feedback: When the anti-tampering response is triggered, an error message is displayed to the user or written to a log file. The adversary can immediately discern the nature of the defensive feature as well as the time at which the mechanism was triggered.
- Indiscernible: The defense mechanism terminates the app without providing any error details and without logging the reason for the termination. The adversary does not learn information about the nature of the defensive feature, but can discern the approximate time at which the feature was triggered.
- Stealth: The anti-tampering feature either does not visibly respond at all to the detected tampering, or the response happens with a significant delay. 

See also MASVS V8.8: "The app implements multiple different responses to tampering, debugging and emulation, including stealthy responses that don't simply terminate the pap."

#### Scattering

--[ TODO ] --

#### Integration

--[ TODO ] --

## Assessing Obfuscation

The simplest way of making code less comprehensible is stripping information that is meaningful to humans, such as function and variable names. Many more intricate ways have been invented by software authors - especially those writing malware and DRM systems - over the past decades, from encrypting portions of code and data, to self-modifying and self-compiling code.

A standard implementation of a cryptographic primitive can be replaced by a network of key-dependent lookup tables so the original cryptographic key is not exposed in memory ("white-box cryptography"). Code can be into a secret byte-code language that is then run on an interpreter ("virtualization"). There are infinite ways of encoding and transforming code and data!

Things become complicated when it comes to pinpointing an exact academical definition. In an often cited paper, Barak et. al describe the black-box model of obfuscation. The black-box model considers a program P' obfuscated if any property that can be learned from P' can also be obtained by a simulator with only oracle access to P. In other words, P’ does not reveal anything except its input-output behavior. The authors also show that obfuscation is impossible given their own definition by constructing an un-obfuscable family of programs <sup>[2]</sup>.

Does this mean that obfuscation is impossible? Well, it depends on what you obfuscate and how you define obfuscation. Barack’s result only shows that *some* programs cannot be obfuscated - but only if we use a very strong definition of obfuscation. Intuitively, most of us know from experience that code can have differing amounts of intelligibility and that understanding the code becomes harder as code complexity increases. Often enough, this happens unintentionally, but we can also observe that implementations of obfuscators exist and are more or less successfully used in practice <sup>[3]</sup>.

Unfortunately, reseachers don't agree on whether obfuscation effectiveness can ever be proven or quantified, and there are no widely accepted methods of doing it. In the following sections, we provide a taxonomy of commonly used types of obfuscation. We then outline the requirements for achieving what we would consider *robust* obfuscation, given the de-obfuscation tools and research available at the time of writing. Note however that the field is rapidly involving, so in practice, the most recent developments must always be taken into account.

### Obfuscation Controls in the MASVS

The MASVS lists only two requirements that deal with obfuscation <sup>[4]</sup>. The first requirement is V8.11:

```
"8.11 All executable files and libraries belonging to the app are either encrypted on the file level and/or important code and data segments inside the executables are encrypted or packed. Trivial static analysis does not reveal important code or data."
```

This requirement simply says that the code should be made to look fairly incomprehensible to someone inspecting it in a common disassembler or decompiler. This can be achieved by doing a combination of the following.

**Stripping information**

The first simple and highly effective step involves stripping any explanative information that is meaningful to humans, but isn窶冲 actually needed for the program to run. Debugging symbols that map machine code or byte code to line numbers, function names and variable names are obvious examples.

For instance, class files generated with the standard Java compiler include the names of classes, methods and fields, making it trivial to reconstruct the source code. ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable.

Stripping this information makes a compiled program less intelligible while fully preserving its functionality. Possible methods include removing tables with debugging symbols, or renaming functions and variables to random character combinations instead of meaningful names. This process sometimes reduces the size of the compiled program and doesn窶冲 affect its runtime behavior.

**Packing, encryption, and other tricks**

In addition to stripping information, there's many ways of making apps difficult and annoying to analyze, such as:

- Splitting up code and data between Java bytecode and native code; 
- Encrypting strings;
- Encrypting parts of the code and data withing the program;
- Encrypting whole binary files and class files.

This kind of transformations are "cheap" in the sense that they don't add significant runtime overhead. They form a part of every effective software protection scheme, no matter the particular threat model. The goal is simply to make it hard to understand what is going on, adding to the overall effectiveness of the protections. Seen in isolation, these techniques are not highly resilient against manual or automated de-obfuscation.

The second requirement, V8.12, deals with cases where obfuscation is meant to perform a specific function, such as hiding a cryptographic key, or concealing some portion of code that is considered sensitive.

```
8.12: If the goal of obfuscation is to protect sensitive computations, an obfuscation scheme is used that is both appropriate for the particular task and robust against manual and automated de-obfuscation methods, considering currently published research. The effectiveness of the obfuscation scheme must be verified through manual testing. Note that hardware-based isolation features should prefered over obfuscation whenever possible."
```

This is where more "advanced" (and often controversial) forms of obfuscation, such as white-box cryptography, come into play. This kind of obfuscation is meant to be truly robust against both human and automated analysis, and usually increases the size and complexity of the program. The methods aim to hide the semantics of a computation by computing the same function in a more complicated way, or encoding code and data in ways that are not easily comprehensible.

A simple example for this kind of obfuscations are opaque predicates. Opaque predicates are redundant code branches added to the program that always execute the same way, which is known a priori to the programmer but not to the analyzer. For example, a statement such as if (1 + 1) = 1 always evaluates to false, and thus always result in a jump to the same location. Opaque predicates can be constructed in ways that make them difficult to identify and remove in static analysis.

Other obfuscation methods that fall into this category are:

- Pattern-based obfuscation, when instructions are replaced with more complicated instruction sequences
- Control flow obfuscation
- Control flow flattening
- Function Inlining
- Data encoding and reordering
- Variable splitting
- Virtualization
- White-box cryptography

### Obfuscation Effectiveness

To determine whether a particular obfuscation scheme is depends on the exact definition of "effective". If the purpose of the scheme is to deter casual reverse engineers, a mixture of cost-efficient tricks is sufficient. If the purpose is to achieve a level of resilience against advanced analysis performed by skilled reverse engineers, the scheme must achieve the following:

1. Potency: Program complexity must increased by a sufficient amount to significantly impede human/manual analysis. Note that there is always a trade off between complexity and size and/or performance.
2. Resilience against automated program analysis. For example, if the type of obfuscation is known to be "vulnerable" to concolic analysis, the scheme must include transformations that cause problems for this type of analysis.

#### General Criteria

--[ TODO - describe effectiveness criteria ] --

**Increase in Overall Program Complexity**

--[ TODO ] --

**Difficulty of CFG Recovery**

--[ TODO ] --

**Resilience against Automated Program Analysis**

--[ TODO ] --

#### The Use of Complexity Metrics

--[ TODO  - what metrics to use and how to apply them] --

#### Common Transformations

--[ TODO  - describe commonly used schemes, and criteria associated with each scheme. e.g., white-box must incorportate X to be resilient against DFA,  etc.] --

##### Control-flow Obfuscation

--[ TODO ] --

##### Polymorphic Code

--[ TODO ] --

##### Virtualization

--[ TODO ] --

##### White-box Cryptography

--[ TODO ] --

## Background and Caveats

--[ TODO ] --

### Academic Research on Obfuscation Metrics

-- TODO [Insert and link references] --

Collberg et. al. introduce potency as an estimate of the degree of reverse engineering difficulty. A potent obfuscating transformation is any transformation that increases program complexity. Additionally, they propose the concept of resilience which measures how well a transformation holds up under attack from an automatic de-obfuscator. The same paper also contains a useful taxonomy of obfuscating transformations <sup>[5]</sup>.

Potency can be estimated using a number of methods.  Anaeckart et. al apply traditional software complexity metrics to a control flow graphs generated from executed code <sup>[6]</sup>. The metrics applied are instruction count, cyclomatic number (i.e. number of decision points in the graph) and knot count (number of crossing in a function’s control flow graph). Simply put, the more instructions there are, and the more alternate paths and less expected structure the code has, the more complex it is.

Jacubowsky et. al. use the same method and add further metrics, such as number of variables per instruction, variable indirection, operational indirection, code homogeneity and dataflow complexity <sup>[7]</sup>. Other complexity metrics such as N-Scope <sup>[8]</sup>, which is determined by the nesting levels of all branches in a program, can be used for the same purpose <sup>[9]</sup>.

All these methods are more or less useful for approximating the complexity of a program, but they don’t always accurately reflect the robustness of the obfuscating transformations. Tsai et al. attempt to remediate this by adding a distance metric that reflects the degree of difference between the original program and the obfuscated program. Essentially, this metric captures how the obfuscated call graph differs from the original one. Taken together, a large distance and potency is thought to be correlated to better robustness against reverse engineering <sup>[10]</sup>.

In the same paper, the authors also make the important observation is that measures of obfuscation express the relationship between the original and the transformed program, but are unable to quantify the amount of effort required for reverse engineering. They recognize that these measure can merely serve as heuristic, general indicators of security.

Taking a human-centered approach, Tamada et. al. describe a mental simulation model to evaluate obfuscation <sup>[11]</sup>. In this model, the short-term memory of the human adversary is simulated as a FIFO queue of limited size. The authors then compute six metrics that are supposed to reflect the difficulty encountered by the adversary in reverse engineering the program. Nakamura et. al. propose similar metrics reflecting the cost of mental simulation <sup>[12]</sup>.

More recently, Rabih Mosen and Alexandre Miranda Pinto proposed the use of a normalized version of Kolmogorov complexity as a metric for obfuscation effectiveness. The intuition behind their approach is based on the following argument: if an adversary fails to capture some patterns (regularities) in an obfuscated code, then the adversary will have difficulty comprehending that code: it cannot provide a valid and brief, i.e., simple description. On the other hand, if these regularities are simple to explain, then describing them becomes easier, and consequently the code will not be difficult to understand. The authors also provide empirical results showing that common obfuscation techniques managed to produce a substantial increase in the proposed metric. They found that the metric was more sensitive then Cyclomatic measure at detecting any increase in complexity comparing to original un-obfuscated code <sup>[13]</sup>.

This makes intuitive sense and even though it doesn’t always hold true, the Kolmogorov complexity metric appears to be useful to quantify the impact of control flow and data obfuscation schemes that add random noise to a program.

### Experimental Data

With the limitations of existing complexity measures in mind we can see that more human studies on the subject would be helpful. Unfortunately, the body of experimental research is relatively small - in fact, the lack of empirical studies is one of the main issues researchers face  <sup>[14]</sup>. There are however some interesting papers linking some types of obfuscation to higher reverse engineering difficulty.

Nakamura et. al performed an empirical study to investigate the impact of several novel cost metrics proposed in the same paper <sup>[12]</sup>. In the experiment, twelve subjects were asked to mentally execute two different versions (with varying complexity) of three Java programs. At specific times during the experiment, the subjects were required to describe the program state (i.e., values of all variables in the program). The accuracy and speed of the participants in performing the experiment was then used to assess the validity of the proposed cost metrics. The results demonstrated that the proposed complexity metrics (some more than others) were correlated with the time needed by the subjects to solve the tasks. 

Sutherland et al. examine a framework for collecting reverse engineering measurement and the execution of reverse engineering experiments <sup>15</sup>. The researchers asked a group of ten students to perform static analysis and dynamic analysis on several binary programs and found a significant correlation between the skill level of the students and the level of success in the tasks (no big surprise there, but let’s count it as preliminary evidence that luck alone won’t get you far in reverse engineering).

In a series of controlled experiments, M. Ceccato et. al. tested the impact of identifier renaming and opaque predicates to increase the effort needed for attacks  <sup>[3] [16] [17]</sup>. In these studies, Master and PhD students with a good knowledge of Java programming were asked to perform understanding tasks or change tasks on the decompiled (either obfuscated or clear) client code of client-server Java applications. The experiments showed that obfuscation reduced the capability of subjects to understand and modify the source code. Interestingly, the results also showed that the presence of obfuscation reduced the gap between highly skilled attackers and low skilled ones: The highly skilled attackers were significantly faster in analyzing the clear source code, but the difference was smaller when analyzing the obfuscated version. Among other results, identifier renaming was shown to at least double the time needed to complete a successful attack <sup>[16]</sup>.

<img src="Images/Chapters/0x07b/boxplot.png" width="650px" />

*Boxplot of attack efficiency from the Ceccato et. al. experiment to measure the impact of identifier renaming on program comprehension. Subjects analyzing the obfuscated code gave less correct answers per minute.*

### The Device Binding Problem

In many cases it can be argued that obfuscating some secret functionality misses the point, as for all practical purposes, the adversary does not need to know all the details about the obfuscated functionality. Say, the function of an obfuscated program it to take an input value and use it to compute an output value in an indiscernible way (for example, through a cryptographic operation with a hidden key). In most scenarios, the adversaries goal would be to replicate the functionality of the program – i.e. computing the same output values on a system owned by the adversary. Why not simply copy and re-use whole implementation instead of painstakingly reverse engineering the code? Is there any reason why the adversary needs to look inside the black-box?

This kind of attack is known as code lifting and is commonly used for breaking DRM and white-box cryptographic implementations <sup>[18]</sup>. For example, an adversary aiming to bypass digital media usage could simply extract the encryption routine from a player and include it in a counterfeit player, which decrypts the digital media without enforcing the contained usage policies <sup>19</sup>. Designers of white-box implementations have to deal with another issue: one can convert an encryption routine into a decryption routine without actually extracting the key <sup>[20]</sup>.

Protected applications must include measures against code lifting to be useful. In practice, this means binding the obfuscated functionality to the specific environment (hardware, device or client/server infrastructure) in which the binary is executed. Preferably, the protected functionality should execute correctly only in the specific, legitimate computing environment. For example, an obfuscated encryption algorithm could generate its key (or part of the key) using data collected from the environment <sup>[21]</sup>. Techniques that tie the functionality of an app to specific hardware are known as device binding.

Even so, it is relatively easy (as opposed to fully reverse engineering the black-box) to monitor the interactions of an app with its environment. In practice, simple hardware properties such as the IMEI and MAC address of a device are often used to achieve device binding. The effort needed to spoof these environmental properties is certainly lower than the effort required for needed for fully understanding the obfuscated functionality.

What all this means is that, for most practical purposes, the security of an obfuscated application is only as good as the device binding it implements. For device binding to be effective, specific characteristics of the system or device must be deeply intertwined with the various obfuscation layers, and these characteristics must be determined in stealthy ways (ideally, by reading content directly from memory). Advanced device binding methods are often deployed in DRM and malware and some research has been published in this area <sup>[22]</sup>.

## References

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
