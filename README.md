# american fuzzy lop

[![Build Status](https://travis-ci.org/google/AFL.svg?branch=master)](https://travis-ci.org/google/AFL)

Originally developed by Michal Zalewski <lcamtuf@google.com>.

See [QuickStartGuide.txt](docs/QuickStartGuide.txt) if you don't have time to read
this file.

## 1) Challenges of guided fuzzing

Fuzzing is one of the most powerful and proven strategies for identifying
security issues in real-world software; it is responsible for the vast
majority of remote code execution and privilege escalation bugs found to date
in security-critical software.

Unfortunately, fuzzing is also relatively shallow; blind, random mutations
make it very unlikely to reach certain code paths in the tested code, leaving
some vulnerabilities firmly outside the reach of this technique.

There have been numerous attempts to solve this problem. One of the early
approaches - pioneered by Tavis Ormandy - is corpus distillation. The method
relies on coverage signals to select a subset of interesting seeds from a
massive, high-quality corpus of candidate files, and then fuzz them by
traditional means. The approach works exceptionally well, but requires such
a corpus to be readily available. In addition, block coverage measurements
provide only a very simplistic understanding of program state, and are less
useful for guiding the fuzzing effort in the long haul.

Other, more sophisticated research has focused on techniques such as program
flow analysis ("concolic execution"), symbolic execution, or static analysis.
All these methods are extremely promising in experimental settings, but tend
to suffer from reliability and performance problems in practical uses - and
currently do not offer a viable alternative to "dumb" fuzzing techniques.

模糊测试是识别现实软件中安全问题的最强大且经过验证的策略之一； 它是迄今为止在安全关键软件中发现的绝大多数远程代码执行和权限升级错误的罪魁祸首。

不幸的是，模糊测试也相对较浅。 盲目的随机突变使其不太可能到达测试代码中的某些代码路径，从而使某些漏洞完全超出了该技术的范围。

已经有许多尝试来解决这个问题。 由 Tavis Ormandy 首创的早期方法之一是语料库蒸馏。 该方法依靠覆盖信号从大量高质量的候选文件语料库中选择感兴趣的种子子集，然后通过传统方式对它们进行模糊测试。 该方法效果非常好，但需要这样的语料库随时可用。 此外，块覆盖率测量仅提供对程序状态的非常简单的理解，并且对于指导长期的模糊测试工作不太有用。

其他更复杂的研究集中在程序流分析（“concolic执行”）、符号执行或静态分析等技术上。 所有这些方法在实验环境中都非常有前途，但在实际使用中往往会遇到可靠性和性能问题——并且目前还没有提供“哑”模糊技术的可行替代方案。

## 2) The afl-fuzz approach

American Fuzzy Lop is a brute-force fuzzer coupled with an exceedingly simple
but rock-solid instrumentation-guided genetic algorithm. It uses a modified
form of edge coverage to effortlessly pick up subtle, local-scale changes to
program control flow.

Simplifying a bit, the overall algorithm can be summed up as:

  1) Load user-supplied initial test cases into the queue,

  2) Take next input file from the queue,

  3) Attempt to trim the test case to the smallest size that doesn't alter
     the measured behavior of the program,

  4) Repeatedly mutate the file using a balanced and well-researched variety
     of traditional fuzzing strategies,

  5) If any of the generated mutations resulted in a new state transition
     recorded by the instrumentation, add mutated output as a new entry in the
     queue.

  6) Go to 2.

The discovered test cases are also periodically culled to eliminate ones that
have been obsoleted by newer, higher-coverage finds; and undergo several other
instrumentation-driven effort minimization steps.

As a side result of the fuzzing process, the tool creates a small,
self-contained corpus of interesting test cases. These are extremely useful
for seeding other, labor- or resource-intensive testing regimes - for example,
for stress-testing browsers, office applications, graphics suites, or
closed-source tools.

The fuzzer is thoroughly tested to deliver out-of-the-box performance far
superior to blind fuzzing or coverage-only tools.

American Fuzzy Lop 是一种强力模糊器，结合了极其简单但坚如磐石的仪器引导遗传算法。 它使用一种修改形式的边缘覆盖来轻松地获取程序控制流的细微的、局部范围的变化。

稍微简化一下，整体算法可以总结为：

将用户提供的初始测试用例加载到队列中，

从队列中取出下一个输入文件，

尝试将测试用例修剪到不会改变程序的测量行为的最小尺寸，

使用平衡且经过充分研究的各种传统模糊测试策略反复变异文件，

如果任何生成的突变导致仪器记录新的状态转换，请将突变输出添加为队列中的新条目。

转到2。

发现的测试用例也会定期剔除，以消除那些被更新、覆盖率更高的发现所淘汰的测试用例； 并经历其他几个仪器驱动的工作最小化步骤。

作为模糊测试过程的一个副作用，该工具创建了一个小型的、独立的有趣测试用例语料库。 这些对于播种其他劳动或资源密集型测试制度非常有用 - 例如，用于压力测试浏览器、办公应用程序、图形套件或闭源工具。

该模糊器经过彻底测试，其开箱即用的性能远远优于盲目模糊测试或仅覆盖工具。


## 3) Instrumenting programs for use with AFL

When source code is available, instrumentation can be injected by a companion
tool that works as a drop-in replacement for gcc or clang in any standard build
process for third-party code.

The instrumentation has a fairly modest performance impact; in conjunction with
other optimizations implemented by afl-fuzz, most programs can be fuzzed as fast
or even faster than possible with traditional tools.

The correct way to recompile the target program may vary depending on the
specifics of the build process, but a nearly-universal approach would be:

当源代码可用时，可以通过同伴注入检测
在任何标准构建中可作为 gcc 或 clang 的直接替代品的工具
第三方代码的流程。

该仪器对性能的影响相当有限； 和这个结合
afl-fuzz 实现的其他优化，大多数程序都可以快速模糊测试
甚至比传统工具更快。

重新编译目标程序的正确方法可能会根据不同的环境而有所不同
构建过程的具体细节，但几乎通用的方法是：

```shell
$ CC=/path/to/afl/afl-gcc ./configure
$ make clean all
```

For C++ programs, you'd would also want to set `CXX=/path/to/afl/afl-g++`.

The clang wrappers (afl-clang and afl-clang++) can be used in the same way;
clang users may also opt to leverage a higher-performance instrumentation mode,
as described in llvm_mode/README.llvm.

When testing libraries, you need to find or write a simple program that reads
data from stdin or from a file and passes it to the tested library. In such a
case, it is essential to link this executable against a static version of the
instrumented library, or to make sure that the correct .so file is loaded at
runtime (usually by setting `LD_LIBRARY_PATH`). The simplest option is a static
build, usually possible via:

对于 C++ 程序，您还需要设置“CXX=/path/to/afl/afl-g++”。

clang 包装器（afl-clang 和 afl-clang++）可以以相同的方式使用；
clang 用户还可以选择利用更高性能的仪器模式，
如 llvm_mode/README.llvm 中所述。

测试库时，您需要找到或编写一个简单的程序来读取
来自标准输入或文件的数据并将其传递到测试库。 在这样一个
在这种情况下，必须将此可执行文件链接到静态版本
检测库，或确保加载正确的 .so 文件
运行时（通常通过设置“LD_LIBRARY_PATH”）。 最简单的选择是静态
构建，通常可以通过：


```shell
$ CC=/path/to/afl/afl-gcc ./configure --disable-shared
```

Setting `AFL_HARDEN=1` when calling 'make' will cause the CC wrapper to
automatically enable code hardening options that make it easier to detect
simple memory bugs. Libdislocator, a helper library included with AFL (see
libdislocator/README.dislocator) can help uncover heap corruption issues, too.

PS. ASAN users are advised to review [notes_for_asan.txt](docs/notes_for_asan.txt) file for important
caveats.

调用“make”时设置“AFL_HARDEN=1”将导致 CC 包装器
自动启用代码强化选项，使其更容易检测
简单的内存错误。 Libdislocator，AFL 附带的辅助库（请参阅
libdislocator/README.dislocator）也可以帮助发现堆损坏问题。

附言。 建议 ASAN 用户查看 [notes_for_asan.txt](docs/notes_for_asan.txt) 文件以了解重要信息
注意事项。

## 4) Instrumenting binary-only apps

When source code is *NOT* available, the fuzzer offers experimental support for
fast, on-the-fly instrumentation of black-box binaries. This is accomplished
with a version of QEMU running in the lesser-known "user space emulation" mode.

QEMU is a project separate from AFL, but you can conveniently build the
feature by doing:

当源代码*不*可用时，模糊器会提供实验支持
黑盒二进制文件的快速、动态检测。 这样就完成了
QEMU 版本运行在鲜为人知的“用户空间模拟”模式下。

QEMU 是一个独立于 AFL 的项目，但您可以方便地构建
通过执行以下操作来实现功能：

```shell
$ cd qemu_mode
$ ./build_qemu_support.sh
```

For additional instructions and caveats, see qemu_mode/README.qemu.

The mode is approximately 2-5x slower than compile-time instrumentation, is
less conducive to parallelization, and may have some other quirks.

有关其他说明和注意事项，请参阅 qemu_mode/README.qemu。

该模式大约比编译时检测慢 2-5 倍，即
不太利于并行化，并且可能有一些其他的怪癖。

## 5) Choosing initial test cases

To operate correctly, the fuzzer requires one or more starting file that
contains a good example of the input data normally expected by the targeted
application. There are two basic rules:

  - Keep the files small. Under 1 kB is ideal, although not strictly necessary.
    For a discussion of why size matters, see [perf_tips.txt](docs/perf_tips.txt).

  - Use multiple test cases only if they are functionally different from
    each other. There is no point in using fifty different vacation photos
    to fuzz an image library.

You can find many good examples of starting files in the testcases/ subdirectory
that comes with this tool.

PS. If a large corpus of data is available for screening, you may want to use
the afl-cmin utility to identify a subset of functionally distinct files that
exercise different code paths in the target binary.

为了正确运行，模糊器需要一个或多个启动文件
包含目标通常期望的输入数据的一个很好的示例
应用。 有两个基本规则：

- 保持文件小。 尽管不是绝对必要的，但低于 1 kB 是理想的。
  有关大小为何重要的讨论，请参阅 [perf_tips.txt](docs/perf_tips.txt)。

- 仅当功能不同时才使用多个测试用例
  彼此。 使用五十张不同的度假照片是没有意义的
  对图像库进行模糊测试。

您可以在 testcases/ 子目录中找到许多启动文件的好示例
这个工具附带的。

附言。 如果有大量数据可供筛选，您可能需要使用
afl-cmin 实用程序用于识别功能不同的文件的子集
在目标二进制文件中执行不同的代码路径。


## 6) Fuzzing binaries

The fuzzing process itself is carried out by the afl-fuzz utility. This program
requires a read-only directory with initial test cases, a separate place to
store its findings, plus a path to the binary to test.

For target binaries that accept input directly from stdin, the usual syntax is:

模糊测试过程本身由 afl-fuzz 实用程序执行。 这个节目
需要一个包含初始测试用例的只读目录，一个单独的位置
存储其发现，以及要测试的二进制文件的路径。

对于直接从 stdin 接受输入的目标二进制文件，通常的语法是：

```shell
$ ./afl-fuzz -i testcase_dir -o findings_dir /path/to/program [...params...]
```

For programs that take input from a file, use '@@' to mark the location in
the target's command line where the input file name should be placed. The
fuzzer will substitute this for you:

对于从文件获取输入的程序，请使用“@@”来标记位置
应放置输入文件名的目标命令行。 这
模糊器将代替你：

```shell
$ ./afl-fuzz -i testcase_dir -o findings_dir /path/to/program @@
```

You can also use the -f option to have the mutated data written to a specific
file. This is useful if the program expects a particular file extension or so.

Non-instrumented binaries can be fuzzed in the QEMU mode (add -Q in the command
line) or in a traditional, blind-fuzzer mode (specify -n).

You can use -t and -m to override the default timeout and memory limit for the
executed process; rare examples of targets that may need these settings touched
include compilers and video decoders.

Tips for optimizing fuzzing performance are discussed in [perf_tips.txt](docs/perf_tips.txt).

Note that afl-fuzz starts by performing an array of deterministic fuzzing
steps, which can take several days, but tend to produce neat test cases. If you
want quick & dirty results right away - akin to zzuf and other traditional
fuzzers - add the -d option to the command line.


您还可以使用 -f 选项将变异数据写入特定的
文件。 如果程序需要特定的文件扩展名等，这很有用。

未检测的二进制文件可以在 QEMU 模式（在命令行中添加 -Q）或传统的盲模糊器模式（指定 -n）中进行模糊测试。

您可以使用 -t 和 -m 覆盖默认超时和内存限制
执行的过程； 可能需要触及这些设置的目标的罕见示例
包括编译器和视频解码器。

[perf_tips.txt](docs/perf_tips.txt) 中讨论了优化模糊测试性能的技巧。

请注意，afl-fuzz 首先执行一系列确定性模糊测试
步骤，这可能需要几天的时间，但往往会产生整洁的测试用例。 如果你
想要立即获得快速而肮脏的结果 - 类似于 zzuf 和其他传统方法
模糊器 - 将 -d 选项添加到命令行。

## 7) Interpreting output

See the [status_screen.txt](docs/status_screen.txt) file for information on
how to interpret the displayed stats and monitor the health of the process.
Be sure to consult this file especially if any UI elements are highlighted in
red.

The fuzzing process will continue until you press Ctrl-C. At minimum, you want
to allow the fuzzer to complete one queue cycle, which may take anywhere from a
couple of hours to a week or so.

There are three subdirectories created within the output directory and updated
in real time:

  - queue/   - test cases for every distinctive execution path, plus all the
               starting files given by the user. This is the synthesized corpus
               mentioned in section 2.
               Before using this corpus for any other purposes, you can shrink
               it to a smaller size using the afl-cmin tool. The tool will find
               a smaller subset of files offering equivalent edge coverage.

  - crashes/ - unique test cases that cause the tested program to receive a
               fatal signal (e.g., SIGSEGV, SIGILL, SIGABRT). The entries are
               grouped by the received signal.

  - hangs/   - unique test cases that cause the tested program to time out. The
               default time limit before something is classified as a hang is
               the larger of 1 second and the value of the -t parameter.
               The value can be fine-tuned by setting AFL_HANG_TMOUT, but this
               is rarely necessary.

Crashes and hangs are considered "unique" if the associated execution paths
involve any state transitions not seen in previously-recorded faults. If a
single bug can be reached in multiple ways, there will be some count inflation
early in the process, but this should quickly taper off.

The file names for crashes and hangs are correlated with parent, non-faulting
queue entries. This should help with debugging.

When you can't reproduce a crash found by afl-fuzz, the most likely cause is
that you are not setting the same memory limit as used by the tool. Try:

有关信息，请参阅 [status_screen.txt](docs/status_screen.txt) 文件
如何解释显示的统计数据并监控进程的运行状况。
请务必查阅此文件，特别是如果任何 UI 元素在
红色的。

模糊测试过程将继续，直到您按下 Ctrl-C。 至少，你想要
允许模糊器完成一个队列周期，这可能需要从
几个小时到一周左右。

在输出目录中创建并更新了三个子目录
实时：

- 队列/ - 每个独特执行路径的测试用例，以及所有
  用户给定的启动文件。 这是合成的语料库
  第 2 节中提到。
  在将此语料库用于任何其他目的之前，您可以缩小
  使用 afl-cmin 工具将其缩小。 该工具会发现
  提供同等边缘覆盖范围的较小文件子集。

- 崩溃/ - 独特的测试用例，导致被测试的程序收到
  致命信号（例如 SIGSEGV、SIGILL、SIGABRT）。 条目是
  按接收到的信号分组。

- 挂起/ - 导致测试程序超时的独特测试用例。 这
  将某些内容分类为挂起之前的默认时间限制是
  1 秒和 -t 参数值中的较大者。
  该值可以通过设置AFL_HANG_TMOUT进行微调，但是这个
  很少有必要。

如果关联的执行路径，则崩溃和挂起被视为“唯一”
涉及先前记录的故障中未见的任何状态转换。 如果一个
单个错误可以通过多种方式到达，会有一些计数膨胀
在此过程的早期，但这应该很快逐渐减少。

崩溃和挂起的文件名与父级、非故障相关
队列条目。 这应该有助于调试。

当您无法重现 afl-fuzz 发现的崩溃时，最可能的原因是
您没有设置与该工具使用的内存限制相同的内存限制。 尝试：


```shell
$ LIMIT_MB=50
$ ( ulimit -Sv $[LIMIT_MB << 10]; /path/to/tested_binary ... )
```

Change LIMIT_MB to match the -m parameter passed to afl-fuzz. On OpenBSD,
also change -Sv to -Sd.

Any existing output directory can be also used to resume aborted jobs; try:

更改 LIMIT_MB 以匹配传递给 afl-fuzz 的 -m 参数。 在 OpenBSD 上，
还将-Sv 更改为-Sd。

任何现有的输出目录也可用于恢复中止的作业； 尝试：

```shell
$ ./afl-fuzz -i- -o existing_output_dir [...etc...]
```

If you have gnuplot installed, you can also generate some pretty graphs for any
active fuzzing task using afl-plot. For an example of how this looks like,
see [http://lcamtuf.coredump.cx/afl/plot/](http://lcamtuf.coredump.cx/afl/plot/).

如果您安装了 gnuplot，您还可以为任何内容生成一些漂亮的图表。
使用 afl-plot 进行主动模糊测试任务。 作为一个例子，
请参阅[http://lcamtuf.coredump.cx/afl/plot/](http://lcamtuf.coredump.cx/afl/plot/)。

## 8) Parallelized fuzzing

Every instance of afl-fuzz takes up roughly one core. This means that on
multi-core systems, parallelization is necessary to fully utilize the hardware.
For tips on how to fuzz a common target on multiple cores or multiple networked
machines, please refer to [parallel_fuzzing.txt](docs/parallel_fuzzing.txt).

The parallel fuzzing mode also offers a simple way for interfacing AFL to other
fuzzers, to symbolic or concolic execution engines, and so forth; again, see the
last section of [parallel_fuzzing.txt](docs/parallel_fuzzing.txt) for tips.

afl-fuzz 的每个实例大约占用一个核心。 这意味着在
多核系统中，并行化对于充分利用硬件是必要的。
有关如何模糊多核或多网络上的常见目标的提示
机器，请参考[parallel_fuzzing.txt](docs/parallel_fuzzing.txt)。

并行模糊测试模式还提供了一种将 AFL 与其他接口连接的简单方法
模糊器、符号或 concolic 执行引擎等； 再次，参见
[parallel_fuzzing.txt](docs/parallel_fuzzing.txt) 的最后一部分提供提示。

## 9) Fuzzer dictionaries

By default, afl-fuzz mutation engine is optimized for compact data formats -
say, images, multimedia, compressed data, regular expression syntax, or shell
scripts. It is somewhat less suited for languages with particularly verbose and
redundant verbiage - notably including HTML, SQL, or JavaScript.

To avoid the hassle of building syntax-aware tools, afl-fuzz provides a way to
seed the fuzzing process with an optional dictionary of language keywords,
magic headers, or other special tokens associated with the targeted data type
-- and use that to reconstruct the underlying grammar on the go:

  [http://lcamtuf.blogspot.com/2015/01/afl-fuzz-making-up-grammar-with.html](http://lcamtuf.blogspot.com/2015/01/afl-fuzz-making-up-grammar-with.html)

To use this feature, you first need to create a dictionary in one of the two
formats discussed in dictionaries/README.dictionaries; and then point the fuzzer
to it via the -x option in the command line.

(Several common dictionaries are already provided in that subdirectory, too.)

There is no way to provide more structured descriptions of the underlying
syntax, but the fuzzer will likely figure out some of this based on the
instrumentation feedback alone. This actually works in practice, say:

  [http://lcamtuf.blogspot.com/2015/04/finding-bugs-in-sqlite-easy-way.html](http://lcamtuf.blogspot.com/2015/04/finding-bugs-in-sqlite-easy-way.html)

PS. Even when no explicit dictionary is given, afl-fuzz will try to extract
existing syntax tokens in the input corpus by watching the instrumentation
very closely during deterministic byte flips. This works for some types of
parsers and grammars, but isn't nearly as good as the -x mode.

If a dictionary is really hard to come by, another option is to let AFL run
for a while, and then use the token capture library that comes as a companion
utility with AFL. For that, see libtokencap/README.tokencap.


默认情况下，afl-fuzz 变异引擎针对紧凑数据格式进行了优化 -
例如，图像、多媒体、压缩数据、正则表达式语法或 shell
脚本。 它不太适合那些特别冗长和复杂的语言
多余的措辞 - 特别是包括 HTML、SQL 或 JavaScript。

为了避免构建语法感知工具的麻烦，afl-fuzz 提供了一种方法
使用可选的语言关键字字典来种子模糊测试过程，
魔术标头或与目标数据类型关联的其他特殊标记
-- 并用它来重建底层语法：

[http://lcamtuf.blogspot.com/2015/01/afl-fuzz-making-up-grammar-with.html](http://lcamtuf.blogspot.com/2015/01/afl-fuzz-making- up-grammar-with.html)

要使用此功能，您首先需要在两者之一中创建一个字典
字典/README.dictionaries 中讨论的格式； 然后将模糊器指向
通过命令行中的 -x 选项。

（该子目录中也已经提供了几个常用词典。）

没有办法提供更结构化的底层描述
语法，但模糊器可能会根据以下内容找出其中的一些内容
仅仪器反馈。 这在实践中确实有效，例如：

[http://lcamtuf.blogspot.com/2015/04/finding-bugs-in-sqlite-easy-way.html](http://lcamtuf.blogspot.com/2015/04/finding-bugs-in- sqlite-easy-way.html)

附言。 即使没有给出显式字典，afl-fuzz 也会尝试提取
通过观察检测来了解输入语料库中现有的语法标记
在确定性字节翻转期间非常接近。 这适用于某些类型
解析器和语法，但不如 -x 模式。

如果字典真的很难找到，另一个选择是让 AFL 运行
一段时间，然后使用附带的令牌捕获库
与 AFL 的实用性。 为此，请参阅 libtokencap/README.tokencap。
## 10) Crash triage

The coverage-based grouping of crashes usually produces a small data set that
can be quickly triaged manually or with a very simple GDB or Valgrind script.
Every crash is also traceable to its parent non-crashing test case in the
queue, making it easier to diagnose faults.

Having said that, it's important to acknowledge that some fuzzing crashes can be
difficult to quickly evaluate for exploitability without a lot of debugging and
code analysis work. To assist with this task, afl-fuzz supports a very unique
"crash exploration" mode enabled with the -C flag.

In this mode, the fuzzer takes one or more crashing test cases as the input,
and uses its feedback-driven fuzzing strategies to very quickly enumerate all
code paths that can be reached in the program while keeping it in the
crashing state.

Mutations that do not result in a crash are rejected; so are any changes that
do not affect the execution path.

The output is a small corpus of files that can be very rapidly examined to see
what degree of control the attacker has over the faulting address, or whether
it is possible to get past an initial out-of-bounds read - and see what lies
beneath.

Oh, one more thing: for test case minimization, give afl-tmin a try. The tool
can be operated in a very simple way:

基于覆盖范围的崩溃分组通常会产生一个小数据集，
可以手动或使用非常简单的 GDB 或 Valgrind 脚本快速分类。
每次崩溃也可以追溯到其父级非崩溃测试用例
队列，更容易诊断故障。

话虽如此，重要的是要承认一些模糊测试崩溃可能是
如果没有大量调试，很难快速评估可利用性
代码分析工作。 为了协助完成这项任务，afl-fuzz 支持一个非常独特的
使用 -C 标志启用“崩溃探索”模式。

在这种模式下，模糊器将一个或多个崩溃测试用例作为输入，
并使用其反馈驱动的模糊测试策略来快速枚举所有
可以在程序中访问的代码路径，同时将其保留在
崩溃状态。

不会导致崩溃的突变会被拒绝； 任何改变也是如此
不影响执行路径。

输出是一个小的文件语料库，可以非常快速地检查以查看
攻击者对故障地址的控制程度如何，或者是否
有可能超越最初的越界读取 - 并查看其中的内容
下面。

哦，还有一件事：为了最小化测试用例，请尝试 afl-tmin。 工具
可以通过非常简单的方式进行操作：

```shell
$ ./afl-tmin -i test_case -o minimized_result -- /path/to/program [...]
```

The tool works with crashing and non-crashing test cases alike. In the crash
mode, it will happily accept instrumented and non-instrumented binaries. In the
non-crashing mode, the minimizer relies on standard AFL instrumentation to make
the file simpler without altering the execution path.

The minimizer accepts the -m, -t, -f and @@ syntax in a manner compatible with
afl-fuzz.

Another recent addition to AFL is the afl-analyze tool. It takes an input
file, attempts to sequentially flip bytes, and observes the behavior of the
tested program. It then color-codes the input based on which sections appear to
be critical, and which are not; while not bulletproof, it can often offer quick
insights into complex file formats. More info about its operation can be found
near the end of [technical_details.txt](docs/technical_details.txt).

该工具适用于崩溃和非崩溃测试用例。 在车祸中
模式下，它会很乐意接受已检测和未检测的二进制文件。 在里面
非崩溃模式，最小化器依靠标准 AFL 仪器来使
在不改变执行路径的情况下使文件更简单。

最小化器以兼容的方式接受 -m、-t、-f 和 @@ 语法
afl-绒毛。

AFL 最近添加的另一个工具是 afl-analyze 工具。 它需要一个输入
文件，尝试顺序翻转字节，并观察的行为
测试过的程序。 然后，它根据显示的部分对输入进行颜色编码
哪些是批判性的，哪些不是； 虽然不是防弹的，但它通常可以提供快速
深入了解复杂的文件格式。 有关其操作的更多信息可以找到
接近 [technical_details.txt](docs/technical_details.txt) 末尾。

## 11) Going beyond crashes

Fuzzing is a wonderful and underutilized technique for discovering non-crashing
design and implementation errors, too. Quite a few interesting bugs have been
found by modifying the target programs to call abort() when, say:

  - Two bignum libraries produce different outputs when given the same
    fuzzer-generated input,

  - An image library produces different outputs when asked to decode the same
    input image several times in a row,

  - A serialization / deserialization library fails to produce stable outputs
    when iteratively serializing and deserializing fuzzer-supplied data,

  - A compression library produces an output inconsistent with the input file
    when asked to compress and then decompress a particular blob.

Implementing these or similar sanity checks usually takes very little time;
if you are the maintainer of a particular package, you can make this code
conditional with `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` (a flag also
shared with libfuzzer) or `#ifdef __AFL_COMPILER` (this one is just for AFL).

模糊测试是一种奇妙但未充分利用的技术，用于发现非崩溃
设计和实现也有错误。 有相当多有趣的错误
通过修改目标程序发现调用 abort() 时，比如说：

- 当给定相同的值时，两个 bignum 库会产生不同的输出
  模糊器生成的输入，

- 当要求解码相同的图像库时，图像库会产生不同的输出
  连续多次输入图像，

- 序列化/反序列化库无法产生稳定的输出
  当迭代序列化和反序列化模糊器提供的数据时，

- 压缩库产生与输入文件不一致的输出
  当要求压缩然后解压缩特定的 blob 时。

实施这些或类似的健全性检查通常只需要很少的时间；
如果您是特定包的维护者，您可以编写此代码
以`#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_Production`为条件（也有一个标志
与 libfuzzer 共享）或 `#ifdef __AFL_COMPILER` （这仅适用于 AFL）。

## 12) Common-sense risks

Please keep in mind that, similarly to many other computationally-intensive
tasks, fuzzing may put strain on your hardware and on the OS. In particular:

  - Your CPU will run hot and will need adequate cooling. In most cases, if
    cooling is insufficient or stops working properly, CPU speeds will be
    automatically throttled. That said, especially when fuzzing on less
    suitable hardware (laptops, smartphones, etc), it's not entirely impossible
    for something to blow up.

  - Targeted programs may end up erratically grabbing gigabytes of memory or
    filling up disk space with junk files. AFL tries to enforce basic memory
    limits, but can't prevent each and every possible mishap. The bottom line
    is that you shouldn't be fuzzing on systems where the prospect of data loss
    is not an acceptable risk.

  - Fuzzing involves billions of reads and writes to the filesystem. On modern
    systems, this will be usually heavily cached, resulting in fairly modest
    "physical" I/O - but there are many factors that may alter this equation.
    It is your responsibility to monitor for potential trouble; with very heavy
    I/O, the lifespan of many HDDs and SSDs may be reduced.

    A good way to monitor disk I/O on Linux is the 'iostat' command:
    请记住，与许多其他计算密集型计算类似
    任务，模糊测试可能会给您的硬件和操作系统带来压力。 尤其：

- 您的 CPU 运行时会很热，需要足够的冷却。 大多数情况下，如果
  冷却不足或停止正常工作，CPU 速度将下降
  自动节流。 也就是说，特别是当模糊测试较少时
  合适的硬件（笔记本电脑、智能手机等），这并非完全不可能
  为了让某些东西爆炸。

- 目标程序最终可能会不稳定地占用千兆字节的内存或
  用垃圾文件填充磁盘空间。 AFL 试图强化基本记忆
  限制，但无法阻止每一个可能发生的事故。 底线
  是你不应该对可能发生数据丢失的系统进行模糊测试
  是不可接受的风险。

- 模糊测试涉及对文件系统进行数十亿次读取和写入。 论现代
  系统，这通常会被大量缓存，从而导致相当适度的
  “物理”I/O - 但有许多因素可能会改变这个方程式。
  您有责任监控潜在的问题； 非常重
  I/O，许多 HDD 和 SSD 的寿命可能会缩短。

  在 Linux 上监视磁盘 I/O 的一个好方法是“iostat”命令：
    

```shell
    $ iostat -d 3 -x -k [...optional disk ID...]
```

## 13) Known limitations & areas for improvement

Here are some of the most important caveats for AFL:

  - AFL detects faults by checking for the first spawned process dying due to
    a signal (SIGSEGV, SIGABRT, etc). Programs that install custom handlers for
    these signals may need to have the relevant code commented out. In the same
    vein, faults in child processed spawned by the fuzzed target may evade
    detection unless you manually add some code to catch that.

  - As with any other brute-force tool, the fuzzer offers limited coverage if
    encryption, checksums, cryptographic signatures, or compression are used to
    wholly wrap the actual data format to be tested.

    To work around this, you can comment out the relevant checks (see
    experimental/libpng_no_checksum/ for inspiration); if this is not possible,
    you can also write a postprocessor, as explained in
    experimental/post_library/.

  - There are some unfortunate trade-offs with ASAN and 64-bit binaries. This
    isn't due to any specific fault of afl-fuzz; see [notes_for_asan.txt](docs/notes_for_asan.txt)
    for tips.

  - There is no direct support for fuzzing network services, background
    daemons, or interactive apps that require UI interaction to work. You may
    need to make simple code changes to make them behave in a more traditional
    way. Preeny may offer a relatively simple option, too - see:
    https://github.com/zardus/preeny

    Some useful tips for modifying network-based services can be also found at:
    https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop

  - AFL doesn't output human-readable coverage data. If you want to monitor
    coverage, use afl-cov from Michael Rash: https://github.com/mrash/afl-cov

  - Occasionally, sentient machines rise against their creators. If this
    happens to you, please consult http://lcamtuf.coredump.cx/prep/.

Beyond this, see INSTALL for platform-specific tips.

以下是 AFL 的一些最重要的注意事项：

- AFL 通过检查第一个生成的进程是否由于以下原因而死亡来检测故障
  信号（SIGSEGV、SIGABRT 等）。 安装自定义处理程序的程序
  这些信号可能需要注释掉相关代码。 在相同的
  静脉，由模糊目标产生的子处理中的错误可能会逃避
  检测，除非您手动添加一些代码来捕获它。

- 与任何其他暴力工具一样，模糊器提供的覆盖范围有限，如果
  加密、校验和、加密签名或压缩用于
  完全包装要测试的实际数据格式。

  要解决此问题，您可以注释掉相关检查（请参阅
  实验/libpng_no_checksum/以获得灵感）； 如果这是不可能的，
  您还可以编写一个后处理器，如中所述
  实验/post_library/。

- ASAN 和 64 位二进制文件之间存在一些不幸的权衡。 这
  不是由于 afl-fuzz 的任何特定错误； 请参阅 [notes_for_asan.txt](docs/notes_for_asan.txt)
  获取提示。

- 没有直接支持模糊网络服务、后台
  守护进程或需要 UI 交互才能工作的交互式应用程序。 您可以
  需要进行简单的代码更改以使它们以更传统的方式运行
  方式。 Preeny 也可能提供一个相对简单的选项 - 请参阅：
  https://github.com/zardus/preeny

  还可以在以下位置找到一些修改基于网络的服务的有用提示：
  https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop

- AFL 不输出人类可读的报道数据。 如果你想监控
  覆盖范围，使用 Michael Rash 的 afl-cov：https://github.com/mrash/afl-cov

- 有时，有知觉的机器会反抗它们的创造者。 如果这
  发生在你身上的情况，请查阅http://lcamtuf.coredump.cx/prep/。

除此之外，请参阅安装以获取特定于平台的提示。
