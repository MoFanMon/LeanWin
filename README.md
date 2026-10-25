# LeanWin 0.1

从零实现的 Windows 接口兼容层实验，首个目标平台为 Apple Silicon macOS。
MIT 许可。执行核心使用 C11，窗口后端使用 Objective-C/AppKit，编译工具为系统 Clang 和 Make。

当前原型已经执行专门构建的 32 位、64 位 Windows PE 示例，完成控制台输出和文件读写。
项目包含独立实现的 PE 解析与加载、x86 指令解释器、Windows 调用约定和 65 个接口入口。
Wine、CrossOver、Rosetta、Windows 虚拟机均不属于当前执行链。

**这是很小的接口子集验证版。当前不能运行 DeepSeekQQ 安装器，也不能运行一般的 Python、Qt、Electron、.NET 桌面软件。**
接口名称已实现，不代表对应 Windows 函数的全部参数组合和语义已经实现。
窗口后端已通过编译；本机自动窗口验证被 LaunchServices 的 `-10827` 启动错误阻断，尚未完成可见窗口和按钮返回值验证。

## 编译与运行

需要 macOS 命令行开发工具；Python 3 仅用于生成示例和运行测试，执行核心不需要 Python。

```sh
make
make test
python3 examples/build.py

./build/leanwin inspect examples/bin/hello64.exe
./build/leanwin capabilities
./build/leanwin run examples/bin/hello64.exe --root ./leanwin-drive
```

控制台示例输出 `Hello from a Windows EXE on macOS!`，然后通过 Windows `ExitProcess(37)` 退出。
所以该示例在终端返回 **37**，这是示例约定的退出码。

```sh
./build/leanwin run examples/bin/files32.exe --root ./leanwin-drive
./build/leanwin run examples/bin/files64.exe --root ./leanwin-drive
./build/leanwin run examples/bin/dialog64.exe --root ./leanwin-drive
```

文件示例通过 Windows 接口创建 `example.txt`、写入、关闭、重新打开并读取，再输出读到的内容。
窗口示例调用 `MessageBoxW`；仅在有正常桌面会话的 macOS 上尝试，窗口验证状态见上文。
示例是手工构建的真实 PE/机器码文件。新增内存、资源、线程和进程示例也纳入 Windows CI 原生对照；
窗口示例尚未完成 Windows / macOS 的可见界面验证。

`--root` 指定当前实现所映射的 Windows C: 盘根目录。目录的上一级必须存在。
不提供 `--root` 时使用当前目录下的 `leanwin-drive`。
`--max-steps` 限制解释器执行的指令数量，默认 1,000,000。
`--report FILE` 记录真实指令计数、接口调用数、执行耗时和进程峰值常驻内存。
完整 Windows 退出码写入报告；终端退出码为该值的低 8 位。兼容层错误返回 65，并在标准错误输出具体原因。
报告包含 `status` / `error`，运行失败时也保留已执行的指令数。
默认在导入绑定时拒绝缺失接口；`--defer-imports` 用于诊断实际执行路径：未知导入被调用时立即报错，
包含 DLL、函数名和调用位置，不返回伪造的成功结果。

## 当前范围

| 已实现部分 | 当前限制 |
|---|---|
| PE32 / PE32+ 头、区段、普通与延迟导入分析 | 执行阶段在首选映像基址加载；无完整 Windows 加载器环境 |
| x86、x86-64 整数指令解释执行 | 小范围指令集；无 SSE、AVX、x87、JIT 或异常展开 |
| x86 stdcall、Windows x64 寄存器和栈参数 | 无完整 PEB、TEB 或 SEH |
| 静态与动态 TLS、模板复制、启动与线程通知 | 单个 EXE 的静态槽；无 DLL TLS、重定位或进程退出通知 |
| VirtualAlloc / Free / Protect / Query、进程堆与私有堆 | 受限页保护与分配标志；无映射文件、堆重分配或大页 |
| PE 资源类型、名称、语言选择和实际数据访问 | 仅当前映像；ASCII 名称转大写，其他 Unicode 字符精确匹配；无 MUI |
| 客体线程、挂起/恢复、等待、事件与临界区 | 解释器轮转调度，不并行执行；无线程优先级和命名事件 |
| PE 子进程、命令行、模块路径、退出状态 | 子进程通过另一个 LeanWin 实例运行；启动参数受限 |
| 控制台和同步文件接口 | 无重叠 I/O、命名管道或设备接口；只支持指定参数子集 |
| 模块句柄和动态查找已实现接口 | 不加载任意 DLL；不支持按序号解析接口 |
| `MessageBoxW` 到按需加载的 AppKit 模块 | 仅计划支持 `MB_OK`、空父窗口；实际显示尚未验证 |

执行用客体映像限制为 64 MiB；每个客体进程累计最多创建 16 个线程（含主线程），每个栈为 1 MiB。
每个线程分配 8 KiB 的最小线程记录和槽表，以及最多 1 MiB 的静态 TLS 数据。
动态私有内存合计最多 64 MiB，进程堆以外最多 15 个私有堆；最多 64 个文件、64 个事件、64 个临界区。
客体内存的保留、提交、撤销提交、读写和执行保护由解释器检查；当前映像初始仍按 RWX 映射。
TLS 回调最多 64 个，按目录顺序在 EXE 入口之前以 `DLL_PROCESS_ATTACH` 调用；回调与入口共用指令预算。
新线程分别复制 TLS 模板，以 `DLL_THREAD_ATTACH` / `DLL_THREAD_DETACH` 通知；动态 TLS 有 64 个独立槽。
线程每 256 个执行步骤轮换，也可主动让出执行。全部线程共享指令预算；无可运行线程且没有外部等待来源时明确报告死锁。
支持 x86 `FS` / x64 `GS` 对 TLS 槽表的访问；这只是 TEB 的极小子集，不是完整 Windows 线程环境。
TLS 模板、索引地址和回调表必须在客体映像内，回调目标必须属于可执行区段。
当前仍按首选基址加载，没有补齐 TLS 地址重定位或 `DLL_PROCESS_DETACH`。
文件路径拒绝 `..` 和目录符号链接；零共享模式的冲突检测仅覆盖同一个客体实例。
当前 EXE 以只读方式映射到 `C:\\文件名.exe`，允许安装器读取自身，无需先复制到客体盘。
子进程只能启动客体盘内的普通 PE 文件，校验后通过已打开的文件描述符交给子解释器，拒绝路径穿越与符号链接。
每个进程累计最多启动 8 个子进程，最多两代；继承客体盘与指令预算。已启动的子进程不因关闭句柄而终止。
主线程句柄当前观察子进程整体生命周期，尚不能单独控制子进程主线程。每个进程的指令预算独立计算。
`CreateProcessW` 暂支持空安全属性、禁止继承句柄、默认环境与当前目录、标志 0 / `CREATE_NO_WINDOW`，
不搜索 PATH、不调用 shell。客体运行错误使子解释器以 65 结束；正常退出通过独立通道保留完整 32 位退出码。
客体地址由解释器检查，但这个研究原型没有经过安全审计，不构成完整安全沙箱。

### 接口入口

`KERNEL32.dll` / `KERNELBASE.dll`：

`ExitProcess`, `GetStdHandle`, `WriteFile`, `ReadFile`, `CreateFileW`, `CloseHandle`,
`GetLastError`, `SetLastError`, `GetTickCount64`, `GetCurrentProcessId`, `GetFileSizeEx`,
`GetModuleHandleW`, `LoadLibraryW`, `GetProcAddress`。

字符编码接口：`GetACP`, `GetCPInfo`, `GetCPInfoExW`, `MultiByteToWideChar`, `WideCharToMultiByte`。

内存接口：`GetProcessHeap`, `HeapCreate`, `HeapDestroy`, `HeapAlloc`, `HeapFree`, `LocalAlloc`, `LocalFree`,
`VirtualAlloc`, `VirtualFree`, `VirtualProtect`, `VirtualQuery`, `VirtualQueryEx`（仅当前进程）。

资源接口：`FindResourceW`, `SizeofResource`, `LoadResource`, `LockResource`。

进程与环境接口：`GetCurrentProcess`, `GetExitCodeProcess`, `CreateProcessW`, `GetCommandLineW`,
`GetModuleFileNameW`, `GetStartupInfoW`, `QueryPerformanceFrequency`, `QueryPerformanceCounter`。

线程与同步接口：`GetCurrentThread`, `GetCurrentThreadId`, `CreateThread`, `ExitThread`, `GetExitCodeThread`,
`ResumeThread`, `SuspendThread`, `WaitForSingleObject`, `CreateEventW`, `SetEvent`, `ResetEvent`, `Sleep`,
`SwitchToThread`, `TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`, `InitializeCriticalSection`,
`EnterCriticalSection`, `LeaveCriticalSection`, `DeleteCriticalSection`。

`USER32.dll`：`MessageBoxW`。

其中 `GetStdHandle` 仅提供标准输出、标准错误；`CloseHandle` 关闭普通文件、事件、线程和子进程句柄。
`CreateFileW` 仅支持普通文件、读/写通用访问、零共享、空安全属性/模板和普通文件属性。
读取自身 EXE 还支持 `FILE_SHARE_READ`。`LocalAlloc` 仅支持固定块及零初始化。
未实现的导入、指令和受限参数均应按当前实现返回明确错误，不伪造完整兼容性。

### 字符编码配置

当前客体采用固定的 UTF-8 ANSI 配置，`GetACP()` 返回 65001；它不是 macOS 的系统码页查询。
`CP_ACP`（0）和 `CP_UTF8`（65001）使用相同的 UTF-8 / UTF-16LE 转换，支持长度查询、
显式长度、`-1` 结尾零字符、代理对、非法序列替换或严格报错，以及输出缓冲区不足的错误。
`MultiByteToWideChar` 支持标志 0 / `MB_ERR_INVALID_CHARS`，`WideCharToMultiByte` 支持
0 / `WC_ERR_INVALID_CHARS`；UTF-8 不接受默认字符参数。单次输入或输出缓冲区限制为 16 MiB。
GBK/936、1252 等其他码页与额外标志暂不支持，返回明确错误。完整 NLS、区域设置及旧码页兼容仍需后续实现。

可一次列出全部缺失导入，而不是逐个遇到第一个错误：

```sh
python3 tools/compatibility.py /path/to/program.exe --output import-report.json
```

存在缺失导入时返回 1，没有缺失时返回 0。该命令不执行 EXE，也不把入口名称齐全视为程序兼容。

## 精简与效率

当前采取的精简方式是：小型原生执行核心、客体内存按需分配、窗口模块按需加载、
无常驻管理进程、无默认大型运行库、分析导入时不创建临时文件。

这只能支持“原型依赖少、体积小”的结论。解释执行不具备成熟 JIT/原生执行的指令性能，
因此目前没有证据说明本项目在真实软件上比 Wine 或 CrossOver 更快。
用下面的命令生成本机实际测量结果；结果包含启动与示例执行，文件缓存为温缓存，没有竞品基线。

```sh
python3 tools/benchmark.py reports/benchmark.json
```

原始测量数据见 [reports/benchmark.json](reports/benchmark.json)。
DeepSeekQQ 的实际导入分析与阻断原因见 [reports/deepseekqq.json](reports/deepseekqq.json)。

## 本机验证记录

2026-10-25，在 Apple Silicon macOS 上：87 项测试在普通版和 AddressSanitizer /
UndefinedBehaviorSanitizer 版中分别通过；额外检查 120 个固定种子的变异 PE 分析输入、
120 个变异 TLS 执行输入、120 个变异资源目录执行输入，以及 4 个实际执行示例。
可用 `python3 tools/sanitize.py` 重新构建并运行这些检查；结果写入
[reports/validation.json](reports/validation.json)。

当前核心可执行文件约 103 KiB；可选窗口模块约 50 KiB，精确字节数见测量报告。
控制台小示例的新进程启动与执行测量见报告中的各架构中位数；不以单次数字代替真实软件性能。
这些数字仅对应仓库内的微型示例和本机环境，不能外推到一般 Windows 应用。
DeepSeekQQ 安装器分析到 153 个静态导入项，其中 92 项入口名称尚未实现；严格模式首先停在
`kernel32.dll!GetFullPathNameW`。诊断模式执行了 619 条指令、3 次接口调用，停在 `0x405bf3` 的
SSE2 `MOVD XMM0, ECX`，尚未进入安装界面，也未验证安装器 TLS 生命周期完成。
完整缺失清单见 [reports/deepseekqq-imports.json](reports/deepseekqq-imports.json)。
静态导入项数量不等于完整依赖数量，也不是兼容性百分比。

同一组控制台、文件、TLS、编码、内存、资源、线程、事件、进程和环境示例可在 LeanWin 与真实 Windows 上运行并检查结果：

```sh
# macOS / Linux
python3 tools/smoke.py --runner ./build/leanwin --output reports/smoke.json

# Windows；直接调用 Windows 加载器执行生成的 EXE
python tools/smoke.py --output reports/windows-native.json
```

GitHub Actions 配置了 macOS / Linux 的完整内存检测，以及 Windows 的 26 项原生执行检查。
2026-10-25 的[首次跨系统验证](https://github.com/MoFanMon/LeanWin/actions/runs/40173962767)全部通过，
结果记录在 [reports/ci.json](reports/ci.json)。本机 `validation.json` 仅记录本机检查，Windows 结果由独立 CI 任务提供。
每次运行的真实结果与报告以仓库的 [Actions](https://github.com/MoFanMon/LeanWin/actions) 为准。

## 结构与下一步

```text
Windows EXE
    ↓
PE 解析、区段映射与导入绑定          src/pe.c
    ↓
x86 指令解释器、Windows 调用约定     src/vm.c
    ↓
Windows 接口 → POSIX 文件/进程接口
             → AppKit 窗口模块       src/gui.m（按需加载）
```

1. 增加编译器生成的 Win32 测试程序，并扩展真实 Windows 上的接口语义与界面验证。
2. 补全加载环境：PEB/TEB、进程退出通知、DLL TLS、重定位和异常；扩展现有堆与线程调度的参数语义。
3. 优先实现安装器启动所需的 SSE2 数据搬运，再扩充指令覆盖；用基本块缓存/JIT 逐步替代解释器热点，验证收益后再优化。
4. 实现真实窗口、消息循环和 GDI，再扩展通用控件、注册表、COM 与进程间协作。
5. 以 DeepSeekQQ / Inno Setup 的导入清单建立回归目标。运行安装器之后，还需要兼容应用本体、QQ 和 NapCat 的完整依赖链。

## 技术参考

当前代码为独立实现，没有复制 Wine / CrossOver 的代码或打包它们的二进制文件。
参考资料用于理解层次与公开接口：

- [Microsoft PE/COFF 格式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows x64 调用约定](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [Thread Local Storage](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-local-storage)
- [MultiByteToWideChar](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar)
- [WideCharToMultiByte](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)
- [Wine 的加载器与接口实现概述](https://github.com/wine-mirror/wine/blob/master/README.md)
- [CodeWeavers 开源组件说明](https://www.codeweavers.com/crossover/source)

未来如果引入上游代码，应分别保留、遵循相应许可证；当前 MIT 许可仅覆盖本项目原创代码。
