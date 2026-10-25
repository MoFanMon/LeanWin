# LeanWin 0.1

从零实现的 Windows 接口兼容层实验，首个目标平台为 Apple Silicon macOS。
MIT 许可。执行核心使用 C11，窗口后端使用 Objective-C/AppKit，编译工具为系统 Clang 和 Make。

当前原型已经执行专门构建的 32 位、64 位 Windows PE 示例，完成控制台输出和文件读写。
项目包含独立实现的 PE 解析与加载、x86 指令解释器、Windows 调用约定和 15 个接口入口。
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
示例是手工构建的真实 PE/机器码文件，Windows 本机上的执行结果尚未交叉验证。

`--root` 指定当前实现所映射的 Windows C: 盘根目录。目录的上一级必须存在。
不提供 `--root` 时使用当前目录下的 `leanwin-drive`。
`--max-steps` 限制解释器执行的指令数量，默认 1,000,000。
`--report FILE` 记录真实指令计数、接口调用数、执行耗时和进程峰值常驻内存。
完整 Windows 退出码写入报告；终端退出码为该值的低 8 位。兼容层错误返回 65，并在标准错误输出具体原因。

## 当前范围

| 已实现部分 | 当前限制 |
|---|---|
| PE32 / PE32+ 头、区段、普通与延迟导入分析 | 执行阶段在首选映像基址加载；无完整 Windows 加载器环境 |
| x86、x86-64 整数指令解释执行 | 小范围指令集；无 SSE、AVX、x87、JIT 或异常展开 |
| x86 stdcall、Windows x64 寄存器和栈参数 | 单线程；无完整 PEB、TEB、TLS 或 SEH |
| 控制台和同步文件接口 | 无重叠 I/O、命名管道或设备接口；只支持指定参数子集 |
| 模块句柄和动态查找已实现接口 | 不加载任意 DLL；不支持按序号解析接口 |
| `MessageBoxW` 到按需加载的 AppKit 模块 | 仅计划支持 `MB_OK`、空父窗口；实际显示尚未验证 |

执行用客体映像限制为 64 MiB，栈为 1 MiB，最多 64 个已打开文件。
文件路径拒绝 `..` 和目录符号链接；零共享模式的冲突检测仅覆盖同一个客体实例。
客体地址由解释器检查，但这个研究原型没有经过安全审计，不构成完整安全沙箱。

### 接口入口

`KERNEL32.dll` / `KERNELBASE.dll`：

`ExitProcess`, `GetStdHandle`, `WriteFile`, `ReadFile`, `CreateFileW`, `CloseHandle`,
`GetLastError`, `SetLastError`, `GetTickCount64`, `GetCurrentProcessId`, `GetFileSizeEx`,
`GetModuleHandleW`, `LoadLibraryW`, `GetProcAddress`。

`USER32.dll`：`MessageBoxW`。

其中 `GetStdHandle` 仅提供标准输出、标准错误；`CloseHandle` 目前仅关闭普通文件句柄。
`CreateFileW` 仅支持普通文件、读/写通用访问、零共享、空安全属性/模板和普通文件属性。
未实现的导入、指令和受限参数均应按当前实现返回明确错误，不伪造完整兼容性。

## 精简与效率

当前采取的精简方式是：小型原生执行核心、只映射客体映像和固定栈、窗口模块按需加载、
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

2026-10-24，在 Apple Silicon macOS 上：26 项测试通过，120 个固定种子的变异 PE 输入及
4 个实际执行示例通过 AddressSanitizer / UndefinedBehaviorSanitizer 检查。
可用 `python3 tools/sanitize.py` 重新构建并运行这些检查；结果写入
[reports/validation.json](reports/validation.json)。

当前核心可执行文件 53,032 字节；可选窗口模块 51,184 字节。
控制台小示例在 20 次新进程测量中的启动加执行中位数约 2.8–2.9 ms，进程峰值常驻内存中位数约 1.28 MiB。
这些数字仅对应仓库内的微型示例和本机环境，不能外推到一般 Windows 应用。
DeepSeekQQ 安装器分析到 153 个静态导入项，其中 140 项入口名称尚未实现；执行首先被 TLS 加载环境限制阻断。
静态导入项数量不等于完整依赖数量，也不是兼容性百分比。

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

1. 增加编译器生成的 Win32 测试程序，并在真实 Windows 上交叉验证示例与接口语义。
2. 补全基础加载环境：PEB/TEB、TLS、重定位、异常、堆与线程同步；避免依赖“总能加载在首选基址”的假设。
3. 扩充整数和 SIMD 指令覆盖；用基本块缓存/JIT 逐步替代解释器热点，验证收益后再优化。
4. 实现真实窗口、消息循环和 GDI，再扩展通用控件、注册表、COM 与进程间协作。
5. 以 DeepSeekQQ / Inno Setup 的导入清单建立回归目标。运行安装器之后，还需要兼容应用本体、QQ 和 NapCat 的完整依赖链。

## 技术参考

当前代码为独立实现，没有复制 Wine / CrossOver 的代码或打包它们的二进制文件。
参考资料用于理解层次与公开接口：

- [Microsoft PE/COFF 格式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows x64 调用约定](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Wine 的加载器与接口实现概述](https://github.com/wine-mirror/wine/blob/master/README.md)
- [CodeWeavers 开源组件说明](https://www.codeweavers.com/crossover/source)

未来如果引入上游代码，应分别保留、遵循相应许可证；当前 MIT 许可仅覆盖本项目原创代码。
