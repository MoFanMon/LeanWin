# 更新记录

## 2026-10-30

### 窗口类基础与安装器字符串路径

- 新增 InitCommonControls / Ex 和窗口类注册、查询、注销共 7 个接口，入口总数为 89；COMCTL32 的模块和导出解析独立于 KERNEL32 / USER32。
- 窗口类按进程保存，支持 32 / 64 位结构、名称副本、ASCII 大小写查询、atom、重复和错误输入处理；字符串只读区按需分配。这里只登记元数据，尚无控件实例、窗口或消息分发。
- 补充字节立即数赋值（含高字节和 REX 选择）、REP RET、SCAS / REPE / REPNE、NOT；扫描检查完整操作数和全局指令预算。
- 普通版与 ASan/UBSan 版各 137 项测试；新增 120 个变异窗口类结构输入，合计 600 个变异输入。Windows 原生对照扩展为 68 项；macOS、Linux、Windows 三平台 CI 全部通过，准确测试提交与结果见 reports/ci.json。
- DeepSeekQQ 诊断模式越过 InitCommonControls，执行到 12,711 条指令、32 次接口调用，当前停在 LOCK INC（0x407fc2）；尚未出现安装界面或完成安装。

## 2026-10-29

### x87 控制状态与环境

- 实现初始化、控制字加载/保存、状态字读取、异常标记清除与等待，以及 14 / 28 字节环境保存/恢复。
- x87 状态按客体线程独立维护；验证保存环境后的异常屏蔽、待处理异常检查和完整内存范围保护。数值栈与浮点算术仍未实现。
- 普通版与 ASan/UBSan 版各运行 124 项测试；加入 120 个变异 x87 环境输入，总计 480 个变异输入。Windows 原生对照扩展为 52 项。
- macOS / Linux 的完整 CI 与真实 Windows 的 52 项对照全部通过，准确提交与结果见 `reports/ci.json`。
- DeepSeekQQ 诊断模式越过 x87 初始化，执行到 12,100 条指令、28 次接口调用，当前缺少 InitCommonControls；尚未出现安装界面或完成安装。

### 区域设置与客体系统信息

- 新增 13 个入口，总数为 82：线程区域设置、默认 LCID/语言/UI 语言、区域数据查询、序数比较、ASCII 大小写映射和 GetSystemInfo。
- 支持 en-US、zh-CN、invariant 的固定配置；线程设置独立并同步到 TEB，新线程使用用户默认区域。
- 区域查询支持字符串/数值布局、长度查询和缓冲区错误；序数比较支持 UTF-16 与嵌入零字符。明确拒绝未实现的语言学排序、Unicode 大小写、其他 LCID 或映射标志。
- 117 项普通版与 ASan/UBSan 测试通过，Windows 原生对照扩展为 44 项。
- macOS / Linux 的完整 CI 及 Windows 的 44 项原生对照全部通过，准确提交与任务见 `reports/ci.json`。
- DeepSeekQQ 诊断模式推进到 11,949 条指令、19 次接口调用；当前停在 x87 FNINIT，尚未出现安装界面或完成安装。静态缺失导入降为 78 项。

### SIMD 与版本接口

- 实现安装器使用的 MOVD/MOVQ、MOVUPS、MOVAPS、PSHUFD，保留完整 XMM 数据和线程隔离；检查完整内存范围、页保护和对齐，未宣称完整 SSE2 支持。
- 增加 VerSetConditionMask、VerifyVersionInfoW、GetVersion、GetVersionExW，接口入口共 69 个；明确固定客体版本配置与比较限制，并处理 x86 的 64 位参数和返回值。
- 补充实际启动路径需要的 ADC、SBB、无符号 DIV，以及除零/商溢出诊断。
- 普通版和 ASan/UBSan 版各通过 104 项测试；保留 360 个 PE/TLS/资源变异输入。Windows 对照用例扩展为 34 项。
- macOS、Linux 的完整 CI 和真实 Windows 的 34 项原生对照全部通过；修正了原生返回的条件掩码最高位标记，并明确极端版本输入的支持范围。准确测试提交与报告见 `reports/ci.json`。
- 重新测试 DeepSeekQQ：诊断模式从 619 条推进到 11,878 条指令、9 次接口调用，当前缺少 SetThreadLocale；尚未出现安装界面或完成安装。静态缺失导入由 92 项降至 88 项。

## 2026-10-25

### 内存、资源、进程和线程

- 接口入口由 20 个扩展到 65 个：支持虚拟内存、进程/私有堆、固定 LocalAlloc，以及 PE 资源查询与数据访问。
- 增加最多 16 个客体线程的轮转调度、挂起/恢复、真实退出状态、事件、等待与临界区；静态 TLS 支持线程通知，动态 TLS 支持 64 个槽。
- `CreateProcessW` 在独立的 LeanWin 实例中执行客体盘内 PE，传递命令行和模块路径，并通过独立通道保留完整 32 位退出码；不通过 shell 启动。
- 增加进程环境和高分辨率时钟接口，以及原始 EXE 的只读客体映射；为进程、线程、内存、资源和路径设置边界检查。
- 补充实际启动路径遇到的字节读写、SETcc、标志保存恢复、CPUID、整数乘法/移位、MOVS/STOS；CPUID 不声明尚未实现的浮点和 SIMD 功能。
- 增加 `--defer-imports` 诊断模式：缺失入口在被调用时失败；运行报告保留失败前的真实指令与接口计数。
- 普通版与 ASan/UBSan 版各通过 87 项测试；增加 120 个资源目录变异执行输入。原生 Windows 对照覆盖扩展为 26 项。
- 修正 glibc 的 XSI 声明配置和 Win32 资源名称大写查询规则后，macOS、Linux 的完整检查与 Windows 的 26 项原生执行全部通过；准确提交见 `reports/ci.json`。
- DeepSeekQQ 仍不能完成安装：诊断模式执行到 619 条指令、3 次接口调用后，遇到 SSE2 MOVD；153 项静态导入中仍缺少 92 项入口名称。详见 `reports/deepseekqq.json`。

### 字符编码与导入诊断

- 增加 `GetACP`、`GetCPInfo`、`GetCPInfoExW`、`MultiByteToWideChar`、`WideCharToMultiByte` 的 UTF-8 配置实现。
- 字符转换支持 UTF-16 代理对、长度查询、严格/替换模式、参数与缓冲区检查；其他码页暂不支持。
- 新增完整静态导入诊断工具和 13 项回归测试，测试总数为 48。
- Windows 原生对照示例扩展为 8 项；当前 DeepSeekQQ 的下一处错误是 `GetExitCodeProcess`，仍有 135 项静态导入未实现。

### TLS 与测试基础设施

- 支持单个 EXE 主线程的静态 TLS：复制模板、零填充、写入模块索引，提供最小 FS/GS 槽表访问。
- 按顺序调用 `DLL_PROCESS_ATTACH` 回调，处理 x86 stdcall / Windows x64 参数和栈空间。
- 为 TLS 地址、数据大小、区段和回调数量增加边界检查；回调与入口共用指令预算。
- 新增 9 项 TLS 测试；全部 35 项测试同时运行普通版与 ASan/UBSan 版。
- 增加 120 个变异 TLS 执行输入；检测脚本检查独立日志，避免错误被负面测试捕获后漏报。
- 增加同一组 6 个 PE 示例在 LeanWin 和 Windows 上的对照执行脚本，以及 GitHub Actions 配置。
- macOS / Linux 检测与 Windows 原生示例交叉验证均通过，原始 CI 任务与结果见 `reports/ci.json`。
- 重新测试 DeepSeekQQ：当前停在 `kernel32.dll!GetACP` 的导入绑定，尚不能启动安装器。

限制：TLS 支持仍不包含多线程、任意 DLL、动态 TLS API、重定位或退出回调。界面显示尚未验证。
