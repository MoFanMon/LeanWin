# 更新记录

## 2026-10-25

### 内存、资源、进程和线程

- 接口入口由 20 个扩展到 65 个：支持虚拟内存、进程/私有堆、固定 LocalAlloc，以及 PE 资源查询与数据访问。
- 增加最多 16 个客体线程的轮转调度、挂起/恢复、真实退出状态、事件、等待与临界区；静态 TLS 支持线程通知，动态 TLS 支持 64 个槽。
- `CreateProcessW` 在独立的 LeanWin 实例中执行客体盘内 PE，传递命令行和模块路径，并通过独立通道保留完整 32 位退出码；不通过 shell 启动。
- 增加进程环境和高分辨率时钟接口，以及原始 EXE 的只读客体映射；为进程、线程、内存、资源和路径设置边界检查。
- 补充实际启动路径遇到的字节读写、SETcc、标志保存恢复、CPUID、整数乘法/移位、MOVS/STOS；CPUID 不声明尚未实现的浮点和 SIMD 功能。
- 增加 `--defer-imports` 诊断模式：缺失入口在被调用时失败；运行报告保留失败前的真实指令与接口计数。
- 普通版与 ASan/UBSan 版各通过 87 项测试；增加 120 个资源目录变异执行输入。原生 Windows 对照覆盖扩展为 26 项。
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
