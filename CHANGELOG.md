# 更新记录

## 2026-10-25

- 支持单个 EXE 主线程的静态 TLS：复制模板、零填充、写入模块索引，提供最小 FS/GS 槽表访问。
- 按顺序调用 `DLL_PROCESS_ATTACH` 回调，处理 x86 stdcall / Windows x64 参数和栈空间。
- 为 TLS 地址、数据大小、区段和回调数量增加边界检查；回调与入口共用指令预算。
- 新增 9 项 TLS 测试；全部 35 项测试同时运行普通版与 ASan/UBSan 版。
- 增加 120 个变异 TLS 执行输入；检测脚本检查独立日志，避免错误被负面测试捕获后漏报。
- 增加同一组 6 个 PE 示例在 LeanWin 和 Windows 上的对照执行脚本，以及 GitHub Actions 配置。
- macOS / Linux 检测与 Windows 原生示例交叉验证均通过，原始 CI 任务与结果见 `reports/ci.json`。
- 重新测试 DeepSeekQQ：当前停在 `kernel32.dll!GetACP` 的导入绑定，尚不能启动安装器。

限制：TLS 支持仍不包含多线程、任意 DLL、动态 TLS API、重定位或退出回调。界面显示尚未验证。
