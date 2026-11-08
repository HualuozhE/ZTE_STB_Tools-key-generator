# ZTE_STB_Tools 一键算号机 (One-Click Key Generator)

[中文](#中文说明) | [English](#english)

---

<a id="中文说明"></a>
## 中文说明

### 项目简介

本软件是中兴机顶盒调试工具 **ZTE STB Tools** 系列的配套**一键算号机**（注册码生成器）。ZTE STB Tools 首次运行需要输入注册码解锁功能，手动算号需要借助在线 3DES 工具进行多轮解密、加密、拼装，流程繁琐且容易出错。本软件将该过程完全自动化：粘贴机器特征码，点击"一键算号"，1 秒内同时生成两组注册码，注册码自动置入剪贴板，粘贴回工具即完成激活。全程本机离线运行。

### 功能特性

- **一键算号**：粘贴机器特征码（`sq` 开头的整串），点击按钮即可出码
- **双版本同时生成**：
  - 注册码（2.1.1 / 8.1.1 通用）——自动置入剪贴板
  - 注册码（通杀 2.0.0、1.1.0 等其他版本）——点击【复制】按钮复制
- **红字流水线日志**：显示解析、解密、生成、复制的完整过程
- **完全静态编译**：单个 exe 文件（约 2.5 MB），不依赖任何运行库，Windows 10/11 x64 直接运行
- **内置自检**：命令行加 `--selftest` 参数可用验收样例自校验（输出 PASS/FAIL 与退出码）

### 支持版本

| 注册码类型 | 适用工具版本 |
|---|---|
| 2.1.1 / 8.1.1 通用版 | ZTE_STB_Tools_V2.1.1_T02、V8.1.1_C02 |
| 通杀版（2.0.0、1.1.0 等） | V1.1.0_T07、V2.0.0_T02、V2.0.0_T04、中兴 stb7.5.8 等 |

### 相关工具下载（网盘）

ZTE STB Tools 全版本安装包以及配套工具都在同一个网盘分享中：

- **下载链接**：<https://wwbug.lanzoum.com/b01n4lriub>
- **提取密码**：`btxw`

网盘内容清单：

| 文件 | 说明 |
|---|---|
| ZTE_STB_Tools_V1.1.0_T07 | 老版本调试工具 |
| ZTE_STB_Tools_V2.0.0_T02 | 调试工具 |
| ZTE_STB_Tools_V2.0.0_T04 | 调试工具 |
| ZTE_STB_Tools_V2.1.1_T02 | 调试工具（注册码用"2.1.1/8.1.1 通用版"） |
| ZTE_STB_Tools_V8.1.1_C02 | 调试工具（注册码用"2.1.1/8.1.1 通用版"） |
| 中兴 stb7.5.8 | 调试工具 |
| 开心电视助手 9.0 | 激活后用于向盒子安装/管理 app |

推荐搭配：先用本工具算号激活 ZTE STB Tools → 打开机顶盒 ADB 权限 → 用开心电视助手 9.0 安装当贝桌面、投屏软件等应用。

### 使用方法

1. 运行 ZTE STB Tools，获取机器特征码（`sq` 开头的整串）
2. 粘贴到本软件"机器特征码"输入框
3. 点击【一键算号】
4. 从对应版本框复制注册码（2.1.1/8.1.1 版已自动在剪贴板），粘贴回工具完成激活

### 算号原理（概述）

- 机器特征码去除 `sq` 前缀后为 HEX 字节流：头部 + 16 字节 3DES 密钥 + 0x78 字节密文
- 密钥按"16 字节 + 8 字节 0x00"扩充至 24 字节，3DES/ECB/PKCS7 解密得到版本串、硬件特征码（16 字节）与注册表特征码（12 字节）
- 按模板拼装注册码明文（特征码 + 版本字节 + 有效期 + 二次密钥密文 + 结尾 5 字节），用注册码密钥（8 字节前缀 + 注册表特征码后 8 字节）做 3DES 加密，最终组装为 `长度 + 0001 + 密钥前 8 字节 + 填充 8 字节 + 密文` 的 HEX 字符串
- 密码学实现基于 Windows CNG（`bcrypt.dll`），密文与参考样例逐字节一致

### 激活后的典型用途

打开中兴机顶盒（如常见的 **ZTE B860AV2.1-A** 等型号）的 **ADB/SSH 调试权限**，从而向盒子安装当贝桌面、投屏软件及其他实用 TV 应用；配合"开心电视助手"等工具可完成 TV 应用的安装与管理，解除运营商对应用安装的限制。

### 编译方法

- Visual Studio 2026（v145 工具集）+ Windows 10/11 SDK，MFC 静态库
- 直接用 MSBuild 编译 `ZTE_STB_Tools+key-generator.vcxproj`（Release | x64），或运行 `build_release.bat`
- 产物：`bin\x64\Release\ZTE_STB_Tools+一键算号机.exe`

### 目录结构

```
├── app.cpp                        # MFC 界面与程序入口
├── app.rc / resource.h            # 资源文件（对话框模板）
├── KeyGen.h / KeyGen.cpp          # 算号核心算法（BCrypt 3DES）
├── verify/                        # 算法验证测试（含验收样例）
├── 算号原理方法.txt                # 算号原理参考资料
├── 正确示例+...txt                 # 验收用例：机器码与正确注册码
├── ZTE_STB_Tools+一键算号机.exe    # 成品程序（Release x64 静态编译）
└── build_release.bat              # 一键编译脚本
```

### 免责声明

本项目仅用于对自有设备进行调试与个性化改造的技术学习与研究，请遵守当地法律法规，勿用于任何商业或非法用途。使用本软件产生的一切后果由使用者自行承担。

---

<a id="english"></a>
## English

### Introduction

This program is a **one-click key generator** for the ZTE STB Tools series — debug/activation tools for ZTE operator set-top boxes. ZTE STB Tools requires a registration code on first launch; manual key derivation involves multiple rounds of 3DES decryption/encryption with online tools, which is tedious and error-prone. This tool fully automates the process: paste the machine code, click one button, and get two registration codes at once, with the primary one automatically placed on the clipboard. Everything runs offline.

### Features

- **One-click generation**: paste the machine code (the whole string starting with `sq`), click the button
- **Two code variants at once**:
  - Registration code for 2.1.1 / 8.1.1 (universal) — auto-copied to clipboard
  - Registration code that also covers 2.0.0, 1.1.0 and other versions — via the "Copy" button
- **Red pipeline log**: shows the full parse/decrypt/generate/copy process
- **Fully static build**: a single exe (~2.5 MB), no runtime dependencies, runs on Windows 10/11 x64 out of the box
- **Built-in self-test**: launch with `--selftest` to verify the algorithm against the acceptance vector (writes PASS/FAIL, exit code 0/1)

### Supported versions

| Code type | Tool versions |
|---|---|
| 2.1.1 / 8.1.1 universal | ZTE_STB_Tools_V2.1.1_T02, V8.1.1_C02 |
| All-versions variant | V1.1.0_T07, V2.0.0_T02, V2.0.0_T04, ZTE stb7.5.8, etc. |

### Related downloads (cloud drive)

All ZTE STB Tools installers and companion tools are shared in one cloud-drive folder:

- **Link**: <https://wwbug.lanzoum.com/b01n4lriub>
- **Access code**: `btxw`

Contents:

| File | Notes |
|---|---|
| ZTE_STB_Tools_V1.1.0_T07 | Older debug tool |
| ZTE_STB_Tools_V2.0.0_T02 | Debug tool |
| ZTE_STB_Tools_V2.0.0_T04 | Debug tool |
| ZTE_STB_Tools_V2.1.1_T02 | Debug tool (use the 2.1.1/8.1.1 universal code) |
| ZTE_STB_Tools_V8.1.1_C02 | Debug tool (use the 2.1.1/8.1.1 universal code) |
| ZTE stb7.5.8 | Debug tool |
| Kaixin TV Assistant 9.0 | For installing/managing TV apps after activation |

Recommended workflow: activate ZTE STB Tools with this generator → enable ADB on the box → use Kaixin TV Assistant 9.0 to install Dangbei launcher, screen-mirroring apps, etc.

### Usage

1. Run ZTE STB Tools to obtain the machine code (the whole string starting with `sq`)
2. Paste it into the "机器特征码" (machine code) input box
3. Click "一键算号" (one-click generate)
4. Copy the code for your tool version (the 2.1.1/8.1.1 one is already on the clipboard) and paste it back into the tool

### Algorithm overview

- After stripping the `sq` prefix, the machine code is a HEX byte stream: header + 16-byte 3DES key + 0x78-byte ciphertext
- The key is expanded to 24 bytes by appending 8 zero bytes; 3DES/ECB/PKCS7 decryption yields the version string, the 16-byte hardware feature code and the 12-byte registry feature code
- The registration-code plaintext is assembled from a template (feature codes + version byte + validity dates + secondary-key ciphertext + 5-byte tail), encrypted with the registration key (8-byte prefix + last 8 bytes of the registry feature code) using 3DES, and assembled into a HEX string: `length + 0001 + key[0..7] + filler[8] + ciphertext`
- Crypto is implemented with Windows CNG (`bcrypt.dll`); output is byte-identical to the reference vector

### Typical use after activation

Enable **ADB/SSH debug access** on ZTE set-top boxes (e.g. the common **ZTE B860AV2.1-A**), then install a third-party launcher (Dangbei), screen-mirroring apps and other useful TV apps, removing the operator's restrictions on app installation.

### Building

- Visual Studio 2026 (v145 toolset) + Windows 10/11 SDK, static MFC
- Build `ZTE_STB_Tools+key-generator.vcxproj` (Release | x64) with MSBuild, or run `build_release.bat`
- Output: `bin\x64\Release\ZTE_STB_Tools+一键算号机.exe`

### Disclaimer

This project is intended for technical learning and research on devices you own. Comply with local laws and regulations; do not use it for commercial or illegal purposes. Use at your own risk.
