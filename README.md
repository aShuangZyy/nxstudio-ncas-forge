# NX Studio 免登录（本地 MITM 伪造 NCAS 会话）

让 **Nikon NX Studio（Windows）** 启动时不再弹"尼康工坊"登录框、直接进入主界面。
做法是**在本机跑一个只拦尼康账号域名的微型代理**，把 app 启动时那两笔账号请求的响应
换成"成功"的假响应——不修改 NX Studio 的任何文件，也不碰尼康服务器。

> 仅适用于你自己拥有许可的软件、在本机自用与研究的场景。请先读 [docs/security.md](docs/security.md)。

## 原理（30 秒版）

```
NX Studio 启动
   ├─ POST auth.accounts.cld.nikon.com/.../token     （换服务令牌）
   └─ POST faapi.www.accounts.cld.nikon.com/nxs/refresh_token  （用刷新令牌换会话）
        │
        └─ 本机代理把这两笔答案改成 {"response_code":"0000", "access_token":..., "refresh_token":...}
              ↓
        app 认为会话成立 → 直接 Build 主窗口（登录框不再出现）
```

拦截只针对 `*.cld.nikon.com`；其它域名走**盲隧道**（只转发、不解密），浏览器照常上网。
技术细节与"为什么这样可以"见 [docs/how-it-works.md](docs/how-it-works.md)。

## 环境要求

| 项 | 要求 |
|---|---|
| 系统 | Windows 10 / 11 |
| 软件 | Nikon NX Studio（开发时验证版本 **1.10.1.3003**） |
| Python | 3.8+（`cryptography` 包，`setup.ps1` 会自动装） |
| 权限 | **不需要管理员**（证书装在"当前用户"根存储） |

## 快速开始

```powershell
git clone <this repo> nxstudio-ncas-forge
cd nxstudio-ncas-forge

# 一条命令搞定：首次会自动生成证书/信任/rules.json 并先自检，然后启动 NX Studio
# （NX Studio 退出后自动还原代理、停掉本地代理进程）
powershell -NoProfile -ExecutionPolicy Bypass -File start-nxstudio.ps1

# 可选：在桌面放一个双击即用的图标（图标调用的就是上面这条）
powershell -NoProfile -ExecutionPolicy Bypass -File make-shortcut.ps1
```

分步执行（调试时用）：

```powershell
powershell ... -File setup.ps1                                  # 只做一次性准备
powershell ... -File check.ps1                                  # 只自检（-Quick 跳过真代理往返）
powershell ... -File start-nxstudio.ps1 -NoSetup -SkipCheck     # 不做前置检查，直接启动
```

指定安装路径 / 换端口：

```powershell
.\start-nxstudio.ps1 -App "D:\Nikon\NXStudio\NXStudio.exe" -Port 8899
```

## 卸载 / 回滚

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1
```

会停掉代理进程、关掉系统代理、从"当前用户根存储"移除 `NX-Forge-CA`，并删除 `certs/ rules.json logs/`。
只想临时还原网络：`restore-proxy.ps1`。

## 目录结构

```
setup.ps1              一次性准备（证书 / 信任 / rules.json）
check.ps1              自检 + 端到端功能测试
start-nxstudio.ps1     启动 NX Studio（自动设代理、退出后还原）
restore-proxy.ps1      紧急还原：关代理 + 停 MITM
uninstall.ps1          完全卸载
make-shortcut.ps1      生成桌面图标
lib/common.ps1         共用函数
scripts/mitm.py        本地代理：规则命中→伪造；未命中→盲隧道；明文 HTTP→透明直通
scripts/mkcerts.py     生成本机 CA + 叶证书（私钥只在本机，永不提交）
scripts/mkforge.py     生成伪造 JWT 与 rules.json
docs/how-it-works.md   抓包/反编译得到的真实协议与判定逻辑
docs/faq.md            常见问题
docs/security.md       安全、隐私与合规
certs/  rules.json  logs/    ← 全部由脚本生成，已在 .gitignore 里
```

## 已知限制

- 代理进程必须**每次启动时都在运行**（`start-nxstudio.ps1` 会帮你管这个生命周期）。
- **云/账号类功能不可用**（云端同步、在线服务等会拿到"空"的成功响应）；本地浏览、调整、导出不受影响。
- 只在 NX Studio **1.10.1.3003 (Windows)** 上实测通过；其它版本可能改协议，`check.ps1` + `logs/` 里的抓包可用来重新确认。
- 不修改任何 Nikon 文件，因此**不动安装目录、不需要管理员**；代价是"脱离代理就恢复原状"。

## English quick start

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File setup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File check.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File start-nxstudio.ps1
```

A tiny local proxy answers the two NCAS calls NX Studio makes at startup with a forged
`{"response_code":"0000", ...}` payload, so the app builds its main window without showing the
sign in dialog. Only `*.cld.nikon.com` is intercepted; everything else is blind tunnelled
(no TLS interception). No Nikon binary is patched, no admin rights are needed, and
`uninstall.ps1` removes the local CA again. This is an independent interoperation experiment
for software you own - see [docs/security.md](docs/security.md).