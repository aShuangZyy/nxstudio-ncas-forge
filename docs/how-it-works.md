# 它是怎么工作的（抓包 + 反编译得到的真实行为）

> 所有结论都来自**本机对 NX Studio 1.10.1.3003 (Windows) 的可复现观察**：系统代理指向本机抓包代理，
> 记录 app 自己发出的请求；再对 `NkSNSLib.dll` / `NkLogin.dll` 做静态分析交叉验证。
> 文中不包含任何账号标识、令牌或厂商内部凭据；开发期观察到的值一律以占位符代替。

## 1. 启动时序

| 时刻 | 现象 |
|---|---|
| 0 s | 进程起来，尚未创建可见窗口 |
| ~3 s | 若凭据库里存在**刷新令牌**，向账号域名建立 TLS（不存在则完全不联网） |
| ~3 s | `POST auth.accounts.cld.nikon.com/auth/realms/system/protocol/openid-connect/token`（服务令牌，`client_id=ncas`） |
| ~3 s | `POST faapi.www.accounts.cld.nikon.com/nxs/refresh_token`（`function_id` / `service_id` / `refresh_token` / `secret_key`） |
| ~4 s | 会话成立 → 创建 `MainFrame` 主窗口；**会话不成立则创建 `#32770` 登录/试用对话框**（该对话框资源属于 `NkLogin.dll`，由 MFC 弹出） |

关键点：**登录框不是"必须先点掉"的模态步骤，而是会话建立失败时的分支产物**。所以只要这两笔请求返回"成功"，主界面就会出来。

## 2. 需要伪造的两笔请求

`faapi` 那笔（插件侧 `NkSNSLib.dll` 里对应的处理函数）请求体字段是固定的四个：

```
function_id=NX_STUDIO
service_id=NX_STUDIO
refresh_token=<刷新令牌>
secret_key=<应用内置密钥>          ← 由 app 发送，我们不需要知道它的值
```

响应里 app 真正读取的是：

```
response_code     ← 决定成败（见下一节）
access_token      ← 字符串，存回凭据库
refresh_token     ← 字符串，存回凭据库
```

也就是说：**只要给出这两个字符串字段 + 一个"成功"的 `response_code`**，app 就会把它们当作会话物料。

## 3. `response_code` 的判定语义（本次能过关的关键）

反编译出的判定逻辑等价于：

```c
int verdict(const char *code) {
    if (strlen(code) < 2) return 0x1030;          // 失败
    if (code[0] != 'E') return 0;                 // ← 成功：任何不以 'E' 开头的码
    long n = strtol(code + 1, NULL, 10);
    if (n == 1)             return 0x1002;
    if (n == 99)            return 0x1030;
    if (n == 3 || n == 5 || (n >= 108 && n <= 191)) return 0x1015;
    if (n >= 303 && n <= 391) return 0x1007;
    if (n >= 407 && n <= 450) return 0x1003;
    if (n == 2 || (n >= 501 && n <= 509)) return 0x1001;
    if (n == 4 || n == 6 || (n >= 603 && n <= 692)) return 0x1010;
    return 0x1030;                                // 其它 E 码（含 E1301）→ 失败
}
```

**所以成功码要写 `"0000"`，而不是 `"E0000"`**：后者会走进兜底分支被判为失败（这个坑本项目踩过，现象是"响应被接受了但登录框照旧、而且弹得更快"）。

顺带确认的现实情况：真实服务器对普通账号常返回 `E1301`（`"Not agrees to terms consent"`），落进兜底 → 失败。

## 4. 为什么伪造能被接受

- 这条路径上**没有 JWT 签名校验**：抓包显示 app 从不请求 JWKS（`certs` 端点），伪造的 RS256 令牌即使由本机 CA 签发也照收。
- `response_code` 之外它只把 `access_token` / `refresh_token` 当**不透明字符串**转发与保存。
- 因此伪造响应不需要"像真的"：形状对、字段全、成功码对即可。

## 5. 为什么不做"改文件"型免登录

早期尝试过对 `NkvSNS.md8` / `NkLogin.dll` 打补丁（状态字段、状态 getter、vtable 槽、`Configure` 的模式位等），
实测**只能改变登录框的标题，无法阻止它出现**，也无法让主窗口提前创建。
静态短路"成功判定"这条路也不划算：跳过判定后 app 手里没有任何令牌物料，后续所有走网络的流程会更早崩掉。
**伪造响应**正好相反：既让判定成功，又真的给了它两份可用的会话物料。

## 6. 版本与自证方法

结论对应 **NX Studio 1.10.1.3003 (Windows)**。换了版本若失效，可以这样自己确认协议有没有变：

1. 运行 `start-nxstudio.ps1`，它在 `logs/mitm-*.log` 里记录 app 发出的每个请求（头、体、响应）。
2. 看是否出现新的域名/路径 → 在 `rules.json` 里加一条同样的规则。
3. 用 `check.ps1` 里的功能测试确认伪造响应被接受。

`mitm.py` 对**未命中规则**的域名只做 TCP 转发（盲隧道，不解密），因此开着它上网不会有证书告警。