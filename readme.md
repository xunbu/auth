# 互联网常用认证与授权机制
||认证|授权|
|---|---|---|
|作用|确认请求方身份|允许某个身份做什么|
|常见场景|前端向后端证明身份|用户授权客户端访问资源|
|相关术语|session_id、JWT|oAuth2|

一个流程中认证与授权通常配合使用。  

---
# 认证机制
## 基于session_id的认证
### 时序图
```mermaid
sequenceDiagram
    participant User
    participant Server
    participant Database

    User->>Server: 登录请求 (用户名/密码)
    Server->>Database: 验证用户凭据
    Database-->>Server: 验证结果
    alt 验证成功
        Server->>Database: 生成并存储 session_id
        Database-->>Server: 确认存储
        Server-->>User: 返回 session_id (Cookie/Header)
    else 验证失败
        Server-->>User: 返回错误信息
    end

    User->>Server: 后续请求 (携带 session_id)
    Server->>Database: 验证 session_id
    Database-->>Server: 返回验证结果
    alt session_id 有效
        Server-->>User: 返回请求数据
    else session_id 无效
        Server-->>User: 返回 401 或重定向登录
    end

    User->>Server: 注销请求
    Server->>Database: 删除 session_id
    Database-->>Server: 确认删除
    Server-->>User: 返回注销成功
```
### 详细步骤说明
#### 1. 用户登录阶段
##### 步骤 1.1：用户提交凭据
- 用户通过客户端（浏览器/移动应用）提交用户名和密码。
- 客户端通过 HTTPS 加密传输凭据到服务器。
##### 步骤 1.2：服务器验证凭据
- 服务器查询数据库，验证用户名和密码是否匹配。
- 密码通常以哈希形式存储，需比对哈希值。
##### 步骤 1.3：生成 `session_id`
- 验证成功后，服务器生成唯一 `session_id`（如 UUID）。
- `session_id` 包含用户 ID、时间戳等信息（可选签名）。
- 服务器将 `session_id` 和用户信息存储到数据库（如 Redis 或会话表）。
##### 步骤 1.4：返回 `session_id` 给客户端
- 通过以下方式返回：
  - **HTTP Cookie**（推荐）：
    ```http
    Set-Cookie: session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Strict
    ```
  - **响应体**（JSON）：
    ```json
    { "session_id": "abc123" }
    ```
##### 步骤 1.5：客户端存储 `session_id`
- 浏览器自动保存 Cookie，或客户端手动存储（如 localStorage）。
---
#### 2. 会话验证阶段
##### 步骤 2.1：客户端发起请求
- 每次请求自动携带 `session_id`：
  - **Cookie**：浏览器自动附加到请求头。
  - **Header**：手动添加（如 `Authorization: Bearer abc123`）。
##### 步骤 2.2：服务器验证 `session_id`
- 服务器从请求中提取 `session_id`。
- 查询数据库检查是否有效（存在且未过期）。
##### 步骤 2.3：返回验证结果
- **有效**：执行请求并返回数据。
- **无效**：返回 `401 Unauthorized` 或重定向到登录页。
---
#### 3. 会话管理阶段
##### 步骤 3.1：会话过期
- 设置会话有效期（如 30 分钟）。
- 超时后自动失效，需重新登录。
##### 步骤 3.2：主动注销
- 用户退出时：
  - 服务器删除数据库中的 `session_id`。
  - 客户端清除本地 `session_id`。
##### 步骤 3.3：安全性增强
- **HTTPS**：全程加密。
- **HttpOnly Cookie**：防 XSS。
- **SameSite Cookie**：防 CSRF。
- **会话轮换**：定期更新 `session_id`。
---
#### 4. 异常处理
- **会话劫持**：检测异常 IP/设备，强制注销。
- **并发控制**：限制同一用户的活跃会话数。
- **日志记录**：记录会话生命周期事件。
---
## 基于JWT的认证
### 什么是 JWT？
JWT（JSON Web Token）是一种用于在各方之间安全地传输信息的开放标准（RFC 7519）。 JWT 是一种紧凑、自包含的方式，用于以 JSON 对象安全地传输信息。 由于其数字签名，因此可以信任和使用该信息。 JWT 可以使用密钥（使用 HMAC 算法）或使用 RSA 或 ECDSA 的公钥/私钥对进行签名。
### 时序图
```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Database

    Client->>Server: POST /login (用户名+密码)
    Server->>Database: 验证用户凭据
    alt 验证成功
        Server->>Server: 生成 JWT (Header+Payload+Signature)
        Server-->>Client: 返回 JWT (JSON/Cookie)
    else 验证失败
        Server-->>Client: 返回 401
    end

    Client->>Server: 请求 (携带 JWT)
    Server->>Server: 验证 JWT 签名和过期时间
    alt JWT 有效
        Server->>Database: 执行业务逻辑
        Server-->>Client: 返回数据
    else JWT 无效
        Server-->>Client: 返回 401
    end
```
### JWT 的结构
JWT 通常由三部分组成，这些部分用点（.）分隔：
1.  **Header（头部）**: 描述 JWT 的元数据，通常包括令牌的类型（`typ`）和所使用的签名算法（`alg`）。 例如：
    ```json
    {
      "alg": "HS256",
      "typ": "JWT"
    }
    ```
2.  **Payload（载荷）**: 包含 JWT 的声明（claims）。声明是关于实体（通常是用户）和其他数据的声明。 有三种类型的声明：*reserved*（保留）、*public*（公开）和 *private*（私有）声明。 例如：
    ```json
    {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022
    }
    ```
3.  **Signature（签名）**: 用于验证消息的完整性。签名是通过以下方式计算得出的：将编码后的头部、编码后的载荷以及密钥使用头部中指定的算法进行签名。
JWT的结构示意图：
```mermaid
graph LR
A[Header] --> B(Base64Url Encode)
C[Payload] --> D(Base64Url Encode)
E[Signature] --> F(Generated using Header, Payload and Secret)
B --> G(Concatenate with '.')
D --> G
F --> G
G --> H{JWT}
```
### JWT 的生成
JWT 的生成过程如下：
1.  **创建 Header**: 定义 JWT 的元数据，指定签名算法和令牌类型。
2.  **创建 Payload**: 包含要传输的数据（声明）。例如，用户 ID、用户名等。
3.  **Base64UrlEncode Header 和 Payload**: 将 Header 和 Payload 分别进行 Base64Url 编码。
4.  **创建 Signature**: 使用 Header 中指定的算法，将编码后的 Header 和 Payload 与一个密钥进行签名。
5.  **组合**: 将编码后的 Header、编码后的 Payload 和签名用点（.）连接起来，形成最终的 JWT。
例如，使用 HMAC SHA256 算法 (HS256) 生成 JWT 的步骤如下:
1.  **Header**:
    ```json
    {
      "alg": "HS256",
      "typ": "JWT"
    }
    ```
2.  **Payload**:
    ```json
    {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022
    }
    ```
3.  **Base64UrlEncode**:
    *   Encoded Header: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`
    *   Encoded Payload: `eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ`
4.  **Signature**:
    假设密钥 `secret` 为 `'your-secret-key'`。  
    Signature = HMACSHA256(base64UrlEncode(header) + "." +base64UrlEncode(payload),secret)  
    计算得到的签名 (示例): `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`  
5.  **JWT**:
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
### 详细步骤说明
1. 登录请求阶段
```http
POST /api/auth/login HTTP/1.1
Content-Type: application/json

{
    "username": "user123",
    "password": "securePassword"
}
```
2. 服务端验证
-验证用户名密码是否匹配数据库记录
-检查账户是否被锁定/禁用
-验证通过后准备生成JWT
3. 生成并返回JWT
服务端响应示例：
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "token": "eyJhbG...",
    "expires_in": 3600
}
```
4. 客户端存储
常见存储方式：
```javascript
// Web存储
localStorage.setItem('jwt', token);

// Cookie（推荐HttpOnly）
document.cookie = `jwt=${token}; HttpOnly; Secure; SameSite=Strict`;
```
5. 携带JWT的请求
```http
GET /api/protected-resource HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsIn...
```
6. 服务端验证
验证过程伪代码:
```python
def verify_jwt(token):
    try:
        # 1. 解析token
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        
        # 2. 检查过期时间
        if payload['exp'] < time.time():
            raise ExpiredSignatureError
            
        # 3. 返回用户信息
        return {
            'user_id': payload['sub'],
            'roles': payload['roles']
        }
    except Exception as e:
        raise InvalidTokenError
```
### 令牌刷新机制
```mermaid
graph TD
    A[访问令牌过期] --> B[使用refresh token请求新令牌]
    B --> C{验证refresh token}
    C -->|有效| D[颁发新的access/refresh token]
    C -->|无效| E[要求重新登录]
```
刷新请求示例
```http
POST /api/auth/refresh HTTP/1.1
Authorization: Bearer [refresh_token]
```

# 授权机制
## 基于`session_id`和`jwt`的简单授权机制
对于后端、授权服务、资源服务在同一方的程序而言，可以使用简单的基于`session_id`和`jwt`的简单授权机制。
在使用前文提到的基于`session_id`和`jwt`的方式认证后。前端每次请求都携带`session_id`和`jwt`，资源服务将对其进行验证。
## oAuth2
### 时序图（授权码模式）
```mermaid
sequenceDiagram
    participant User as 用户
    participant Client as 客户端
    participant AuthServer as 授权服务器
    participant ResourceServer as 资源服务器

    Note over User,Client: 1. 启动OAuth流程
    Client->>User: 重定向到授权端点
    User->>AuthServer: 访问授权页面(带client_id/scope/redirect_uri等参数)

    Note over User,AuthServer: 2. 用户认证
    AuthServer->>User: 显示认证界面
    User->>AuthServer: 提交凭证(用户名/密码)

    Note over AuthServer: 3. 颁发授权码
    AuthServer-->>User: 重定向到Client(带授权码code)
    User->>Client: 转发授权码

    Note over Client,AuthServer: 4. 获取访问令牌
    Client->>AuthServer: 发送code+client_secret到令牌端点
    AuthServer-->>Client: 返回访问令牌(access_token)

    Note over Client,ResourceServer: 5. 访问受保护资源
    Client->>ResourceServer: 携带access_token请求API
    ResourceServer-->>Client: 返回请求的资源数据

```
> oAuth2机制依赖于重定向机制，因此无法使用Post方法给客户端直接传输Token。
> 由于跨域问题，授权服务无法保证能通过cookie将Token传输给客户端
> 因此oAuth2机制通过重定向机制以GET方法给客户端传递授权码code（授权码方式）或通过GET方法直接传递Token（隐式流模式）
# 认证、授权完整流程
## 不同类型应用使用不同的oAuth2实现
| 应用类型             | 推荐授权方式                   | 备注                                                |
|----------------------|-------------------------------|-----------------------------------------------------|
| 服务器端web应用   | 授权码授权                    | 客户端秘密保管在服务器                              |
| 单页面应用 SPA       | 授权码授权 + PKCE             | 不再推荐使用隐式授权                                |
| 原生移动应用         | 授权码授权 + PKCE             | 防止令牌被劫持                                      |
| 高度信任官方客户端   | 密码模式/授权码+PKCE          | 不推荐密码方式，首选授权码+PKCE                     |
| 服务之间通信         | 客户端凭证授权                | 无用户上下文，代表自身身份                          |
## oAuth2授权码授权（服务器web应用）
### 时序图
```mermaid
sequenceDiagram
    participant User as 用户浏览器
    participant WebApp as 服务器端Web应用
    participant AuthServer as 授权服务器
    participant API as 资源服务器(API)

    Note over User,API: 授权码模式（最安全的服务器端流程）
    User->>WebApp: 访问应用首页
    WebApp->>User: 返回登录页面（带OAuth2登录链接）

    User->>AuthServer: 点击登录跳转授权页<br>(response_type=code, client_id, redirect_uri, scope, state)
    AuthServer->>User: 返回登录/授权页面
    User->>AuthServer: 输入账号密码并授权
    AuthServer->>User: 302重定向到redirect_uri<br>?code=AUTH_CODE&state=XYZ

    User->>WebApp: 携带code访问回调接口
    WebApp->>AuthServer: 用code换token（POST请求）<br>client_id, client_secret, code, redirect_uri
    AuthServer->>WebApp: 返回access_token和refresh_token<br>(通常JSON格式)

    WebApp->>User: 设置会话Cookie/Session
    WebApp->>API: 用access_token调用API<br>Authorization: Bearer {token}
    API->>WebApp: 返回受保护资源
    WebApp->>User: 渲染受保护页面
```

## oAuth2隐式授权(单页面应用)
### 时序图
```mermaid
sequenceDiagram
    participant User as 用户浏览器
    participant SPA as 单页应用(SPA)
    participant AuthServer as 授权服务器
    participant API as 资源服务器(API)

    Note over User,API: 隐式授权流程（适用于SPA）
    User->>SPA: 访问前端应用
    SPA->>User: 返回前端页面（含OAuth2跳转逻辑）
    
    User->>AuthServer: 重定向到授权端点<br>(response_type=token, client_id, redirect_uri, scope)
    AuthServer->>User: 返回登录页面
    User->>AuthServer: 输入账号密码并授权
    AuthServer->>User: 302重定向到redirect_uri<br>#access_token=XXX&token_type=Bearer&expires_in=3600
    Note right of User: 令牌通过URL片段(#)传递，<br>前端JS提取但不会发送到服务器

    User->>SPA: 前端解析URL中的access_token
    SPA->>API: 携带令牌访问API<br>Authorization: Bearer {access_token}
    API->>SPA: 返回受保护资源
```

## oAuth2+PKCE机制完整流程(单页面应用)
### 时序图
```mermaid
sequenceDiagram
    participant User as 用户
    participant SPA as 单页应用(SPA)
    participant AS as 授权服务器
    participant RS as 资源服务器
    Note over SPA,AS: 1. 初始化流程
    SPA->>SPA: 生成code_verifier(随机43-128字符)
    SPA->>SPA: 计算code_challenge = SHA256(code_verifier)
    User->>SPA: 点击登录按钮
    SPA->>AS: GET /authorize?response_type=code<br>&client_id=SPA_CLIENT_ID<br>&redirect_uri=SPA_CALLBACK_URI<br>&scope=openid profile<br>&code_challenge=xxx<br>&code_challenge_method=S256<br>&state=随机值
    Note right of AS: 2. 用户认证
    AS->>User: 显示登录页面
    User->>AS: 提交凭据
    AS->>User: 302重定向到SPA_CALLBACK_URI<br>?code=AUTHORIZATION_CODE<br>&state=原值
    Note over SPA,AS: 3. 获取Access Token
    SPA->>AS: POST /token<br>grant_type=authorization_code<br>&code=AUTHORIZATION_CODE<br>&redirect_uri=SPA_CALLBACK_URI<br>&client_id=SPA_CLIENT_ID<br>&code_verifier=原始值
    AS->>AS: 验证code_verifier匹配code_challenge
    AS->>SPA: 返回JSON: {access_token, refresh_token, expires_in}
    Note over SPA,RS: 4. 访问受保护资源
    SPA->>RS: GET /api/resource<br>Authorization: Bearer ACCESS_TOKEN
    RS->>AS: 内省token验证
    AS->>RS: 返回token有效性和scope
    RS->>SPA: 返回请求的资源数据
    Note over SPA,AS: 5. Token刷新(可选)
    SPA->>AS: POST /token<br>grant_type=refresh_token<br>&refresh_token=REFRESH_TOKEN<br>&client_id=SPA_CLIENT_ID
    AS->>SPA: 返回新的{access_token, refresh_token}
```
### 详细流程
#### **1. 初始化流程（SPA准备PKCE参数）**
- **SPA生成 `code_verifier`**  
  - 一个随机字符串（43-128字符，仅包含字母、数字、`-`、`.`、`_`、`~`）。  
  - **安全要求**：必须使用密码学安全的随机生成器（如 `crypto.getRandomValues()`）。  
- **SPA计算 `code_challenge`**  
  - 对 `code_verifier` 进行 SHA-256 哈希，然后 Base64-URL 编码。  
  - 公式：`code_challenge = base64url(sha256(code_verifier))`。  
- **存储 `code_verifier`**  
  - 仅保存在内存中（不写入 `localStorage` 或 Cookie），后续换取 Token 时使用。
---

#### **2. 用户发起授权请求（前端跳转）**
SPA 构造授权请求 URL，重定向用户到 **授权服务器（AS）**：  
```http
GET /authorize?
  response_type=code
  &client_id=SPA_CLIENT_ID
  &redirect_uri=https://spa.example.com/callback
  &scope=openid profile
  &code_challenge=xxx（生成的code_challenge）
  &code_challenge_method=S256
  &state=随机值（防CSRF）
```
- **关键参数**：  
  - `response_type=code`：要求返回授权码（Authorization Code）。  
  - `code_challenge` 和 `code_challenge_method`：PKCE 的核心，防止授权码截获攻击。  
  - `state`：随机值，用于防止 CSRF（回调时需验证是否匹配）。  
- **用户交互**：  
  - AS 展示登录页面，用户输入凭据（或选择社交登录）。  
  - AS 可能要求用户同意请求的权限（`scope`）。

---

#### **3. 授权服务器回调SPA（携带授权码）**
AS 认证成功后，重定向回 SPA 的 `redirect_uri`：  
```http
HTTP 302 Redirect to:
https://spa.example.com/callback?
  code=AUTHORIZATION_CODE
  &state=原值（必须与请求时一致）
```
- **安全验证**：  
  - SPA 必须检查 `state` 是否与初始请求一致，防止 CSRF。  
  - 仅接受匹配预注册的 `redirect_uri`（防止开放重定向攻击）。

---

#### **4. SPA 用授权码换取 Token（PKCE验证）**
SPA 向 AS 的 Token 端点发送请求，附带 `code_verifier`：  
```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTHORIZATION_CODE
&redirect_uri=https://spa.example.com/callback
&client_id=SPA_CLIENT_ID
&code_verifier=原始值（非code_challenge）
```
- **PKCE 关键验证**：  
  - AS 会重新计算 `code_challenge`（用收到的 `code_verifier`），验证是否与初始请求的 `code_challenge` 一致。  
  - 如果匹配，AS 返回 Token；否则拒绝请求。  
- **响应示例**：  
  ```json
  {
    "access_token": "xxx",
    "refresh_token": "xxx", // 可选（需明确请求offline_access scope）
    "expires_in": 3600,
    "token_type": "Bearer"
  }
  ```

---

#### **5. SPA 使用 Access Token 访问资源**
SPA 在请求头中携带 `access_token` 访问资源服务器（RS）：  
```http
GET /api/userinfo
Authorization: Bearer ACCESS_TOKEN
```
- **资源服务器的验证**：  
  - RS 可能通过 **Token 内省（Introspection）** 或 **JWT 自验证** 检查 Token 有效性。  
  - 验证通过后返回请求的资源数据。

---

#### **6. Token 刷新（可选）**
如果 `access_token` 过期，SPA 用 `refresh_token` 获取新 Token：  
```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
&client_id=SPA_CLIENT_ID
```
- **安全限制**：  
  - `refresh_token` 需通过 HTTPS 传输。  
  - 纯 SPA 应限制 `refresh_token` 有效期（如 30 天）。
---
## oAuth2客户端凭证流程（服务之间通信）
### 时序图
```mermaid
sequenceDiagram
    participant ServiceA as 服务A（客户端）
    participant AuthServer as 授权服务器
    participant ServiceB as 服务B（资源服务器）

    Note over ServiceA,ServiceB: 客户端凭证模式（无用户参与）
    ServiceA->>AuthServer: 请求access_token<br>（client_id, client_secret, grant_type=client_credentials）
    AuthServer->>ServiceA: 返回access_token<br>（无refresh_token）
    ServiceA->>ServiceB: 调用API<br>Authorization: Bearer {access_token}
    ServiceB->>AuthServer: 验证令牌（可选）
    AuthServer->>ServiceB: 令牌有效性响应
    ServiceB->>ServiceA: 返回API数据
```
### 详细流程
1. **服务A获取令牌**  
   - 直接向后端授权服务器发送请求（HTTP POST），无需用户交互：  
     ```http
     POST /token HTTP/1.1
     Content-Type: application/x-www-form-urlencoded

     grant_type=client_credentials
     &client_id=SERVICE_A_ID
     &client_secret=SERVICE_A_SECRET
     ```
   - **安全要求**：`client_secret`必须严格保密（使用环境变量/密钥管理服务）。

2. **授权服务器响应**  
   - 返回仅包含`access_token`的响应（通常不生成`refresh_token`）：  
     ```json
     {
       "access_token": "eyJhbGci...",
       "token_type": "Bearer",
       "expires_in": 3600
     }
     ```

3. **服务A调用服务B**  
   - 在API请求头中携带令牌：  
     ```http
     GET /api/data HTTP/1.1
     Authorization: Bearer eyJhbGci...
     ```

4. **服务B验证令牌**（两种方式）  
   - **自省（Introspection）**：调用授权服务器的验证接口（更安全）：  
     ```http
     POST /introspect HTTP/1.1
     token=eyJhbGci...
     ```
   - **本地验证**：若使用JWT，直接校验签名和过期时间。

---