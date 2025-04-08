# 互联网常用认证与授权机制
||认证|授权|
|---|---|---|
|作用|确认请求方身份|允许某个身份做什么|
|常见场景|前端向后端证明身份|用户授权客户端访问资源|
|相关术语|session_id、JWT|oAuth2|

一个流程中认证与授权通常配合使用。
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
## 基于session_id认证与oAuth2(授权码)授权机制的完整流程
### 时序图
```mermaid
sequenceDiagram
    participant Browser as 用户浏览器
    participant Frontend as 前端应用
    participant Backend as 后端服务
    participant AuthServer as OAuth授权服务器
    participant Resource as 资源API

    Note over Browser,Frontend: 1. 初始访问
    Browser->>Frontend: GET /home
    Frontend->>Browser: 返回登录按钮(未登录状态)

    Note over Browser,AuthServer: 2. 启动OAuth流程
    Browser->>Frontend: 点击登录
    Frontend->>Browser: 重定向到/auth/oauth?provider=xx
    Browser->>Backend: GET /auth/oauth?provider=xx
    Backend->>Browser: 302重定向到AuthServer(带client_id/redirect_uri/state等)
    
    Note over Browser,AuthServer: 3. 用户认证
    Browser->>AuthServer: 显示授权页面
    AuthServer->>Browser: 用户输入凭证
    Browser->>AuthServer: POST 提交登录表单
    
    Note over AuthServer: 4. 颁发授权码
    AuthServer->>Browser: 302重定向到Backend(带code和state)
    Browser->>Backend: GET /oauth/callback?code=ABC123&state=XYZ
    
    Note over Backend,AuthServer: 5. 换取令牌
    Backend->>AuthServer: POST /token (code+client_secret验证)
    AuthServer->>Backend: 返回access_token和refresh_token
    
    Note over Backend: 6. 建立会话
    Backend->>Backend: 验证用户信息(可调用/userinfo端点)
    Backend->>Browser: Set-Cookie: session_id=SSO123 (HttpOnly/Secure)
    
    Note over Browser,Frontend: 7. 前端获知登录状态
    Browser->>Frontend: GET /home (携带Cookie)
    Frontend->>Backend: GET /api/session (检查登录状态)
    Backend->>Frontend: 返回用户基本信息
    
    Note over Frontend,Resource: 8. 访问受保护资源
    Frontend->>Backend: GET /api/data (携带Cookie)
    Backend->>Resource: GET /data (携带Authorization: Bearer access_token)
    Resource->>Backend: 返回数据
    Backend->>Frontend: 返回应答数据
```

### 令牌刷新机制
```mermaid
graph LR
A[前端请求API] --> B{后端检查token过期?}
B -- 已过期 --> C[后端用refresh_token获取新access_token]
C --> D[更新session存储]
D --> E[继续处理原请求]
B -- 有效 --> E
```

## 基于Token的无状态oAuth2机制完整流程(BFF/Cookie 模式)
### 时序图
```mermaid
sequenceDiagram
    participant User as 用户浏览器
    participant SPA as 前端应用
    participant Backend as 后端API服务
    participant AuthServer as OAuth授权服务器
    participant Resource as 资源服务器

    Note over User,SPA: 1. 初始化请求
    User->>SPA: 访问 https://app.com
    SPA->>User: 返回前端页面(检测无Token显示登录按钮)

    Note over User,AuthServer: 2. 触发OAuth授权码流程
    User->>SPA: 点击登录
    SPA->>User: 重定向到 /auth/oauth?provider=google
    User->>Backend: GET /auth/oauth?provider=google
    Backend->>User: 302重定向到AuthServer(带client_id/redirect_uri/state/code_challenge(PKCE))

    Note over User,AuthServer: 3. 用户认证
    User->>AuthServer: 展示授权页面
    AuthServer->>User: 用户输入凭证并同意授权
    AuthServer->>User: 302重定向到Backend回调URL(带code和state)

    Note over User,Backend: 4. 后端处理回调
    User->>Backend: GET /oauth/callback?code=ABC&state=XYZ
    Backend->>AuthServer: POST /token (code+code_verifier+client_secret)
    AuthServer->>Backend: 返回JWT格式的access_token和refresh_token

    Note over Backend: 5. 无状态响应生成
    Backend->>Backend: 验证JWT签名/有效期<br>(无需存储会话状态)
    Backend->>User: Set-Cookie: app_token=<JWT>(HttpOnly/Secure/SameSite=Lax)<br>前端可通过/js/get-token接口获取用户基本信息

    Note over User,SPA: 6. 前端获取用户信息
    User->>SPA: 自动跳转回/home
    SPA->>Backend: GET /js/userinfo (携带Cookie)
    Backend->>SPA: 返回用户基本信息(email/name等)

    Note over SPA,Resource: 7. 访问受保护资源
    SPA->>Backend: GET /api/data (携带Cookie)
    Backend->>Resource: GET /data (携带Authorization: Bearer <JWT>)
    Resource->>Backend: 验证JWT后返回数据
    Backend->>SPA: 返回API响应
```

## 基于Token的无状态oAuth2机制完整流程(纯 SPA 模式)
### 时序图
```mermaid
sequenceDiagram
    participant User as 用户浏览器
    participant SPA as 前端应用 (运行在浏览器)
    participant Backend as 后端API服务
    participant AuthServer as OAuth授权服务器

    Note over User,SPA: 1. 初始化与检测登录状态
    User->>SPA: 访问 https://app.com
    SPA->>User: 返回前端页面
    SPA->>SPA: 检查本地存储(内存)是否有有效Token
    alt 无有效Token
        SPA->>User: 显示登录按钮
    else 有效Token
        SPA->>User: 显示已登录状态
        SPA->>Backend: (后续API请求) GET /api/userinfo (携带 Bearer Token)
        Backend->>SPA: 返回用户信息
    end

    Note over User,AuthServer: 2. 用户触发登录 (OAuth授权码+PKCE流程)
    User->>SPA: 点击登录按钮
    SPA->>SPA: 生成 code_verifier 和 code_challenge (PKCE)
    SPA->>SPA: 存储 code_verifier (例如：SessionStorage 或 内存)
    SPA->>User: 302 重定向到 AuthServer 授权端点 (带 client_id, redirect_uri(指向SPA), state, code_challenge, scope, response_type=code)

    Note over User,AuthServer: 3. 用户在授权服务器认证和授权
    User->>AuthServer: (浏览器地址栏已是AuthServer) 显示登录和授权页面
    AuthServer->>User: 用户输入凭证并同意授权
    AuthServer->>User: 302 重定向回 SPA 的 redirect_uri (带 code 和 state)

    Note over SPA,AuthServer: 4. SPA 处理回调并交换Token
    User->>SPA: (浏览器加载SPA的redirect_uri) GET /callback?code=ABC&state=XYZ
    SPA->>SPA: 验证 state 是否匹配
    SPA->>SPA: 取出之前存储的 code_verifier
    SPA->>AuthServer: POST /token (使用 code, code_verifier, client_id, redirect_uri, grant_type=authorization_code)
    Note right of SPA: SPA可以直接调用AuthServer的Token端点，\n或者通过一个简单的后端代理来避免CORS和暴露client_id(如果需要保密)
    AuthServer->>SPA: 返回 access_token, refresh_token, id_token (JWTs)

    Note over SPA: 5. SPA 存储Token并更新UI
    SPA->>SPA: 存储 Tokens (安全方式，如内存变量，避免LocalStorage)
    SPA->>SPA: (可选) 解码 id_token 获取用户信息 或 调用 /userinfo 端点
    SPA->>User: 更新UI，显示用户已登录

    Note over SPA,Backend: 6. SPA 访问受保护的后端API
    User->>SPA: (例如，导航到需要数据的页面)
    SPA->>SPA: 从存储中获取 access_token
    SPA->>Backend: GET /api/data (携带 Authorization: Bearer <access_token> 头)

    Note over Backend: 7. 后端API验证Token并处理请求
    Backend->>Backend: 验证收到的 access_token (签名, 有效期, audience, issuer - 可能需获取AuthServer的公钥/JWKS)
    opt 需要访问其他资源服务器
        Backend->>ResourceServer: GET /resource (携带原始或新的Token)
        ResourceServer->>Backend: 返回资源数据
    end
    Backend->>SPA: 返回API响应数据
```