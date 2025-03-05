信息对象格式遵循[RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)、[ARI](https://datatracker.ietf.org/doc/draft-ietf-acme-ari)、[profile](https://datatracker.ietf.org/doc/draft-aaron-acme-profiles)协议标准。  
**1.获取ACME目录元数据（可能含有CA服务条款网址、订单支持的profile配置文件名列表）**  
英文名：getDirectoryMeta `异步`  
输入参数：`string` ACME目录URL，必需  
输出参数  
（1）成功：`object` 目录元数据  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**2.创建账户**  
英文名：newAccount `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|
|contact|array|否|联系方式，示例：`['mailto:example@example.com']`|
|eabMacKey|string|否|绑定外部账户的MAC密钥（此功能未测试，请谨慎使用）|
|eabKeyId|string|否|绑定外部账户的MAC密钥ID（此功能未测试，请谨慎使用）|

输出参数  
（1）成功

|名|类型|必有|说明|
|---|---|---|---|
|accountUrl|string|是|账户URL|
|accountInfo|object|是|账户信息|

（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**3.获取账户URL**  
英文名：getAccountUrl `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|

输出参数  
（1）成功：`string` 账户URL  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**4.获取账户信息**  
英文名：getAccountInfo `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|

输出参数  
（1）成功：`object` 账户信息  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**5.更新账户私钥**  
英文名：updateAccountKey `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|
|newAccountKey|string|是|新账户私钥（pem格式）|

输出参数  
（1）成功：`string` `'success'`  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**6.更新账户联系方式**  
英文名：updateAccountContact `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|
|contact|array|是|新联系方式，示例：`['mailto:example@example.com']`|

输出参数  
（1）成功：`string` `'success'`  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**7.停用账户**  
英文名：deactivateAccount `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|

输出参数  
（1）成功：`string` `'success'`  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**8.创建订单**  
英文名：newOrder `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|
|domains|array|是|域名、IP地址，示例：`['www.example.com', '0.0.0.0']`|
|profile|string|否|配置文件名|
|notBefore|date|否|生效时间|
|notAfter|date|否|过期时间|
|replaceCertificate|string|否|替代证书（pem格式）|

输出参数  
（1）成功

|名|类型|必有|说明|
|---|---|---|---|
|orderUrl|string|是|订单URL|
|orderInfo|object|是|订单信息对象|

（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**9.获取订单信息**  
英文名：getOrderInfo `异步`  
输入参数：`string` 订单URL，必需  
输出参数  
（1）成功：`object` 订单信息对象  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**10.获取订单授权信息**  
英文名：getOrderAuthorization `异步`  
输入参数：`string` 订单URL，必需  
输出参数  
（1）成功：`array` 授权信息对象  
元素：`object` 单个授权信息对象  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**11.完成订单**  
英文名：finalizeOrder `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|
|orderUrl|string|是|订单URL|
|csr|string|是|CSR（pem格式）|

输出参数  
（1）成功

|名|类型|必有|说明|
|---|---|---|---|
|status|string|是|状态（`'success'`）|
|retryAfter|number|否|重试等待时间（单位：秒）|

（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**12.获取订单证书**  
英文名：getOrderCertificate `异步`  
输入参数：`string` 订单URL，必需  
输出参数  
（1）成功：`array` 证书  
元素：`string` 单张证书（pem格式）  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**13.停用授权**  
英文名：deactivateAuthorization `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|
|authorizationUrl|string|是|授权URL（订单信息对象中属性`authorizations`的值的元素）|

输出参数  
（1）成功：`string` `'success'`  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**14.获取挑战验证值（用于验证挑战是否完成的文件内容、DNS解析记录值...）**  
英文名：getChallengeKeyAuthorization `同步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|challenge|object|是|挑战信息对象（授权信息对象中属性`challenges`的值的元素）|
|accountKey|string|是|账户私钥（pem格式）|

输出参数  
（1）成功：`string` 挑战验证值  
（2）输入参数校验失败：`string` 失败原因  
**15.请求CA验证挑战**  
英文名：respondChallenge `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|是|账户私钥（pem格式）|
|challengeUrl|string|是|挑战URL（挑战信息对象中属性`url`的值）|

输出参数  
（1）成功

|名|类型|必有|说明|
|---|---|---|---|
|status|string|是|状态（`'success'`）|
|retryAfter|number|否|重试等待时间（单位：秒）|

（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**16.获取证书ARI续订信息**  
英文名：getCertificateRenewalInfo `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|certificate|string|是|证书（pem格式）|

输出参数  
（1）成功：`object` ARI续订信息  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  
**17.吊销证书**  
英文名：revokeCertificate `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|directoryUrl|string|是|ACME目录URL|
|accountKey|string|否（此参数不传则必传certificateKey）|账户私钥（pem格式）|
|certificateKey|string|否（此参数不传则必传accountKey）|证书私钥（pem格式）|
|certificate|string|是|证书（pem格式）|
|reason|number|否|吊销原因数字代码|

输出参数  
（1）成功：`string` `'success'`  
（2）输入参数校验失败：`string` 失败原因  
（3）HTTP(S)请求失败  
`err.response`存在：`object` `err.response.data`+`retryAfter`属性（如果`err.response.headers['retry-after']`存在）  
`err.response`不存在：`object` `axios`返回的完整错误信息  