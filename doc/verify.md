**1.验证挑战是否完成**  
英文名：verify `异步`  
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|authorization|object|是|授权信息对象，`api.getOrderAuthorization`方法返回数组的元素|
|accountKey|string|是|账户私钥|
|type|string|是|挑战类型，合法值有`http-01`、`dns-01`、`tls-alpn-01`（目前不支持`tls-alpn-01`，计划在未来支持）|

输出参数  
（1）验证成功：`string` `'success'`  
（2）验证失败、验证过程中发生错误（如HTTP请求失败）：`string` `'fail'`  
（3）输入参数校验失败：`string` 失败原因