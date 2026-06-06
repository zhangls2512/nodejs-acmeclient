**v1.2.0（2026.6.6）**  
1.`A` `api`模块新增`getChallengeKeyAuthorizationEx`方法  
1.`A` `crypto`模块新增`generateMLDSAKeyPair`方法  
**v1.1.0（2026.1.23）**  
1.`U` `verify`模块`verify`方法`type`入参合法值移除`tls-alpn-01`  
**v1.0.19（2026.1.22）**  
1.`F` 修复`api`模块`getChallengeKeyAuthorization`方法逻辑错误  
1.`F` 修复User-Agent请求头构造逻辑错误  
**v1.0.18（2026.1.22）**  
1.`F` 修复jws构造逻辑错误  
**v1.0.17（2026.1.21）**  
1.`F` 微调代码风格  
**v1.0.16（2025.11.14）**  
1.`U` `updatelog.md`文件更名为`CHANGELOG.md`  
**v1.0.15（2025.10.14）**  
1.`F` 修复`crypto`模块`getCsrInfo`方法如果CSR无备用名subjectAltName会异常  
**v1.0.14（2025.6.7）**  
1.`F` 删除`api.md`文件最后的两个无用空格  
**v1.0.13（2025.4.26）**  
1.`F` 修复`crypto`模块`getCertificateInfo`方法如果证书无公用名CN会异常  
**v1.0.12（2025.4.6）**  
1.`F` 移除`api`模块重复的`getAccountUrl`方法  
**v1.0.11（2025.3.19）**  
1.`F` 修改`crypto`模块`getCertificateInfo`方法获取`startDate`、`endDate`的逻辑以兼容低于`23.0.0`的`Nodejs`版本  
**v1.0.10（2025.3.6）**  
1.`F` 修复`api`模块`getOrderCertificate`方法未输出替代证书  
**v1.0.9（2025.3.5）**  
1.`F` 修复`api`模块`getAccountUrl`方法未导出  
**v1.0.8（2025.3.5）**  
1.`U` 优化`api.md`文件中的文本表述  
**v1.0.7（2025.3.5）**  
1.`A` `api`模块新增`getAccountUrl`方法  
2.`U` `api`模块`getOrderAuthorizations`方法更名为`getOrderAuthorization`  
**v1.0.6（2025.3.2）**  
1.`U` `api`模块`newOrder`方法新增输入参数`replaceCertificate`  
2.`F` `verify`模块`verify`方法验证失败输出`fail`而非抛出`fail`  
**v1.0.5（2025.2.14）**  
1.`F` 修复判断输入参数是否传递的逻辑  
**v1.0.4（2025.2.4）**  
1.`U` 优化`.md`文件中的文本表述  
**v1.0.3（2025.2.4）**  
1.`U` 优化`README.md`文件中的文本表述  
**v1.0.2（2025.2.4）**  
1.`U` 优化`.md`文件中的文本表述  
**v1.0.1（2025.2.3）**  
1.`U` `api`模块`updateAccountContact`方法成功输出`'success'`  
2.`F` 验证`type`为`dns-01`挑战时未递归解析CNAME记录、未使用`_acme-challenge`子域  
3.`F` `.md`文件中文本未换行  
**v1.0.0（2025.2.3）**  
1.`A` 第一版本