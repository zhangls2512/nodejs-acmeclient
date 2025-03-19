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