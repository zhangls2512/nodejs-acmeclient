**1.生成RSA密钥对**
英文名：generateRSAKeyPair `同步`
输入参数：`number` 密钥长度，合法值有`2048`、`3072`、`4096`，非必需，默认值为`2048`
输出参数
（1）成功

|名|类型|必有|说明|
|---|---|---|---|
|privateKey|string|是|私钥（pem格式）|
|publicKey|string|是|公钥（pem格式）|

（2）输入参数校验失败：`string` 失败原因
**2.生成ECDSA密钥对**
英文名：generateECDSAKeyPair `同步`
输入参数：`string` 密钥曲线，合法值有`prime256v1`、`secp384r1`、`secp521r1`，非必需，默认值为`prime256v1`
输出参数
（1）成功

|名|类型|必有|说明|
|---|---|---|---|
|privateKey|string|是|私钥（pem格式）|
|publicKey|string|是|公钥（pem格式）|

（2）输入参数校验失败：`string` 失败原因
**3.获取密钥信息**
英文名：getKeyInfo `同步`
输入参数：`string` 密钥（pem格式），必需，目前仅支持RSA、ECDSA
输出参数
（1）成功

|名|类型|必有|说明|
|---|---|---|---|
|keyType|string|是|密钥使用的加密算法类型，合法值有`RSA`、`ECDSA`|
|keyBits|number|是（对于RSA密钥）|密钥长度|
|curveName|string|是（对于ECDSA密钥）|密钥曲线|
|isPrivate|boolean|是|是否是私钥|
|isPublic|boolean|是|是否是公钥|

（2）输入参数校验失败：`string` 失败原因
**4.生成CSR**
英文名：generateCSR `同步`
输入参数

|名|类型|必需|说明|
|---|---|---|---|
|commonName|string|否|通用名称CN，默认值为`subjectAltName[0]`|
|subjectAltName|array|是|域名、IP地址，示例：`['www.example.com', '0.0.0.0']`|
|privateKey|string|是|私钥（pem格式），目前仅支持RSA、ECDSA|

输出参数
（1）成功：`string` CSR（pem格式）
（2）输入参数校验失败：`string` 失败原因
**5.获取CSR信息**
英文名：getCsrInfo `同步`
输入参数：`string` CSR（pem格式），必需
输出参数
（1）成功

|名|类型|必有|说明|
|---|---|---|---|
|commonName|string|是|通用名称CN|
|subjectAltName|array|是|域名、IP地址，示例：`['www.example.com', '0.0.0.0']`|
|publicKey|string|是|公钥（pem格式）|
|signatureAlgorithm|string|是|签名算法，示例：`SHA256withRSA`|

（2）输入参数校验失败：`string` 失败原因
**6.分离多个证书（常用于分离叶证书、中间证书）**
英文名：extractCertificates `同步`
输入参数：`string` 证书（pem格式），必需
输出参数
（1）成功：`array` 证书
元素：`string` 证书（pem格式）
（2）输入参数校验失败：`string` 失败原因
**7.获取证书信息**
英文名：getCertificateInfo `同步`
输入参数：`string` 证书（pem格式），必需
输出参数
（1）成功：`array` 证书信息
元素

|名|类型|必有|说明|
|---|---|---|---|
|commonName|string|是|通用名称CN|
|subjectAltName|array|是|域名、IP地址，示例：`['www.example.com', '0.0.0.0']`|
|issuerCommonName|string|是|颁发者通用名称CN|
|startDate|date|是|颁发时间|
|endDate|date|是|到期时间|
|authorityKeyIdentifier|string|是|AKI扩展值（用于向ACME服务器查询证书ARI续订信息）|
|serialNumber|string|是|序列号（用于向ACME服务器查询证书ARI续订信息）|

（2）输入参数校验失败：`string` 失败原因