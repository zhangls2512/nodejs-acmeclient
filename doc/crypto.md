**1.生成RSA密钥对**  
英文名：generateRSAKeyPair `同步`  
输入参数：`number` 密钥长度，非必需，默认值为`2048`  
输出参数
|名|类型|必有|说明|
|---|---|---|---|
|privateKey|string|是|私钥（pem格式）|
|publicKey|string|是|公钥（pem格式）|

**2.生成ECDSA密钥对**  
英文名：generateECDSAKeyPair `同步`  
输入参数：`string` 密钥曲线，非必需，默认值为`prime256v1`  
输出参数
|名|类型|必有|说明|
|---|---|---|---|
|privateKey|string|是|私钥（pem格式）|
|publicKey|string|是|公钥（pem格式）|

**3.生成MLDSA密钥对**  
英文名：generateMLDSAKeyPair `同步`  
输入参数：`number` 密钥格维度，非必需，默认值为`65`  
输出参数
|名|类型|必有|说明|
|---|---|---|---|
|privateKey|string|是|私钥（pem格式）|
|publicKey|string|是|公钥（pem格式）|

**4.获取密钥信息**  
英文名：getKeyInfo `同步`  
输入参数：`string` 密钥（pem格式），必需，目前仅支持`RSA`、`ECDSA`、`MLDSA`  
输出参数
|名|类型|必有|说明|
|---|---|---|---|
|keyType|string|是|密钥算法，合法值有`RSA`、`ECDSA`、`MLDSA`|
|keyBits|number|是（对于`RSA`密钥）|密钥长度|
|curveName|string|是（对于`ECDSA`密钥）|密钥曲线|
|dimension|number|是（对于`MLDSA`密钥）|密钥格维度|
|isPrivate|boolean|是|是否是私钥|
|isPublic|boolean|是|是否是公钥|

**5.生成CSR**  
英文名：generateCsr `同步`  
输入参数
|名|类型|必需|说明|
|---|---|---|---|
|commonName|string|否|通用名称CN，默认值为`subjectAltName[0]`|
|subjectAltName|array|是|域名、IP地址，示例：`['www.example.com','0.0.0.0','::1']`|
|privateKey|string|是|私钥（pem格式），目前仅支持`RSA`、`ECDSA`、`MLDSA`|

输出参数：`string` CSR（pem格式）  
**6.获取CSR信息**  
英文名：getCsrInfo `同步`  
输入参数：`string` CSR（pem格式），必需  
输出参数
|名|类型|必有|说明|
|---|---|---|---|
|commonName|string|是|通用名称CN|
|subjectAltName|array|是|域名、IP地址，示例：`['www.example.com','0.0.0.0','::1']`|
|publicKey|string|是|公钥（pem格式）|
|signatureAlgorithm|string|是|签名算法，示例：`SHA256withRSA`|

**7.分离多个证书（常用于分离叶证书、中间证书）**  
英文名：extractCertificates `同步`  
输入参数：`string` 证书（pem格式），必需  
输出参数：`array` 证书（元素：`string` pem格式证书）  
**8.获取证书信息**  
英文名：getCertificateInfo `同步`  
输入参数：`string` 证书（pem格式），必需  
输出参数：`array` 证书信息（元素见下）
|名|类型|必有|说明|
|---|---|---|---|
|commonName|string|是|通用名称CN|
|subjectAltName|array|是|域名、IP地址，示例：`['www.example.com','0.0.0.0','::1']`|
|issuerCommonName|string|是|颁发者通用名称CN|
|startDate|date|是|颁发时间|
|endDate|date|是|到期时间|
|authorityKeyIdentifier|string|是|AKI扩展值（用于向ACME服务器查询证书ARI续订信息）|
|serialNumber|string|是|序列号（用于向ACME服务器查询证书ARI续订信息）|