本包是一个基于Nodejs的ACME客户端，可用于无状态运行的云函数。  
**一、本包说明**  
1.可用于无状态运行的云函数，传递输入参数即可运行，运行结束后无数据残留。  
2.尽可能只保留与ACME客户端有关的功能。如crypto模块中的获取CSR信息功能，并没有输出CSR的全部信息，只输出可能与ACME客户端有关的信息。  
3.校验输入参数的逻辑较为简单，主要校验必需参数是否传递、参数是否在合法值范围内，未对参数类型等进行校验。使用时请严格按照使用文档中的要求传递输入参数，降低产生不可预见错误的可能性。  
**二、文件用途说明**  
doc/：各模块使用文档  
src/：各模块源代码  
updatelog.md：本包更新日志  
**三、各模块功能说明**  
api：与请求ACME服务器提供的API相关的功能  
crypto：与密钥、CSR、证书相关的功能  
verify：与验证挑战相关的功能  
**四、通用使用文档**  
1.前期准备  
安装Nodejs：[Nodejs 官网](https://nodejs.org)  
安装本包：`npm install nodejs-acmeclient`  
在`node_modules`文件夹同级目录下新建一个js文件，如`test.js`  
在新建的js文件中粘贴以下代码：
```js
const nac = require('nodejs-acmeclient') // nac可自定义
async function test() { //test可自定义
  // 要运行的代码
}
test()
```
2.模块使用文档结构说明  
（1）文件名：如`api.md`表示模块名是`api`  
（2）方法

* 英文名
* 同步/异步
* 输入参数
* 输出参数

输入、输出参数有以下两种情况：  
`string` 说明  
输入参数以`(输入参数)`形式传递。  
输出参数为string类型，如`'success'`。

|名|类型|必需|说明|
|---|---|---|---|
|a|string|是|a说明|
|b|number|否|b说明|

输入参数以`({a: 输入参数a, b: 输入参数b})`形式传递。  
输出参数格式如`({a: 输出参数a, b: 输出参数b})`，示例：`{a: '测试', b: 0}`。  
（3）示例代码（替换上方要运行的代码）
```js
try {
  const res= nac.模块名.方法英文名(输入参数) // 同步
  const res= await nac.模块名.方法英文名(输入参数) // 异步
  console.log(res)
} catch (err) {
  console.error(err)
}
```
3.运行代码  
在`test.js`文件同级目录下的命令行终端中运行：`node test`