# gravity
Hello Gravity

## crypto模块  
### ec包(`crypto/ec`)  
`ec`包对椭圆曲线相关的签名算法进行了二次包装以对外提供同一的API。  

#### 3个关键流程  
包中所有算法都由`Worker`接口规定的三个流程组成  
1. `Worker.GenerateKey()`利用给定的熵源随机生成公私钥对用于后续的签名和验签  
2. `Worker.Sign()`利用私钥对给定的消息摘要进行签名  
3. `Worker.Verify()`基于公钥对摘要的签名进行验证  

#### 公私钥结构  
对于每个具体算法，  
+ 公钥都实现`ec.go`里面声明的`PublicKey`空接口   
+ 私钥都实现`ec.go`里面声明的`PrivateKey`接口   
  - 这个接口的`Public()`函数返回这个私钥对应的公钥  

#### 具体实现  
目前，`Worker`接口的具体实现有  
+ `ecdsa.Worker256`：标准库的ECDSA算法，签名长度为256  
+ `ecdsa.Worker512`：标准库的ECDSA算法，签名长度为512    
+ `ed22519.Worker`：拓展库的EDDSA算法，签名长度为512  
+ `secp.Worker`：私人库的secp256k1算法，签名长度为256
