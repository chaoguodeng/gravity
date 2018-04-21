# gravity
Hello Gravity

## crypto模块  
### ec包(`crypto/ec`)  
`ec`包对椭圆曲线相关的签名算法进行了二次包装以对外提供同一的API。  

包中所有算法都由`Worker`接口规定的三个流程组成  
1. `Worker.GenerateKey()`利用给定的熵源随机生成公私钥对用于后续的签名和验签  
2. `Worker.Sign()`利用私钥对给定的消息摘要进行签名  
3. `Worker.Verify()`基于公钥对摘要的签名进行验证  

目前，`Worker`接口的具体实现有  
+ `ecdsa.Worker256`  
+ `ecdsa.Worker512`    
+ `ed22519.Worker`  
+ `secp.Worker`
