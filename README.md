# msauth

minecraft的微软验证登陆

## 使用

1.调用SetClient(clientID，clientSecret)设置clientID，一般clientSecret留空，clientid要先向azure申请,具体见<https://wiki.vg/Microsoft_Authentication_Scheme>

2.Login()登陆即可获取玩家档案和AccessToken

具体例子见example/example.go