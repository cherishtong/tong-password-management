# tong-password-management
基于Rust的密码管理软件,目前第一版已经发布，欢迎大家使用。

打包windows图标到程序：

```
cargo rustc --release  --bin password-management  -- -C link-arg=resource.res
```

![预览图](https://github.com/China-zhaotong/tong-password-management/blob/main/imgs/preview.png)