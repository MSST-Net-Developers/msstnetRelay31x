# MSST-Net Relay 3.1.x

MSST-Net 的 UDP 中转服务。两台设备无法直连时，由它转发 WireGuard 加密的数据，并代理游戏发现广播。适用于 MSST-Net Core 3.1.x 与 Coordinator 3.1.x，不支持 3.0.x 客户端。

同一个程序有两种运行方式：

- **官方中转**（默认）：向 Coordinator 登记，出现在中转列表里，供所有用户使用。
- **自托管中转**：自己部署，建房时用连接串指定，只为指定了它的房间服务。

## 文档

**使用教程与完整文档见文档站：<https://msst-net.msst2031.cn>**

仓库内的技术文档（英文，面向开发者）：

| 文档 | 内容 |
|---|---|
| [REFERENCE.md](REFERENCE.md) | 报文处理、信任模型、Coordinator 接口、配置项与资源上限 |
| [SELF_HOSTED.md](SELF_HOSTED.md) | 自托管模式：配置、连接串、登记流程 |
| [REGISTRATION_AUTH.md](REGISTRATION_AUTH.md) | 注册认证（sreg v1，`0x0E`） |
| [SECURE_DISCOVERY.md](SECURE_DISCOVERY.md) | 安全游戏发现（sdisc v1） |

## 快速开始

从 [Actions](https://github.com/MSST-Net-Developers/msstnetRelay31x/actions) 的构建产物下载对应平台的二进制，或自行编译（需要 Go 1.27+）：

```bash
go build -o msstnetRelay31x .
./msstnetRelay31x -config config.yaml               # 首次运行生成默认配置（权限 0600）
./msstnetRelay31x -config config.yaml -print-link   # 自托管：打印连接串后退出
```

默认监听 UDP 21031。按文档站说明填好 `config.yaml` 后重启即可。

## 开发

```bash
go vet ./... && go test -race ./...
```

CI 在 Linux、macOS、Windows 上运行测试，并构建 linux / windows / darwin 的 amd64 与 arm64 版本。

## 许可证

MIT，见 [LICENSE](LICENSE)。发行的二进制包含第三方组件（BSD-3-Clause、MIT、Apache-2.0），分发时请一并附上 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES)。
