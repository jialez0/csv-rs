# Launch Management API（启动管理接口）

## 概述

Host Linux内核通过一组ioctl来提供对这些API的访问，`csv-rs` 通过`/dev/kvm`节点向Host Linux内核发送ioctl命令。使用`csv-rs`制作的二进制APP需要具备与`/dev/kvm`节点交互的权限。`csv-rs` 同时需要提供ccp内核驱动模块设备节点的文件描述符，这是与海光安全处理器交互的关键。

使用这些API来实现对CSV KVM虚拟机的管理。Launch API支持CSV、CSV2和CSV3三种不同的安全虚拟化技术版本。

## 核心概念

### Launcher状态机

Launcher采用类型状态模式，确保启动流程的正确执行顺序：

1. **New** - 初始状态，表示新的启动流程
2. **Started** - 已启动状态，表示加密上下文已创建
3. **Measured** - 已测量状态，表示已获得虚拟机度量值

### 支持的CSV版本

| 版本 | 初始化方法 | 特点 |
|------|-----------|------|
| CSV1 | `Launcher::new()` | 基础加密虚拟化 |
| CSV2 | `Launcher::new_es()` | 增强安全特性，需要加密状态 |
| CSV3 | `Launcher::new_csv3()` | 最新安全特性，支持NUMA配置（待完善） |

## API详细说明

### 1. 初始化阶段

#### 1.1 CSV1初始化

```rust
use csv_rs::api::launch::Launcher;
use std::fs::File;

let kvm_fd = File::open("/dev/kvm")?;
let csv_fd = File::open("/dev/sev")?;

// 初始化CSV1启动器
let launcher = Launcher::new(kvm_fd, csv_fd)?;
```

**说明**：
- 创建基本的CSV KVM实例
- 不需要额外参数
- 适用于基础的加密虚拟化场景

#### 1.2 CSV2初始化

```rust
use csv_rs::api::launch::Launcher;
use std::fs::File;

let kvm_fd = File::open("/dev/kvm")?;
let csv_fd = File::open("/dev/sev")?;

// 初始化CSV2启动器
let launcher = Launcher::new_es(kvm_fd, csv_fd)?;
```

**说明**：
- 创建支持加密状态的CSV2 KVM实例
- 启用虚拟机内存加密保护
- 启用虚拟机vCPU寄存器加密完整性保护
- 后续需要使用`update_vmsa()`加密VMSA

#### 1.3 CSV3初始化

```rust
use csv_rs::api::launch::{Launcher, Csv3Init};
use std::fs::File;

let kvm_fd = File::open("/dev/kvm")?;
let csv_fd = File::open("/dev/sev")?;

// 创建CSV3初始化参数
// nodemask=0 使用默认NUMA策略
let csv3_init = Csv3Init::new(0);

// 初始化CSV3启动器
// 内部自动执行两步：
//   1. ES_INIT (CSV2初始化)
//   2. CSV3_INIT (CSV3特定初始化)
let launcher = Launcher::new_csv3(kvm_fd, csv_fd, &csv3_init)?;
```

**NUMA配置说明**：

`nodemask`参数控制客户机内存分配的NUMA节点亲和性：

- **默认行为**：设置`nodemask = 0`使用系统默认NUMA策略
- **指定节点**：设置掩码中的位以绑定到特定NUMA节点
  - 示例：`nodemask = 0b11`（或`3`）绑定到NUMA节点0和1
  - 示例：`nodemask = 0b100`（或`4`）仅绑定到NUMA节点2

```rust
// 绑定到NUMA节点0和1
let csv3_init = Csv3Init::new(0b11);

// 仅绑定到NUMA节点2
let csv3_init = Csv3Init::new(0b100);
```

**说明**：
- CSV3需要两步初始化：先CSV2，再CSV3特定初始化
- CSV3虚拟机启用内存加密完整性保护，vCPU寄存器加密完整性保护，嵌套页表加密完整性保护
- 支持灵活的NUMA内存分配策略，提供更细粒度的性能优化控制（待完善）

### 2. 启动阶段

#### 2.1 完整启动（带证书和会话）

```rust
use csv_rs::api::launch::{Launcher, Start, Policy, Session};
use csv_rs::certs::csv::Certificate;

// 定义启动策略
let policy = Policy {
    flags: PolicyFlags::ENCRYPTED_STATE | PolicyFlags::CSV3,
    minfw: Version { major: 1, minor: 0 },
};

// 准备DH证书和会话信息
let cert: Certificate = /* 加载证书 */;
let session: Session = /* 创建会话 */;

let start = Start {
    policy,
    cert,
    session,
};

// 启动加密客户机上下文
let started_launcher = launcher.start(start)?;
```

**说明**：
- 创建加密的客户机上下文
- 需要：提供策略
- 可选：DH证书和会话信息
- 建立租户与安全处理器之间的安全通道

#### 2.2 原始启动（分别传入参数）

```rust
let started_launcher = launcher.start_raw(&policy, &cert, &session)?;
```

**说明**：
- 与`start()`功能相同
- 参数分别传入，更灵活

#### 2.3 仅策略启动

```rust
let started_launcher = launcher.start_with_policy_only(policy)?;
```

**说明**：
- 仅提供策略，不提供证书和会话
- 适用于简化场景或测试

### 3. 数据更新阶段

#### 3.1 注册加密内存区域

```rust
started_launcher.register_kvm_enc_region(&guest_data)?;
```

**说明**：
- 手动注册加密内存区域
- 对应`KVM_MEMORY_ENCRYPT_REG_REGION` ioctl
- 可以与其他操作组合使用

#### 3.2 更新加密数据（自动注册内存区域）

```rust
// 在Started状态下
started_launcher.update_data(&guest_data)?;
```

**说明**：
- 使用VEK（虚拟机加密密钥）加密客户机数据
- 自动注册KVM加密内存区域（不需要手动调用`register_kvm_enc_region()`）
- 适用于CSV/CSV2

#### 3.3 更新数据（不注册内存区域）

```rust
started_launcher.update_data_without_registration(&guest_data)?;
```

**说明**：
- 加密数据但不自动注册内存区域
- 需要先手动调用`register_kvm_enc_region()`
- 提供更灵活的控制

#### 3.4 更新VMSA（CSV2）

```rust
started_launcher.update_vmsa()?;
```

**说明**：
- 加密VMSA（虚拟机保存区）
- 仅用于CSV2
- 设置vCPU时必须调用

#### 3.5 设置客户机私有内存（CSV3）

```rust
started_launcher.set_guest_private_memory()?;
```

**说明**：
- 通知内核/固件将客户机内存标记为私有/安全
- 对应`KVM_CSV3_SET_GUEST_PRIVATE_MEMORY`
- CSV3特有，必须在加密数据前调用

#### 3.6 加密数据（CSV3）

```rust
use csv_rs::api::launch::types::Csv3LaunchEncryptData;

let encrypt_data = Csv3LaunchEncryptData {
    gpa: guest_physical_address,  // 客户机物理地址
    uaddr: userspace_address,      // 用户空间地址
    len: data_length,              // 数据长度
};

started_launcher.encrypt_data(&encrypt_data)?;
```

**说明**：
- CSV3专用的数据加密方法
- 对应`KVM_CSV3_LAUNCH_ENCRYPT_DATA`
- 需要明确指定GPA、用户空间地址和长度

#### 3.7 加密VMCB（CSV3）

```rust
started_launcher.encrypt_vmcb()?;
```

**说明**：
- 加密VMCB（虚拟机控制块）内容，机密vCPU寄存器状态
- 对应`KVM_CSV3_LAUNCH_ENCRYPT_VMCB`
- CSV3中相当于CSV2的`update_vmsa()`

### 4. 测量阶段

#### 4.1 获取度量值

```rust
// 从Started状态转换到Measured状态
let measured_launcher = started_launcher.measure()?;

// 获取度量值
let measurement = measured_launcher.measurement();
println!("Measure: {:?}", measurement.measure);
println!("MNonce: {:?}", measurement.mnonce);
```

**说明**：
- 从CSV固件请求度量值
- 返回包含度量值和随机nonce的结构
- 用于远程证明

### 5. 秘密注入阶段

#### 5.1 注入秘密数据

```rust
use csv_rs::api::launch::{Secret, Header, HeaderFlags};

// 创建秘密头
let header = Header {
    flags: HeaderFlags::empty(),
    iv: [0u8; 16],                // 初始化向量
    mac: [0u8; 32],               // 完整性保护MAC
};

// 创建秘密数据包
let secret = Secret {
    header,
    ciphertext: encrypted_secret_data,
};

// 注入秘密到客户机
let guest_address = 0x100000; // 客户机中的目标地址
measured_launcher.inject(&secret, guest_address)?;
```

**说明**：
- 将加密的秘密数据注入到客户机
- 应在成功的证明流程后调用（启动阶段`start()`时，需提供DH证书和会话信息）

### 6. 完成阶段

#### 6.1 完成启动

```rust
// 完成CSV启动流程，转换客户机到就绪状态
let handle = measured_launcher.finish()?;
```

**说明**：
- 完成整个CSV启动流程
- 将客户机转换到可运行状态
- 返回句柄供后续使用

## 数据结构详解

### Policy（策略）

描述HYGON安全处理器将强制执行的策略。

```rust
pub struct Policy {
    pub flags: PolicyFlags,   // 策略标志
    pub minfw: Version,       // 期望的最小平台固件版本
}
```

**PolicyFlags选项**：

| 标志 | 值 | 说明 |
|------|-----|------|
| `NO_DEBUG` | 0x0001 | 禁止调试客户机 |
| `NO_KEY_SHARING` | 0x0002 | 禁止与其他客户机共享密钥 |
| `ENCRYPTED_STATE` | 0x0004 | 需要CSV2保护 |
| `NO_SEND` | 0x0008 | 客户机不能发送到其他平台 |
| `DOMAIN` | 0x0010 | 客户机不能传输到域外平台 |
| `CSV` | 0x0020 | 客户机不能传输到非CSV平台 |
| `CSV3` | 0x0040 | 需要CSV3保护（同时也需要CSV2） |

**从u32转换**：
```rust
let policy: Policy = Policy::from(0x00040001u32); // NO_DEBUG + ENCRYPTED_STATE
```

### Session（会话）

租户和HYGON安全处理器之间的安全通道。

```rust
pub struct Session {
    pub body: SessionBody,  // 会话体
    pub sig: SessionSig,    // 签名
}
```

**SessionBody字段**：
- `nonce: [u8; 16]` - 用于派生共享密钥的随机数
- `wrap_tk: [u8; 32]` - 包装的密钥（TEK|TIK）
- `wrap_iv: [u8; 16]` - 初始化向量
- `wrap_mac: [u8; 32]` - 包装密钥的完整性保护
- `session_mac: [u8; 32]` - CSV会话数据的完整性保护
- `vm_digest: [u8; 32]` - 虚拟机摘要
- `pubkey_digest: [u8; 32]` - 公钥摘要
- `vm_id: [u8; 16]` - 虚拟机ID
- `vm_version: [u8; 16]` - 虚拟机版本
- `user_data: [u8; 64]` - 用户数据

### Measurement（度量值）

CSV客户机的度量值。

```rust
pub struct Measurement {
    pub measure: [u8; 32],  // 度量值
    pub mnonce: [u8; 16],   // 随机nonce
}
```

### Secret（秘密）

包含要注入到客户机的秘密信息的数据包。

```rust
pub struct Secret {
    pub header: Header,           // 包头
    pub ciphertext: Vec<u8>,      // 加密的秘密数据
}
```

## 完整使用示例

### CSV3完整启动流程

```rust
use csv_rs::api::launch::{Launcher, Csv3Init, Policy, PolicyFlags, Start};
use csv_rs::certs::csv::Certificate;
use csv_rs::Version;
use std::fs::File;

fn launch_csv3_guest() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 打开设备文件
    let kvm_fd = File::open("/dev/kvm")?;
    let csv_fd = File::open("/dev/sev")?;
    
    // 2. 初始化CSV3
    let csv3_init = Csv3Init::new(0); // 默认NUMA策略
    let launcher = Launcher::new_csv3(kvm_fd, csv_fd, &csv3_init)?;
    
    // 3. 配置策略
    let policy = Policy {
        flags: PolicyFlags::ENCRYPTED_STATE | PolicyFlags::CSV3,
        minfw: Version { major: 1, minor: 0 },
    };
    
    // 4. 准备证书和会话（实际应用中需要从文件或网络加载）
    let cert = Certificate::load_from_file("dh_cert.cert")?;
    let session = create_session()?; // 需要实现会话创建逻辑
    
    let start = Start {
        policy,
        cert,
        session,
    };
    
    // 5. 启动加密上下文
    let mut started = launcher.start(start)?;
    
    // 6. 设置客户机私有内存（CSV3必需）
    started.set_guest_private_memory()?;
    
    // 7. 加载并加密客户机数据
    let guest_code = std::fs::read("guest_binary.bin")?;
    started.encrypt_data(&Csv3LaunchEncryptData {
        gpa: 0x1000000,
        uaddr: guest_code.as_ptr() as u64,
        len: guest_code.len() as u32,
    })?;
    
    // 8. 加密VMCB
    started.encrypt_vmcb()?;
    
    // 9. 获取度量值
    let measured = started.measure()?;
    let measurement = measured.measurement();
    println!("Guest measurement: {:?}", measurement.measure);
    
    // 10. （可选）注入秘密
    // let secret = create_secret()?;
    // measured.inject(&secret, 0x2000000)?;
    
    // 11. 完成启动
    let _handle = measured.finish()?;
    
    Ok(())
}
```

## 错误处理

所有API调用都可能返回`std::io::Error`。错误可能来自：
- ioctl调用失败
- 权限不足（需要访问`/dev/kvm`和`/dev/sev`）
- CSV固件错误
- 参数无效

建议使用适当的错误处理：

```rust
match launcher.start(start) {
    Ok(started) => { /* 继续启动流程 */ },
    Err(e) => eprintln!("启动失败: {}", e),
}
```

## 权限要求

使用Launch API需要以下权限：
- 读写`/dev/kvm`设备
- 读写`/dev/sev`设备
- 通常需要root权限或特定的用户组权限

## 注意事项

1. **状态顺序**：必须严格按照New → Started → Measured → Finish的顺序执行
2. **CSV3特殊要求**：CSV3必须先调用`set_guest_private_memory()`再加密数据
3. **线程安全**：Launcher不是线程安全的，避免并发访问

## 相关文档

- [Platform API](../platform/README.md) - 平台管理接口
- [Guest API](../guest/README.md) - 客户机侧接口
- [DCU API](../dcu/README.md) - DCU接口
