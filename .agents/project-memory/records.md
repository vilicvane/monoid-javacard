# Project Memory Records

## af4f994

1. [user] 所有 API 变更都必须事先获得用户明确同意。API、协议、审批。
2. [user] 当前工作范围限定在 Monoid Java Card 项目；暂时撤回对 Monoid APP 的改动，在原有 API 的基础上实现 Solana 签名。
3. [user] 批准在现有 0x41 Sign 中新增 message 字段：cipher 为 eddsa 时传入原始 Message，ECDSA 继续使用 digest，指令编号、Key 和 {signature} 返回结构保持不变。
4. [user] ~~Extended APDU 和短 APDU 命令链接均未获批准；先分析实际签名需求，再决定长请求传输方案。用户测试过很多不支持 Extended APDU 的卡片。~~ superseded by 6.
5. [agent] 采用紧凑 CBOR、10 字节 index 和 m/44'/501'/0'/0' 四级路径时，seed 派生的 eddsa Sign 请求在 255 字节短 APDU 中最多容纳 160 字节 Message；SDK 离线序列化的 legacy 单笔 SOL 转账为 150 字节 Message / 245 字节请求，加计算额度与优先费后为 202 / 297，向已有代币账户 TransferChecked 为 214 / 309。常用交易已需要超过单条短 APDU 的请求容量。
6. [user] 批准增加通用的多段请求传输，定位为传输层约定，客户端传输层适配后业务调用不区分单段与多段；用户测试过很多不支持 Extended APDU 的卡片，因此采用短 APDU。
7. [user] 多段传输需要区分单段、首段、中间段和末段，以支持发送部分数据后放弃旧命令、重新发送新命令，包括同一指令的重试。
8. [agent] 实现使用 CLA 00/90/B0/A0 分别表示单段/首段/中间段/末段，INS/P1/P2 保持业务含义；新单段或首段替换旧请求，中间段和末段必须匹配当前请求，业务仅在完整请求到齐后执行。请求总长上限 8192 字节，长请求以 AES-CBC 密文暂存于持久区，每请求随机加密密钥及明文工作块均使用 CLEAR_ON_DESELECT 瞬态存储。
9. [agent] ~~实体卡确认切换算法时仅丢弃旧上下文仍会触发 SystemException.NO_TRANSIENT_SPACE，GC 需等 APDU 边界；复用现有空 6100 / GET RESPONSE 来完成回收后执行原请求，保持同一业务调用。暂缓的完整请求也使用加密暂存，可由新单段/首段取消；数据管理命令释放曲线上下文以提供工作 RAM，Hello、认证、系统信息和连续同算法操作保留上下文。~~ superseded by 18; APDU 边界才执行回收的实体卡观察仍适用。
10. [agent] GET RESPONSE 必须使用 CLA 00；Java SmartcardIO 默认自动续传会沿用末段 CLA A0，需关闭该自动处理（sun.security.smartcardio.t1GetResponse=false），由适配后的传输层统一发送 00 C0 00 00。
11. [agent] 2026-10-11 在 ACS ACR1552 / ATR 3b8a800150564a434f503453494471 的实体卡上，四级 SLIP-0010 派生和 Ed25519 签名复用上下文时，150/202/4096/8096 字节 Message 含传输耗时约 4.06/4.94/13.87/23.05 秒。长请求缓冲已创建时，回收后可用 deselect RAM 为无曲线上下文 3408、Ed25519 736、secp256k1 3120 字节；Ed25519 常驻占用 2672 字节，连续签名与三轮 BTC/Solana 切换后数值稳定。请求缓冲额外常驻瞬态内存 96 字节、持久密文 8192 字节；这些是空闲时测量，非签名过程中最低可用 RAM。
12. [user] 核心使用场景是每次操作只进行一种算法的一次签名；请假设每次操作后 RAM 都会被清空。单次签名、RAM 生命周期、上下文复用。
13. [agent] 记录 12 是设计与评估所需的使用场景假设，不代表现有卡片会在每次签名或每个 APDU 结束时自动清空全部 RAM；RAM 内容清零也不等于数组空间被回收或持久上下文被销毁。连续签名保留 RAM 状态的收益不能作为该场景下性能的依据，应分别验证持久初始化结果在 transient 内容清零后的复用，以及切算法释放工作区后的复用。
14. [user] 每次 Command 结束后手动清空一次工作 RAM。命令生命周期、主动擦除。
15. [agent] ~~在 Command 正常返回或异常退出时统一擦除解码副本、派生中间值、私钥和签名工作区，保留可复用的持久初始化对象；响应已发送部分及被替换缓冲也主动擦除。认证会话和尚未完成的请求/响应按各自生命周期保留，不能在中间 APDU 清空。擦除内容不释放仍被引用的 RAM 分配，不等价于整卡复位或 GC。~~ superseded by 17–18.
16. [agent] 当前 Java Card 3.1.0 转换器在异常表连续 catch-all 项使引用间距达到 255 时无法正确生成 CAP；使用 Command 外层统一 finally 减少重复清理字节码，ED25519Keystore.load 以 catch(Throwable) 执行失败清理后原样重抛，保持全部异常清理语义。研究复现确认 jc310r20210706 仍存在该限制，无需修改 SDK 或添加无意义 catch。
17. [user] 目标是去掉复杂的内存管理，尽可能为每次操作提供完整的可用内存，以减轻后续维护的心智负担；“每次操作后清空 RAM”包含释放临时内存容量，不只是擦除数据。
18. [agent] 采用操作级资源生命周期：签名上下文及 HMAC 按需创建，在 Command 退出时擦除并解除引用；请求加密工作区与响应缓冲各自在完整请求/响应结束或取消时释放。删除按算法选择释放旧上下文的准备阶段；正常下一操作使用上一 APDU 的 GC 边界，新单段替换未完成传输时才由传输层复用空 6100 / GET RESPONSE 等待旧缓冲回收。仅保留认证/传输控制状态和持久数据；当前 Ed25519 对象不能与所引用的 RAM 简单分离，故每次重新构建，延迟需重新实测。
19. [agent] 2026-10-11 实体卡操作级释放验证：22 项主回归、最终版本 5 项补充回归均通过。81 次主回归空闲内存采样及最终版本复位/SELECT 后首条查询均回到 3712 字节 deselect RAM（含查询自身响应缓冲，非签名峰值）。三轮 BTC/两次 Solana 交替中，六次四级 SLIP-0010 + 150 字节 Ed25519 完整操作 5.906–5.963 秒，三次五级 BIP32 + ECDSA 为 1.528–1.536 秒；正常签名无空 6100。每次 SELECT 与 deselect 共用释放入口，以恢复未执行 finally 的复位中断。临时 7D/7E 应用已删除、原应用可选，安装前后 registry 完全一致。
20. [agent] 按用户要求，将混合的 Solana 接入、分段传输和内存管理草稿存入 stash 285d6abd37951dd46bf57b5cb5baf18ebe635525，源码与 README 恢复到 af4f994，准备逐步重写；34 个已跟踪文件及 6 个新增文件均核对 Git blob 一致。保留项目约定及忽略目录中的研究证据；前述草稿实现与测试结果仅作为历史参考，不代表恢复后的当前代码，用户需求及 API 审批约束继续有效。
21. [agent] 重写首先增加 Sign API 请求结构与分支：CommandSign 按 cipher 读取 ecdsa 的 digest 或 eddsa 的原始 message，Keystore 在读取密钥与派生前分出 EdDSA，暂以已有 UNSUPPORTED_CIPHER 返回，等待接通实现；能力列表仍仅公布已支持的算法。模拟器验证 7 种请求分支及 13 项原有回归通过，此阶段不代表 Ed25519 已可通过 Monoid API 签名。
22. [user] 重新审视后沿用当前外部 API 的 ecdsa/digest 与 eddsa/message 约定；Keystore 的签名入口按 digest/message 输入语义拆分，而非按 ECDSA/EdDSA 命名。若预见两种曲线的签名流程无法通过干净的修改接入现有结构，先讨论其他方式。
23. [agent] ~~将 Curve 合并进 CurveSECP256k1，并扩展重命名至底层签名、OneShot 与 low-S 辅助方法；此前误将这些结构变更理解为用户授权。~~ superseded by 24.
24. [agent] 用户明确 Curve 最多改名，不应删除父类、合并实现或扩大重构范围；已撤回 23 的全部改动，恢复原有继承关系及底层方法，仅保留此前批准的 Sign 请求分支与 Keystore.signDigest/signMessage 拆分。后续重命名应限于名称及必要引用调整。
25. [agent] 按用户更正，将 Keystore 摘要入口命名为 signECDSADigest，移除 cipher 参数与重复判断，内部固定传入 Signer.CIPHER_ECDSA；调用处同步更新。Signer.sign 保留原名，signMessage 暂保持原状。
26. [agent] 按用户要求将消息入口改为 signEDDSAMessage 并移除 cipher；接入检查的第一个缺口是 SLIP10Ed25519Deriver 仅接受原始 seed，每次固定以 "ed25519 seed" 生成 master，不能从已存储 master 继续派生。为沿用 Keystore 的 seed→master→child 组织方式，下一步建议增加 deriveFromMaster；本轮未接通签名，保留占位错误，编译通过。
27. [user] SLIP-0010 沿用原有 BIP32 的职责划分：LibSLIP10Ed25519.derive 从 master（密钥 + chain code）按路径派生，seed→master 由 Keystore 负责，不新增另一套完整入口或改变外部签名 API；取代记录 26 中另加 deriveFromMaster 的提议。
28. [agent] signEDDSAMessage 已复用取密钥、seed→master 和 master 类型/长度校验，按用户要求停在下一处结构接入问题：现有 Curve 的密钥接口绑定 ECPrivateKey，而 ED25519Signer 接收 32 字节 seed，不能原样沿用该曲线接口。尚未决定 Ed25519 曲线选择的组织位置，未接通路径派生与签名，合法 master 仍返回 UNSUPPORTED_CIPHER；13 项原有模拟器回归通过，不代表 Ed25519 签名验证通过。
29. [user] 采用并列的 WeierstrassCurve 与 EdwardsCurve 结构；现有 Curve 改名为 WeierstrassCurve，保留 getSharedPrivateKey、derivePublicKey 等方法及 ECPrivateKey 类型，EdwardsCurve 定义符合自身密钥表示的接口，暂不提取共同 Curve 父类。
30. [user] 保留单个 Keystore，通过接受 WeierstrassCurve / EdwardsCurve 参数的同名重载表达两类公钥派生流程，暂不拆成抽象 Keystore 及两个子类。
31. [agent] ~~新增 EdwardsCurve 最小抽象接口：密钥/公钥长度，以及由私钥 seed 派生公钥的缓冲区与整数组重载；不暴露由 ED25519Signer 管理的 ED25519Key。~~ superseded by 34.
32. [agent] ~~CurveED25519 暂在 derivePublicKey 中局部创建 ED25519Signer，导入 seed 后复制公钥并在 finally 中 clear；此包装只完成编译验证。~~ superseded by 34.
33. [user] 上一个 commit（af4f994）是完成签名验证后的阶段性提交，其中许多实现可能在本轮重构；设计时应按原型内部结构可重构的前提考虑 ED25519Signer，以对齐原有项目实现为方向。
34. [agent] 完成 ED25519Signer 拆分并移除旧 signer/session：CurveED25519 持有操作内数学上下文、seed 展开和公钥运算，EdwardsCurve 改为 getSharedPrivateKey 返回 ED25519Key、derivePublicKey 接受该密钥；ED25519Key 保存展开后的 scalar/prefix/publicKey；LibED25519 在一次同步调用内两遍读取完整 message，第二遍结束后才输出签名，Signer.sign 通过类型重载调用它。签名退出时擦除 scratch，密钥由操作拥有者调用 curve.clear 清理；换钥使旧引用失效，拒绝跨上下文密钥。没有新增常驻上下文、曲线注册或 Keystore 接线。29 项模拟器测试及 Java Card 3.0.5 CAP 转换/校验通过；签名覆盖 RFC8032 五组向量、SLIP→Solana 独立预期、重叠输出和失败重试。模拟器仅在 build 下生成 ECCurve 的 KeyBuilder 适配，CAP 使用原生产代码；本轮未测试实体卡，也未验证命令级内存回收。
35. [user] 同意将 Signer.sign 两个重载命名为 signECDSADigest 和 signEDDSAMessage，与 Keystore 的命名对齐，在方法名中明确预计算摘要和原始消息的输入语义；取代记录 25、34 中保留 Signer.sign 或使用其重载的命名约定。
36. [agent] Keystore.signEDDSAMessage 在 master 校验后，通过 EdwardsCurve.ED25519 常量识别 curveName；其他曲线名返回已有 UNSUPPORTED_CURVE。有效 Ed25519 请求仍以 UNSUPPORTED_CIPHER 占位，等待接上 SLIP-0010 派生和签名；尚未创建曲线上下文或更新能力列表。
37. [agent] 按用户提出的初始化成本标准审查 shared：旧 shared 曲线/HMAC 与 Command 结束请求 GC 已同时存在，不能据此确认原设计假设无 GC。secp256k1 初始化只申请 EC 私钥容器和 ECDH，HMAC 初始化只申请引擎/密钥或 SHA512 fallback，实际装钥和计算仍逐次执行；应区分跨 Command 缓存与同一次派生内复用。2026-10-10 旧实体卡记录中 secp/HMAC/异常对象联合初始化为 266ms；同一 seed/path 复用 ED 上下文派生+导入约 1056ms，重建约 2769ms，差值约 1.713s；均含 APDU/PCSC 等，非当前各构造函数的纯计时。当前 ED 构造仍触发两次随机 EC keypair 生成；忽略目录模拟器实验在 ecKeyGeneration=false/true 两组下各通过 5 条 RFC8032 公钥/签名向量，提示可先优化初始化。未修改生产实现、去除 shared 或测试实体卡；禁用 keygen 的卡片兼容性及节时尚未验证。
38. [user] 200 多毫秒的初始化已是相当大的开销；即使只有数十毫秒，也建议沿用原来的共享对象。当前几秒的 Ed25519 签名是因卡片缺少相关原生算法支持而不得不忍受的速度，不能据此把额外初始化成本视为便宜。初始化成本、shared 复用；修订记录 18 中每次操作都销毁完整上下文的统一策略。
39. [agent] 按用户要求实现 EdwardsCurve.requireSharedCurve，并对齐原有 WeierstrassCurve 结构：静态 ed25519 实例由 init 创建，getSharedCurve 按名称返回现有实例或 null，requireSharedCurve 统一抛 UNSUPPORTED_CURVE，dispose 仅解除引用。获取前需显式 init；尚未接入 Applet 初始化/卸载或替换 Keystore 内的临时名称校验。模拟器直接核对重复获取同一实例、未知名称及 dispose 行为通过，原有 6 项 Ed25519 测试通过；暂存区未改动。
40. [agent] 按用户要求将 EdwardsCurve.init/dispose 接入 MonoidApplet 安装/卸载生命周期，并将 Keystore.signEDDSAMessage 的临时名称判断替换为 EdwardsCurve.requireSharedCurve 调用；尚未接上 SLIP 派生和实际签名，能力列表不变。安装时新增数学初始化后，MonoidAppletTest 与 main.Run 同步设置已有模拟器配置，Gradle run 复用既有 ECCurve 模拟器适配。13 项 Applet 模拟器回归通过，演示 Hello 返回 9000，CAP 转换/校验通过；未测试实体卡，暂存区未改动。
41. [agent] 按用户批准的配置归属调整，CurveED25519 构造器不再修改 MathSupport；MonoidApplet.install 在创建数学资源前统一按 mathCardType 配置，字段按用户反馈增加 math 前缀以明确属于数学库，默认 JCOP4_P71，main.Run 与 Applet 测试在模拟器安装前指定 SIMULATOR。MathSupport 默认值集中到私有 reset，构造及每次 setCard 都恢复默认再应用卡型，消除配置叠加；独立 Ed25519 测试仍在构造前显式配置。配置只应在上下文创建前选择，不支持带着旧上下文运行时切换。29 项模拟器测试、Hello 9000、CAP 转换/校验及 7 种配置之间 49 次切换的全部 19 个字段对比通过；未使用实体卡或修改暂存区。
42. [user] 项目惯例是 feature detection，通过 API 可用性做分支，不按卡片型号或版本匹配，也不在卡内验证功能是否符合实现预期。兼容列表和具体实现的兼容验证结果以文档给出，不编码到 Applet。原有自研实现没有 MathSupport 这种卡型预设；引入的 CardType 列表会暗示对未确认卡片的支持，误导后续使用者。后续数学库适配遵循此方向，取代记录 41 中继续维护卡型配置入口的设计方向。
43. [agent] 移除 MathSupport、全部卡型常量/setCard、MonoidApplet.mathCardType 及模拟器入口配置。MathResources 创建实际使用的引擎：XY 不可用时申请 X，PACE 和 X-only 所需的 ECDSA 辅助不可用时使用已有软件路径，仅 NO_SUCH_ALGORITHM 触发备选分支；不增加卡内验算。BigNat/ECCurve/ECPoint 去除上游型号兼容开关，收敛为当前实体卡使用的 RSA private/NOPAD、固定缓冲长度、精确 EC 位数与原生 keygen 路径。模拟器 EC 容量/KeyBuilder、RSA 重用/长度/补零适配集中在 gradle/simulator.gradle，仅生成 host run/test 源码，CAP 不包含它们。doc/cards.md 明确文档与运行时分支的边界。29 项模拟器回归、Hello 9000 和 CAP 转换/校验通过；未验证本轮实体卡及不可用算法分支对应的真实卡型，Keystore 派生/签名接线仍待完成；暂存区未改动。
44. [agent] 开始将实际使用的 BigNat 运算迁入既有 LibMath，沿用字节数组、偏移、长度和输出缓冲区的接口风格。首步仅迁移 shiftRight，由 BigNatInternal 委托调用，因此模乘和 Ed25519 签名实际使用新实现；保留 0–7 位移位、已左对齐 carry 和原地输出语义。新增独立 BigInteger 对照测试，30 项模拟器测试及 Java Card 3.0.5 CAP 转换和校验通过。其余 BigNat 运算及共享 RSA 资源尚未迁移，本轮未测试实体卡，暂存区未改动。
45. [user] 明确下一阶段重构目标：按当前实际需求，参考 CurveSECP256k1 的组织方式去掉新增的 ECCurve 和 ECPoint；将必要的大整数算法迁入 LibMath，直接用 byte 数组表示大整数，最终去掉 BigNat 和 BigNatInternal。这是阶段目标，不要求一次性完成全部改动。
46. [user] 同意省去 LibMath 的 Derived from 文件头；来源说明和完整第三方许可证集中保留在 third-party/jced25519，并随分发携带，不为每个基础运算重复文件头声明。
47. [agent] 完成记录 45 的全部阶段目标：移除 ECCurve、ECPoint、BigNat、BigNatInternal 及无调用的 MathAllocator/MathStatus；CurveED25519 直接持有共享 255-bit ECPrivateKey 和 XY KeyAgreement，保留 setK(1)、零标量单位点及 Wei→Edwards 转换，无随机 keypair 生成；密钥、nonce、响应和转换值使用 byte[]。LibMath 保留按字节估商取模、模加减、RSA 模平方组合的模乘和 p−2 模逆；MathResources 仅一个共享 RSA512 key/Cipher 和 160B transient scratch。39 项模拟器测试（约 10.8 万次取模对照）、Hello 9000、生产 CAP 转换/验证通过；独立代码审查通过。2026-10-12 同实体卡对比冻结的本轮重构前源码，构造 1808→342ms，Solana 四级 SLIP+导入 939→673ms、150B Message 签名 2088→1417ms；均为独立探针 APDU 时间，不含上下文/派生器初始化，构造一项单列。共享曲线+签名器创建后 deselect 空闲 RAM 1616→3088B，带已导入密钥 1520→2992B；静态显式数组合计 1563→482B，不含原生对象。十组实体卡回归及十组取模微基准通过，clear/deselect/物理 reset 后同上下文可重新导入并正确签名。7A/7B 临时包全部删除，卡片 registry 前后一致，原 Monoid 两个应用可选。外部 API、APP 和暂存区未改动；Keystore EdDSA 接线仍属后续工作。中途逐位取模虽正确但签名约 6.4s，已以最终估商实现替换，不能作为当前性能。来源和许可证集中保留，测试脚本与证据位于忽略的 .research/ed25519/byte-array-refactor-card。 详见 [重构验证记录](./47.md)。
48. [agent] 按用户批准的设计移除 MathResources，将一个 RSA512 key/Cipher 和 160B transient scratch 收入 LibMath 私有静态共享字段，沿用 LibHMACSha512 的 init/dispose 并接入 Applet 安装/卸载；mod、modMult、modInv、modExp 删除 resources 参数，CurveED25519 不再持有或清理数学资源。各运算 finally 仅清理自己负责的数组，嵌套模幂不擦除外层中间值；取模用私有重载承载算法，保持 CAP 的异常处理范围较小。40 项模拟器测试、Hello 9000、CAP 转换/校验和格式检查通过；本轮未使用实体卡，记录 47 的时间与 RAM 实测对应此次调整前的源码，后续硬件复测需先适配忽略目录内的旧探针。未修改暂存区或外部 API。

## b883572

49. [agent] 接通 Keystore.signEDDSAMessage：沿用已有 seed→master 转换，调用 LibSLIP10Ed25519 在 master 副本内派生，再经共享 EdwardsCurve 导入 ED25519Key 并签原始 Message。Signer 入口接收 EdwardsCurve，内部识别 CurveED25519 后调用 LibED25519；finally 清理 Safe 返回的 key 副本、master/派生值和展开密钥，共享原生资源继续保留。41 项模拟器测试及 CAP 转换/校验通过；新增原有认证 0x41 短 APDU 集成测试，从已存 seed/master 分别派生 m/44'/501'/0'/0' 并签 1B Message，与 Node crypto 独立结果一致。能力列表及 Ed25519 ViewKey 尚未接入，长请求传输仍未恢复；本轮未使用实体卡或改动外部 API。
50. [user] Lib 前缀表示静态方法库；同意将 LibSLIP10Ed25519.derive 静态化，每次调用创建一次工作数组、沿路径复用并在 finally 清理，不增加共享状态或 init/dispose。LibED25519 保留绑定曲线及签名工作区的实例结构，重命名为 ED25519Signer；外层 Signer 负责分派，具体签名器实现算法。
51. [user] 同意进一步移除签名器实例，直接调用静态 LibED25519.sign(sharedCurve, ...)。曲线作为参数传入，三个临时数组在方法内创建并在 finally 清零和清理曲线工作区；共享曲线与原生引擎继续复用。此方案取代记录 50 中保留 ED25519Signer 实例的命名与组织决定，Lib 前缀表示静态库的约定继续有效。
52. [agent] 接通原有 0x40 ViewKey 的 Ed25519 公钥查询：Keystore 按记录 30 增加接受 EdwardsCurve 的 seed/master 同名重载；命令按曲线名分派，保留 {publicKey, chainCode} 结构。hardened SLIP-0010 派生后返回 32B 编码公钥和 32B chain code，finally 清理 Safe 返回的 key 副本、master 和展开私钥。42 项模拟器测试及 CAP 转换/校验通过；认证短 APDU 从已存 seed/master 派生 m/44'/501'/0'/0'，公钥与 chain code 均与 Node crypto 独立结果一致。能力声明和长请求传输仍待接入；本轮未使用实体卡或修改暂存区。
53. [agent] 接通 Hello/SystemInformation 共用的能力声明，最终结构按记录 54。CommandSystemInformation 汇总两类曲线及对应 cipher，移除 WeierstrassCurve 和 Signer 中不再使用的独立列表 writer，沿用 Text 常量及 CBOR writer 风格。两条指令测试核对完整嵌套结构和曲线/算法对应关系，15 项 Applet 模拟器回归（含 ECDSA/EdDSA 签名）及 CAP 转换/校验通过；长请求传输仍待接入，本轮未使用实体卡或修改暂存区。
54. [user] 明确批准调整能力声明，将 ciphers 放到对应的 curve 下面：features = {curves: [{name: 'secp256k1', ciphers: ['ecdsa']}, {name: 'ed25519', ciphers: ['eddsa']}] }，移除独立的 features.ciphers；签名请求保持不变。取代记录 53 最初采用的两份独立能力列表。

## 42eda62

55. [agent] 阶段性提交完成后，从单条短 APDU 的完整接收恢复传输层工作：CBORApduReader.receive 显式调用 setIncomingAndReceive，首读完整时直接使用 APDU 缓冲；未收齐时才分配精确长度 transient 数组，后续 receiveBytes(0) 并复制累计。Command 外层 finally 擦除接收副本、解除引用并请求 GC，接收异常不进入业务异常转换；GET RESPONSE 仍走原有路径。17 项接收/Applet 模拟器测试和 CAP 转换/校验通过，覆盖接收状态、255B 请求及空请求拒绝后重试；jCardSim 预装完整请求，不能据此声称真实分批接收路径已验证。本轮未使用实体卡，新增接收改动未提交。跨 APDU 的首/中/末段仍待实现；旧 8192B 上限与 AES 持久缓存是历史实现选择，当前 Sign/LibED25519 需要完整 Message byte[]，下一步需明确长请求缓冲及消息读取方式，不能直接恢复旧暂存实现并声称支持 8KB 签名。
56. [agent] 为接入可分块读取的长请求暂存，将 CBORReader 的底层 getBuffer 抽象替换为 read(offset) 与 read(offset, out, outOffset, length)，组织对齐 CBORWriter；CBORBufferReader 和 CBORApduReader 仍通过现有数组实现，业务解析接口不变，键匹配通过读取接口逐字节比较。22 项 CBOR/接收/Applet 模拟器测试及 CAP 转换/校验通过；尚未增加加密暂存、跨 APDU 状态机或改变签名输入，当前 bytes() 仍分配完整字段副本，不能据此声称长 Message 已不占整块 RAM。未使用实体卡或修改暂存区。
57. [agent] 完成短 APDU 分片接收：CLA 00/90/B0/A0 区分单/首/中/末段，新单/首段替换旧请求，续段须匹配 INS/P1/P2，完整接收后才执行业务。最大请求 8192B，EncryptedBuffer 持久区保存 AES-CBC 密文、每请求换 transient key，RAM 保留 16B 块和少量状态；结束/异常/替换/选择清理密钥和明文块，小型原生资源与存储继续复用。GET RESPONSE 使用 00 C0；收包中返回 6883 并保留请求、无响应返回 6985，错误 C0 头不破坏待续传数据，新请求取消旧响应。CBOR 字段分配/跳过前检查长度，writer 扩容覆盖本次完整需求并擦除旧数组，响应 reset/发送清除对应数据。60 项模拟器测试和两份 Java Card 3.0.5 CAP 转换/校验通过，包含 8192/8193B 边界、替换/错序、选择/复位、512B Message 派生签名独立对照及 600B Create/Get 三段响应。jCardSim 默认新 PRNG 未播种导致每次同序列，已仅在 test/run 启用其安全随机属性；AES KeyBuilder host 适配仅用于模拟器，生产 CAP 无此替换。未使用实体卡，未提交或改变暂存区；真实 receiveBytes 分批交付、当前 RAM/时延仍未验证。当前 bytes() 与签名仍复制整块 Message，不能声称 8KB 签名已能在卡上运行，也未实现全部 Command 解码副本主动清理或旧草稿的空 6100 延迟执行。
58. [user] 覆盖生命周期方法时应保留父类调用，不因当前默认实现为空就省略；MonoidApplet.deselect 应调用 super.deselect，再执行自身清理。
59. [user] 同意移除当前 EncryptedBuffer 方案：既然签名仍要求完整 Message 在 RAM 中，就用 transient 数组拼接完整请求，CBOR 定位 Message 的偏移和长度后直接在原缓冲上签名，避免再分配整块消息副本；外部请求及分片协议保持不变。
60. [agent] 按记录 59 完成重构：CBORApduReader 合并完成状态，按完整 APDU 的累计 Lc 以 256B 粒度扩容 transient 数组，扩容擦除旧数组并请求 GC，结束/错误/替换/选择擦除并释放当前自有缓冲；单段首读完整仍借用 APDU buffer，不存其字段引用且响应发送后不擦除 APDU buffer。CBORReader 恢复统一数组读取，新增 bytesLength/getOffset/getBuffer 定位字段，CommandSign→Keystore→Signer 透传原数组及 Message 区间至已有 LibED25519.sign；移除 EncryptedBuffer、专属测试和 AES host 适配。57 项模拟器测试、两份 CAP 转换/校验及格式检查通过，包含原分片回归、借用与擦除、512/1167B Message 位于 CBOR 首尾的独立签名对照。8192B 保留为协议上限而非预分配容量；扩容的新旧数组在 GC 前可能共存，实体卡峰值 RAM、时延和真实 receiveBytes 分批交付仍未验证。本轮未使用实体卡、未提交、未改变暂存区。
61. [user] Command.dispose 的职责是解除 static 持久引用以支持 Applet 卸载，不承担日常传输清理；移除其 clearTransport 调用，并将仅包装 reset 的 writer.clear 合并回 reset。GET RESPONSE 仍应在接收新请求及重置响应前处理。
62. [agent] 2026-10-12 再次确认源码版本不一致：12:39:43 直接读取的 CBORReader 仍有数组与 Message 区间接口，后续源码却恢复为旧的抽象 read 接口，文件修改时间为 12:51:38，导致子类和 CommandSign 的 Java 诊断；12:58 恢复后，57 项模拟器测试及两份 CAP 转换/校验通过，JDT 对 CBORApduReader/CommandSign 报告 0 problems。已核对的会话写入与格式化记录不能解释覆盖，VS Code 本地历史无该文件近期记录；用户确认该时间段未保存、撤销或接受/恢复更改。覆盖进程及机制尚未确定，不能把编译恢复视为已解决复发原因；暂存区保持不变。
63. [agent] 当前 Monoid API 完成实体卡集成测试，短签名和分片基本流程通过，但末段扩容会造成 transient RAM 不足，详见 [实测结果与限制](./63.md)。未修改内存策略或协议；隔离包清理及原应用回归通过，源码按已刷卡哈希冻结，暂存区未动。
64. [user] 同意将请求保存为固定大小的 transient chunks，并让 CBOR 跨块读取、Ed25519 对 Message 区间遍历两遍；不再拼成连续数组或复制整条 Message，保持外部 API 和现有 APDU 分片协议。仍保留所有 Message 字节，目标是消除请求扩容时新旧数组共存的 RAM 峰值。
65. [agent] 已实现记录 64，60 项模拟器测试、CAP 校验及 14 组实体卡测试通过；255B 分片下 1167B Message 签名和 600B Create 均已通过，详见 [实现及实测](./65.md)。隔离测试包已清理，原应用正常，暂存区未改。
66. [agent] 更正 Message 内存约束的表述：Pure Ed25519 要求原始 Message 可完整重读两遍，并不要求全部同时驻留 RAM；此前是 byte[] 接口和当前 transient chunk 存储的实现限制。若签名直接从持久暂存区分块重读，EncryptedBuffer 可以降低 RAM 占用；客户端重传两遍还需严格的一致性校验。用户要求先提交当前阶段，再讨论后续方案，尚未批准恢复持久暂存或修改传输协议。

## 8abf0c5

67. [agent] 实体卡测得当前纯 RAM 版本的可重复 Message 上限：普通响应缓冲时 seed 1184B、master 1458B；读取 600B 数据后分别降至 928B、946B，详见 [容量边界实测](./67.md)。每组上限加 1B 均失败，全部成功签名与独立实现一致，失败后小消息签名均恢复正常；隔离包清理和原应用复核通过。未修改生产代码或 API。
68. [agent] 按用户要求修复响应缓冲保留容量的问题：按需分配，完整发送/取消/deselect/发送失败后擦除、解除引用并请求 GC，未完成的多段响应继续保留；65 项模拟器测试及 CAP 校验通过，实体卡大响应后仍可正确签 seed 1184B / master 1458B，详见 [修复与复测](./68.md)。记录 67 中大响应造成的持续容量下降已解决；未重新测定修复后的精确上限。
69. [agent] 持久化暂存的加密必要性应基于既定保护目标，而非仅因存储介质是 persistent。Java Card 对象隔离与 Applet 访问控制可保护应用层明文；现有 Safe 也直接持久保存 seed/master。成功卸载重装不会继承旧 Applet 对象，但 reset/断电保留 persistent 内容；仅重装 Monoid 保留独立 Safe 的数据。临时密钥加密额外提供中断后无法解密残留内容的属性，目前未确定有此要求。后续优先评估普通持久缓冲及明确访问/清理规则，尚未实施持久暂存或修改 API；不能将公开 Solana Message 的特性自动推广到所有通用请求。依据 Oracle JCRE §11.3.4.2 与持久对象/防火墙定义，以及当前 Safe 和安装脚本。

## ecae74d

70. [user] 批准按需持久化扩展，并明确小型分段请求仍用 RAM，超过阈值才使用持久存储；不采用所有分段请求一律持久化的方案。
71. [agent] 请求接收器保留前 512B 完整 CBOR 请求于 RAM，溢出部分按 256B 块按需持久分配；持久引用表确保 reset 后仍可擦除未完成请求。69 项模拟器测试、CAP 校验及 9 组实体卡测试通过，8192B 请求可签 seed 8096B / master 8114B Message，详见 [实现与实测](./71.md)。取消/错误/reset/超限恢复通过，隔离包已清理且原应用正常；API 和分片协议保持不变。

## 74a31cd

72. [user] doc/cards.md 面向用户选购卡片，研究过程与详细实测应按 Project Memory 保存到对应数字 MD 文件；README 保持简洁，以命令定义为主，具体传输协议另设对应文档。

## 760dae7

73. [user] 同意按现有 secp256k1 item 结构补齐独立 Ed25519 key：新增 ed25519 类型，保存 32B 私钥 seed，支持导入、随机创建、公钥查询和直接签名；区别于用于层级派生的通用 seed/master。最初的 0x0402 编码由 74 替代；详见 [原实现与验证](./73.md)。

74. [user] 同意将原 EC item 类别明确为 Weierstrass（保持 0x0400/0x0401），Edwards 独立为 0x0500/0x0501；没有 curve 参数的 getECKeyPublicKey 也应按曲线类型区分。详见 [类型与方法拆分](./74.md)。

75. [user] 始终假设当前执行环境可信；移除取得的 key/master 副本及类似用法中纯防御性的敏感数据擦除。功能性初始化、状态失效和资源释放仍保留，详见 [清理边界与验证](./75.md)。

76. [agent] 按用户要求完成当前版实体卡验证和性能对照：发现并修复 Safe 满容量删除的尾槽越界，新增回归先失败后通过；全部 74 项模拟器测试及 CAP 校验通过。旧 Monoid 与当前版共用修复后的 Safe，各通过 16 组实体卡测试和 32 次独立验签，覆盖当前 0x0501、派生、算法切换、最大请求、取消和真实复位。短 Ed25519 中位耗时增加约 2%–2.8%，BTC 基本不变，最大请求略快；空闲 RAM 均恢复到 2320B。所有隔离包成功卸载、注册表恢复原样，未出现本次 AID 无法删除；详见 [删除修复与实卡对照](./76.md)。

## 29d69cb

77. [agent] 按用户许可完成 BIP340/BIP86 基础验证，未改正式 API 或生产源码。复用现有 secp256k1 点乘、LibMath 和 BIP32，模拟器与实体卡各通过 7 组、48 次独立验签和 30 组模乘边界；实卡完整测试命令中位耗时为裸签 417ms、加 TapTweak 544ms、五级派生后签名约 1.10–1.11s。隔离测试包全部卸载、原注册表恢复；尚未集成完整 Monoid 或实现卡内签名自验，详见 [实验范围、数据和限制](./77.md)。

78. [user] 要求按现有 Java Card 结构和风格完整实现并更新文档，并明确批准 0x41 的 schnorr/digest32 与 Sign/ViewKey 可选 taproot 对象：空对象为 BIP86，merkleRoot32 为脚本树承诺，ViewKey 返回调整后 x-only 公钥但保留原节点 chainCode，secp256k1 能力增加 schnorr；详见 [批准的 API](./78.md)。

79. [agent] 完成批准的 Schnorr/Taproot 集成及文档：89 项模拟器测试、CAP 校验和 23 组实卡测试通过，81 次独立验签中含 41 次 Schnorr。复用现有曲线、LibMath 与命令结构；实卡发现 BIP32 每层临时数组及软件 HMAC 工作区累积，改为单次派生内复用，五级减少 916B 数组数据，分片签名恢复。完整 Sign 中位耗时：裸 Schnorr 728ms、独立 BIP86 904ms、五级派生 BIP86 1685ms；空闲 RAM 恢复到 2192B。隔离包已卸载、注册表完全恢复、原应用正常；详见 [实现、内存诊断与验收](./79.md)。

80. [user] 同意将 Sign/ViewKey 的 taproot 扩展为 Taproot | boolean：省略/false 不调整，true/{} 为 BIP86，merkleRoot 对象语义不变；false 与省略完全等价，ECDSA/EdDSA 也允许携带，只有启用时才限制曲线与 cipher。详见 [布尔值语义与验证](./80.md)。

## 239b4cb

81. [agent] 用户授权卸载原 Monoid/Safe 并安装最新版，但原 Monoid 包 F06D6F6E6F696401 与实例 F06D6F6E6F69640101 均拒绝 DELETE（6985），复位后仍失败；已排除 CAP 中新旧 Applet AID 长度导致工具匹配失败。注册表未变，旧实例可 SELECT，但 Hello 返回 6F00；Safe 未尝试删除，最新版尚未安装，未执行 PIN 初始化或更新。详见 [证据与阻塞状态](./81.md)。

82. [agent] 用户换卡后，已将 239b4cb 的正式 Safe/Monoid CAP 安装至新卡，原卡删除问题仍未解决。新卡原无应用实例，无需卸载；正式 AID、复位前后 Hello/SystemInformation、PIN 均未设置和原系统包保留检查通过，连接已释放。新卡 ATR 为 3B8C80015432433134504A34313890009A，尚未在此卡重跑签名测试；详见 [安装与验证](./82.md)。

83. [agent] 用户主动要求找到并导入原有示例 key/seed；已确认 scripts/run.ps1 的 addTestKeys 入口，使用用户提供的当前 PIN 将其固定 seed64、master64、secp256k1 私钥32 三项导入当前卡。卡原无条目，复位后逐项读回、派生公钥及 chainCode 均匹配；保留现有 PIN，未重装或运行完整测试。当前 Monoid ID 为 39DD14B6、Safe ID 仍为 1D73DAB3，详见 [示例导入与验证](./83.md)。

84. [agent] 用户提出参考 Tangem 激光攻击增加冗余认证；核对原始研究与当前源码后，建议讨论授权状态冗余编码、敏感操作边界复核及平台 SensitiveResult，避免简单重复 OwnerPIN.check 消耗多次尝试额度。现有缓存 Safe PIN 检查不等于独立用户认证；尚未实施、未测实体卡，也未批准 API 或会话语义变化，详见 [风险与候选方向](./84.md)。

85. [user] 同意先实现所讨论的授权状态冗余编码与 PIN 写入边界复核，再核对代码；后续实现与验证记录见 [授权加固](./85.md)。

86. [user] 明确假设卡上可安装任意 Applet，不能凭 Monoid AID 信任代码；批准 Safe 内部独立认证并保持方法签名与 APDU 不变。后续优先选择各调用方分别认证、交替使用时保留各自授权；若不可行才退回单一授权并去掉 SafeSession。分析需考虑现实执行顺序，并认可用户未必审查其他 Applet 源码时授权隔离的价值。实现与验证见 [Safe 会话授权](./86.md)。

87. [user] 要求用临时 AID 在实体卡验证 Shareable，并指出同一次刷卡重复获取接口不应清除授权；会话复用、实卡验证、模拟器差异和运行时兼容条件见 [实卡证据与限制](./87.md)。

88. [user] 要求把最新固件以正式 AID 安装到刚换上的卡，并先给测试密钥脚本增加一个 Ed25519 示例后导入；安装、四项示例验证及新卡片 ID 见 [正式安装与示例密钥](./88.md)。

89. [user] 要求调研手机安装 Applet、部署密钥不暴露或一次性签名授权，以及第三方 Applet 能否绕过 GlobalPlatform 安装其他 Applet；进一步明确希望把安装密钥留在卡内，由 Monoid 签署安装信息 digest，再由手机拿签名安装，并询问 SCP03。详见 [研究结果、权限边界与待验证项](./89.md)。

90. [user] 放置测试卡并授权验证 GP 签名安装方案；卡片身份、临时安全域、ECC 配置障碍、Token 对照及清理结果见 [GP 实卡验证](./90.md)。

91. [agent] 社区研究找到 GPShell 3.0.0 的完整 ECC Token/DAP 实现与面向 JCOP 4.5 的实卡测试代码；完整曲线编码、非末片 Le 和长命令 SCP02 包装存在可对照差异，但工具自身拒绝 secp256k1，未找到同款卡的 GP secp256k1 成功日志。NXP 文档明确支持指定 JCOP4 P71 配置的 GP P-256 DAP；本轮未访问卡片，详见 [社区证据与后续验证方向](./91.md)。

92. [agent] 按用户许可完成社区方案的九组实卡对照：精确身份匹配 JCOP4 P71D321/patch1，短 RSA PUT KEY 分片成功，272/275B ECC 与273B RSA 请求末片均6A86，208B本地P-256参数导入6A80；尚未进入ECC验签。所有临时域已清理，原注册表与ISD密钥表完全恢复，详见 [实卡对照及限制](./92.md)。

93. [agent] 继续完成18组GP实卡对照：PUT KEY在第二个128B非末片即6A86，支持累计长度限制的判断；STORE DATA元数据和RSA单包/三段导入成功，P-256与secp256k1均在公钥Q导入阶段6A80，尚未进入ECC验签。另发现PUT KEY Format2报错后仍留下RSA密钥条目，已定位尾字段兼容性并逐域清理；原注册表及ISD密钥保留，详见 [失败位置、对照与清理](./93.md)。

94. [agent] 定位当前 svn144945 对应的厂商手册为 DocNo469542 Rev4.2（2022-08-05），正文需 NXP NDA 与文档授权，公开材料未给出 GP ECC 导入特例。旧版 Amendment E 要求完整 DGI 不跨 APDU，但上轮已按此测试仍失败，故不能解释公钥 Q 的6A80。按用户要求继续查流出资料，找到并保存旧版模拟器手册与标记保密的432810简版数据表公开镜像，仍未找到管理员手册或ECC导入步骤；未访问卡片，详见 [厂商文档与待确认条件](./94.md)。

95. [agent] 按用户明确的本机gp.exe目标静态核对：GlobalPlatformPro24.10.15/f2af9ef的字节码与公开源码一致，EC导入仅固定P-256公钥加曲线引用00，无完整参数或secp256k1分支；内建Token生成仅RSA，可附加外部Token。不能由该主机工具揭示NXP卡端拒绝原因，未访问卡片，详见 [反编译与源码核对](./95.md)。

96. [agent] 按用户许可补测随机P-256公钥：临时域named PUT KEY仍6A88，STORE DATA带reference00的CRT返回6A80；own-parameter路径在合法Q导入时PC/SC0x458失联，重放同一Q在新域中再次复现。用户两次重放卡片后均成功清理，原完整注册表和ISD密钥保留；ECC验签仍未到达，ISD对照未执行，详见 [复现、恢复与证据边界](./96.md)。

97. [user] 明确批准向当前测试卡55690320的ISD写入可能永久保留的标准P-256全局曲线参数00，并继续公钥导入与Token验证；[agent] 已通过STORE DATA164+107B配置成功，随机P-256公钥导入及有效Token加载/安装通过，缺失或错误Load/Install Token四项均6982。全局参数按批准保留，其余临时域/包/实例/密钥全清，详见 [成功路径、对照与最终状态](./97.md)；取代90–96中P-256配置未解决的状态。

## 10426f8

98. [user] 将授权加固目标收敛为抵抗单次翻转，重复检查由31轮减为3轮，保留short宽编码及现有auth反码；要求通用真假常量、复用循环并批准批量完成其余同类检查，按谓词语义选择保守结果，随后同意继续剩余修改并要求实卡测试。[agent] 已接入Safe和Monoid授权路径，并将Access PIN持久状态改为short及反码、与PIN事务写入；Applet导出限制要求每包编译LibSecurity，由Inplate同步一份源码。138项测试、两个CAP及21组实卡验证通过，三种签名独立验签通过，临时应用全清且原注册表一致，详见 [编码结果与保守检查](./98.md)。

## 44ef108

99. [user] 要求开始Security Key第一组ES256算法，先修改Java Card README中的API定义；README按最终交付结果描述，不写计划中或待开发，文档和实现一并完成后提交。API文档只保留必要签名和相关注释，删除近期加入的解释性正文。[agent] 已定义secp256r1独立密钥、0x0402类型、生成/导入、公钥查询和现有ECDSA摘要签名入口；不包含P-256 HD派生或协议接入，详见 [API定义与实现边界](./99.md)。

100. [user] 要求去掉secp256r1后的P-256别名，核对curve/cipher语义并按建议更新README；Cryptography按曲线树状列出cipher，Features使用通用类型并引用该列表；随后要求同步现有常量并排除README提交。[agent] 已将常量、命令分支、能力声明及测试统一为bip340和ed25519，保留Curve名称及ecdsa，修正Bitcoin文档的ECDSA编码说明；138项模拟器测试和两份CAP验证通过，详见 [语义审计与命名边界](./100.md)。

## 7f72789

101. [user] 要求实现用于Passkey的第一种签名方式，并严格沿用现有实现风格。[agent] 已完成独立P-256/ES256的创建、随机生成、公钥查询、签名及能力声明；实卡定位并修正原生ECDSA输出容量假设，改按getLength分配；149项模拟器测试、两份CAP和实卡9组验证通过，临时包已清理，详见 [ES256实现与实卡验证](./101.md)。

102. [user] 不要对可控数据做防御性的验证。[agent] 移除Keystore对已存P-256密钥的重复校验及对应测试，把摘要长度校验移到CommandSign外部请求入口；保留输入与算法本身的必要约束，详见 [信任可控数据](./102.md)。

## c6b426c

103. [user] 要求为list增加data prefix参数的重载，按Data前缀筛选条目。[agent] Safe Java/Shareable新增list(short type, byte[] dataPrefix)，类型与原始字节前缀同时匹配；null或空前缀不限制数据，保持顺序、返回结构及会话授权，Monoid包装层将前缀复制到global array；未扩展APDU请求。151项模拟器测试、两份CAP和格式检查通过；未测试实体卡。

## 697188b

104. [user] 希望为现有secp256r1密钥增加派生能力，供未来Passkey按Credential ID等信息生成专用密钥，允许标准或自定义方案，先讨论建议；检索能力完成后要求提出与现有输入语义自洽的参数。[agent] 比较SLIP-0010、SLIP-0022与HKDF后，建议通用上下文HKDF及P-256拒绝采样，参数提案为独立secp256r1的Key增加derivation:{context}，供ViewKey/Sign共用；尚未获准具体算法/API，也未实现，详见 [派生方案与凭证边界](./104.md)。

105. [user] 接受先List再Sign，选择新增独立key字段并替换data prefix重载；key仅创建时指定，最终保留keyPrefix便于查询自定义数据格式；保留固定index，推测其8字节ID原用于稳定hex展示；要求实卡验证后提交。[agent] 将可检索元数据与私密Data分离，Create写入key，List/View/Get读取，List支持keyPrefix且保持Access授权，取代103的原始Data匹配；修复两个Create路径已有的alias跨Applet复制遗漏，155项模拟器测试、两份CAP及8组实卡测试通过，临时包已清理；600B key返回的RAM限制按106暂不扩展，详见 [检索字段、历史依据与权限边界](./105.md)。

106. [user] 明确要求相对较大数据的支持必须等遇到具体使用场景再考虑，不为假设的极限场景增加卡片实现和验证成本；本轮key预期通常十几个字节，二三十个字节已足够。[agent] 将实际数据规模作为设计和验收依据，已观察到的超出场景的限制如实记录，不据此自动增加缓冲、协议、容量上限或内存管理复杂度。

## 2728592

107. [user] 指出现有path存在隐含语义，询问seed到master遵循的规范，并提出保留基础入口、后续增加BTC/EVM/Solana打包配置的方向；进一步询问以HD钱包惯例作为API上下文如何解读。[agent] 核对BIP32、SLIP-0010与BIP39，明确seed参数实为HMAC标签；修正最初必须新增scheme的倾向，当前可用文档固定每条曲线的HD方案，不必预建通用KDF选择器；区分代码接受扩展节点与API约定master为根节点，重新审视104的context扩展；既有BIP32无效标量处理缺失已记录，尚未修改API或实现，详见 [派生语义与链级预设](./107.md)。

108. [user] 认可显式Key.type与嵌套派生签名，要求仅允许taproot:false的分支直接禁止该参数；随后批准自有派生改从seed/master开始，要求更新README并调整已有实现的API，指出实现方法名也需适配，并要求实卡测试后提交。[agent] ViewKey/Sign接入类型核对与bip32/slip10分支，Keystore使用固定主节点标签并拒绝旧参数及不适用的Taproot；签名方法明确为ED25519/BIP340，派生公钥方法明确BIP32/SLIP10Ed25519；157项模拟器测试及实卡11组验证通过，24次签名独立验签通过，临时包已清理，原卡基线保持一致；monoid-p256-v1算法细节仍需确定，本轮不实现，详见 [显式类型与完整签名约定](./108.md)。

## 59f6e04

109. [user] 开始确定自定义派生算法，讨论用途命名与规范编号，指出版本号容易暗示语义延续，并质疑Monoid Derivation 001与monoid-001的编号关系。[agent] 修正建议为统一规范编号Monoid-001/API monoid-001，另设描述性标题，不另建派生算法编号序列；固定完整派生语义并将用途留给应用context；只是建议，未更改API或算法，详见 [自定义派生规范命名](./109.md)。

110. [user] 批准Monoid-001命名并要求按此前讨论的标准KDF加拒绝采样实现派生。[agent] 接入HKDF-SHA512的Extract/Expand与P-256标量拒绝采样，master为64B PRK，seed/master同源等价；沿用ViewKey/Sign并保持空context有效，明确拒绝不适用的参数；170项模拟器测试与实卡8组验证通过，11次签名独立验签通过，临时包已清理且原卡基线一致，详见 [算法定义与验证](./110.md)。

## 16070d4

111. [user] 要求提交Monoid-001并开始统一派生缓存，直接改造三个Lib类；随后要求全局共用32条缓存并扩大实卡覆盖。[agent] 已提交Monoid-001；三类改为KeyDerivation子类，由Keystore复用实例；全局32条持久缓存按FIFO淘汰，匹配实例及完整master/input，事务发布条目和游标，命中返回操作副本且不写持久存储；183项模拟器测试及实卡14组验证通过，65组交替派生、41次独立验签、132次公钥核对，空闲RAM读数稳定，临时包已清理，详见 [统一派生缓存](./111.md)。

## 9e9d45c

112. [user] 询问历史签名耗时差异，随后批准修复持久CBOR游标并实卡对照。[agent] 五个标量和四组快照迁入CLEAR_ON_DESELECT，解析/API不变；184项模拟器测试通过，同卡两版264次操作、146次独立验签及复位恢复通过。直接ECDSA约996→635ms，缓存BIP32签名1472→884ms、Monoid-001 1520→901ms、300B Ed25519 3410→2746ms，实测RAM增加80B；临时包已清理，详见 [签名耗时与CBOR游标修复](./112.md)。

113. [user] 要求协调Payload装配与顺序读取、核对历史并独立记录skill，随后要求同Payload顺序遍历实测并授权有效后继续实现。[agent] 历史确认2025-07-17的cd1fade改为从map首部查找；336次三模式实卡探针测得顺序解析约108–164ms，重复查找约287–496ms。Sign/ViewKey接入CBORMap字段偏移索引，保留乱序、首个重复字段和按算法读取；192项模拟器测试与两版278次实卡操作通过，156次独立验签，直接ECDSA 630→517ms、BIP32 879→679ms、Monoid-001 901→688ms，空闲RAM不变；临时包清理并将全部13条CBOR命令的推荐顺序提取到cbor-field-order.json供APP读取，提供JS重排模板及5项通过的Node测试，并更新skill，详见 [CBOR读取顺序与成本](./113.md)。

## 1bb6f1b

114. [user] 要求先提交当前代码，再将最新Applet安装到已放好的APP测试卡，后续由APP会话接入和用户验收。[agent] 已提交CBOR改动并将正式Safe/Monoid安装至51433520；旧Safe接口需同步更新，重装前核对四个公开测试密钥，随后恢复原数据、索引、DeFi别名及PIN。新Monoid ID为304BC794、Safe ID为FC512DFA；复位、数据/公钥、7次独立签名验证及最终应用列表检查通过，读卡器已释放，详见 [APP测试卡安装](./114.md)。

## 428ab67

115. [user] 要求可选条目的端到端加密双卡备份，接受多次交替刷卡；批准独立Identity/Safe/Monoid包编号00/01/02，Identity只持有长期密钥及随机4B ID、无PIN，提供通信密钥加解密；比较两种GHASH后选定软件版，要求完整AES-GCM接入及实卡计时，并测试多记录所需的更大数据。[agent] 已实现四个Identity SIO接口及固定P-256 HPKE Auth封装，Safe委托读取ID；原生GCM缺失由软件CTR/GHASH与原生AES解决，协议不变。216项模拟器测试及实卡完整互操作、篡改拒绝、复位恢复通过；修复实卡Util.arrayCompare有符号排序导致的公钥误拒绝及标量采样偏差。32B密钥加密/解密中位597/552ms，含探针GC为658/613ms；原ID生命周期及卸载验证保留。后续独立大负载GCM测试通过581条实卡/755条模拟APDU及8项定向单测：1KB RAM加解密各约5.65s，持久缓冲约8.45/8.54s，4KB持久缓冲33.53/33.84s；探针4KB RAM分配不足，持久缓冲及篡改恢复正确。临时包全清、原注册表及密钥元数据一致，未修改APP或安装正式AID；以上大负载为算法探针，条目备份仍未接入，详见 [备份、稳定身份与AID分配](./115.md)。

## a0d0a7f

116. [user] 接受Identity保持小接口、Safe处理条目GCM、Monoid负责传输的分工，要求先提交再确定API；批准Secret标记、精简后的Get/Set/Export/Import及随机生成项固定secret，随后选择Hello.safe.publicKey并授权实现；之后批准Hello增加可选safe布尔值，省略/false不返回Safe区块、true返回完整信息。[agent] 已提交Identity/GCM阶段结果a0d0a7f，未推送且保留无关暂存SVG。本轮接入上述API：Get普通认证且仅返回非secret数据；Set数据和flag原子更新，单独降级拒绝；Export为Safe PIN、Import普通认证并保留index/元数据/secret，完全重复成功、冲突6985。Safe内完成HPKE通信密钥封装及AES-GCM条目加密，每条144B开销；Identity接口按调用取得，不持久缓存。239项模拟器测试及CAP检查通过，实卡主suite162次操作验证32/256B普通与secret条目往返、篡改/权限/冲突、P-256及传输后Ed25519签名；32B热Export/Import约1.47/1.53s，256B约2.80/3.60s。诊断后去除跨SIO重复复制、短响应借APDU、精简共享上下文，并仅在RAM不足时将Import私有明文工作区回退持久空间；同版本前后测得上下文reset RAM增量由1213降至628B，最终查询余量1412/1408B不是峰值。补充60次操作验证256B tag错误不发布及正常恢复、传输后未缓存BIP32/ECDSA和BIP340/Taproot、保留Identity实际卸装Safe/Monoid后的加密恢复及签名；临时包全清、原注册表/SELECT/Hello基线一致，正式CAP验证但未部署。README保持签名式文档，封装规范独立至doc/item-transfer.md；历史草案已由当前实现覆盖，验证与SIO/任意收件公钥信任边界详见 [条目导出导入](./116.md)。

117. [user] 要求使用两张没有锁 AID 的新卡安装最新应用、在第一张生成测试数据后进行双卡复制；明确允许清空源卡已有旧 Monoid 包。[agent] 已完成56050420（Safe ID9BF4F117）到56038920（958A7EFA）的实卡复制：两卡保留同版正式Identity/Safe/Monoid及系统注册表，Identity公钥不同。64B seed、三种独立私钥、32/256B普通数据共6项经加密导出导入，保留index/key/alias/secret；源列表不变，重复导入后目标仍恰好6项。两卡8公钥及HD chainCode一致，各10次独立签名验真，未读取私钥明文。六项Export/首次Import命令累计10.836/11.053s，排除认证、核对和换卡；读卡器释放，未改生产代码或提交，详见 [双实体卡加密复制](./117.md)。

## d64d0fb

118. [user] 将当前卡命名为 Test 1、上一张卡命名为 Test 2，要求记录以便经常复用。[agent] 按刚完成的实卡身份核对：Test 1 = CPLC序列号56050420、Safe ID9BF4F117；Test 2 = 56038920、Safe ID958A7EFA。二者分别是记录117双卡测试的源卡和目标卡，但名称不绑定后续复制方向。操作前仍核对实际卡身份，PIN不写入项目记忆。

119. [user] 要求升级APP测试卡并保留原有密钥，明确这些导入密钥即使是公开测试材料也应为secret:true。[agent] 实卡51433520的4项数据逐字节匹配旧fixture，保留当前defi/test/空别名及原索引、PIN后，从旧Safe00/Monoid01迁移为d64d0fb的Identity00/Safe01/Monoid02；最终四项均secret，Safe ID839FA0FD、Monoid IDAA0FCB9E。冷复位、4项加密导出解密核对、Safe PIN明文Get拒绝、7次独立验签及系统注册表一致性检查通过，读卡器释放，详见 [APP测试卡三Applet迁移](./119.md)。

120. [user] 批准将build-install的两个开关替换为Install、ReinstallMonoid、ReinstallSafe三个互斥Mode，默认ReinstallMonoid。[agent] 脚本改为ValidateSet及三个显式分支：Install按Identity→Safe→Monoid首次安装；ReinstallMonoid只卸装Monoid；ReinstallSafe先卸Monoid/Safe再按Safe→Monoid安装，保留Identity但不备份恢复Safe数据。保留构建/GP失败即停止及成功后RunCommands的行为，README补充调用示例。20项隔离替身检查覆盖默认值、三种顺序、参数传递、无效Mode、构建失败及每一步GP失败；格式检查通过，未执行真实构建或访问实体卡。

121. [user] 批准将响应writer改为按需追加chunk，保留小响应借用APDU及首次搬出前缀的一次复制。[agent] CBORBufferWriter/CBORApduWriter改用256B transient块与持久引用表，增长不替换旧块，直接分块发送；逆序释放保持中断后的连续引用，List/GET RESPONSE协议不变。12项writer及完整242项模拟器测试、三份CAP转换验证、格式与模板检查通过；未访问实体卡，尚未测量List实卡上限或峰值，详见 [响应writer按需追加chunk](./121.md)。

122. [user] 希望List返回数量不受RAM容量限制，明确单条元数据不大且仍打包分包发送；批准writer按需持久化、Safe逐项枚举及复用条目读取缓冲。[agent] 保留一次执行生成完整响应，writer前512B为RAM、后续256B块按需持久化；Safe.list返回带count/maxMetadataLength/next的枚举SIO，游标与私有prefix为RESET transient，List使用单个global缓冲读取index/key/alias，保持原API与null/empty语义。249项模拟器测试、三份CAP、格式及模板检查通过，包括40项List、512/513B边界、授权撤销与清理恢复。未访问实体卡，实际耗时/峰值未测；Safe/Monoid须成对更新，既有short响应长度限制仍在，详见 [List逐项枚举与响应持久化](./122.md)。

123. [user] 要求先实测不复用条目读取缓冲时的GC行为，如能回收则偏向原有可读getter。[agent] 卡55690320隔离测试五种模式：复用、无参getter、逐条请求GC、退出helper再请求GC、helper不请求GC。10/40/80/120条共28次List含失败恢复；复用最低可用RESET为1557B且120条成功，不复用40条只剩192B、80/120条均在第46条getKey耗尽RAM，两种显式GC也无效；完整响应清理后恢复2112B。因此保留复用，没有修改正式源码或暂存区；25项隔离模拟器测试和三份CAP检查通过，临时包已清理、原注册表与SELECT/Hello基线一致、读卡器释放，详见 [List getter的实卡GC对照](./123.md)。

124. [user] 希望处理接近满卡时List失败而无法发现index的问题，并要求先做持久空间不足的实卡GC对照再决定枚举接口。[agent] 卡55690320的六档36次主体对照确认：120条仅枚举消耗2480B、完整响应消耗10128B，2080B余量时仅枚举完成97条后next失败，逐条GC无改善；后续APDU均回收。补充同一iterator分批实测：每批4/8条在APDU边界回收80/160B，创建iterator后仅余512B时每批4条仍完成120条，8条则失败。因此支持保留现有next接口，后续用GET RESPONSE驱动有限量枚举/编码；尚未实现正式流式List。五个隔离包全清、原注册表/行为基线一致，生产源码与暂存树未动，详见 [满卡List可读性](./124.md)。

125. [user] 批准CBORResponse逐单元生成、writer固定RAM窗口打包续传及每APDU最多4条的方案，明确保留现有枚举接口。[agent] List接入固定RAM窗口与GET RESPONSE逐包枚举/GC，保留旧缓冲响应及Safe SIO；267项模拟器测试、三份正式CAP、格式与模板检查通过。实卡55690320的120条/7569B响应分30包，基线16.780s；剩余2080B/1056B仍完整返回，544B时List和已知index的Get均返回INTERNAL，释放占位后恢复。取消/重选/错误GET续传检查通过，所有完成边界内存读数恢复；四个临时包全清，原注册表/响应基线和暂存区不变，详见 [List流式响应与分批枚举](./125.md)。

## 1e5a5d8

126. [user] 要求提交前序改动并增加4KiB持久空间写入guard，随后要求只在写入前检查并加入预计数据长度，接受少量对象开销、不再写后复查；要求再次实卡测试后提交。[agent] 前序改动已提交；Safe按新增数组和完整目录扩容长度预估，不足预计长度+4096B时返回6A84。当前版本通过273项测试、三个CAP及格式/模板检查；卡55690320的89个验证命令符合预期，包括7次低空间6A84、原值保留、读取/删除及释放后的创建/导入恢复。四个临时包全清，原注册表及应用行为基线一致。保留既有Set逐字段更新语义，详见 [Safe持久空间写入guard](./126.md)。

## 37c30cd

127. [user] 要求全路径派生缓存覆盖seed和公钥，并核对Solana历史耗时及回退。[agent] 全局32条FIFO按算法/原始seed或master/来源类型/完整path或context保存DerivedKey；命中跳过master及路径派生，并复用公钥和Ed25519展开结果，复位后恢复工作密钥、每次仍重新计算nonce。281项单测及三个手动检查、三份CAP、格式/模板检查通过；同卡55690320两版各95条命令、46公钥及含补充对照的118次签名独立核对通过，View中位1093→621ms、300B Sign2617→2086ms、冷复位首次View加空Sign3662→2662ms，空闲RAM一致。直接密钥对照也快约80–92ms；192条独立RSA探针复现持久key实例参数设置可差5.33ms/次，因此上述为整版收益而非纯缓存微基准。四个临时包全清、原注册表/SELECT/Hello保持；历史解析回退及计时边界详见 [全路径缓存与Solana耗时](./127.md)。

## f8d1fb3

128. [user] 希望解决单条Safe Item的data过大时操作耗尽RAM的问题，并明确批准SafeDataShareable长度/范围读取接口及相关Safe SIO签名调整。[agent] 保留单个Index及持久byte[]，输入按块复制，Get/Export复用固定窗口响应；大加密工作区使用临时持久空间，APDU/CBOR及8192B请求上限不变。实卡发现并修复合法version0导致每APDU重复分配16B的初始化缺陷。301项测试、三个CAP通过；卡55690320最终192项命令记录验证普通读写到8000B、独立加密往返到4097B及三种曲线验签。8000B创建/读取/替换约2.15/2.93/1.87s，4097B加密导出/导入约36.29/36.07s；各档空闲RAM一致但未测峰值。所有临时包已清，原注册表及应用行为基线一致，未正式部署，详见 [Safe Item分块读写](./128.md)。

129. [user] 审阅PIN原子性修改后，指出并列API参数要求不一致且不同步可恢复，要求撤回。[agent] 恢复原有PIN分步更新与包装器内部global复制，删除专属测试，保留大data改动和暂存区；Set未修改。当前Safe PIN认证后重复设置相同PIN可同步缓存，单独认证不刷新副本。已撤回方案的308项测试及46条实卡命令证据仅作研究记录，详见 [PIN原子性尝试与撤回](./129.md)。

## e2abc6e

130. [user] 要求添加卸载所有Monoid Applet的脚本。[agent] 新增scripts/uninstall.ps1，可选Reader；通过GP注册表From归属枚举正式02/01/00包实例，依次先删实例再删包，覆盖旧版AID、多实例及部分安装，无需CAP或构建。跳过未安装项，GP失败即停止，不使用force、不删除其他包；执行会清除Safe数据及Identity。AID由Inplate同步，README给出调用方式；Windows PowerShell5.1下24组隔离mock检查通过，含历史实卡注册表fixture，格式与模板检查通过，未执行实卡卸载。

## ae6a2e9

131. [user] 要求设计卡上Security Key Applet及Monoid对其他Applet的授权流程，未来由APP管理授权；提出通过Safe Item Type授权管理凭证记录，并明确FIDO PIN由Security Key Applet自行保存验证；要求UP等缺乏硬件验证手段的声明默认开启以方便早期调试，后续允许用户在APP关闭。[agent] 提议CTAP前端、Monoid受限签名/Type范围数据访问、Safe持久授权/凭证分层，授权绑定安装实例且每次核对，与CTAP PIN/UV分离；软件UP策略不等于跳过真实PIN/授权检查或统一置真所有协议字段。识别CLEAR_ON_DESELECT跨上下文限制、CAP接口依赖阻碍独立升级、普通可编辑Safe Item不宜保存授权表等边界。仅设计研究，具体API未批准、未改生产代码或访问实卡，详见 [Security Key与Applet授权草案](./131.md)。

132. [user] 要求先验证Applet切换流程。[agent] 在55690320隔离验证Client→Monoid SIO→Safe的Monoid-001/P-256派生签名；原路径因DESELECT失败，改RESET后未缓存派生仍失败，单独启用SHA-512 externalAccess后通过。完成12轮普通APDU/SIO交替、冷复位及保留客户端/Safe/Identity独立卸装Monoid，60次独立验签和14次公钥对照通过；切回Monoid需重验普通命令认证，每轮空闲RAM稳定。模拟器368断言通过但不模拟完整防火墙且验签使用显式host shim。接口CAP独立及不持久持有SIO的卸载方案可行，正式授权/CTAP/API未实现；临时包全清、原注册表和SELECT/Hello基线一致，详见 [Applet切换与SIO签名验证](./132.md)。

133. [user] 在核对真实SIO流程及Safe既有RESET用法后，批准正式接入相关适配。[agent] P-256/Monoid-001初始化、派生、缓存工作副本和ECDSA结果迁为RESET；SHA-512/HMAC/ECDH启用externalAccess，保留原DESELECT复制方法及命令认证/传输生命周期。新增切换保留、复位清零和缓存恢复测试；302项模拟器测试、三份CAP及格式/模板检查通过。冻结正式源码实卡验证SIO派生签名、6轮入口交替、复位和8组既有算法，累计68次独立验签、25次公钥核对；临时实例/包全清、原卡基线一致。正式SIO授权API和CTAP仍未新增，详见 [P-256共享签名正式适配](./133.md)。

## 633e4d1

134. [user] 要求继续Security Key接入；授权允许多把固定密钥（client不能继续派生）和一个seed同时存在，types/keys/seed均可选且独立；types简化为[type,writable]，不再细分创建/修改/删除权限；seed仅用于Monoid-001，domain在001派生阶段加入。[agent] writable布尔值false为只读、true为读写，未列出type无权限；同步token/tokenHash及Monoid私钥边界，撤回通用domain-master和互斥授权方向；省略/空数组不授予该能力，Set整体替换时省略会清除旧能力。建议固定密钥按当前grant内keySlot选择，domain/clientContext做长度分隔；固定Key保持原标准派生结果。整体管理/SIO接口、选择器及精确编码仍需确认，仅P-256已有SIO实卡验证，其他算法需适配。未改生产源码或访问实卡，详见 [Applet授权API提案](./134.md)。

135. [user] 要求实卡测量32B token的SHA-256耗时。[agent] 卡55690320隔离探针240条命令全部校验，复用原生共享引擎的16/64/256轮差分约2.37ms/次；完整单次APDU直接7.70ms、SIO9.44ms，重新创建引擎加hash分别28.88/30.59ms，比复用多约21.2ms。三CAP及15项哈希检查通过，两实例/三包已清理，原注册表和应用基线一致，读卡器释放。正式授权API仍未批准，未改生产源码，详见 [原生SHA-256 token计时](./135.md)。

136. [user] 批准移除整个项目的对外master支持并前移后续type；APP交给其他会话。[agent] Java Card已删除master条目、创建及ViewKey/Sign入口，secp256k1/secp256r1/Ed25519改为0301/0302/0401，内部seed→master算法与缓存保留；旧master/曲线类型的index和导出数据不能直接沿用，不含数据迁移或实卡部署。更新文档、示例和拒绝旧入口/新type映射测试，304项模拟器测试、三个CAP转换校验及Prettier/Inplate通过。用户回忆master源于Megnat时期Tangem SDK流程，当前SDK可佐证该模式但不能确认历史版本；entropy只对应助记词，passphrase参与之后的seed计算。详见 [移除对外master支持](./136.md)。

## 5cabdcb

137. [user] 批准按原结构合并Monoid/Safe，Identity暂不更名；默认Install，仅明确ReinstallMonoid清数据；原型尚无用户，不加旧布局拦截或迁移，要求实卡通过后提交。未来逐卡锁定仅作为兼容方向，不实现、不展开。[agent] Safe合并存储类与包装层，条目/枚举/数据收归Monoid02，去掉独立Safe CAP和SIO/session；Identity00改为接受Monoid，保留外部协议及PIN语义。294项测试、两CAP和格式/模板检查通过；卡55690320临时E0/E2验证29次独立验签、分段读写/List、加密导入导出、PIN及保留Identity重装恢复。修正测试对signed-short类型编码及类别筛选的假设，生产CBOR未改；临时包全清、原卡基线一致，未正式部署。后续Type授权和Safe PIN不能预设覆盖secret，详见 [合并存储与未来导出锁](./137.md)。

## b8898d7

138. [user] 确定固定成员多卡Bundle、Identity内密钥不可读、入组后仅Bundle导出、保留非对称接收；最终为0x23 Create Bundle、0x24 Import Bundle、0x25 Reset Bundle。创建生成新K并替换本卡Bundle，一次返回hash及按请求顺序排除自身的全部成员包；目标卡任意顺序导入并直接比较响应hash，无额外回刷。[agent] 完成独立HPKE入组域、95B开销Bundle条目、固定名单原子发布/幂等/冲突检查，完整通信加解密留Identity，APDU/PIN/存储/签名留Monoid；Reset保留身份/条目/PIN，不属永久锁卡。统一monoididentity/MonoidIdentityApplet/IdentityShareable、`MONOID_IDENTITY_*`及CAP名，AID不变。提前申请global64及响应window、Import直接返回预留global32的实际hash，解决两次实卡RAM失败。最终310项JUnit零失败错误跳过、5项JS、两CAP零警告错误且verify、全仓格式/模板/diff通过；249源/生成input哈希一致。卡55690320与两个独立host密码学peer完成91/91操作，覆盖V1/V2至1024B、Secret/分片/篡改、双包顺序与hash、替换/重置/幂等/冲突及响应取消/复位恢复；三卡验证为模拟器。全部临时E0/E2清理，registry及原应用基线一致，未正式部署或提交推送。详细单次耗时与证据见 [Bundle导出策略](./138.md)。
139. [user] 确定Hello直接返回全部信息、Identity稳定ID、publicKey/bundle外层、pins:{access,safe}、bundle为byte[]|false，删除safe开关/嵌套结构/unlocked/features；APP未来重装预期同步两PIN。[agent] 已实现请求{}与version/id/publicKey/bundle/pins响应，能力仍由System Information提供；删除Monoid随机ID及持久SafePIN副本/自动复验，内部Safe访问按当前Command授权和PIN已设未锁检查，Access操作不再重置Safe错误次数。APP自动同步未实现，重装仍清条目和两PIN、保留Identity/Bundle。最终310项JUnit、5项JS、两CAP及全仓格式/模板/diff通过；实卡91/91通过，复位清授权但保留身份/Bundle/PIN/条目；Hello零散单次约215ms（无Bundle）/235ms（有Bundle），非专门benchmark。临时包全清、原基线一致，未正式部署或提交推送，详见 [Hello合并后语义](./139.md)。

140. [user] 要求依次卸载三张测试卡上的旧版Monoid包。[agent] 2026-10-19分别核对Test 1（CPLC56050420）、Test 2（CPLC56038920）及APP测试卡（CPLC51433520），执行当时的scripts/uninstall.ps1，按02→01→00删除各卡三个正式Applet及所属包，旧Safe数据/PIN和Identity密钥随卸载清除；旧显示ID仅保留为历史标识。三卡卸载后均复查Monoid注册表项全部消失，其余系统包和ISD条目不变，未安装新版本。证据分别保存在忽略目录.research/uninstall-56050420-20261019-211855/、.research/uninstall-56038920-20261019-212041/及.research/uninstall-51433520-20261019-212236/的before、uninstall、after日志。

141. [user] 要求卸载脚本去掉向后兼容。[agent] 完成三张旧卡卸载后，scripts/uninstall.ps1仅处理当前Monoid02和Identity00，删除独立Safe01条目及Inplate中的LEGACY_MONOID_SAFE_PACKAGE_AID；保留按注册表From发现实例、跳过缺失包和出错停止。README已符合两包布局。PowerShell语法、Inplate及定向格式/diff检查通过；未提交推送。

142. [user] 要求测Bundle内存峰值，并考虑少写多读数据直接持久化的性能；得知AES固定16B分组后撤回扩大到32B缓冲的提议。[agent] 卡51433520控制92/92、插桩152/152通过，最低可查询RESET为ImportBundle39B、非对称256B导出/导入68/69B；1024B大数组本就持久化，余量反而更多。同卡三种未插桩分配策略各63/63通过，输入副本持久化令32/256B导入增加22–26ms，全私有数组持久化令256B传输增加750–890ms；逐字节持久输出是源码支持的解释，复用16B工作区批量写出仍未实现或验证。替代策略仅测空闲RAM，未量化其峰值；全部E0/E2已清、原注册表/正式源/暂存区保持，详见 [Bundle峰值与持久存储性能](./142.md)。

143. [user] 批准复用16B缓冲批量写出AES-GCM，再测持久临时数组代价。[agent] 正式源码仅修改AES输出，分配策略不变；310项测试、两CAP及126次性能/152次峰值实卡操作通过。原策略1024B传输四个单样本快25.7–28.9%；持久私有数组实验的256B额外耗时由30.6–35.3%降至3.9–4.7%。组合实验最低RESET非对称256B导入/导出69/68→702/710B，重新导入Bundle39→249B，仍非充裕或全操作顺序保证；不能归因为单独AES改动。E0/E2全部清理，registry恢复、原暂存及无关改动保持，未正式部署或提交，详见 [AES-GCM分组写出与持久化复测](./143.md)。

144. [user] 要求对比16B/64B缓冲，并追问两套AES-GCM上下文含义。[agent] 同卡51433520四隔离版本对照，16项离线测试及CAP验证通过；三组各71/71，当前策略64B第19次256B非对称导出失败，诊断6F22确认Result.read的64B global分配NO_TRANSIENT_SPACE。持久策略64B相对16B，256B快1.1–1.4%、1024B快1.6–2.0%，均三次样本；warm RAM少96B，对应通信密钥/条目数据两套AES各多48B。正式保留16B，研究版本未采用；两套调用顺序允许考虑共享底层实例，但未实现测量。临时包全部清理、原registry/源码/暂存保持，详见 [AES-GCM缓冲大小对照](./144.md)。

145. [user] 批准共享一个AES-GCM实例、保留16B缓冲，要求实卡比较内存与性能。[agent] Identity按需持有并注入两条路径，各自AESKey/协议状态保留，APDU/SIO与分配策略不变。310项测试、两CAP及同卡51433520两组各71次性能/152次插桩检查通过；预热空闲RESET1537→1640B，256B非对称导入/导出最低69/68→172/171B，Bundle重新入组39→142B；初始化后137条匹配操作均+103B。14场景三样本中位变化−0.10%至+0.65%，最大+44ms，不能视为完全零成本；少写多读私有数组直接持久化仍仅为实验。临时包全清、registry及原暂存/无关改动保持，未正式部署或提交推送，详见 [Identity共享AES-GCM实例](./145.md)。

146. [user] 批准将临时私有数组直接持久化，保留共享AES-GCM和16B缓冲，并要求实卡核对组合收益；确认小数据传输的额外耗时可以接受。[agent] 两个分配helper改为new byte[]，删除RAM阈值/异常回退，310项测试和两CAP通过。本轮卡51433520新增142次性能及152次内存操作全通过，内存基线明确复用145；256B非对称导入/导出最低RESET172/171→805/813B，重新入组142→352B，99项改善、53项不变；签名后256B Bundle导出/导入459/474→842/836B，重复三次稳定。32/256B传输多31–127ms、3.46–4.57%，1024B基本不变，空闲RAM不变。检查点不代表完整原生峰值或所有操作顺序；新增临时持久写入/占用，未测满卡或耐久。解释入组tag校验与同密钥/名单幂等、不同配置拒绝。临时包全清、registry恢复，未正式部署或提交，详见 [通信临时私有数组持久化](./146.md)。

147. [user] 批准Reader增加显式bytesGlobal两重载，Bundle导入直接读取global并删除再次复制，默认分配不变。[agent] 三份生产源码调整，312项测试、两正式CAP和四组各40次实卡命令通过；同卡51433520两版性能/峰值均本轮重新构建测量。三成员正常/幂等导入最低采样RESET352→720B，净增368B；接收点和最终空闲RAM不变，移除376B载荷不等于精确净收益。三样本中位1040.084→1007.846ms、1020.511→980.351ms，快3.10%/3.94%；独立解密确认真实密钥，冲突/tag拒绝/恢复/SELECT/ResetBundle均通过。保持共享AES、16B和持久私有数组，不默认global；引用只在调用链内传递。临时包全清、registry恢复，外部暂存的上轮内容保留，无无关源码改动；未正式部署或提交推送，详见 [Bundle导入直接读取global数组](./147.md)。

## 837bc04

148. [user] 批准按真实调用方完整AID派生私有token及隔离加解密；Bundle先从根密钥派生调用方密钥，管理限唯一Monoid AID；去掉全部Applet AID版本后缀。明确两张Bundle卡加源Safe PIN、保留目标Identity后替换Monoid取得明文是认可的迁出功能。[agent] 实现首命令前持久绑定、后续本地三轮完整字节比较且不自动重绑；开放其他Applet同AID跨卡传输，固定Monoid管理权限、独立版本常量与生成配置；两种信封绑定运行时AID、旧密文不兼容。更新协议与恢复边界文档，验证详情见 [稳定AID与调用方隔离](./148.md)。

149. [user] 要求实卡测新增检查开销。[agent] 卡55690320旧版/新版/只跳过重复检查的新版三组计时，加两组内存，384次命令全通过。完整单次token检查路径净增57–95ms，Hello三次约263ms；旧→新Hello220→468ms，三成员Create2395→2652ms。固定RAM多占179B，另每次token占global32B，创建Bundle最低648→373B，导入676→465B。10个隔离CAP通过验证，临时包全清、原注册表/响应不变，未改生产实现或提交；详见 [Identity检查的实卡开销](./149.md)。

150. [user] 提议Identity按AID缓存固定token以避免重复计算。[agent] 实现32槽持久FIFO，完整运行时AID三轮核对、私有字节持有/global副本、事务发布及已有事务跳过写缓存；复位/淘汰不改变结果，API与公式不变。325项JUnit、2正式及8隔离CAP通过；卡55690320缓存前后278次命令全通过，Hello中位467.73→391.84ms，复位后467.86→391.82ms，Bundle导出约省28ms；所有空闲及17项采样最低RAM不变。探针确认后续及复位后命中且无HMAC。临时包已清，原registry/响应保留，未正式部署或提交；详见 [Identity持久token缓存](./150.md)。

151. [user] 要求先去掉每次token校验的持久副本并测改善。[agent] Safe直接以global局部变量调用LibSecurity包内数组重载，移除候选字段/回调；三轮比较及计数检查、首次持久绑定、缓存、HMAC和PIN路径不变。327项JUnit、两正式及8隔离CAP通过；卡55690320两版278次操作全通过，Hello391.65→266.18ms（快32.04%），Create Bundle2634.49→2484.06ms，传输省18–62ms；对照基本不变，空闲及17项最低采样RAM均不变。临时包全清、原registry/响应保留，未正式部署或提交；详见 [直接比较global token](./151.md)。

152. [user] 要求将AID三次加入token hash，实卡测性能通过后提交推送。[agent] 缓存未命中时三轮独立读取运行时完整AID并立即加入HMAC，复用原16B数组；缓存/最终三轮比较、首次绑定和PIN不变，新token不自动重绑。329项JUnit、5项JS、两正式和12隔离CAP通过；卡55690320两版310次操作全通过，重算完整请求144.28→147.57ms（+3.29ms），命中77.48→77.46ms、Hello266.44→266.50ms；16项业务区间重叠，17项RAM最低值和空闲读数均不变。临时包全清、原registry/响应保留，未正式部署，详见 [三次AID输入](./152.md)。

## 5df1f5e

153. [user] 批准开始Applet授权管理，命令从0x50开始、接口与Monoid同包，不另拆API CAP。[agent] 实现0x50/51/52及客户端身份接口，types/keys/seed独立可选，Secret PIN管理、Set整份原子替换、Reset同事务清目录；客户端安装时随机token的hash通过SIO取得，回调后复核授权，不保留客户端对象。369 JUnit/6 JS/两份生产CAP通过；55690320实卡80个逻辑交互验证回调失效拒绝、客户端重装及Reset回滚/清空，临时E0/E2/E3已清，原registry和SELECT/Hello结果不变。四Key完整Set约2.06s、399B List约612ms；只修主机runner的secret:false，卡端源码不变。数据/签名服务SIO仍未实现，未正式部署或提交；见 [授权管理接入](./153.md)。

154. [user] 批准0x23 Create Bundle和0x24 Join Bundle，Create拒绝覆盖已有Bundle；恢复0xFF Reset并要求无需PIN、空请求/响应。[agent] 0686ab4实现同事务清条目/派生缓存/Bundle，却误解为保留两PIN及锁死状态，已被157纠正。Import统一改Join，0x25不支持，Bundle安全分支三轮保守检查。该旧版334项JUnit、5项JS、两CAP及隔离卡55690320的161次操作/满32缓存跨SIO回滚均通过，临时包清理且原卡基线保留；这些证据不验证157的新语义，详见 [Bundle创建/加入与原子Reset历史](./154.md)。

155. [user] 希望用专门文档集中安全边界及此前约定，供后续audit作基准。[agent] 新增doc/security.md并从README/架构链接，按当前合并架构核对PIN权限、Secret、Identity/AID隔离、Bundle固定成员和认可的同AID迁出路径，注明GP/host信任、持久内存、事务和物理验证边界，并按157纠正Reset为清除两PIN/认证、恢复未初始化状态；待审查的PIN输入转换与未实现能力不列为已验证保证。详见 [安全审计基线](./155.md)。

156. [user] 提议Hello nonce签名以检测Monoid Applet被替换，接受独立安装密钥方向，要求先记录、完成当前Reset需求后继续。[agent] 现有Hello公钥属于Identity且随Monoid重装保留，不能证明Monoid未换；建议安装生成P-256密钥、客户端首次信任后pinning，正常重装换key，未来安装key的Reset行为待定，并需明确升级同步。具体nonce/proof字段及签名编码尚未批准；无生产/README/实卡改动，详见 [Hello挑战与安装身份提案](./156.md)。

## 0686ab4

157. [user] 纠正Reset本意为恢复刚安装的未初始化状态：无需PIN，同时清条目/缓存/Bundle、两PIN及错误次数/锁死/认证，保留Identity；Hello nonce先不做。[agent] 将154的保留PIN实现与测试保留为历史，当前文档同步Hello双PIN false及重新初始化流程，新增持久状态原子发布/成功后清认证的约束；纠正版335项JUnit、5项JS、两CAP及Inplate通过；卡55690320隔离274次操作、12次独立验签及满32缓存/FIFO/两PIN4/4/认证/Bundle真实回滚通过，成功后双PINfalse/原始tries5/认证0，双PIN锁死后可重设并验签。6次Reset含一次abort，日志峰值3072/5120B；临时包全清、264源哈希与原卡基线不变，未正式部署或推送，详见 [Reset恢复未初始化状态](./157.md)。

## a415033

158. [user] 卡片自更新希望复用Identity通信P-256密钥进行同卡加密备份恢复，并询问已有Bundle时是否也允许自收件非对称传输。[agent] 纠正此前GP Token签名解读，相关签名接口未获批准。当前Bundle密文本已能同卡解开，保留Identity/Bundle重装Monoid可恢复；新增self-HPKE例外会使157旧Reset后也能恢复。用户随后在159选择并批准实现Identity重置，截断跨Reset恢复；源Bundle hash约束仅为未采纳的agent建议。self-HPKE具体API/协议未定未实现，无新实卡验证；156用途不变，详见 [同卡加密恢复方向](./158.md)。

159. [user] 要求并批准实现Reset同时重置Identity。[agent] prepareReset在事务外准备新密钥对/ID/tokenSecret/空缓存并返回新token，reset在Monoid事务内发布并清Bundle及旧通信key引用，与Monoid绑定/条目/PIN/缓存同步；其他Applet旧token失效、不自动重绑。实现/文档及337项JUnit、5项JS、两CAP零警告转换校验、全仓格式/模板/diff检查通过，模拟器不证明持久字段回滚；未实卡、未提交。用户重新审视同AID替换恢复：Reset仅在执行后使旧本卡密文失效，不能阻止跳过Reset的GP替换，不撤回他卡/明文，尚不满足160新边界；具体协议/API未批准，实卡harness尚未冻结构建。157旧验证仅为历史，self-HPKE未实现，详见 [Reset同时重置Identity](./159.md)。

160. [user] 明确有Bundle时明文恢复需要Safe PIN加第二张卡，无Bundle时Safe PIN即可；认为交叉GP管理过于复杂，倾向按成员派生发送密钥、本卡只能加密其他卡可解密；进一步提出Safe PIN归Identity所有、解密须验本卡Safe PIN，实现双卡双PIN，成员可设不同PIN，并提出双卡允许新卡入组。考虑回刷A的nonce方案后，选择先取C公钥再A批准、B核验并加密、C入组的较简流程；后续建议Safe PIN改名Secret PIN。[agent] 两张不同既有成员分别验PIN，批准绑定Bundle/C身份；A无需持久pending nonce，保留root授予历史密文读取能力且需认证同步名单，具体协议/API未批准未实现。PIN改名不隐式放宽secret:false或明文Get权限。159的Reset尚不达新边界；建议发送端加密也由Identity验PIN，PIN变更/重置不能绕过旧解密授权，Import将收紧为接收卡Secret PIN。详见 [Bundle明文恢复边界](./160.md)。

161. [user] 要求暂留两卡临时探针，继续Android测试。[agent] ACR1552 R FW1.01.01上Test1/56050420与Test2/56038920用已知UID、不同CID并行激活，两种顺序40次交替及4次空闲后读取均保留双RAM标记/SELECT计数；协议停用和RF循环全清，FWTI12绕过旧Timer提前超时。OPPO PKB110/Android16的独立ReaderMode APK记录130events：两组10读hold保留，close/connect全清；缓存A两次connect虽成功却实际读TES2。JDI确认两个独立Tag、不同cookie但handle同为1，不能用旧Tag UID判实际卡；OEM内部差异未定位，公开API未复现同时双CID，不推广为硬件不支持。两卡E8/E801及临时APK保留，APK已force-stop、NFC仍on，未改生产APP/正式卡数据，详见 [ACR1552与Android双卡及RAM实测](./161.md)。

162. [user] 批准Secret PIN归Identity及按成员发送密钥恢复边界的实现，随后明确暂不做Extend Bundle、保留固定名单；实测期间明确允许删除Test1/Test2旧Monoid/Identity及测试数据。[agent] Hello改pins.secret，Authenticate/SetPIN改secret?:true，Import须接收卡Secret PIN；Identity独立验PIN并按caller门禁，Monoid重装留Secret PIN，0xFF无PIN轮换Identity并清两PIN/数据/Bundle。Bundle仍02原型，增加65B sender，总开销160B，以root+runtime AID+sender派生；拒绝同卡Bundle及入组后旧self-HPKE。双卡双PIN指完整新导出/解密链路，历史密文不再要求源PIN，GP替换其他成员后的授权恢复仍为明确边界。0x25暂缓未批准不实施。353项JUnit、5项JS、两正式CAP及格式/模板/diff通过；Test1/Test2隔离267事件/27次独立P256验签，双向Bundle、不同PIN、Monoid重装恢复、5次Reset及2次跨SIO回滚通过；另55690320单卡41事件/6签名。共存RAM不足已定位为256B复制缓冲分配失败，获准删旧应用后同请求通过；采样RAM最低160/175B，非保证余量。三卡E0/E2全清，Test1/Test2留E8、无正式Monoid，55690320原有应用基线保留；268源哈希一致，未提交，见 [Secret PIN与成员发送密钥](./162.md)。

163. [user] 明确命名语义：assertXxx失败抛异常且返回void，requireXxx失败抛异常且成功返回所需值。[agent] 将9个生产void require声明及调用改assert，将4个返回值的本地测试assert helper改require；保持有返回值的requireAuth/Identity/Key/SharedCurve等，APDU/CBOR/Shareable签名不变。353项JUnit、两CAP零警告转换校验及格式/模板/diff通过；两包22个CAP组件与重命名前逐字节一致，162实卡结果仍适用，不重复刷卡；保留旧268源manifest，见 [断言与取值命名](./163.md)。

164. [user] 要求审查monoid-javacard未处理的单点翻转、记录临时报告并修复非低风险项；随后要求复核问题及修复是否属实、符合惯例，并授权处置、实卡通过后提交。[agent] F-01在指令/写入跳过模型下成立，SafeItem以不可变ItemState共同发布data与exact short secret；F-03按既有LibSecurity循环检查caller，补未授权caller一次假匹配仍拒绝的测试；F-04改用数组LibSecurity.check与保守SAFE_TRUE，删除专用SenderComparison；F-05保留。纠正F-02：新增两项PIN结果不一致测试在旧版也通过，SensitiveResult仅核对native保存结果，不能修复两者一致错误。卡55690320新Identity LOAD6985；最小E4 control成功运行5AC39000并卸载，仅增加SensitiveResult.reset()的同AID变体首块LOAD6985，未执行assertion。该额外依赖已撤回，保留原有冗余回归。最终358项JUnit/44套件及两CAP通过；卡55690320加独立host peers通过100事件/12次P256验签，覆盖secret更新、PIN、重装恢复、Bundle自收件拒绝/他成员导入、Reset；非新双实卡测试。268源哈希一致，E0/E2/E4全清，原卡registry/SELECT/Hello保留。区分单bit数据损坏、比较结果翻转、指令跳过，不宣称完整抗故障；未推送。详见 [单点故障审计与数据保护修复](./164.md)。

## 312c069

165. [user] 要求提交授权管理后实现Security Key，先审阅接口再批准完整实现；接口缺口需停下讨论，后续已批准精确Type可写授权的removeAll。实卡事务故障后，明确选择幂等及重试收敛，避免不必要原子操作，不采用新增prepare/apply接口。[agent] Monoid会话/受限代理、65B P-256公钥和独立CTAP2.0/ClientPIN1已实现。resident替换先预清理同RP/user重复项但保留首条，再提交新记录并清旧；成功重试收敛，每次生成新随机ID，GC不保证当次空间回收。FIDO Reset先提交removeAll，再提交PIN重置，保留必要底层事务和Identity.prepareReset。最终436项JUnit/6项JS/三正式CAP/Inplate/格式通过。卡55690320的v10标准FIDO AID普通/扩展流程、v9三个提交边界注入及重试、同RP四账户加另一RP一账户共323逻辑事件/67次独立验签通过；三个注入均7F9000且原连接继续可用。两个冻结manifest的122份生产Java一致；临时包全清，registry/原应用SELECT/Hello基线恢复。v8旧外层事务持久回滚正确但连接失联为历史证据，不当作新方案证明。未测浏览器端到端、物理故障、最新峰值RAM或最大容量；随后按用户要求在55690320保留独立E0/E2/E3试用安装（标准FIDO AID），已授权卡内随机64B seed及F101可写，注册/签名/发现与自测凭证清理通过；原应用保留，勿自动删除这次留卡安装。其余可简化事务另列后续整理，当前生产代码未改。未提交推送。[user] 2026-10-21反馈本机WebAuthn试用正常但等待偏长。[agent] 核对留卡样本注册2.51s、known-ID登录1.82s、单凭证resident发现及签名1.69s，前置PIN协商及token另约0.95s；不是浏览器端到端时间。随后只读审查确认Security Key持久CBOR热游标、逐字节持久响应、凭证中间副本和重复句柄查表等优化候选；派生/公钥缓存已生效，未改实现或重新刷卡。详见 [Security Key接入](./165.md)。

166. [user] 要求完成Security Key性能优化并持续检查显著瓶颈，已放卡授权独立测试；后续明确卡数据无需保留并退出RDP以继续完整组合对照。[agent] 保留小型CBOR transient状态、APDU响应批量写与公钥/签名输出窗口、准确长度分配、内部seed读取、目录revision及同会话派生输入复用；OneShot等长输出不再复制。ClientPIN命令scratch改DESELECT，所有认证/失效边界保留。456项JUnit和三CAP通过。初轮D3-only/core分开实测，直接APDU解析候选慢约2–3%而回退。获准清除原E0/E2/E3及试用数据后，在55690320以完整新旧三CAP对照：每版8注册/30断言验签通过，known-ID1818→1049ms、resident1746→1095ms、注册2542→1820ms、PC/SC重连后SELECT/GetInfo/PIN/首次登录3075→1854ms（167纠正：未验证真实掉电）；四凭证全部返回7727→4820ms。完整profile另通过6注册/134断言、108阶段样本/8控制，采样最低RESET1005B、DESELECT1680B、持久32228B，非连续峰值。未放宽检查或4KiBguard；完整测试包均正常清理，保留独立账本与原无关registry。最新留卡试用状态见 [Security Key性能优化](./166.md)，未提交推送。

167. [user] 反馈RDP新卡在Windows可用，iPhone NFC的WebAuthn注册/登录不稳定：PIN弹窗最近2–3秒或不出现，输入同一PIN后再次刷卡等待至少5秒才报错。[agent] 修复扩展APDU响应仍固定256B的传输缺陷，69项相关测试及三正式CAP通过；模拟器须用Ne32767避开其Le0000归一化缺陷。独立JVM复现取协商公钥后断电再用旧key会将正确PIN报31并扣重试，重选不触发，重新协商恢复；未证明iOS实际断电顺序。WebKit公开层使用扩展APDU且31/33映射同一提示，私有NFC行为与用户iOS版本未知。初期未触卡，随后用户批准仅更新51574920的SecurityKey并清FIDO PIN；经RDP ACR39U核对CPLC后只替换D3并重授权，一seed三F101元数据/内容哈希保留、仅tokenHash变化，D0/D2及旧应用保留；新ledger ready；用户后续确认iPhone登录成功，但弹PIN约6秒、PIN后再次贴卡约10秒且未显示账户选择，清空用户名后约4秒显示3个账户，选中似乎无需再次刷卡即登录，具体命令轨迹未知；旧cold基准的六次重连未换ECDH公钥，已纠正为PC/SC重连，未证明真实掉电，不宣称已解决全部iPhone故障，详见 [iPhone NFC兼容排查](./167.md)。

168. [user] 要求同卡比较 Monoid 与参考 FIDO2Applet，取得 short 结果后要求停止扩展 APDU/断电实验、先从源码解释差距。[agent] 55690320 两版各6注册35断言独立验签；known-ID约1060/184ms、三账户全断言3552/583ms。源码定位公共对象分配/回收、持久记录与字段双份物化、3账户5次完整读取及跨应用授权成本；warm派生/ECDH已复用，不将差距归为每次重算密钥。所有C槽清理并保持基线，旧D试用按既有清数据授权移除，RDP卡51574920未动；见 [同卡性能对照](./168.md)。

169. [user] 要求继续优化Security Key至接近参考性能，约每操作额外200ms可接受，并授权本轮必要接口变更先做后列出审阅。[agent] 减少重复分配/记录复制，增加范围及直接数据SIO接口，保留认证及撤销边界；同卡完整登录均达额外200ms目标，首次注册1102ms、替换916ms仍未达标，539项测试及正式CAP通过，200次连续登录与64次凭证替换通过，缓存预热后无空间累计消耗；无实测收益的GC调度接口已撤回，临时包已清理。接口、证据与限制见 [Security Key性能继续优化](./169.md)。


    随后按要求更新RDP卡51574920并保留种子及3凭证，FIDO PIN随重装清除。用户在客户端成功创建SSH SK后一度无法打开Windows PIN管理；再次尝试及再次创建均正常。只读确认卡上新增1条非驻留SSH凭证，原3条凭证哈希不变；未定位根因，不修改固件。-K错误映射与诊断边界一并记入169。

170. [user] 密钥可按不会原地修改的前提设计缓存，客户端可自主缓存，对合理缓存API修改持开放态度；hash或显式缓存仅为举例。持久对象增多后不必激进请求GC。[agent] 完成4槽持久凭证/解析偏移缓存、会话seed及最近派生复用，增加getData及isDataCurrent两个SIO，保留当前授权和数据身份检查；取消空槽填充的无效GC请求。554测试及3CAP通过，同卡known-ID285→253ms、三账户740→611ms，实际RF-reset541→481ms/995→844ms；首次填缓存及替换注册有额外成本。全部C槽隔离程序已清理，51574920未动，未提交推送；完整接口、性能、验证范围及GC证据边界见 [Security Key凭证与派生缓存优化](./170.md)。

171. [user] 要求完全不调用requestObjectDeletion的实卡对照，观察持续创建/替换的自动回收、性能及剩余空间。[agent] 同卡55690320三CAP隔离对照，禁用21处、167编译类零调用。原版完成16条256B记录、512次替换及128次删除重建，逐次读回通过，空间稳定1599/1584/27812B；禁用版初始化第6命令NO_TRANSIENT_SPACE，RAM12/0B而持久33168B。最短64B流程第2次替换后的Get失败、RESET9B；256B首次Get失败；对应原版两组各32次替换/16次重建均通过。独立无请求持久分配每次仅保留一份256B，121次后NO_RESOURCE且没有空间回升；充足RAM的基线同探针也不自动回收。64B首个完整替换读回879→553ms，但只是失败前单次样本，不能推广为持续收益。结论限这张卡/布局，不证明每处GC必要；正式策略及125源哈希不变，未跑FIDO整组或提交推送。C槽全清、原registry一致、读卡器释放，见 [完全禁用显式GC实卡对照](./171.md)。

172. [user] Java Card 3.0.5 的项目行为以手头实测卡为准，并要求验证失去引用的 RAM 在真实下电后是否释放。[agent] 四类数组独立新安装，33 次 RF 复位均有 RESET 标记证明；RESET、DESELECT、global 及持久数组丢弃引用后，两次断电均无空间回升。显式请求后下一 APDU 恢复：四份 256B transient/global 对应 1024B RAM 与 64B 持久元数据，持久数组对应 1088B。保留引用时 transient 只清内容、持久数据保留，GC 不释放；清引用后仍需请求。空载首次 RF 的一次性偏移已隔离，未定位内部来源，不混入数组回收量。采用实测项目基线，不改正式策略；125 源哈希一致，临时 C 槽全清、原 registry 保留，未提交推送。[blog] 下电清零不等于释放对象，见 [真实断电后的回收行为](./172.md)。

173. [user] 要求通过 Project Memory 建立项目技能，在 Java Card 开发中记录有趣或有价值的问题及关键信息，留作未来博客素材。[agent] 新增 project-memory-javacard-blog 技能及符号链接；在相关数字记录中加入“博客兴趣点”，索引以 [blog] 标记，保留事实、边界和参考，按主题更新去重，不自动写作或发布，见 [博客兴趣点记录约定](./173.md)。

174. [user] 要求实卡比较同一缓存命中操作收尾始终请求GC与跳过GC，计时至客户端收到完整响应。[agent] 55690320同一隔离三CAP、同凭证/会话交替ABBA/BAAB，各40次；SKIP平均245.830ms、AFTER-send平均305.286ms，20组配对平均差59.456ms、中位差58.632ms。无host日志/验签插入的紧接GetInfo均约34.08ms，增量体现在本次完整ResponseAPDU返回前；8次独立BEFORE对照平均303.861ms。99断言与1注册独立验证，探针确认warm/单响应/模式计数。不能由PC/SC时间断言内部GC准确执行点，也不推导手机UI耗时。实验结束时正式策略未改、125源哈希一致，临时C槽全清、原registry保留、读卡器释放。[user] 随后接受约60ms增量。[agent] 据此将Security Key完整CTAP及会话清理统一请求GC，去掉requiresObjectDeletion链和专用状态，保留实际缓存/枚举/授权；纯传输分片不新增。6个生产文件及1测试文件调整，554测试/三CAP通过；新构建未再实卡安装，未提交推送。多命令登录可能累计开销，60ms不是固定上限。[blog] send返回不代表完整响应已到客户端，见 [响应收尾GC延迟实测](./174.md)。

175. [user] 批准统一 Monoid 与 Security Key 的 CBOR Reader/Writer 并抽到公共库，Identity 独立；要求实卡对比性能和内存。[agent] 完成monoidlib library CAP，560测试/4CAP通过，Identity源码及组件不变。ACR39U接触式55690320/T=1同卡各6注册59断言；缓存命中291→319ms、PIN握手285→310ms，完整FIDO布局RAM余量不变、持久余量增加404B，包含公共库净减829B。两版多应用布局的600B Ed25519均失败，独立诊断确认NO_TRANSIENT_SPACE；移除临时SK后两版32/600/1536B各3签名通过，新版此布局RAM多16B。临时包全清、原registry一致，未访问另一会话的ACR1552/J3R452，未提交推送。[blog] 共享代码不等于共享RAM或提速，见 [公共 CBOR 库](./175.md)。

176. [user] 继续统一APDU Reader/Writer到公共库，协议差异留各Applet，完成后同卡比较性能和内存。[agent] 最终两个Applet均由ApduTransport组合公共Reader/Writer，Identity独立，协议/容量/GC策略不变。578测试/65套件、4CAP及格式/模板检查通过；ACR39U/55690320同卡基线与unified-transport各6注册63断言、22传输检查及12Ed验签通过，其中9Ed为移除测试SK后的独立布局。热登录320→326ms、PIN310→321ms、小Create646→619ms、Set1536B813→802ms；FIDO RAM仍389/384B、热态持久少444B。正式LOAD72729B，比最初多422B、比前轮direct少116B；Identity14源/10LOAD组件不变，120源匹配冻结候选。首次APDU轮单次6E00保留为失败，独占12次新Index创建及重装后的全套均未复现，根因未定。[user] 错误复现前暂不追查，可能另会话并发，授权继续。[agent] 临时包全清、原registry及暂存补丁保留，未触另一会话读卡器或提交推送；旧direct数据单列。[blog] CAP转换器异常表间距与公共库方法分发成本，见 [公共APDU收发层](./176.md)。

177. [user] 将J3R452换到ACR39U，要求相同固件跨卡比较并将GP管理密钥改为默认值。[agent] 绑定CPLC28767821/ICD600/GP2.3/SCP02i55；三把钥轮换后独立默认认证通过，KVN01/IDs1,2,3、旧FF已移除，不记录旧钥。四CAP与176最终版逐一SHA一致、120生产源不变，首次安装成功，但provision首条Hello返回INTERNAL，未进入PIN/seed初始化。另开只读连接Hello/SysInfo成功，边界RAM226/256B、持久117392B；独立trace确认首次Hello查询SecretPIN状态及后续设置SecretPIN均NO_TRANSIENT_SPACE，PIN仍未设置，不能完成四CAP初始化/FIDO对照。移除ownedSK后原CAP独立布局初始化/64B读写通过，RAM519/512B，但600BCreate再次INTERNAL并立即停，Ed未执行；不同布局参考Hello317→348ms、64BGet377→408ms。非空List再遇INTERNAL；最后直接Get核实64B内容/600B不存在，删64及导入RFCseed成功，不预先View的首32BEdSign仍INTERNAL，0成功签名。后三类失败未trace不可都归因为RAM，无完整FIDO/Ed性能结果；临时C槽全清、原registry保留、120源及暂存哈希不变，APP未动，未提交推送。[blog] 相同CAP安装成功不等于运行时RAM满足完整布局，见 [J3R452同固件跨卡验证](./177.md)。

178. [user] 分片APDU全部按需用持久存储，完整短APDU继续借用缓冲，并做实卡内存/流程验证。[agent] 只改公共CBORApduReader，578测试/65套件、四CAP验证及模板检查通过。同一ACR39U/28767821独立Monoid布局、同666B请求：基线前两片RAM519→263→7B，候选始终519B、改用544B持久空间，两片合计增加6.642ms；600BCreate由INTERNAL变为成功并核对Index，但首次Get600仍INTERNAL，后续1536/List/Ed未执行。短64B读写约无变化；候选完整四CAP首次Hello仍INTERNAL，未做FIDO，不将旧trace当新证据。120源仅Reader变化、主机/请求哈希一致、库LOAD减15B；正式API/GC策略不变、未提交推送。临时C槽全清，原registry逐项恢复。[blog] 命令边界RAM会掩盖在途占用，见 [分片请求按需持久存储](./178.md)。

179. [user] 要求响应缓冲也按需使用持久存储。[agent] 公共Writer动态chunk和流式window完成修改，短响应仍借用APDU；578测试及四CAP验证通过。J3R452实卡600/1536B读写与List通过，Get均值797/1328ms；600B响应采样RAM始终519/512B，临时持久占用548B在收尾恢复。完整布局冷Hello及独立布局首次Ed签名仍INTERNAL。临时包已清理、原registry及暂存内容保留。[blog] 接收与响应的RAM占用需分别检查，见 [响应缓冲按需持久存储](./179.md)。

180. [user] 要求调通J3R452现有Ed25519和完整布局，补齐遗漏内存优化。[agent] 明确定位Hello/Ed/Bundle响应的NO_TRANSIENT_SPACE，整理低写入私有数组、共享HMAC/AES密钥及pad并修正HMAC512bit容量；ECDH合并实验已撤回。最终同一四包安装完成6次FIDO注册/43次断言、28次Ed及22次EC独立验签、1536B读写、32/256/1024B双模式传输、三成员Bundle和通信后签名/复位。Bundle为单实卡加两个软件对端；通信热后RAM771/784B稳定，非峰值。581测试/65套件及四CAP验证通过，120源哈希匹配；临时包清除、原registry及暂存保留，未提交推送。[blog] 见 [完整布局内存整理](./180.md)。

## ac72c0e

181. [user] 阶段性提交推送后继续抽取其他共用部分到lib。[agent] 前阶段已提交推送ac72c0e；后续将无状态LibSecurity及通用Utils移入monoidlib，Identity由模板保留独立实现；SafeDataSource改为抽象类并归入复制方法，删除重复private分配/复制封装，APDU/SIO及内存策略不变。P-256静态数组受library CAP初始化限制暂不抽取。581测试/65套件及四CAP验证通过；J3R452同卡6注册38验签、10项拒绝/恢复检查通过，LOAD减324B，RAM边界不变，持久余量增276B。已知ID/三凭证均值519→590ms、1320→1385ms，各5样本有波动，非孤立分发成本。临时包全清、原registry保留；后续抽取未提交。[blog] 见 [共用安全检查与字节工具](./181.md)。

182. [user] 批准分开数据互通与扩展审批资格，不为互通再刷A；最终批准Create23、Join24、Extend25、Approve Bundle Extension26独立命令及统一data字段，B批准响应直接用于C入组；要求沿用原有风格、多用空行。[agent] Create只收其他卡公钥，返回bundle及按序data数组；Extend publicKey→data，Approve data→{publicKey,data}，Join {publicKey,data}→bundle。root-HMAC加另一Identity签名证明扩展资格，数据解密不查名单，同root重Join幂等。最终593测试/67套件、6项JS及四CAP验证通过，实卡证据仍对应更早版本；详见 [Extend Bundle](./182.md)。

183. [user] 要求将旧版Bundle数据迁移到新卡，并批准临时替换Test 2的Monoid后恢复。[agent] Test 1/Test 2两条相同记录已加密备份；使用旧EXP token15的临时relay在Test 2卡内解密并重加密给新J3R452，明文未出卡。Test 2原程序/记录/Identity/Bundle恢复、临时包全清；新卡两条Import及幂等验证通过，seed派生公钥、普通数据摘要与全部元数据一致，保持未入组。GP 24.10.15的install-only实际空操作，已字节码确认并改用create；见 [旧版Bundle迁移](./183.md)。

## bf09b81

184. [user] 多卡同步暂不加入删除/活动标记，批准账户名称附加index与seed/domain隔离一起实现。[agent] 凭证新增scope32、key改为scope||rpHash；以固定78B用途context的派生公钥SHA256确定scope，每次Make/Get/Next重查，覆盖查询/替换/缓存，保持全局Reset。UV后名称带16位hex，保留存储原名；持久缓存320B。610测试/69套件与四CAP通过，未实卡或系统UI验证；旧记录需另迁移，见 [凭证隔离与使用记录](./184.md)。

185. [user] 澄清Access PIN用于APP管理Security Key的key/seed授权，FIDO PIN始终独立。[agent] 0x50/51/52统一走Safe.checkAccess，保留回调后复核及token/grant/secret隔离；不增加AID特例或接口字段。611测试/69套件、四CAP及格式/模板检查通过，未实卡部署或修改APP；见 [Access管理授权与独立FIDO PIN](./185.md)。

## b531981

186. [user] 选择Monoid通用HMAC与独立OTP Applet；要求近期多组OTP，提出上电配额/跨断电不回退后重新审视必要性，并讨论预装证书、一次贴卡多轮验证可信时间。[agent] secret读取边界不放宽；签名时间凭据可约束未来窗口，单独主机时间/单调状态不能证明真实时间。具体接口/协议/配额未批准，未改生产代码或实卡；见 [OTP入口与职责划分](./186.md)。

187. [user] Authority共用密钥，选择账户派生Bundle Token并批准allowPeerExtension控制成员双卡扩展，Authority独立签发不受限。[agent] 复用Join24和HPKE Auth，安装公钥认证单卡入组；策略随密文绑定并在Extend/Approve执行，相同root+策略才幂等，不覆盖既有Bundle。入组包增加flags且不兼容旧包，条目密文不变；无新APDU/SIO、APP或服务端实现；626测试/70套件与四CAP通过，未实卡/提交，见 [Authority职责与边界](./187.md)。

188. [user] 要求Reset保留Card ID并允许安装恢复ID，批准flags+可选ID4/Authority65格式。[agent] Identity接入安装配置、持久公钥与指定实例AID，Reset保留两配置但轮换密钥/token并清数据/PIN/Bundle；脚本增加安装参数，无新业务SIO/APDU。65测试/4套件、四CAP及格式/模板检查通过，未实卡/提交；见 [Card ID与安装配置](./188.md)。
