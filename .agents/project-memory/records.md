--- af4f994 ---

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

---

b883572 ---

49. [agent] 接通 Keystore.signEDDSAMessage：沿用已有 seed→master 转换，调用 LibSLIP10Ed25519 在 master 副本内派生，再经共享 EdwardsCurve 导入 ED25519Key 并签原始 Message。Signer 入口接收 EdwardsCurve，内部识别 CurveED25519 后调用 LibED25519；finally 清理 Safe 返回的 key 副本、master/派生值和展开密钥，共享原生资源继续保留。41 项模拟器测试及 CAP 转换/校验通过；新增原有认证 0x41 短 APDU 集成测试，从已存 seed/master 分别派生 m/44'/501'/0'/0' 并签 1B Message，与 Node crypto 独立结果一致。能力列表及 Ed25519 ViewKey 尚未接入，长请求传输仍未恢复；本轮未使用实体卡或改动外部 API。
50. [user] Lib 前缀表示静态方法库；同意将 LibSLIP10Ed25519.derive 静态化，每次调用创建一次工作数组、沿路径复用并在 finally 清理，不增加共享状态或 init/dispose。LibED25519 保留绑定曲线及签名工作区的实例结构，重命名为 ED25519Signer；外层 Signer 负责分派，具体签名器实现算法。
51. [user] 同意进一步移除签名器实例，直接调用静态 LibED25519.sign(sharedCurve, ...)。曲线作为参数传入，三个临时数组在方法内创建并在 finally 清零和清理曲线工作区；共享曲线与原生引擎继续复用。此方案取代记录 50 中保留 ED25519Signer 实例的命名与组织决定，Lib 前缀表示静态库的约定继续有效。
52. [agent] 接通原有 0x40 ViewKey 的 Ed25519 公钥查询：Keystore 按记录 30 增加接受 EdwardsCurve 的 seed/master 同名重载；命令按曲线名分派，保留 {publicKey, chainCode} 结构。hardened SLIP-0010 派生后返回 32B 编码公钥和 32B chain code，finally 清理 Safe 返回的 key 副本、master 和展开私钥。42 项模拟器测试及 CAP 转换/校验通过；认证短 APDU 从已存 seed/master 派生 m/44'/501'/0'/0'，公钥与 chain code 均与 Node crypto 独立结果一致。能力声明和长请求传输仍待接入；本轮未使用实体卡或修改暂存区。
53. [agent] 接通 Hello/SystemInformation 共用的能力声明，最终结构按记录 54。CommandSystemInformation 汇总两类曲线及对应 cipher，移除 WeierstrassCurve 和 Signer 中不再使用的独立列表 writer，沿用 Text 常量及 CBOR writer 风格。两条指令测试核对完整嵌套结构和曲线/算法对应关系，15 项 Applet 模拟器回归（含 ECDSA/EdDSA 签名）及 CAP 转换/校验通过；长请求传输仍待接入，本轮未使用实体卡或修改暂存区。
54. [user] 明确批准调整能力声明，将 ciphers 放到对应的 curve 下面：features = {curves: [{name: 'secp256k1', ciphers: ['ecdsa']}, {name: 'ed25519', ciphers: ['eddsa']}] }，移除独立的 features.ciphers；签名请求保持不变。取代记录 53 最初采用的两份独立能力列表。

--- 42eda62 ---

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

--- 8abf0c5 ---

67. [agent] 实体卡测得当前纯 RAM 版本的可重复 Message 上限：普通响应缓冲时 seed 1184B、master 1458B；读取 600B 数据后分别降至 928B、946B，详见 [容量边界实测](./67.md)。每组上限加 1B 均失败，全部成功签名与独立实现一致，失败后小消息签名均恢复正常；隔离包清理和原应用复核通过。未修改生产代码或 API。
68. [agent] 按用户要求修复响应缓冲保留容量的问题：按需分配，完整发送/取消/deselect/发送失败后擦除、解除引用并请求 GC，未完成的多段响应继续保留；65 项模拟器测试及 CAP 校验通过，实体卡大响应后仍可正确签 seed 1184B / master 1458B，详见 [修复与复测](./68.md)。记录 67 中大响应造成的持续容量下降已解决；未重新测定修复后的精确上限。
69. [agent] 持久化暂存的加密必要性应基于既定保护目标，而非仅因存储介质是 persistent。Java Card 对象隔离与 Applet 访问控制可保护应用层明文；现有 Safe 也直接持久保存 seed/master。成功卸载重装不会继承旧 Applet 对象，但 reset/断电保留 persistent 内容；仅重装 Monoid 保留独立 Safe 的数据。临时密钥加密额外提供中断后无法解密残留内容的属性，目前未确定有此要求。后续优先评估普通持久缓冲及明确访问/清理规则，尚未实施持久暂存或修改 API；不能将公开 Solana Message 的特性自动推广到所有通用请求。依据 Oracle JCRE §11.3.4.2 与持久对象/防火墙定义，以及当前 Safe 和安装脚本。

--- ecae74d ---

70. [user] 批准按需持久化扩展，并明确小型分段请求仍用 RAM，超过阈值才使用持久存储；不采用所有分段请求一律持久化的方案。
71. [agent] 请求接收器保留前 512B 完整 CBOR 请求于 RAM，溢出部分按 256B 块按需持久分配；持久引用表确保 reset 后仍可擦除未完成请求。69 项模拟器测试、CAP 校验及 9 组实体卡测试通过，8192B 请求可签 seed 8096B / master 8114B Message，详见 [实现与实测](./71.md)。取消/错误/reset/超限恢复通过，隔离包已清理且原应用正常；API 和分片协议保持不变。

--- 74a31cd ---

72. [user] doc/cards.md 面向用户选购卡片，研究过程与详细实测应按 Project Memory 保存到对应数字 MD 文件；README 保持简洁，以命令定义为主，具体传输协议另设对应文档。
