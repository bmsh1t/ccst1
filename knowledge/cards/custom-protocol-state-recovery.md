---
id: custom-protocol-state-recovery
type: technique-card
related_skills:
  - web2-recon
trigger_tags:
  - custom-binary-protocol
  - protocol-reverse
  - binary-frame
  - message-dictionary
  - state-recovery
risk: medium
maturity: draft
load_priority: low
deep_refs: []
source_refs: []
---

# 自定义协议帧与状态恢复

## Quick Recall

- 输入必须是有来源的 PCAP/PCAPNG、代理导出、客户端日志、原始帧、source 或二进制。
- 先区分 TCP segmentation/reassembly 与应用层 framing，再推断字段；单个报文不足以定结构。
- 路线为 `capture -> framing -> message dictionary -> state machine -> harmless replay`。
- gRPC 和 WebSocket 继续由现有专卡处理，本卡不建立第二套 protocol/finding 状态。

## 能力定位

本卡帮助 `web2-recon` 从非 HTTP 或私有 RPC 证据恢复最小消息语义和会话状态，产出可复核的帧布局、消息字典、状态转换与下一步。它不提供通用 dissector、fuzzer 或 replay runner。

## 触发信号

- 明确出现 custom binary protocol、protocol reverse、binary frame、frame layout 或 message dictionary。
- PCAP/tshark、MessagePack、FlatBuffers、MQTT 或 private RPC 与 framing、opcode、TLV、length、endian、checksum/CRC、状态恢复信号近邻出现。
- 客户端 source/日志可与捕获中的方向、时序、消息类型或错误码交叉对应。

## 流程

1. 保存 capture provenance、SHA-256、采集点、transport、五元组、会话、方向和时序。
2. 先完成 TCP stream 重组，再用多条消息判断定长、分隔符、magic、length prefix 或嵌套 framing。
3. 对齐同类/异类消息，标注 endian、TLV、opcode、sequence、flags、checksum/CRC、compression/encryption 候选。
4. 建立最小 message dictionary：消息类型、方向、前置状态、字段、响应和错误，不猜未知字段含义。
5. 从观测序列恢复 `connect -> auth -> ready -> request/response -> close` 等实际状态转换。
6. 用离线 parser 对同类、异类、truncated 和 invalid controls 验证；只有稳定解码且动作无副作用时才做最小 replay。

## 证据要求

- capture/log/source 的来源、hash、时间、会话、方向、transport 和重组方法。
- 每个 framing/field 假设对应至少两份对照消息及 byte offset，不以可打印字符串代替边界证据。
- message dictionary 与状态转换必须能回指原始 frame；未知、压缩和加密区域保持显式 unknown。
- replay 前记录动作语义、测试资源、预期响应、副作用边界和停止条件；raw request/response 进入现有 evidence 路径。

## 最小验证

1. 同一 parser 能完整消费多份同类消息，并在尾部无静默剩余字节。
2. 异类消息只改变预期 opcode/字段，truncated/invalid control 在预期边界失败。
3. length、endian、checksum/CRC 假设能解释多帧，不依赖单个样本巧合。
4. 状态机只包含已观测转换；无害 replay 必须从正确前置状态开始，并得到可重复响应。

## 常见误判 / 死路

- 裸 `pcap`、`protobuf`、`state machine` 或 `handshake` 不足以进入本路线。
- TCP segment、重传、粘包或 TLS record 不是应用消息边界。
- 单个 magic、字符串或长度吻合不能证明完整帧格式。
- 能解析字段不等于存在认证、授权或业务漏洞；replay 成功也必须解释状态和影响。

## 停止条件

- 缺少 capture provenance、方向或可比较消息，无法区分 transport 与应用帧。
- 数据仍被未知加密/压缩保护，且当前证据不能定位其边界或密钥来源。
- 连续假设不能同时解释多帧及 negative controls。
- 下一步需要有副作用的未知 opcode、批量 fuzz 或超出当前范围的主动交互。

## 推荐动作

- gRPC/protobuf transport 转 `knowledge/cards/grpc-api-boundaries.md`，WebSocket 转 `knowledge/cards/websocket-realtime-api.md`。
- 只有对象、身份或状态差异可重复时，才交给现有验证与 finding 流程。
- 将跨目标有效的 framing、checksum 或验证技巧写为带证据链接的 knowledge candidate，不保存目标凭据或原始敏感载荷。
