---
id: second-order-sink
type: technique-card
related_skills:
  - web2-vuln-classes
  - bb-methodology
  - triage-validation
trigger_tags:
  - second-order
  - delayed-sink
  - async-sink
  - stored-render
risk: medium-to-high
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1119120"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "1104349"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "833470"
  - type: corpus-report
    corpus: hackerone-disclosed-reports
    id: "245228"
---

# 二阶/延迟 sink 注入（异步模板、SSTI、跨端反序列化）

## Quick Recall

- 触发：输入先被存储/排队，后续由异步任务、模板、解析器或另一端消费。
- 最小验证：用无害 marker 追踪写入点、延迟任务和最终 sink 的完整链路。
- 证据门：必须关联注入点与危险消费上下文，并记录实际执行/状态差异。
- 停止：消费端做正确编码/白名单，或无法把输入关联到危险 sink。

## 适用场景

- 用户输入被持久化后由异步任务/其他服务消费
- 存在邮件/通知模板、报表、跨端数据传递
- 反序列化黑名单过滤序列化数据

## 触发信号

- 用户字段流入异步邮件/模板渲染 sink
- 服务端把数据反序列化后回传客户端消费
- 黑名单未覆盖解析器接受的等价编码

## 发散问题

- 这个字段稍后会在哪个上下文被谁消费？
- 消费端是模板/反序列化/执行器吗？
- 黑名单漏掉了哪些等价写法？

## 推荐动作

- 标记注入点，追踪其到延迟 sink 的数据流。
- 在 sink 处用无害探针确认解析/执行语义。
- 对反序列化测黑名单等价绕过。

## 关联 Skills

- web2-vuln-classes
- bb-methodology
- triage-validation

## 停止条件

- 延迟 sink 对数据做上下文正确编码/白名单
- 无法把注入点关联到危险消费端

## 检查要求

- 必须证明注入在延迟 sink 处被解析/执行并产生影响，且可复现。

## 可晋升经验

- 注入点先问"稍后谁在什么上下文消费"，异步模板与跨端反序列化是高价值二阶 sink。
