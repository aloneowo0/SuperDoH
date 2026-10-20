# Domain Docs

## Layout

单上下文：根目录 CONTEXT.md，架构决策放在 docs/adr/。

## Before exploring

- 先阅读 CONTEXT.md。
- 如果存在 CONTEXT-MAP.md，按照映射阅读相关上下文。
- 阅读与当前工作相关的 ADR。
- 文档不存在时继续工作，不提前创建占位文档；由 domain-modeling 在术语或决策确定时按需创建。

## Vocabulary

输出、测试和规格使用 CONTEXT.md 定义的领域语言，避免混用明确不推荐的同义词。
缺少术语时交由 domain-modeling 补充，不要将实现细节写进词汇表。

## ADR conflicts

若方案与已有 ADR 冲突，明确指出冲突及理由，不要静默覆盖既有决策。
