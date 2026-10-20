# Issue tracker: GitHub

Issues、spec 和任务统一保存在 aloneowo0/SuperDoH 的 GitHub Issues，使用 gh CLI 操作。

## Conventions

- 发布 spec：创建 GitHub issue，完整正文从文件传入。
- 阅读任务：获取 issue 正文、标签与评论。
- 列出任务：按状态和标签筛选。
- 评论、标记、关闭任务均使用 gh issue 对应命令。
- 不在 issue 中发布凭据、访问密钥或未脱敏日志。
- 从仓库 remote 确认目标；不在 clone 内运行时显式指定 --repo aloneowo0/SuperDoH。

## Pull requests as a triage surface

PRs as a request surface: no.

## When a skill says "publish to the issue tracker"

创建 GitHub issue。

## When a skill says "fetch the relevant ticket"

读取对应 GitHub issue 及评论。
