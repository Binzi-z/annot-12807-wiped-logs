# 日志被清理后的残留取证

攻击者清理了部分日志，只留下命令历史与文件清单的残片。

```
evidence/bash_history.txt   带时间戳的命令历史
evidence/auth_excerpt.log   认证日志片段
evidence/files.txt          可疑文件的落地时间与属主
labels.json                 入口向量 / 持久化方式 / 涉及账号
triage.py                   现有分诊脚本（只做关键词匹配）
tests/                      骨架测试
```

## Run

```bash
python -m pytest tests -q
python triage.py evidence timeline.json
```

## 现状

`triage.py` 把命中 curl / wget / crontab 的行原样列出，不排序、不关联账号，
也不区分噪声命令。真正的入口向量与持久化手法需要人工从输出里翻。

## 标注

- 入口向量：`web shell upload`
- 持久化：`cron`
- 涉及账号：`www-data`

`bash_history.txt` 里另有若干日常命令，属于噪声，报出来算误报。
