---
tags:
  - IT/Splunk
  - IT/蓝队
---
Knowledge Objects是一组用于发现和分析数据的工具。即splunk界面中，点设定，其中第一个大分类就叫Knowledge！

- 权限：即私人、某个APP、所有APP——所以反推，能调整这些权限的都算Knowledge Object。

## [Knowledge Object 5大分类](https://docs.splunk.com/Documentation/Splunk/9.2.0/Knowledge/WhatisSplunkknowledge)

### 1. Data Interpretation

- 字段
- 字段提取（自动、手动）
	- 字段计算——eval。

#### Field Extractions

3个使用入口：

- Settings——字段
- 侧边栏最下面
- Event Actions menu（搜索结果每行中的按钮，**最快——直接到达选择提取方式的界面**）

field extractor自动帮我们构建正则表达式。

检查提取字段消耗了多少搜索性能：Inspect Job——`command.search.kv`。


### 2. Data Classification

- Event Types：保存搜索时可选。之后调用：eventtype=<your_saved_eventtype>
- Transactions

#### Event Types

创建方式（还可以配置颜色）：

- 将搜索结果保存为——Event Types
- 每行搜索结果的actions——build Event Types
- Settings——New Event Types

> [!NOTE] Event Types不可包含时间范围——而保存报告可以



### 3. Data Enrichment

- Lookups
- Workflow Actions：就是Event Actions里的按钮。

#### Lookups

- [[SPL memo#lookup]]
- [[SPL memo#inputlookup]]

##### Lookups四种类型

- file-base：CSV
- external：script
- KV store
- geospatial

##### External lookups

就是调用服务器上的脚本。

- `$SPLUNK_HOME/bin/scripts`
- `$SPLUNK_HOME/etc/apps/<AppName>/bin/scripts`

##### KV store lookups

适用于大型文件。（CSV的话会读取整个文件而KV不是）

需要admin定义conf

创建lookup definition后，填充store的方式：用 `| outputlookup <definition_name>` 命令，将搜索结果写入。

另一种方式：splunk REST API。

##### KV store VS. CSV

- 可以每行更新
- 支持字段加速
- 支持多用户访问锁
- 大小写不敏感（CSV默认敏感，但是也能调不敏感）

##### Geospatial lookups

输入KML/KMZ文件，输出geo信息（似乎不是点信息，而是直接绘制地图/区域）的字段。




#### Workflow Actions

创建方式：Settings——字段。

- 传递指定字段的值：`$<field>$` 
- 如果值需要转义（加个感叹号）：`$!<field>$`


### 4. Data Normalization

- 字段别名
- Tags

#### Field Aliases

- GUI配置方式：既有字段名=别名

> [!NOTE] One alias for each sourcetype

#### Tags

- 用键值对，指定描述性的名字
- **tag名是大小写敏感的！**
- 可以用通配符
- 也可用这种形式搜索字段与其分配的值：`tag::<field>=<tag_name>`


### 5. Data Models

- Hierarchy Structured Datasets


## 还有保存的搜索，Report、alert、macros等

### Macros

创建方式：Settings——高级搜索

#### 添加参数

另外：可以用fieldformat来让结果可以用数字顺序排列。用eval的话则是以字母排列。

![[splunk-macros.png]]


## [命名约定](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Developnamingconventionsforknowledgeobjecttitles)

6 segmented keys：

1. Group：组织内的团队名、所属
2. Type：Knowledge Object Type
3. Platform：大部门？
4. Category：职能
5. Time：na for NOT time-base
6. Description：描述

主要是为了表达清楚下面的信息：

- WHO：Group
- WHAT it does：Type、Platform、Category、Time
