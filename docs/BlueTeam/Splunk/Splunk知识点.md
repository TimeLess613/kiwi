---
tags:
  - IT/Splunk
  - IT/蓝队
---

## Search time operations sequence

1. [[Knowledge Object#Field Extractions|Field Extractions]]
2. [[Knowledge Object#Field Aliases|Field Aliases]]
3. Calculated Fields
4. [[Knowledge Object#Lookups|Lookups]]
5. [[Knowledge Object#Event Types|Event Types]]
6. [[Knowledge Object#Tags|Tags]]

> [!NOTE] 所以前者无法参照后者


## 各种限制

[https://docs.splunk.com/Documentation/Splunk/9.1.0/Admin/Limitsconf](https://docs.splunk.com/Documentation/Splunk/9.1.0/Admin/Limitsconf)

> [!NOTE] 少用sort，到上限的话会统计到一半就不统计了！！


## 索引储存的逻辑——分片（TERM理解）

- 首先知道有主/次分隔符。下面列举一部分常见的
	- 主分隔符：空格、各种括号、分号、逗号、引号、百分号（有坑）、tab、叹号
	- 次分隔符：英文句号、正斜杠、冒号、等号、井号、下划线、短横线、美元符、百分号（有坑）

- 储存逻辑（TSIDX文件）：splunk会按主、次分隔符的顺序来切割每个event的各个term保存到index。如“ip=127.0.0.1”，首先已被主分隔符切割，然后会按次分隔符被切割成“ip”、“127”、“0”、“1”、“ip=127.0.0.1”
	- 其导致的结果：如果搜索127.0.0.1，splunk会这样搜索：`127 AND 0 AND 1`（实际上似乎是用Lispy Expression），其返回事件中任何位置包含这些数字的事件。
	- 而搜索`TERM(127.0.0.1)`也会无结果，因为按照index储存逻辑，并没有"127.0.0.1"这一项（因为不是被主分隔符划分）
- 所以搜索被次分隔符划分太多的项目可用TERM命令直接搜被保存的一整个term（上述的“ip=127.0.0.1”）即可省略不必要的搜索。
- 另外：如果可用`字段=TERM(值)`的搜索时，字段不能用别名。所以代替方法：`TERM(值) 字段别名=值`。

> [!NOTE] TERM忽略次要分隔符
> 即根据主要分隔符划分，将`TERM()`作为单个term进行检索

> [About event segmentation](https://docs.splunk.com/Documentation/Splunk/9.2.0/Data/Abouteventsegmentation)
> **Lispy Expression**: to build a **bloom filter** and check against TSIDX files.

> [!NOTE] 搜索短语似乎也会踩坑
> 如搜索`index=security "failed password"`，由于Lispy Expression解析为：`[ AND failed index::security password ]`，似乎会返回包含failed和password的event而不是"failed password"顺序的。



## Search Optimization

### Search Scheduler（调度）

同时搜索数有上限，所以有优先度：

1. Ad-hoc：即手动搜索
2. realtime计划：用户保存的。可以跳过的
3. continue计划：用户保存的。不可跳过，可以暂时停止
4. 自动搜索计划

### Search Acceleration

用Data Summary。

#### 加速的3种命令类型

- Streaming：在indexer上运行，流式处理每条event。如eval。
	- **Distributable Streaming**：event的顺序不重要，一般在indexer上运行。但是如果在其之前有需要在search head上运行的命令，那么其余的命令也必须在search head上运行（即一旦搜索处理移至search head，则无法返回indexer）。如：eval、fields、regex。
	- **Centralized Streaming**（Stateful Streaming）：event的顺序很重要。仅在search head上运行，对每个event应用transformation。如：transaction、head、dedup、streamstats，以及在Transforming命令后的所有命令。
- **Transforming**：在search head上运行，将结果转换为数据表的命令。如统计类。

#### 加速的3种创建方法

1. Report acceleration：用自动创建的summaries，缩短特定种类的Report搜索时间。
2. Summary indexing：手动创建。仅推荐用于无法高速化的Report（即下策？）
3. Data model acceleration：加速在数据模型中的所有字段。简单，首选。

#### 1. Report acceleration（即保存搜索为Report，并需要启动高速化）

- 保存：其高速化Summary基本上每10分钟更新并将最近搜索结果分别保存为各个file chunk，并与一起保存在index的bucket中
- bucket：index的目录构造。根据数据鲜度分为Hot/Warm/Cold等。其中Hot/Warm为SSD硬盘，而Cold为一般硬盘。（具体参照：[HowSplunkstoresindexes](https://docs.splunk.com/Documentation/Splunk/9.1.3/Indexer/HowSplunkstoresindexes)）
- 需要权限：`schedule_search`。（对于Power和Admin，默认就有）

> [!NOTE] Report acceleration必须包含Transforming命令
> 且Transforming命令前不能使用Non-streaming命令——要使用distributable streaming命令。

#### 3. Data model acceleration

两种类型：

- Adhoc：`高速化生成的文件`临时保存在search head。
	- 临时：用户使用pivot editor期间
- Persistent：`高速化生成的文件`永久保存在indexer
	- 需要权限：`accelerate_datamodel`，或admin（注意没有power user）
	- 必须只能使用Streaming命令

编辑高速化选择时间范围后，高级设置一般不动。除非高速化报错。

##### 高速化生成的文件：Tsidx Files（Time-Series Index Files）

> [[Splunk知识点#索引储存的逻辑——分片（TERM理解）]]

当数据存储到splunk时（index化时），会将raw data和Tsidx文件存到HOT bucket。
每5分钟更新，每30分钟删除过期。

Tsidx文件主要有两部分：

- `Lexicon`列表：存储了在data中找到的term，用字母表顺序排列。且index化时会将各字段名和值存储为键值对形式。
- `Posting`列表：存储了每个term与raw data的对应指针


> [[SPL memo#datamodel]]
> [[SPL memo#tstat]]




## time

`_time` 字段（timestamp）实际存储的是unix时间，。在log一栏界面并可显示为账号设置的本地时区（与log详细中的时区不一定一样）。

### earliest&latest

@timeUnit：round down (look back) to the nearest specified unit.

- @timeUnit后面也可以 +/- 来移动时间。如：`@d+3h`

#### timeUnit总结

- 都是小写
- 单复数没区别
- 月份是mon、month、months，而不是m（分钟）

### 默认时间字段（`date_*`）

- zone
- year
- month
- mday
- wday
- hour
- minute
- second

是从raw data的 timestamp 中提取的。即如果没有timestamp就不会提取——而这些data的timestamp为index的时间。

> [!NOTE] 这些字段不会考虑计算用户的时区配置（因为是从raw data的timestamp分隔得来的）
> 所以：筛选数据时可先用 `strftime(_time, "%H")` 获取用户本地时区的时间。（即strftime会考虑时区——搜索结果的时间列也是用这个函数进行转化并展示的）



> [[SPL memo#bin]]
> [[SPL memo#relative_time]]
> [[SPL memo#格式化]]




## 搜索模式

`智能模式`的搜索行为取决于你的搜索行为/类型——对于转换搜索，其行为类似于`快速模式`；对于非转换命令的搜索，其行为类似于`详细模式`。





## 统计处理

### 3类Data Series

- single-series
- multi-series（将single的x轴的值用by分组显示）
- time-series（可以是single或multi）

### chart

可用over创建single-series，用by创建multi-series。
chart仅能跟两个字段参数——即x、y轴。

- limit=0：无限制
- useother=f
- usenull=f
- span：如果x轴是数字，可为x轴分组

### timechart

### top

### rare

### [[SPL memo#stats]]

4类函数：

- Aggregate：如count、sum、dc。
- Event Order
- Multivalue：如list、value。list是列出所有值，value是列出唯一值
- Time

### [[SPL memo#eval-functions详解]]

11类函数。
eval自己在stats中也能当做函数。如`| stats count(eval(X=YY))`。注意，这似乎不是表示赋值，而是相当于where？？

### rename

竟然可以用通配符

### sort

对于字母：sorted lexicographically（按字典顺序）——所以大写在小写前面。
可以每列应用不同排序（如第一列升第二列降）