# DockerXScan
DockerXScan——Docker镜像漏洞扫描器

参考clair并实现其核心算法，docker镜像逐层分析，并提取其版本特征。
通过匹配特征，来比对CVE漏洞。

0.4版本实现了clair的所有功能，并其基础上进行精简,同时也修复了之气的一些bug，目前来说是相对稳定版本，建议使用0.4版本进行测试。



参考链接：https://github.com/coreos/clair
