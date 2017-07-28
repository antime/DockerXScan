# DockerXScan
DockerXScan——Docker镜像漏洞扫描器

参考clair并实现其核心算法，docker镜像逐层分析，并提取其版本特征。
通过匹配特征，来比对CVE漏洞。
0.2版本主要参考clair实现CVE漏洞的采集入库，以及漏洞信息的增删改查。

参考链接：https://github.com/coreos/clair
