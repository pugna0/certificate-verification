---
layout: post
title: gitflow and continuous integration
categories: gitflow ci devops
image: gitflow-mode.png
image-pr: demo-pr.png
image-ppl: pipeline-demo.png
author: Pugna0
---

## 持续集成(Continuous Integration) 
    大师Martin Fowler对持续集成是这样定义的:持续集成是一种软件开发实践，即团队开发成员经常集成他们的工作，
    通常每个成员每天至少集成一次，也就意味着每天可能会发生多次集成。每次集成都通过自动化的构建（包括编译，发布，自动化测试)来验证，从而尽快地发现集成错误。
    许多团队发现这个过程可以大大减少集成的问题，让团队能够更快的开发内聚的软件。


### 持续集成的价值

#### 减少风险
    一天中进行多次的集成，并做了相应的测试，这样有利于检查缺陷，了解软件的健康状况，减少假定。

#### 减少重复过程
    减少重复的过程可以节省时间、费用和工作量。说起来简单，做起来难。
    这些浪费时间的重复劳动可能在我们的项目活动的任何一个环节发生，包括代码编译、数据库集成、测试、审查、部署及反馈。
    通过自动化的持续集成可以将这些重复的动作都变成自动化的，无需太多人工干预，让人们的时间更多的投入到动脑筋的、更高价值的事情上。

#### 增强开发者对于自己作品的信心
    持续集成可以建立开发团队对开发产品的信心，因为他们清楚的知道每一次构建的结果，他们知道他们对软件的改动造成了哪些影响，结果怎么样。



## **gitflow 工作流程**
gitflow是基于git的众多工作流程之一。
{% capture imagePath %}{{ page.date | date: "%Y-%m-%d" }}-{{ page.title | slugify }}/{{ page.image }}{% endcapture %}
  ![{{ page.title | slugify }}](/developers/assets/images/{{ imagePath }}){:class="img-responsive"}

The main branches:
- master master分支应该总是处于production-ready状态。
- develop 作为主要的开发分支，用于项目内各developer的源代码同步。

Supporting branches：
- Feature branches 基于develop分支衍生，功能完成后，代码合并回develop分支。
- Release branches 同样基于develop分支衍生，代码上线后合并回develop和master分支。
- Hotfix branches 基于master分支衍生，完成后，合并回develop和master分支。

#### 以xuanwu项目为例，介绍大概工作流程
* 项目地址： [xuanwu](https://gitlab.nexusguard.net/imcomjin/xuanwu)
* git flow: [安装](https://github.com/nvie/gitflow/wiki/Installation)

##### 项目结构
1. main branches： 
- master __protected branch__
- development __protected branch__

2. Supporting branches:
- Feature branches
- Release branches
- Hotfix branches

##### 简单流程
1. 安装gitlfow，并在xuanwu项目下执行
```bash
git flow init
```
    命令来初始化git flow，设置好对应的分支结构.

2. 开始新的分支开发： 
切换到development分支
```bash
git checkout development
```
    基于development分支开始新的feature：
```bash
git flow feature start new-feature
```
。。。
开发完成：
```bash
git flow feature publish new-feature
```
此时会把本地new-feature分支推送到远端仓库。
然后，提交pr：
{% capture imagePath %}{{ page.date | date: "%Y-%m-%d" }}-{{ page.title | slugify }}/{{ page.image-pr }}{% endcapture %}
  ![{{ page.title | slugify }}](/developers/assets/images/{{ imagePath }}){:class="img-responsive"}

基于此时的development分支，开出新的release分支：
大致流程同feature类似，测试环境测试，无问题准备上线时，提交pr到master，并标记tag:
```bash
git tag test-tag
```
到此，工作流程基本完毕，可上线版本已确定（test-tag）。

## **Gitlab-ci**
    gitlab-ci是基于gitlab的持续集成&部署的工作流程。

#### Gitlab Runner
    真正用于执行构建过程的组件,以容器化的方式运行。构建环境应该是一个与生产环境隔离的独立环境。

#### 如何为项目添加gitlab-ci pipeline
    只需在git项目下添加配置文件，命名为: ".gitlab-ci.yml"

例：
```yaml
image: docker.nexusguard.net/centos/python

before_script:
  - pip install --upgrade tox

stages:
  - test
  - publish
  - deploy

test:
  stage: test
  script:
  - tox
  only:
    - master
    - development
    - /^feature\/.*$/
    - merge-requests

publish:
  stage: publish
  image: docker.nexusguard.net/alpine/packer
  before_script:
    - mkdir -p /packer-definitions/modules/xuanwu/files
    - rm -rf /packer-definitions/modules/xuanwu/files/*
    - cp -R * /packer-definitions/modules/xuanwu/files
  script:
    - ssh gitlab.nexusguard.net "cd /opt/packer-definitions; /opt/packer build -var 'tag=${CI_COMMIT_TAG}-${CI_JOB_ID}-${CI_COMMIT_SHA:0:8}' -var 'application=xuanwu' definitions/xuanwu.json"
  only:
    - tags

```

根据自己项目的需求设置好gitlab-ci job的工作流程。[参考文档](https://docs.gitlab.com/ee/ci/yaml/README.html)
然后对于符合要求的代码提交，就会自动触发pipeline的构建过程：
{% capture imagePath %}{{ page.date | date: "%Y-%m-%d" }}-{{ page.title | slugify }}/{{ page.image-ppl }}{% endcapture %}
  ![{{ page.title | slugify }}](/developers/assets/images/{{ imagePath }}){:class="img-responsive"}
    在此可以看到构建的全部过程日志。

### 参考
[continuous integration](https://www.codeproject.com/Tips/859451/Benefits-of-Continuous-Integration)

[git flow](http://nvie.com/posts/a-successful-git-branching-model/)

[gitlab-ci](https://docs.gitlab.com/ee/ci/)

[comparing-workflows#gitflow-workflow](https://www.atlassian.com/git/tutorials/comparing-workflows#gitflow-workflow)