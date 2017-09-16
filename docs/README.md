---
title: Cert Verification
categories: openssl devops
author: Pugna0
---

在我们收到的用户反馈问题中，有一部分是关于用户在启用了NXG的L7防护并开启了https后，访问被保护的网站时，发现浏览器提示证书不正确，为解决此类问题我们应该主动检测用户
所上传的证书的有效性并即使的将问题反馈出来，避免在用户使用的时候才发现问题。

## Description
程序设计目的：
1. 为启用了L7策略防护并开启了ssl验证的客户提供证书有效性的检查。
2. 检查客户从portal上传的证书后，是否正确的加载到了我们的引擎中。
开发语言：
    python

## Topology diagram
![img](https://github.com/pugna0/certificate-verification/blob/master/imgs/cert-verification.png)


## Project Address


## Components
#### Sponsor
整个检查流程的发起端，首先从qlocenter策略的mongodb中获取需要检查的客户的域名，通过kafka发送给IDC端的cert-checker。
sponsor部署在aws上，由crontab每天执行一次。
* 2 * * * /usr/bin/python /mnt/cert_reference/sponsor.py --brokers ip-172-31-30-65.us-west-1.compute.internal --topic ca-checker-domains-topic -v --mongo mongodb://mongo.nexqloud.net:27017

#### Cert-Checker
部署在每个IDC logserver上，证书检查的执行者。接受sponsor发来的所有域名，并对之进行检查，然后将检查结果通过kafka发送给es-aggregator。

#### ES-Aggregator
从kafka收集证书检查的结果信息，写入elasticsearch， 并通过kibana展示。

#### 检查流程
与每个IDC的L7引擎（会进行采样，目前是一半）进行ssl handshake， 获取指定domain的ssl证书链，

##### 证书的检测机制
  首先对证书本身进行检查，检查规则：
  1. 证书是否过期。
  2. 证书中的Common Name和Subject Alternative Name是否能匹配域名。
  3. 证书的签名算法是否为弱算法。
  ~~其次对证书链的完整性做检查：
  1. 如果证书链中只含有一个证书， 那么这个证书必须是由受信任的CA签发。
  2. 如果证书链中含有多个证书，说明用户提供了完整的证书链，那么将从第二个开始的所有证书作为受信任的证书来检查第一个证书,如果通过，则说明用户上传的证书链
  完整，否则视为不完整证书链。再遍历证书链，找到第一个根证书，用mozila-ca-bundle验证这个根证书的有效性，如果通过，则证书验证成功，否则视为不受信任的CA所签发的证书。

  其次对证书链的检查：

  ![img2](https://github.com/pugna0/certificate-verification/blob/master/imgs/cert-chain-verification.png)

  注释： （Mozilla ca bundle作为受信任CA）
  curl -o /mnt/ca/cacert.pem --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem
  以上任何一项检查不通过皆视为无效证书。
``` python2
    def verify_cert_chain(domain, chain, trusted_certs):
        # verify cert self
        ret, msg = verify_cert_self(domain, chain[0])
        if not ret:
            return False, msg

        try:
            store = OpenSSL.crypto.X509Store()
            if len(chain) > 1:
                chain_layer = chain[1:]
                for _cert in chain_layer:
                    store.add_cert(_cert)
                store_ctx = OpenSSL.crypto.X509StoreContext(store, chain[0])
                store_ctx.verify_certificate()

            # verify cert with root ca
            root_ca = load_root_certificates(trusted_certs)
            for _cert in root_ca:
                store.add_cert(_cert)
            store_ctx = OpenSSL.crypto.X509StoreContext(store, chain[-1])
            store_ctx.verify_certificate()

        except X509StoreContextError as cert_err:
            return False, "incomplete cert chain, {0:s} at depth {1:d}.".format(cert_err.args[0][2], cert_err.args[0][1])
        return True, ""
```

### 参考
linux man page: man 1 verify

[verifying-x509-certificate-chain-of-trust-in-python](http://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/)
