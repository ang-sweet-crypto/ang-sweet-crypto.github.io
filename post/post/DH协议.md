+++
date = '2025-12-25T16:00:00+08:00'
draft = false
title = '密钥交换的魔法：DH协议与STS协议🐾'
categories = ["ctf-crypto"]
tags = ["DH协议", "STS协议", "中间人攻击", "密钥交换", "数字签名", "前向保密", "密码学协议"]
series = ["CTF Math 系列"]
math = true
cover = "/covers/reimu2.jpg" 
+++

## 引言
hello！欢迎回到咪猫魔法世界~ 🐾✨

在不安全的网络里，怎么安全交换只有双方知道的共享密钥？这就轮到DH协议登场啦！它能在被监听的信道上，让通信双方算出相同的密钥，却让窃听者无从下手——核心秘诀就是“离散对数难题”的魔力~o( =∩ω∩= )m～

本文专门拆解DH协议的基础原理、中间人攻击的漏洞，以及简化STS协议的防护方案，还给出了可直接运行的Python代码，全程保持“边学边踩坑”的真实感，帮助各位新手师傅们搞懂密钥交换的核心逻辑！

---

## 一、DH协议基础：不安全信道的密钥魔法
DH协议（Diffie-Hellman协议）是密钥交换的经典方案，1976年由Whitfield Diffie和Martin Hellman提出，核心是“公开参数+私有计算”，让双方在不泄露私钥的情况下，协商出共享密钥。

### 1.1 核心原理：离散对数难题
DH协议的安全性完全依赖“离散对数问题”的困难性：
- 已知大素数p、模p的本原根g（g的幂能生成模p的所有非零剩余类），以及 \(g^a \pmod{p}\)，想反推出私钥a，在p足够大时几乎不可能（暴力破解无效）；
- 正向计算很简单：已知a，计算 \(g^a \pmod{p}\) 高效可行。

### 1.2 DH协议流程（基础原始版）
#### 文字版步骤：
1. 公开参数协商：双方先约定公开参数——大素数p和模p的本原根g（可公开传输，无需保密）；
2. 私钥生成：
   - Alice生成私钥a（保密），计算公钥 \(A = g^a \pmod{p}\)，发给Bob；
   - Bob生成私钥b（保密），计算公钥 \(B = g^b \pmod{p}\)，发给Alice；
3. 共享密钥计算：
   - Alice用Bob的公钥B和自己的私钥a，计算 \(K = B^a \pmod{p} = (g^b)^a \pmod{p} = g^{ab} \pmod{p}\)；
   - Bob用Alice的公钥A和自己的私钥b，计算 \(K = A^b \pmod{p} = (g^a)^b \pmod{p} = g^{ab} \pmod{p}\)；
4. 结果：双方得到相同的共享密钥K，窃听者仅能获取p、g、A、B，无法推导K。

#### 原理图解：
```
Alice                  不安全信道                  Bob
  |                        |                        |
  |  生成私钥a，计算A=g^a mod p                  |
  |------------------------------------------->|
  |                        |                        |
  |                                          生成私钥b，计算B=g^b mod p
  |<-------------------------------------------|
  |                        |                        |
  |  计算K=B^a mod p                          |
  |                        |                        |  计算K=A^b mod p
  |                        |                        |
  |  共享密钥K                                  共享密钥K
  |                        |                        |
```

### 1.3 Python代码实现
```python
def dh_simulate(p, g, alice_a, bob_b):
    # 分别生成Alice和Bob的公钥
    alice_A = pow(g, alice_a, p)
    bob_B = pow(g, bob_b, p)
    # 分别计算Alice和Bob的共享密钥
    alice_shared = pow(bob_B, alice_a, p)
    bob_shared = pow(alice_A, bob_b, p)
    # 验证双方计算出的共享密钥是否一致
    # 若共享密钥不一致，说明可能遭受中间人攻击，模拟失败
    assert alice_shared == bob_shared
    return alice_shared

# 手动输入p、g、alice_a、bob_b（可替换为大素数和大私钥）
p = 23  # 模素数（实际应用需用2048位以上大素数）
g = 5   # 模23的本原根（5的幂能生成1~22所有数）
alice_a = 6  # Alice的私钥（保密）
bob_b = 15   # Bob的私钥（保密）

shared_key = dh_simulate(p, g, alice_a, bob_b)
print(f"公共参数:p={p}, g={g}")
print(f"Alice的私钥:{alice_a}, 公钥:{pow(g, alice_a, p)}")
print(f"Bob的私钥:{bob_b}, 公钥:{pow(g, bob_b, p)}")
print(f"共享密钥:{shared_key}")
```

#### 运行结果：
```Python
公共参数:p=23, g=5
Alice的私钥:6, 公钥:8
Bob的私钥:15, 公钥:19
共享密钥:2
```

---

## 二、致命漏洞：中间人攻击如何破解DH协议？
基础DH协议看似完美，但有个致命缺陷——**缺乏身份验证**，中间人能轻松篡改公钥，窃取通信内容！

### 2.1 中间人攻击原理
中间人（Mallory）不需要破解离散对数，只需拦截并伪造公钥，就能在Alice和Bob之间“插一脚”，成为双方的“秘密通信对象”：

#### 文字版步骤：
1. Alice生成公钥A并发送给Bob，中间人拦截A，伪造自己的公钥 \(g^{m1}\) 发给Bob；
2. Bob生成公钥B并发送给Alice，中间人拦截B，伪造自己的公钥 \(g^{m2}\) 发给Alice；
3. Alice用伪造的公钥 \(g^{m2}\) 和自己的私钥a，计算与中间人的共享密钥 \(K1 = (g^{m2})^a \pmod{p}\)；
4. Bob用伪造的公钥 \(g^{m1}\) 和自己的私钥b，计算与中间人的共享密钥 \(K2 = (g^{m1})^b \pmod{p}\)；
5. 后续通信：Alice加密信息用K1，中间人解密后用K2重新加密发给Bob；Bob加密信息用K2，中间人解密后用K1重新加密发给Alice——中间人完全掌控通信内容！

#### 攻击图解：
```
Alice                  中间人                  Bob
  |                        |                        |
  |  发送A=g^a                                 |
  |------------------------------------------->|
  |                        |  伪造并发送g^m1       |
  |                        |---------------------->|
  |                        |                        |
  |                                          发送B=g^b
  |<-------------------------------------------|
  |  伪造并发送g^m2       |                        |
  |<------------------------------------------|
  |                        |                        |
  |  计算K1=(g^m2)^a mod p                    |  计算K2=(g^m1)^b mod p
  |                        |                        |
  |  与中间人共享密钥K1                        与中间人共享密钥K2
  |                        |                        |
```

#### 攻击成功原因：
基础DH协议只验证“公钥计算的密钥一致性”，不验证“公钥的真实归属”——Bob无法确认收到的公钥是不是Alice发的，Alice也无法确认收到的公钥是不是Bob发的。

---

## 三、防护方案：简化STS协议（身份绑定+签名验证）
要抵御中间人攻击，核心是给公钥“验明正身”——简化STS协议（Station-to-Station Protocol）用**数字签名绑定身份与公钥**，既保留DH协议的优势，又补上身份验证的漏洞。

### 3.1 简化STS协议核心逻辑
核心思路：用数字签名证明“公钥属于某个身份”，双方先验证签名，再计算密钥，确保公钥没被篡改。

#### 文字版步骤：
1. 准备工作：Alice和Bob各自拥有RSA密钥对（私钥保密，公钥可公开），用于数字签名和验证；
2. 公开参数：双方约定DH协议的大素数p和本原根g；
3. 临时公钥生成：
   - Alice生成DH临时私钥a，计算临时公钥A；
   - Bob生成DH临时私钥b，计算临时公钥B；
4. 签名公钥：
   - Alice用自己的RSA私钥，对“自己的身份+临时公钥A+Bob的临时公钥B”签名，得到签名Sig_A；
   - Bob用自己的RSA私钥，对“自己的身份+临时公钥B+Alice的临时公钥A”签名，得到签名Sig_B；
5. 交换并验证：
   - Alice发送A和Sig_A给Bob，Bob发送B和Sig_B给Alice；
   - Alice用Bob的RSA公钥验证Sig_B，确认B是Bob的真实公钥；
   - Bob用Alice的RSA公钥验证Sig_A，确认A是Alice的真实公钥；
6. 计算共享密钥：验证通过后，双方用各自的DH私钥和对方的真实公钥，计算共享密钥K。

### 3.2 核心安全点
- 身份绑定：签名将“临时公钥”与“身份”强绑定，中间人无法伪造（没有对方的RSA私钥，签不出合法签名）；
- 前向保密：临时DH密钥使用后立即丢弃，即使长期RSA私钥泄露，也不会影响历史会话的密钥安全；
- 防篡改：签名能验证公钥是否被篡改，一旦中间人替换公钥，签名验证会失败。

### 3.3 Python代码实现（可直接运行）
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# ===================== 步骤1:生成RSA密钥对(用于身份签名) =====================
# Alice的RSA密钥对（私钥保密，公钥可公开）
alice_rsa_private = rsa.generate_private_key(
    public_exponent=65537,  # 公钥指数，常规选65537
    key_size=2048           # 密钥长度，越长越安全
)
alice_rsa_public = alice_rsa_private.public_key()

# Bob的RSA密钥对（私钥保密，公钥可公开）
bob_rsa_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
bob_rsa_public = bob_rsa_private.public_key()

# ===================== 步骤2:DH参数与密钥生成 =====================
# DH公共参数（实际应用需选2048位以上大素数和本原根）
p = 23  # 示例用小素数，方便手动验证
g = 5   # 模23的本原根（5的幂能生成1~22所有数）

# Alice的DH私钥 + 公钥（临时密钥，用完即弃）
alice_dh_private = 6
alice_dh_public = pow(g, alice_dh_private, p)  # 计算 g^a mod p

# Bob的DH私钥 + 公钥（临时密钥，用完即弃）
bob_dh_private = 15
bob_dh_public = pow(g, bob_dh_private, p)  # 计算 g^b mod p

# ===================== 步骤3:对“身份+DH公钥”进行RSA签名 =====================
# Alice签名自己的“身份+DH公钥”（绑定身份与公钥）
alice_identity = b"Alice"  # 身份标识（可替换为真实用户名/设备ID）
alice_sign_data = alice_identity + str(alice_dh_public).encode()  # 待签名数据
alice_signature = alice_rsa_private.sign(
    alice_sign_data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),  # 掩码生成函数
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()  # 哈希算法
)

# Bob签名自己的“身份+DH公钥”（绑定身份与公钥）
bob_identity = b"Bob"
bob_sign_data = bob_identity + str(bob_dh_public).encode()
bob_signature = bob_rsa_private.sign(
    bob_sign_data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# ===================== 步骤4:验证对方签名(防止中间人攻击) =====================
# Alice验证Bob的签名（确认Bob的公钥真实）
try:
    bob_rsa_public.verify(
        bob_signature,
        bob_sign_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Alice验证Bob的签名成功 → Bob的DH公钥可信，无中间人攻击！")
except InvalidSignature:
    print("❌ Alice验证Bob的签名失败 → 存在中间人攻击风险！")

# Bob验证Alice的签名（确认Alice的公钥真实）
try:
    alice_rsa_public.verify(
        alice_signature,
        alice_sign_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Bob验证Alice的签名成功 → Alice的DH公钥可信，无中间人攻击！")
except InvalidSignature:
    print("❌ Bob验证Alice的签名失败 → 存在中间人攻击风险！")

# ===================== 步骤5:计算共享密钥(验证通过后) =====================
alice_shared = pow(bob_dh_public, alice_dh_private, p)  # 计算 (g^b)^a mod p
bob_shared = pow(alice_dh_public, bob_dh_private, p)    # 计算 (g^a)^b mod p

print(f"\nAlice 计算的共享密钥:{alice_shared}")
print(f"Bob 计算的共享密钥:{bob_shared}")
assert alice_shared == bob_shared, "DH共享密钥不一致，流程错误！"
print("🎉 验证通过:Alice与Bob的共享密钥一致，通信可安全进行！")
```

---

## ✨ 咪猫碎碎念
DH协议的核心真的很巧妙——不用传递密钥，却能让双方算出相同的密钥，这就是数论的魔力！但一定要记住：**基础DH协议不防中间人攻击**，必须搭配身份验证！

简化STS协议的核心就是“签名绑定身份”，把“公钥是不是对方的”这个问题，转化为“签名是不是对方签的”——而数字签名的安全性依赖于私钥保密，完美补上了DH的漏洞。

实际应用中，HTTPS、SSH等协议的密钥交换，本质都是DH协议的优化版（比如ECDH，基于椭圆曲线的DH，效率更高），再搭配数字签名和证书，确保通信安全～ 学习时一定要动手跑代码，看着密钥一致的那一刻，真的很有成就感！~o( =∩ω∩= )m

### 参考blog
- [DH密钥交换协议原理详解](https://blog.csdn.net/weixin_43940387/article/details/109235646)
