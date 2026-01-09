+++
date = '2025-12-21T14:00:00+08:00'
draft = false
title = 'RSA基础与大数分解（含多种类型exp）🐾'
categories = ["ctf-crypto"]
tags = ["RSA", "大数分解", "Pollard Rho", "欧拉定理", "模逆元", "CTF密码学", "共模攻击", "Wiener攻击", "RSA应用场景"]
series = ["CTF Crypto 系列"]
math = true
cover = "/covers/reimu3.jpg" 
+++

## 引言
hello！欢迎回到咪猫魔法世界~ 🐾✨

前面啃完数论基础和CryptoHack入门题，这篇聚焦RSA核心——它是1977年由Ron Rivest、Adi Shamir和Leonard Adleman提出的非对称加密算法，本质是数论知识点（欧拉函数、模逆元、大质数判断）的拼接。另外我在这篇文章中还对 RSA安全基石、更多CTF攻击类型、实际应用场景和实战工具等进行了整合，让大家通过这一篇文章就能够大概了解多种 RSA 的“原理+实战+拓展”实际应用~

---

## 一、RSA加密算法基础
### 1.1 核心定义与安全基石
RSA是非对称加密算法的经典代表，加密和解密使用不同密钥，安全性完全建立在“大数分解难题”之上。
- 正向计算容易：两个大质数p、q相乘得到n，操作简单高效；
- 逆向推导极难：已知n，想分解出p和q，以当前经典计算能力需数百年甚至更久，这构成了RSA的安全防线。

### 1.2 RSA 的核心流程
#### 1.2.1 密钥生成
1. 选两个不相等大质数p、q（CTF中常见1024/2048位，实际推荐2048位以上）；
2. 算模数$n = p \times q$（公钥/私钥共用核心模数）；
3. 算欧拉函数$\phi(n) = (p-1)(q-1)$（若n为多素数乘积，$\phi(n)$为各素数减1的乘积）；
4. 选公钥e：满足$1 < e < \phi(n)$且$\gcd(e,\phi(n))=1$，常用65537（费马素数），避免用3/17等小指数；
5. 算私钥d：d是e的模逆元，即$e \times d \equiv 1 \pmod{\phi(n)}$，可通过多种方法求解（如下文方法）。

✅ 最终：公钥$(e,n)$公开（用于加密/验签），私钥$(d,n)$保密（用于解密/签名）。

#### 1.2.2 加密&解密
- 加密（公钥）：$c = m^e \pmod{n}$（m为明文，需满足$m < n$，否则需分组或填充）；
- 解密（私钥）：$m = c^d \pmod{n}$；
- 原理支撑：欧拉定理（$\gcd(m,n)=1$时，$m^{\phi(n)} \equiv 1 \pmod{n}$），因$e \times d = k \times \phi(n) + 1$，故$m^{e \times d} \equiv m \pmod{n}$。

#### 1.2.3 核心特性与应用场景
- 非对称性：公钥加密只能私钥解密，私钥签名只能公钥验签，是应用核心；
- 典型用途：
  1. 密钥分发：HTTPS/SSL中，浏览器用服务器公钥加密临时会话密钥，后续用对称加密通信；
  2. 身份验证：SSH免密登录，本地私钥应答服务器公钥挑战；
  3. 数字签名：软件发布者用私钥签名哈希值，用户用公钥验签，确保软件未篡改。

#### 1.2.4 模逆元的三种求解方法
除了扩展欧几里得算法，模逆元还有两种常用求法，适配不同场景：
1. 扩展欧几里得算法（通用）：适用于任意互素的a和mod，时间复杂度$O(\log n)$，是RSA求逆元的主流方法（代码见下文）；
2. 费马小定理/欧拉定理（模为素数时）：若mod是素数，逆元$=\text{pow}(a, \text{mod}-2, \text{mod})$；若a与mod互素，逆元$=\text{pow}(a, \phi(\text{mod})-1, \text{mod})$；
3. 递推法（批量求逆元）：适用于mod为小素数且需多次调用，公式为$\text{inv}(i) = -(\text{mod}//i) \times \text{inv}(\text{mod}\%i) \pmod{\text{mod}}$。

### 3. 踩坑提醒⭐
- ❌ e与$\phi(n)$不互素：无逆元d，密钥生成失败；
- ❌ 明文$m \ge n$：加密丢失信息，解密无法恢复；
- ❌ 小指数e=3且无填充：易遭低指数攻击或广播攻击；
- ❌ 密钥长度过短：1024位已不安全，推荐2048位及以上；
- ❌ 多用户共用模数n：易遭共模攻击；
- ❌ 私钥d过短：易被Wiener攻击破解。

---

## 二、CTF中的RSA高频考点
### 2.1 基础解密（已知p/q/e/c）
核心是“套公式+求逆元”，支持三种逆元求解方式，代码如下：
```python
# 扩展欧几里得求逆元（通用）
def extended_gcd(a, b):
    old_r, r = a, b; old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_s % b if old_r == 1 else None

# 费马小定理求逆元（mod为素数）
def fermat_inv(a, mod):
    if pow(a, mod-1, mod) != 1:
        return None  # 不互素
    return pow(a, mod-2, mod)

# RSA基础解密（支持两种逆元方法）
def rsa_decrypt(p, q, e, c, inv_method="extended_gcd"):
    n = p*q; phi_n = (p-1)*(q-1)
    # 选择逆元求解方法
    if inv_method == "extended_gcd":
        d = extended_gcd(e, phi_n)
    elif inv_method == "fermat":
        d = fermat_inv(e, phi_n) if is_prime(phi_n) else None
    else:
        return "不支持的逆元方法"
    if d is None:
        return "无逆元，解密失败"
    m = pow(c, d, n)
    return m, bytes.fromhex(hex(m)[2:]).decode('ascii', errors='ignore')

# 测试示例（CTF简化真题）
if __name__ == "__main__":
    p = 857504083339712752489993810777
    q = 1029224947942998075080348647219
    e = 65537
    c = 7760495942927948852192598062454345855440706357543439965601867349749879593207699599408158947159775199700901711500562398488466824912053019375328111429529899211
    print(rsa_decrypt(p, q, e, c))
```

### 2.2 大数分解（Pollard Rho算法+工具辅助）
当未知p/q时，用Pollard Rho算法分解n，搭配米勒-拉宾素性测试，同时可借助工具提升效率：
```python
import random, math

# 米勒-拉宾素性测试（判断大数是否为质数）
def is_prime(n):
    if n < 2: return False
    for a in [2,3,5,7,11]:
        if n == a: return True
        d, s = n-1, 0
        while d%2 == 0: d//=2; s+=1
        x = pow(a, d, n)
        if x == 1 or x == n-1: continue
        for _ in range(s-1):
            x = pow(x,2,n)
            if x == n-1: break
        else: return False
    return True

# Pollard Rho分解大数
def pollard_rho(n):
    if n%2 == 0: return 2
    def f(x): return (pow(x,2,n)+1)%n
    x, y, d = 2, 2, 1
    while d == 1:
        x, y = f(x), f(f(y))
        d = math.gcd(abs(x-y), n)
    return d if d!=n else pollard_rho(n)

# 分解n并解密
def rsa_factor_decrypt(n, e, c):
    if is_prime(n): return "n是质数，无法分解"
    p = pollard_rho(n); q = n//p
    return rsa_decrypt(p, q, e, c)

# 测试（1024位简化n）
if __name__ == "__main__":
    n = 1357902468135790246813579024681357902468135790246813579024681357902468135790246813579024681357902468135790246813579024681357902468135790246813579024681357902468135790246813579024681357902468135790246813579024681357902468135790246813579024681357902468135790246813579024681357902468
    e = 65537; c = 987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321987654321
    print(rsa_factor_decrypt(n, e, c))
```
**工具辅助**：
- 在线分解：[factordb](https://factordb.com)（快速分解中小规模n）；
- 本地工具：[yafu](https://github.com/bbuhrow/yafu)（Windows平台，支持批量分解大n，命令：yafu-x64 "factor(@)" -batchfile 1.txt）。

### 2.3 低加密指数攻击（e=3）
当e=3且n较大无法分解时，通过爆破k使$c - k \times n$为完全立方数，代码如下：
```python
import math

def low_e_attack(e, n, c):
    k = 0
    while True:
        candidate = c + k * n
        # 开e次方（此处e=3）
        m = round(math.pow(candidate, 1/e))
        if pow(m, e) == candidate:
            return m, bytes.fromhex(hex(m)[2:]).decode('ascii', errors='ignore')
        k += 1
        if k > 1000000:  # 限制爆破次数
            return "爆破失败，可能e不是3或k过大"

# 测试（e=3场景）
if __name__ == "__main__":
    e = 3
    n = 123456789012345678901234567890
    c = 987654321098765432109876543210
    print(low_e_attack(e, n, c))
```

### 2.4 小指数广播攻击（e=3+多组n,c）
同一明文m用e=3加密到多个不同n，截获≥3组(n,c)后，用中国剩余定理重构$m^3$，再开方得m：
```python
from functools import reduce

# 中国剩余定理求解
def crt(remainders, mods):
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = extended_gcd(b, a%b)
        return g, y, x - (a//b)*y
    # 计算所有模数的乘积
    M = reduce(lambda x,y: x*y, mods)
    result = 0
    for mi, ri in zip(mods, remainders):
        Mi = M // mi
        g, xi, _ = extended_gcd(Mi, mi)
        if g != 1:
            return None  # 模数不互素
        result = (result + ri * xi * Mi) % M
    return result

# 小指数广播攻击（e=3）
def broadcast_attack(e, nc_pairs):
    if len(nc_pairs) < e:
        return "需至少{}组(n,c)".format(e)
    mods = [n for n, c in nc_pairs]
    remainders = [c for n, c in nc_pairs]
    # 用CRT求m^e mod (n1*n2*n3)
    m_e = crt(remainders, mods)
    if m_e is None:
        return "CRT求解失败"
    # 开e次方
    m = round(math.pow(m_e, 1/e))
    if pow(m, e) == m_e:
        return m, bytes.fromhex(hex(m)[2:]).decode('ascii', errors='ignore')
    return "开方失败"

# 测试（3组n,c）
if __name__ == "__main__":
    nc_pairs = [
        (n1, c1),  # 实际使用时替换为真实n和c
        (n2, c2),
        (n3, c3)
    ]
    print(broadcast_attack(3, nc_pairs))
```

### 2.5 共模攻击（多用户共用n）
多个用户用相同n、不同e（e1与e2互素）加密同一m，截获(c1,e1)和(c2,e2)即可恢复m：
```python
def common_mod_attack(n, e1, c1, e2, c2):
    # 用扩展欧几里得找s1,s2使s1*e1 + s2*e2 = 1
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = extended_gcd(b, a%b)
        return g, y, x - (a//b)*y
    g, s1, s2 = extended_gcd(e1, e2)
    if g != 1:
        return "e1与e2不互素，无法攻击"
    # 计算m = (c1^s1 * c2^s2) mod n（处理负指数）
    m = (pow(c1, s1 % (n-1), n) * pow(c2, s2 % (n-1), n)) % n
    return m, bytes.fromhex(hex(m)[2:]).decode('ascii', errors='ignore')

# 测试示例
if __name__ == "__main__":
    n = 123456789012345678901234567890
    e1 = 65537; c1 = 987654321098765432109876543210
    e2 = 17; c2 = 135790246813579024681357902468
    print(common_mod_attack(n, e1, c1, e2, c2))
```

### 2.6 Wiener攻击（私钥d过短）
当$d < n^{1/4}$时，用连分数逼近求解d，可直接调用owiener库：
```python
# 先安装：pip install owiener（库地址：https://pypi.org/project/owiener/）
import owiener

def wiener_attack(e, n):
    d = owiener.attack(e, n)
    if d is None:
        return "d过长，攻击失败"
    return d

# 测试示例
if __name__ == "__main__":
    e = 30749686305802061816334591167284030734478031427751495527922388099381921172620569310945418007467306454160014597828390709770861577479329793948103408489494025272834473555854835044153374978554414416305012267643957838998648651100705446875979573675767605387333733876537528353237076626094553367977134079292593746416875606876735717905892280664538346000950343671655257046364067221469807138232820446015769882472160551840052921930357988334306659120253114790638496480092361951536576427295789429197483597859657977832368912534761100269065509351345050758943674651053419982561094432258103614830448382949765459939698951824447818497599
    n = 109966163992903243770643456296093759130737510333736483352345488643432614201030629970207047930115652268531222079508230987041869779760776072105738457123387124961036111210544028669181361694095594938869077306417325203381820822917059651429857093388618818437282624857927551285811542685269229705594166370426152128895901914709902037365652575730201897361139518816164746228733410283595236405985958414491372301878718635708605256444921222945267625853091126691358833453283744166617463257821375566155675868452032401961727814314481343467702299949407935602389342183536222842556906657001984320973035314726867840698884052182976760066141
    d = wiener_attack(e, n)
    print(f"破解得到私钥d：{d}")
```

### 2.7 公因数攻击（多组n共享因子）
当多组(n,c)共享同一素因子p时，用gcd求p，再分解n：
```python
def common_factor_attack(ns):
    # 从多组n中找公因数
    p = ns[0]
    for n in ns[1:]:
        p = math.gcd(p, n)
        if p > 1:
            break
    if p == 1:
        return "无共享公因数"
    # 分解每组n
    factors = [(p, n//p) for n in ns]
    return factors

# 测试（两组n共享p）
if __name__ == "__main__":
    ns = [n1, n2]  # 替换为真实n
    print(common_factor_attack(ns))
```

---

## 三、RSA拓展知识
### 3.1 RSA变体
- 多素数RSA：n是三个及以上素数的乘积，效率更高，适用于资源受限场景；
- 双模数RSA（DM-RSA）：用两个独立模数n1、n2加密，需结合CRT解密，抗侧信道攻击能力更强；
- CRT-RSA：解密时用中国剩余定理优化，先算$m1=c^d \pmod{p}$、$m2=c^d \pmod{q}$，再合并m，速度更快。

### 3.2 安全威胁与防护
- 量子计算威胁：[Shor算法](https://en.wikipedia.org/wiki/Shor%27s_algorithm)可多项式时间分解大数，威胁RSA安全，未来需转向[后量子密码学（NIST）](https://csrc.nist.gov/Projects/post-quantum-cryptography)；
- 侧信道攻击：通过计时、功耗信息泄露密钥，可采用双模数RSA或随机化加密防护；
- 填充机制：未填充的RSA易遭攻击，推荐使用[PKCS#1 v1.5](https://datatracker.ietf.org/doc/html/rfc8017)或[OAEP填充](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1)。

### 3.3 CTF真题案例参考
- [BUUCTF (WUSTCTF2020) babyrsa](https://buuoj.cn/challenges)：n较小，直接用yafu分解p/q后解密；
- [NCTF2019 babyRSA](https://www.nctf.cn/challenges)：小指数广播攻击，截获3组(n,c)用CRT重构$m^3$；
- 鹏城杯2025 babyrsa：高精度浮点数泄露私钥参数，反向推算d；
- [BJDCTF2020 rsa_output](https://buuoj.cn/challenges)：共模攻击，多组(e,c)共用n求解m。

---

## ✨ 咪猫碎碎念
> RSA的核心逻辑比较简单——“数论做基础，大数分解保安全”；CTF题本质是“找参数漏洞+套算法模板”。后面补充的攻击类型和拓展知识都是实战中高频遇到的场景，结合工具和真题练习，很快就能上手~ 

> 记住：RSA不算难，难的是遗漏参数漏洞和算法选型错误！

## 四、总结
1. 核心公式：$m^{e \times d} \equiv m \pmod{n}$，密钥生成的关键是 $e$ 与 $\phi(n)$ 互素、求逆元；
2. 分解工具：Pollard Rho算法（代码实现）、[yafu](https://github.com/bbuhrow/yafu)（本地）、[factordb](https://factordb.com)（在线）；
3. 攻击思路：低指数（e=3）、共模（同n多e）、Wiener（d过短）、广播（多n同e同m）、公因数（多n共享p/q）；
4. 安全要点：密钥长度≥2048位、用65537作e、加填充、避免共用模数；
5. 拓展方向：RSA变体、[后量子密码防护](https://csrc.nist.gov/Projects/post-quantum-cryptography)、侧信道攻击应对。
```
