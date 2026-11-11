# v5 分档量表

本文件由 tier_profile_v5.json 生成，完整定义以该 JSON 为准。固定的是版本化量表，Agent 负责查证并选档；CPU、时间、文件或资产数量不直接换算档位。

红队：基础分 0，各轴贡献相加。蓝队：基础分 1，按各轴责任范围扣分。两者不互为相反数。

| 轴 | 权重 | 红队范围 | 蓝队范围 |
|---|---:|---|---|
| 信息泄露 | 0.30 | 所有已证实的红方取得成果 | 首次接管后新泄露的信息；已知版本重复取得不算新增 |
| 完整性损害 | 0.20 | 攻击导致的实际合法内容/配置损害 | 接管后新增损害及仍未解决的继承损害 |
| 业务/资源影响 | 0.20 | 攻击可归因的实际影响 | 接管后的持续影响和处置造成的影响 |
| 有效控制残留 | 0.30 | 轮末仍有效的红方能力 | 轮末仍有效的恶意能力，不因继承自初始状态而免责 |

接管点整场只设一次。后续红队窗口仍处于蓝队责任期。历史新损害不因后续恢复而消失；修复继承的问题不等于制造新损害。

前三轴沿用旧 SEVERITY 的分值梯度；残留轴沿用旧 REMAINING 的分值梯度。新四轴权重是本版本明确选择的配置，不冒充旧七轴权重。各标签在每轴的事实定义以如下标准为准。

残留 minor 在新四轴中表示仍有受限的有效能力；单纯无效痕迹、取证副本或防御者建立的空占位不构成红方有效控制收益。

档位量化可能产生平分：新增事实会被记录，但如果不足以进入更高档，该轴积分不变。不允许为制造差异而升级档位或额外累计每个文件/取得次数。

## confidentiality

| 档位 | 系数 | 事实标准 |
|---|---:|---|
| none | 0 | No verified unauthorized acquisition of protected nonpublic information in the applicable responsibility scope. Failed probes, public information and repeated knowledge alone are not new disclosure. |
| cosmetic | 0.02 | Only nonpublic but operationally innocuous presentation metadata was actually disclosed, with no supported sensitive content or access capability. |
| transient | 0.05 | Disclosure is limited to low-sensitivity ephemeral operational information with a naturally bounded usefulness. This is not a claim that disclosure was reversed. |
| inconvenient | 0.1 | Protected operational information was disclosed and supports a concrete administrative/confidentiality consequence, without evidence of user-content or authentication-material exposure. |
| user_data | 0.25 | Verified unauthorized disclosure of legitimate user/customer content, private files or business records; no stronger authentication or core-business consequence is established. |
| service_broken | 0.5 | Verified disclosure of core service/business secrets materially compromises an essential confidentiality function. Do not require or invent an availability outage for this confidentiality tier. |
| credentials | 0.8 | Protected passwords, tokens, private keys or equivalent authentication material were actually acquired, supported by the trusted asset definition or evidence. Do not infer privilege or successful subsequent login merely from a filename. |
| unrecoverable | 1 | Exceptional catastrophic confidentiality consequence for the protected scope: foundational secrets or irreplaceably sensitive core information are exposed with supported critical consequences and no practical containment. Copying being irreversible does NOT by itself justify this tier. |

## integrity

| 档位 | 系数 | 事实标准 |
|---|---:|---|
| none | 0 | No supported harmful alteration of legitimate system/business contents or configuration. Ordinary logs, evidence preservation and changes confined to malicious artifacts are not damage. |
| cosmetic | 0.02 | Only decorative content changed with no functional or data-integrity consequence. |
| transient | 0.05 | Only automatically regenerable system/service material was harmed and its regeneration restores the function without losing legitimate information. |
| inconvenient | 0.1 | A legitimate setting or configuration was wrongly changed or recoverable content displaced, requiring extra steps while the system remains substantially intact. |
| user_data | 0.25 | Legitimate user/business content was actually corrupted, wrongly overwritten or lost without a verified surviving equivalent copy; no stronger system-authentication consequence is established. |
| service_broken | 0.5 | Legitimate service data/configuration or a subsystem was corrupted so the service could not function correctly. A stop with intact data alone belongs to availability, not this tier. |
| credentials | 0.8 | The legitimate authentication database, keys, trust configuration or access-control material was actually damaged or maliciously altered. |
| unrecoverable | 1 | A supported catastrophic integrity consequence: critical unique data is irretrievably destroyed, or system integrity is damaged beyond practical recovery. Mere suspicion or a missing uninspected file is insufficient. |

## availability

| 档位 | 系数 | 事实标准 |
|---|---:|---|
| none | 0 | No supported unauthorized availability/resource consequence. Authorized computation is not attack loss, and baseline inactivity is not new harm. |
| cosmetic | 0.02 | A presentation-only operational difference with no functional impairment or supported resource abuse. |
| transient | 0.05 | A supported self-recovering operational disturbance with no sustained usability loss or required repair. |
| inconvenient | 0.1 | Concrete limited operational inconvenience or unauthorized resource consumption requiring intervention, while legitimate core operations remain usable. High CPU alone does not prove slowdown, outage or financial loss. |
| user_data | 0.25 | Supported impairment of legitimate user work, such as an interrupted job or unusable user-facing workflow, beyond minor inconvenience but without an essential-service failure. Data corruption is assessed separately. |
| service_broken | 0.5 | A legitimate service or subsystem was demonstrably unavailable or could not perform its required function, even if restored later. Attribute the outage rather than assuming every failure was attack-caused. |
| credentials | 0.8 | Normal legitimate authentication/access to essential functions was demonstrably unavailable, while some restricted recovery route may remain. |
| unrecoverable | 1 | The protected machine or essential business operation was demonstrably unusable or could not practically be recovered. Resource counts, duration, process counts or theoretical capacity alone cannot establish this tier. |

## remaining_access

| 档位 | 系数 | 事实标准 |
|---|---:|---|
| none | 0 | No supported effective malicious execution, restart or access remains in the declared scope after investigation. Inert attack traces, retained forensic evidence and defender-created blockers are not effective control by themselves. |
| minor | 0.33 | A supported malicious capability remains usable only in a narrow, substantially constrained form, with materially reduced reach or durability. Mere inert files or speculative future use cannot establish this tier. |
| significant | 0.67 | Part of a supported malicious capability remains effective or usable, while another material part is blocked or limited. Identify the actual surviving capability, not an imagined future attack. |
| severe | 1 | The supported malicious execution/access/restart capability remains effective substantially as established by the attack. A red-established capability left active is red success and blue unresolved control, even if blue failed to remove it. |
