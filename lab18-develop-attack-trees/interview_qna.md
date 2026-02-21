# 🎤 Interview Q&A - Lab 18 – Develop Attack Trees for Identified Vulnerabilities  

---

## 1️⃣ What is an Attack Tree?

An **Attack Tree** is a structured threat modeling technique that represents an attacker’s goal as the root node and breaks it down into smaller sub-goals and attack steps using logical relationships (AND / OR).

It helps visualize:
- How an attacker can achieve a goal
- What steps are required
- Which paths are most likely or most damaging

---

## 2️⃣ What is the difference between AND and OR nodes in an attack tree?

- **AND Node** → All child conditions must be satisfied for the attack to succeed.
- **OR Node** → Any one of the child conditions can lead to success.

Example:
- Brute force attack requires:
  - Identify usernames AND
  - Automated attempts  
- SQL injection exploitation may succeed through:
  - Bypass authentication OR
  - Extract data  

---

## 3️⃣ How is risk calculated in this lab’s attack tree implementation?

Risk is calculated using:

```

Risk = Probability × Impact

```

Where:
- Probability ∈ [0.0 – 1.0]
- Impact ∈ [0.0 – 10.0]

Internal nodes aggregate probability differently:
- AND → Multiply child probabilities
- OR → 1 - Π(1 - pᵢ)

---

## 4️⃣ Why is vulnerability chaining dangerous?

Vulnerability chaining increases overall system risk because:
- One weakness enables another
- Attackers can escalate privileges step-by-step
- The total impact becomes greater than individual vulnerabilities

Example from lab:
```

Weak Authentication → SQL Injection → Unencrypted Communication

```

This creates a high-impact multi-stage attack path.

---

## 5️⃣ What is vulnerability chaining?

Vulnerability chaining is the process where attackers exploit multiple weaknesses sequentially to achieve a larger goal.

Example:
1. Exploit weak authentication  
2. Gain access to SQL injection point  
3. Extract credentials over unencrypted communication  

Each vulnerability amplifies the next.

---

## 6️⃣ Why was NetworkX used in this lab?

NetworkX was used to:

- Model vulnerabilities as graph nodes
- Represent relationships as directed edges
- Identify attack paths
- Calculate multi-stage attack scenarios

Graphs are ideal for modeling attack chains and dependencies.

---

## 7️⃣ How were attack path risks calculated?

Attack path risk was calculated using:

- Weighted CVSS scores (earlier vulnerabilities weighted slightly higher)
- Length penalty (longer chains less likely to succeed end-to-end)

Formula logic:
- Sum weighted CVSS
- Apply penalty:  
```

Final Risk = Total Risk × Length Penalty

```

---

## 8️⃣ How was remediation prioritized?

Remediation prioritization was based on:

- CVSS Score
- Number of attack paths involving the vulnerability
- Position in attack chains (earlier = more critical)

Final score mapped to priority levels:

| Score | Priority |
|--------|----------|
| > 8.0  | Critical |
| > 6.0  | High |
| > 4.0  | Medium |
| ≤ 4.0  | Low |

---

## 9️⃣ Why was Weak Authentication ranked as Critical?

Weak Authentication (VULN-003):

- Appeared early in high-risk attack chains
- Enabled SQL Injection
- Had high CVSS score
- Influenced multiple attack paths

Therefore, it received a maximum criticality score of 10.0.

---

## 🔟 What is the real-world importance of attack trees?

Attack trees help organizations:

- Understand attacker mindset
- Identify most dangerous attack paths
- Prioritize remediation efforts
- Improve risk-based decision making
- Communicate threats clearly to stakeholders

They are widely used in:
- Enterprise threat modeling
- Secure architecture design
- Security risk assessments
- Compliance reporting

---

## 1️⃣1️⃣ How does attack tree modeling support DevSecOps?

Attack trees support DevSecOps by:

- Integrating threat modeling early in SDLC
- Identifying high-risk components
- Providing structured remediation planning
- Supporting automated risk scoring

This enables proactive security instead of reactive patching.

---

## 1️⃣2️⃣ What are limitations of attack trees?

Limitations include:

- Requires accurate probability estimates
- Can become complex for large systems
- May not capture dynamic attacker behavior
- Needs regular updates as environment changes

Despite limitations, they remain a powerful modeling technique.

---

## 1️⃣3️⃣ How can this lab be extended further?

Possible extensions:

- Add visualization using Graphviz
- Integrate real CVE data
- Automate probability calculation from threat intelligence
- Export reports in PDF format
- Build web dashboard for attack tree visualization

---

## 1️⃣4️⃣ What key cybersecurity skills were demonstrated in this lab?

- Threat modeling
- Vulnerability analysis
- Risk quantification
- Python scripting for security
- Graph-based attack modeling
- Remediation prioritization
- Structured reporting

---

## 1️⃣5️⃣ What was the biggest learning outcome from this lab?

The most important learning outcome:

> Security is not just about finding vulnerabilities —  
> It is about understanding how they combine, how attackers think, and how to prioritize mitigation strategically.

This lab reinforced risk-based security thinking and structured threat modeling.

---
