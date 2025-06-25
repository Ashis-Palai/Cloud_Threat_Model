
# 🛡️ Threat Modeling with PASTA: AWS Bedrock RAG Chatbot

This document presents a comprehensive **PASTA (Process for Attack Simulation and Threat Analysis)** threat modeling analysis for a cloud-native **Retrieval-Augmented Generation (RAG) chatbot** architecture using **AWS Bedrock, ECS Fargate, Streamlit, DynamoDB, OpenSearch, Titan Embeddings, and Amazon S3**.

The objective is to assess threats systematically using the 7-stage PASTA methodology, allowing us to:
- Align technical and business impact in threat identification,
- Integrate architectural understanding (e.g., LLM workflows, user identity, document enrichment),
- Map simulated attack surfaces to controls across CSP-native services (e.g., IAM, Bedrock, VPC, Gateway, etc.).

PASTA enables not just vulnerability identification, but a **risk-oriented narrative** rooted in real-world attacker perspectives and **cloud-specific TTPs**. It’s especially valuable for systems like this where:
- Sensitive data flows between user input, documents, embeddings, and AI inference.
- There are complex multi-boundary interactions (VPC ↔ AWS-managed services).
- Orchestrators (Lambda) hold central control logic that needs careful review.

Each of the upcoming sections will dive into a stage of the PASTA model with relevance to our architecture.
### 🗺️ Architecture Overview

The architectural diagram below illustrates the high-level structure of the AWS Bedrock RAG chatbot system, including boundaries, components, and data flows across Lambda, Bedrock (Claude 3), Titan, S3, OpenSearch, and user-facing services:

![Architecture Diagram](/architecture/bedrock_chatbot_architecture.PNG)


---


## 🔍 PASTA Stage 1: Define the Objectives

This stage defines the **business**, **security**, and **risk** foundation for the RAG chatbot system.

### 1. Business Objectives

The primary goal of this application is to provide an interactive **LLM-powered chatbot** that allows users to query across structured and unstructured enterprise knowledge using a **Retrieval-Augmented Generation (RAG)** framework.  
The system leverages:
- **AWS Bedrock (Claude 3)** for LLM inference,
- **Titan Embeddings + OpenSearch** for semantic search,
- **Amazon S3** as the document source, and
- **DynamoDB** for session memory/state.

Key functional outcomes:
- Deliver fast, context-aware chatbot responses.
- Seamlessly incorporate new document knowledge without retraining.
- Enable enterprise-wide secure access to AI-powered search/assist features.

### 2. Security and Compliance Requirements

Given the nature of document ingestion and LLM interaction, the system must ensure:
- **Data confidentiality** of user input and chat history (via encryption at rest and in transit),
- **IAM-based least privilege** access across Lambda, Bedrock, and storage layers,
- **Protection against prompt injection and session hijacking**,
- **Audit trails** for all sensitive operations (e.g., document embedding, LLM invocation),
- **Regulatory readiness**: GDPR/ISO 27001-style access control and retention policies,
- Compliance with **Cloud Security Alliance (CSA CCM)**, **NIST CSF**, and **AWS Well-Architected Framework** security pillars.

### 3. Business Impact (BIA)

If the system is compromised or unavailable:
- **Data integrity loss** in embeddings or RAG sources may degrade response quality.
- **LLM spoofing or leakage** may cause reputational or compliance damage.
- **Denial of Service (DoS)** on document ingestion pipeline (S3 → Titan → Vector DB) may render chatbot non-functional.
- Impaired or manipulated chatbot responses can lead to **loss of user trust**, especially if misinformation or unauthorized access occurs.

Impact severity: **High**, especially for document-sensitive organizations (e.g., legal, healthcare, or internal ops).

### 4. Risk Profile

The system operates under a **moderate-to-high threat surface**, including:
- External user interactions,
- API gateway exposures,
- LLM model behavior unpredictability,
- Vector DB poisoning or enumeration,
- Weak isolation in serverless contexts.

Mitigation posture includes:
- Tight IAM policies,
- Use of AWS-native threat detection (GuardDuty, CloudTrail),
- Data validation and schema enforcement before embedding,
- Embedding fingerprinting or duplicate detection.

This risk profile sets the tone for deeper analysis in the next stages of the PASTA process.

---

## 🧭 PASTA Stage 2: Define the Technical Scope

This stage identifies the architectural boundaries, actors, data sources/sinks, and all technical dependencies of the RAG-based chatbot system.

### 2.0 Technical Scope Overview

The RAG chatbot is a distributed, cloud-native application deployed across customer-controlled and AWS-managed services. It integrates serverless orchestration, real-time embeddings, and LLM inference across multiple trust zones.

---

### 2.1 Identify Application Boundaries, Actors, Data Sources & Sinks

**Trust Boundaries:**
- **Internet**: Entry point for users accessing the chatbot via Streamlit.
- **AWS Customer VPC**: Hosts ECS, API Gateway, Lambda, DynamoDB, and S3.
- **AWS Managed Services**: Includes Bedrock (Claude 3), OpenSearch, and Titan Embeddings.

**Actors:**
- External: End-users interacting via UI.
- Internal: Lambda (orchestrator), Titan (embedding engine), Bedrock (LLM inference).

**Data Sources:**
- User inputs (chat queries),
- S3 documents (knowledge ingestion),
- DynamoDB (chat memory).

**Data Sinks:**
- OpenSearch (embedding vector storage),
- Bedrock (consumes RAG-enriched prompts),
- Streamlit UI (delivers final response).

---

### 2.2 Application Dependencies from Network Environment

- **API Gateway** acts as the control plane for routing requests to Lambda.
- **VPC endpoints / PrivateLink** are recommended for internal communication with AWS managed services to avoid traffic over the public internet.
- **TLS/HTTPS** is enforced for all inter-service communication.
- Network access is segmented by security groups and NACLs to reduce lateral movement.

---

### 2.3 Application Dependencies from Servers & Infrastructure

- **ECS Fargate**: Stateless container runtime that handles incoming UI traffic, performs pre-processing, and relays requests to the Lambda orchestrator.
- **Lambda**: Central orchestrator managing session state, context fetching, embedding pipelines, and LLM interactions.
- **DynamoDB**: Provides chat session persistence across user interactions.
- **Amazon S3**: Stores static documents to be processed and embedded for semantic context.
- **Amazon OpenSearch (Vector DB)**: Stores embeddings with metadata, enabling semantic search retrieval based on Titan vector matches.
- **AWS Bedrock (Claude 3)**: Executes LLM prompts and returns chat-like responses in context.

All services are deployed through **Infrastructure as Code** using tools like **AWS CDK** or **Terraform**, enabling repeatable, policy-compliant provisioning.

---

### 2.4 Application Dependencies from Software Components

- **Streamlit (Python)**: UI layer where users input queries and receive final responses.
- **FastAPI / Flask**: Lightweight backend server deployed on ECS for routing, validation, and session token handling.
- **LangChain or custom prompt orchestration**: Manages chaining logic for RAG — embedding → search → prompt creation → LLM call.
- **SentenceTransformers or Titan Integration Layer**: Used to convert documents or user queries into embeddings before storing in OpenSearch.
- **OpenSearch Python Client**: Enables querying the vector DB from Lambda using vector similarity.
- **Requests / HTTPX**: For making HTTPS calls from Lambda or ECS to Bedrock, Titan, or internal services.
- **JSON Schema Validators**: Used to validate the structure of prompt templates, documents, and embeddings to prevent malformed data or injection attacks.
- **CI/CD Pipelines**: GitHub Actions or AWS CodePipeline to automate deployment of Lambda, ECS tasks, and IaC modules. Static analysis, policy scans, and OPA gatekeeping may be included.

---

This completes the technical scope definition for the system. Next, we move into identifying threat agents and potential attack vectors in Stage 3.

## 🧩 PASTA Stage 3: Decompose the Application

This stage focuses on breaking down the RAG chatbot application into use cases, data flows, and security-functional boundaries to enable detailed threat enumeration in later stages.

---

### 3.1 Use Case Enumeration

The primary use cases for the AWS Bedrock RAG chatbot include:

- **Chat Interaction**: Users input natural language questions via the Streamlit UI.
- **Query Handling**: ECS backend forwards input to the Lambda orchestrator.
- **Context Enrichment**:
  - Lambda fetches session history from DynamoDB.
  - It queries OpenSearch for relevant embedded content.
  - If required, it generates embeddings via Titan from documents stored in S3.
- **Prompt Construction & LLM Execution**: Enriched prompt is sent to Claude 3 via AWS Bedrock; response returned.
- **Response Delivery**: Lambda updates session history and sends final output to Streamlit via ECS.

---

### 3.2 Data Flow Diagrams

To visualize the system components, communication paths, and trust boundaries, we refer to both manual and automated DFDs:

#### ▶️ Threat Dragon-Based DFD

This diagram, created via OWASP Threat Dragon, maps system entities and their STRIDE-based threat categories:

![Threat Dragon DFD](/threat-dragon/images/DFD_ThreatDragon_Bedrock_Chatbot.png)

#### ▶️ PyTM-Based DFD

Generated from a Python-based threat model, this DFD maps data flows, Lambda orchestration, AWS-managed service boundaries, and embedding logic:

![PyTM DFD](/PyTM/images/dfd.png)



---

### 3.3 Security Functional Analysis and Trust Boundaries

**Defined Trust Boundaries:**

- **Internet Boundary**: Initial untrusted zone where users initiate interaction.
- **Customer VPC Boundary**: Secure zone where ECS, API Gateway, Lambda, DynamoDB, and S3 (private) operate under strict IAM controls.
- **AWS Managed Services Boundary**: Operated by AWS; includes Bedrock, Titan Embeddings, and OpenSearch (vector DB).

**Security Functional Observations:**

- Lambda operates across multiple trust boundaries and holds central access to sensitive systems. It requires strict runtime integrity, IAM role separation, and telemetry.
- Data entering the system passes through multiple stages: ECS > API Gateway > Lambda > vector enrichment > LLM. Each stage is a potential threat insertion point if not validated or encrypted.
- Documents stored in S3 act as upstream knowledge sources and must be immutable and verified before embedding.
- Embedding and search infrastructure (Titan + OpenSearch) is AWS-managed but interacts bidirectionally with Lambda, requiring encryption in-transit, fine-grained policy control, and embedding tamper detection.
- All ingress and egress paths are TLS-enforced. Logging and audit trails must span across boundaries to support full forensic visibility.

---

The decomposition phase provides the architectural clarity needed to map specific threats, attacker motivations, and technical weaknesses in subsequent PASTA stages.

---
## 🔍 PASTA Stage 4: Analyze the Threats

This stage focuses on evaluating the threat landscape by blending system knowledge with threat intelligence, attacker modeling, and likelihood estimation.

---

### 🔹 Objectives

- Analyze architectural and component-level threat scenarios.
- Correlate threat intelligence from external sources (e.g., MITRE, OWASP, CSA).
- Enrich internal threat libraries with LLM- and cloud-native attack patterns.
- Map threat agents to high-value assets and trust zones.
- Assign probabilistic scores to threats based on risk impact and exploitability.

---

### ⚠️ Threat Scenario: Prompt Injection via RAG Context Pollution

**Threat Title:**  
`Prompt Injection via RAG Context Pollution`

**Description:**  
An attacker manipulates the chatbot's context by injecting malicious content through uploaded documents (e.g., S3) or user inputs. These manipulated inputs influence the prompt construction pipeline, potentially causing the LLM to hallucinate, leak data, or impersonate business logic. Because the RAG context is dynamically enriched from OpenSearch and S3, this forms an unmonitored threat surface.

**Potential Impact:**  
- Hallucination of facts and system behaviors  
- Leakage of sensitive data or internal policies  
- Unauthorized financial or transactional actions  
- Loss of trust in AI-driven outputs

**Affected Components:**  
- Amazon S3 (source documents)  
- Titan Embeddings (vector conversion)  
- OpenSearch (context retrieval)  
- AWS Bedrock Claude 3 (LLM inference)  
- Lambda (prompt orchestration)

**Threat Intelligence Mappings:**
- **MITRE ATT&CK:** `T1565.001 – Data Manipulation (Stored Data)`
- **OWASP LLM Top 10:**  
  - `LLM01 – Prompt Injection`  
  - `LLM10 – Training Data Poisoning`


**Countermeasures:**  
- Validate and sanitize documents before ingestion into S3  
- Define clear context boundaries in prompt templates  
- Apply Bedrock Guardrails or Anthropic Constitutional AI constraints  
- Tag embeddings with provenance metadata and filter untrusted sources  
- Monitor OpenSearch for anomalous query patterns  
- Apply LLM static/dynamic scanning (e.g., OpenLLM-Guard, Rebuff)

---


---

### ⚠️ Threat Scenario: Token Replay and API Abuse via Gateway

**Threat Title:**  
`Token Replay and API Abuse via Gateway`

**Description:**  
An adversary captures a valid API token or session credential (e.g., via credential stuffing, insecure transport, or endpoint compromise) and reuses it to interact with the API Gateway. This can lead to unauthorized Lambda invocations, chat session manipulation, or prompt flooding. The serverless and stateless nature of the architecture increases detection difficulty, especially if API throttling is not tightly configured or tokens lack short expiration and binding.

**Potential Impact:**  
- Denial of Service (Lambda resource exhaustion)  
- Unauthorized writes or edits in DynamoDB  
- Excessive use of embedding/LLM resources leading to billing spikes  
- Sensitive data leakage through session impersonation  
- Breach of tenant isolation in multi-user scenarios

**Affected Components:**  
- API Gateway  
- Lambda (orchestration function)  
- DynamoDB (session state)  
- AWS Bedrock (Claude 3 inference)

**Threat Intelligence Mappings:**
- **MITRE ATT&CK:**  
  - [T1078.004 – Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)  
  - [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)

- **OWASP LLM Top 10:**  
  - [LLM03 – Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm03-sensitive-information-disclosure)

**Likelihood:** ✅ Applicable

**Countermeasures:**  
- Use short-lived, signed JWTs with IP/device binding  
- Apply WAF rules and rate limiting at the API Gateway  
- Implement anomaly detection for session usage (e.g., volume spikes from unfamiliar IPs)  
- Encrypt all session data in transit and at rest with strict IAM policies  
- Integrate AWS Cognito or external IdP with token revocation and session awareness  
- Use [Lambda Authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html) to enforce request validation  
- Monitor with CloudTrail and GuardDuty for token misuse indicators

---

---

### ⚠️ Threat Scenario: Vector Index Poisoning in OpenSearch

**Threat Title:**  
`Vector Index Poisoning in OpenSearch`

**Description:**  
An adversary injects poisoned embeddings into the OpenSearch vector store. These embeddings are crafted to appear semantically relevant but are designed to return attacker-controlled content during similarity search. If the document ingestion process (e.g., from S3 to Titan to OpenSearch) lacks validation, a poisoned input can degrade the trustworthiness of the chatbot’s context. This enables attacker-influenced misinformation or hallucination from the LLM, misguiding users in critical decision-making.

**Potential Impact:**  
- LLM hallucination and trust degradation  
- Targeted misinformation dissemination  
- Corruption of business logic or decision workflows  
- Brand damage or loss of credibility due to misleading responses

**Affected Components:**  
- OpenSearch (vector database)  
- Titan Embeddings  
- Amazon S3 (unverified sources)  
- Lambda (embedding pipeline orchestration)

**Threat Intelligence Mappings:**
- **MITRE ATT&CK:**  
  - [T1565.001 – Data Manipulation: Stored Data](https://attack.mitre.org/techniques/T1565/001/)  
    _Applies directly to manipulation of stored embeddings or vector corruption._

- **OWASP LLM Top 10:**  
  - [LLM10 – Training Data Poisoning](https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm10-training-data-poisoning)  
    _In RAG, poisoning embeddings at inference-time is just as harmful as model training-time._

**Likelihood:** ✅ Applicable

**Countermeasures:**  
- Sanitize all input documents prior to embedding (especially user-submitted sources)  
- Implement outlier detection using cosine distance or clustering methods  
- Only accept signed uploads from trusted IAM principals or CI/CD pipelines  
- Monitor OpenSearch for vector injection anomalies or semantic drift  
- Restrict write access to vector DB with fine-grained IAM policies  
- Use ML-based monitoring tools (e.g., [Marqo](https://www.marqo.ai/)) or build custom vector integrity checks

---

---

### ⚠️ Threat Scenario: LLM Response Spoofing in Transit

**Threat Title:**  
`LLM Response Spoofing in Transit`

**Description:**  
An adversary positioned in a compromised or misconfigured network (e.g., via exposed internal endpoints, SSRF, or VPC peering flaws) could intercept or spoof responses from AWS Bedrock’s Claude 3 LLM. Since the inference runs outside the customer VPC and responses flow through Lambda and API Gateway, the integrity of the LLM’s response relies on secure transmission. If attackers modify payloads in transit, they could deliver malicious, misleading, or impersonated content while impersonating the trusted LLM source.

**Potential Impact:**  
- Delivery of malicious or misleading content  
- Impersonation of Claude 3 model outputs  
- User deception and phishing via falsified responses  
- Legal, compliance, or reputational impact from falsified AI decisions

**Affected Components:**  
- AWS Bedrock (Claude 3)  
- Lambda (LLM response handler)  
- API Gateway (response relay)  
- Streamlit UI (end-user response rendering)

**Threat Intelligence Mappings:**
- **MITRE ATT&CK:**  
  - [T1557 – Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/)  
    _Covers interception/manipulation of inter-service communication._  
  - [T1040 – Network Sniffing](https://attack.mitre.org/techniques/T1040/)  
    _Applies to scenarios where VPC network boundaries are misconfigured._

- **OWASP LLM Top 10:**  
  - [LLM04 – Model Output Manipulation](https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm04-model-output-manipulation)  
    _Relevant when outputs from LLMs are tampered with post-generation._

**Likelihood:** ✅ Applicable

**Countermeasures:**  
- Enforce TLS 1.2+ for all Bedrock-to-Lambda and API Gateway communication  
- Use signed responses with HMAC or SHA256 checksums to validate response integrity  
- Invoke Bedrock securely using [AWS PrivateLink](https://docs.aws.amazon.com/bedrock/latest/userguide/network.html) or VPC endpoints  
- Enable VPC Flow Logs and CloudWatch metrics to monitor for anomalous traffic patterns  
- Validate response structure and metadata using API Gateway response transformations  
- Explore LLM output attestation or checksum verification at runtime (experimental but emerging)

---

---

### ⚠️ Threat Scenario: Over-permissioned Lambda Leading to Privilege Escalation

**Threat Title:**  
`Over-permissioned Lambda Leading to Privilege Escalation`

**Description:**  
The Lambda function orchestrating the RAG workflow often has elevated IAM privileges across services such as DynamoDB, S3, Bedrock, OpenSearch, or Titan Embeddings. If the Lambda is compromised (e.g., via SSRF, injection, or logic flaws), an attacker could exploit these permissions to pivot laterally and perform unauthorized actions — such as modifying session data, generating malicious embeddings, triggering LLM prompts, or exfiltrating sensitive documents. This is especially dangerous in environments lacking strong observability or monitoring (e.g., no GuardDuty, no CloudTrail analysis).

**Potential Impact:**  
- Full compromise of RAG pipeline (data + inference)  
- Prompt and context injection leading to LLM abuse  
- Unauthorized access or modification in DynamoDB and OpenSearch  
- Data leakage from S3 or misuse of Bedrock for arbitrary prompts  
- Abuse of LLM quotas, leading to financial and reputational damage

**Affected Components:**  
- Lambda (central orchestrator)  
- IAM roles attached to Lambda  
- Amazon S3, DynamoDB, OpenSearch  
- AWS Bedrock (LLM API)

**Threat Intelligence Mappings:**
- **MITRE ATT&CK:**  
  - [T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/)  
    _Covers abuse of overly broad IAM roles or credentials._  
  - [T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)  
    _Applies when Lambda can write or execute in unauthorized services._  
  - [T1078.004 – Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)  
    _Pertains to use of compromised roles in cloud-native contexts._

- **OWASP LLM Top 10:**  
  - [LLM05 – Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm05-excessive-agency)  
    _Relevant when Lambda enables LLMs to influence or invoke downstream system actions._

**Likelihood:** ✅ Applicable

**Countermeasures:**  
- Apply **least privilege** IAM policies tailored to each Lambda’s function  
- Use **IAM Access Analyzer** to identify and remediate over-permissive roles  
- Break down Lambda logic into smaller functions with tightly scoped access  
- Enable **CloudTrail**, **AWS Config**, and **GuardDuty** for real-time activity monitoring  
- Use runtime detection tools like [Datadog Serverless Monitoring](https://www.datadoghq.com/blog/serverless-monitoring-lambda/) or [Falco](https://falco.org/)  
- Periodically audit roles with tools like [Prowler](https://github.com/prowler-cloud/prowler) or AWS Inspector

---

---

## 🧪 Stage 5: Vulnerability and Weakness Analysis

This stage focuses on identifying and correlating technical vulnerabilities and design weaknesses that could be exploited by the previously defined threats. It bridges the gap between threat scenarios and the actual risk posture by:

- Mapping known vulnerabilities to critical assets (data, components, infrastructure),
- Using established security taxonomies such as CWE (Common Weakness Enumeration),
- Providing the foundation for threat exploitation modeling using threat trees and use/abuse cases in the next sub-stages.

The goal is to translate architectural and threat insights into tangible risk drivers, categorized, quantified, and actionable for both engineering and governance teams.

---

### 🔍 5.1 Correlating Vulnerabilities to Application Assets

Below is a mapping of key application assets (identified in Stage 3 decomposition) to their most relevant technical vulnerabilities based on known cloud-native application flaws, software weaknesses, and architectural posture.

| **Asset / Component**         | **Vulnerability Description**                                        | **Relevant CWE** | **Impact Summary**                                                                 |
|------------------------------|------------------------------------------------------------------------|------------------|-------------------------------------------------------------------------------------|
| Lambda (Orchestrator)        | Overly broad IAM role permissions                                      | CWE-284          | Unauthorized access or escalation to other services within AWS environment         |
| Amazon S3 (Document Source)  | Lack of input validation / file sanitization                          | CWE-20           | Poisoned input can compromise embedding pipeline or bypass downstream logic        |
| OpenSearch (Vector DB)       | Insecure or exposed ingestion APIs                                    | CWE-306          | Unauthorized users could inject malicious vector content into the index            |
| DynamoDB                     | Session/token storage lacks authorization enforcement                 | CWE-862          | Unauthorized users may access or modify session data                               |
| API Gateway                  | Insufficient request validation or input size limits                  | CWE-400          | May lead to DoS via oversized or malformed payloads                                |
| Bedrock (Claude 3)           | Lack of inference response validation or integrity checks             | CWE-345          | Responses could be spoofed or manipulated in-transit without verification          |
| Titan Embedding Process      | No boundary enforcement on input from S3                              | CWE-915          | Enables indirect command injection or prompt pollution through embeddings          |
| ECS Fargate                  | Excessive logging of user inputs / credentials                        | CWE-532          | Potential for sensitive information exposure in logs                               |
| Streamlit UI                 | Lack of context-aware input sanitization                              | CWE-79           | Input may lead to downstream injection into prompts or query parameters            |

These vulnerabilities represent real-world misconfigurations and design flaws observed in AI-integrated cloud architectures, especially those utilizing orchestration and embedding workflows. As the threat landscape continues to evolve around LLMs and AI APIs, it is essential that security posture evaluations remain continuous and control coverage remains adaptive.



