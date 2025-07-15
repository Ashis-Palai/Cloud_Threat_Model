
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

### ⚠️ Threat Scenario: Over-Permissioned Lambda Enabling Insecure Operations

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


---

#### 🧠 Lambda Function (Orchestrator) – Vulnerability Mapping

The Lambda function serves as the central orchestrator for interacting with Amazon Bedrock, S3, OpenSearch, and other services. Below is a detailed vulnerability correlation for Lambda, derived from real-world findings, CVEs, and cloud misconfiguration patterns.

| **#** | **Category**                     | **Vulnerability / CVE / CWE**                                                      | **Phase**        | **Risk**       | **Details / Context**                                                                                 |
| ----- | -------------------------------- | ---------------------------------------------------------------------------------- | ---------------- | -------------- | ----------------------------------------------------------------------------------------------------- |
| 1     | Misconfiguration                 | **Lambda Admin Privileges** (AquaSec)                                              | Provision        | High           | Excessive IAM role permissions; can lead to privilege escalation via `sts:AssumeRole`                 |
| 2     | Configuration                    | **CVE-2024-37293** (ADF Lambda pre-4.0.0) / **CWE-266**                            | Provision        | High           | Auto-deployed Lambda can gain elevated access, privilege misuse in CI/CD automation                   |
| 3     | Code Injection                   | **CVE-2019-10777** / **CWE-78** (Command Injection via unsanitized `FunctionName`) | Build/Dev        | Critical (9.8) | Malicious input in `FunctionName` leads to arbitrary OS command execution via `exec()` in npm scripts |
| 4     | DoS / Input Validation           | **CVE-2018-7560** / **CWE-20** (ReDoS via aws-lambda-multipart-parser)             | Runtime          | High (7.5)     | Malformed multipart input leads to DoS using regex in `multipart-parser`                              |
| 5     | Secrets Handling                 | Lambda Env Vars not encrypted (AquaSec, CNAS-5)                                    | Config / Runtime | High           | Secrets in plaintext (e.g., API keys, DB creds) in Lambda environment variables                       |
| 6     | Supply Chain / Integrity         | **Lambda Code Signing Not Enabled**                                                | Build / Deploy   | Medium         | Lack of validation allows unverified or tampered code                                                 |
| 7     | Logging / Monitoring             | **Lambda Tracing Not Enabled**, **No CloudWatch Alarms**                           | Runtime          | Medium         | Poor observability delays incident detection                                                          |
| 8     | IAM Abuse / Overreach            | **Privilege Analysis**, **No Unique IAM Role**                                     | Provision        | High           | Shared roles increase lateral movement risk                                                           |
| 9     | Network Exposure                 | **Lambda VPC Config**, **Public Lambda Access**, **Internet Exposure**             | Runtime / Config | High           | Unrestricted network access — enables data exfiltration or attack entry points                        |
| 10    | Outdated Runtime                 | **Lambda Old Runtime** (e.g., Python 2.7, Node 10.x)                               | Build / Deploy   | High           | Old runtimes = missing patches, known vulnerabilities                                                 |
| 11    | Software Component Risk          | **CNAS-7**: Known Vulnerable Dependencies                                          | Build            | High           | Use of unpatched libraries (e.g., 3rd-party NLP or parser libraries)                                  |
| 12    | Inadequate Function Limits       | **No Concurrency or Timeout Limits**                                               | Runtime          | Medium         | Risk of runaway invocation (loop), cost spike, or DoS                                                 |
| 13    | Source ARN Not Restricted        | **No SourceArn in Trigger Permissions** (AquaSec, CNAS-3)                          | Provision        | High           | Any principal can invoke the function — abuse potential                                               |
| 14    | Logging Gap                      | **CNAS-10: No resource activity monitoring**                                       | Runtime          | Medium         | Missing audit trail, difficult post-incident analysis                                                 |
| 15    | Dependency Bloat                 | **Use of multipart-parser or similar**                                             | Build / Runtime  | Medium         | Increases attack surface; introduces supply-chain ReDoS                                               |
| 16    | Function Visibility / Asset Mgmt | **Untagged or Untracked Lambda** (CNAS-8)                                          | Config           | Medium         | Functions lack traceability and lifecycle management                                                  |
| 17    | CI/CD Flaws                      | **CNAS-4: Use of untrusted or stale images/layers in deployment**                  | Build            | Medium         | DevOps pushes unscanned packages or images into production                                            |
| 18    | Runtime Input Exploitation       | **CNAS-2: Event Injection** (e.g., JSON input crafting from API Gateway)           | Runtime          | High           | Poor input validation → event-driven attack (e.g., path traversal, logic abuse)                       |

---



---

#### 🧠 S3 – Vulnerability Mapping

| **#** | **Category**               | **Vulnerability / CVE / CWE**                                                                                   | **Phase**            | **Risk**     | **Details / Context**                                                                   |
| ----- | -------------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------- | ------------ | --------------------------------------------------------------------------------------- |
| 1     | XXE / Data Injection       | **CVE-2025-4949** / **CWE-611, CWE-827** – Eclipse JGit & XML manifest in S3                                    | Build (DevOps)       | Medium (6.8) | XXE vulnerability due to improperly parsed XML files stored in S3 used by CI/CD systems |
| 2     | XXE / SSRF                 | **CVE-2025-27136** / **CWE-611** – XML bucket creation via `locals3` triggering SSRF                            | Build / Test Tools   | Medium (5.5) | SSRF or info leak via local mock S3 services used in testing                            |
| 3     | Secrets / Encryption       | **CVE-2022-2582** / **CWE-326** – AWS S3 Crypto SDK storing metadata in plaintext                               | Code Logic           | Medium (4.3) | SDK flaw allows plaintext exposure of object encryption metadata                        |
| 4     | Credential Exposure        | **CVE-2022-43426** / **CWE-256** – Jenkins AWS S3 plugin storing AWS creds in plaintext                         | Provisioning (CI/CD) | Medium (5.3) | Compromise of plaintext AWS access keys via plugin config                               |
| 5     | Public Access Risk         | **S3 Bucket Public Access Block**, **No Public Buckets**, **No Public Access with ACLs**                        | Provision / Runtime  | Critical     | Default S3 allows public access via ACL or policy unless explicitly blocked             |
| 6     | Insecure Acls              | **Block Public ACLs**, **Ignore Public ACLs**, **S3 Bucket All Users Policy**                                   | Provision            | High         | Improper access control due to unblocked ACLs                                           |
| 7     | Policy Gaps                | **Block Public Policy**, **Require MFA Delete**, **CloudTrail Bucket Delete Policy**                            | Provision            | High         | Missing preventive controls increases data tampering and ransomware risk                |
| 8     | Encryption Missing         | **Enable Bucket Encryption**, **S3 Bucket Encryption Enforcement**, **Encryption Customer Key**, **In Transit** | Config / Runtime     | High         | Sensitive data in transit or at rest left unencrypted or under weak encryption config   |
| 9     | Logging Disabled           | **Enable Logging**, **Enable Object Read/Write Logging**, **CloudTrail Audit Logging Missing**                  | Runtime / Compliance | Medium       | Reduced auditability and detection capability for access/misuse                         |
| 10    | Lack of Versioning         | **Enable Versioning**, **MFA Delete**, **S3 Versioned Buckets Lifecycle Configuration**                         | Runtime              | Medium       | Ransomware or data corruption hard to mitigate without object versioning                |
| 11    | Resource Hygiene           | **S3 Bucket Has Tags**, **Lifecycle Configuration**, **S3 DNS Compliant Names**                                 | Management           | Low          | Asset mismanagement, non-compliant naming, untracked buckets                            |
| 12    | Insecure File Serving      | **S3 Bucket Website Enabled**                                                                                   | Runtime / Exposure   | Medium       | Enables static site hosting that could be misused to serve malware or sensitive data    |
| 13    | Insecure Transport         | **S3 Secure Transport Not Enabled**, **S3 Bucket Encryption In Transit**                                        | Runtime              | High         | Allows data transmission over HTTP instead of HTTPS                                     |
| 14    | Attack Surface Expansion   | **S3 Transfer Acceleration Enabled** without rate limiting                                                      | Runtime              | Medium       | Could be used for rapid data exfiltration                                               |
| 15    | CI/CD Supply Chain Risk    | **CNAS-4:** Use of plugins/tools (JGit, Jenkins S3) storing credentials or pushing unvalidated XML              | Build / CI/CD        | High         | Dependency abuse or insecure automation workflow                                        |
| 16    | Improper Access Delegation | **CNAS-3:** Over-permissive IAM policies granting full access to S3 buckets                                     | Provision / Runtime  | High         | IAM misconfiguration leading to lateral movement and exfiltration                       |
| 17    | Known Vulnerable Tools     | **CNAS-7:** Use of known-vulnerable 3rd party plugins (e.g., Jenkins AWS S3 explorer 1.0.8)                     | Build / CI/CD        | Medium       | Plugin with known flaws still widely used                                               |
| 18    | Unmonitored Assets         | **CNAS-8:** Obsolete or unknown buckets with legacy configs                                                     | Runtime / Lifecycle  | Medium       | Buckets from deprecated workflows still online and vulnerable                           |
| 19    | Lack of DDoS Controls      | **S3 Public endpoints not rate-limited**                                                                        | Runtime              | Medium       | No throttling or WAF-style protections for public objects or static websites            |
| 20    | Weak IAM Trust Policies    | **No explicit trust boundaries for cross-account access**                                                       | Provision            | High         | Poor trust setup can lead to third-party unauthorized access                            |



---

#### 🧠 Opensearch (vector db) – Vulnerability Mapping

| **#** | **Category**                        | **Vulnerability / CWE / Misconfiguration**                                                                  | **Phase**            | **Risk**           | **Details / Context**                                                                             |
| ----- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------- | ------------------ | ------------------------------------------------------------------------------------------------- |
| 1     | **Insecure Local Config**           | **CVE-2021-44833** / **CWE-276** – AWS OpenSearch CLI `config.yaml` file readable/executable by all users   | Dev Env (Build)      | **Critical (9.8)** | CLI config file exposes credentials/API config — lateral movement risk                            |
| 2     | **IAM Misuse / Privilege**          | **OpenSearch IAM Authentication not enforced**                                                              | Provision            | **High**           | Lack of IAM enforcement means any user or service can interact with the vector index API          |
| 3     | **Unauthorized Public Access**      | **OpenSearch Collection Public Access**, **Exposed Domain**, **Public Service Domain**, **Access From IPs** | Provision / Runtime  | **Critical**       | Entire vector store exposed to internet or unintended networks                                    |
| 4     | **Insecure Transport Layer**        | **OpenSearch HTTPS Only Disabled**, **OpenSearch TLS Version (Outdated)**                                   | Runtime / Network    | **High**           | Allows downgrade or MITM of vector search queries and payloads                                    |
| 5     | **Improper Access Isolation**       | **Domain Cross Account Access** without restriction                                                         | Runtime / IAM Config | **High**           | Could allow unintended access to entire embedding corpus from another account                     |
| 6     | **Lack of Encryption**              | **OpenSearch Encryption Enabled**, **Encrypted Domain**, **CMK Encryption**, **Node to Node Encryption**    | Storage / Network    | **High**           | Embeddings (intellectual property or user data) exposed in storage or during replication          |
| 7     | **Audit / Logging Gaps**            | **OpenSearch Audit Logs Disabled**, **Logging Not Enabled**                                                 | Runtime / Compliance | **Medium**         | Lack of forensic traceability for similarity queries, embedding misuse or unauthorized scans      |
| 8     | **Version Drift**                   | **OpenSearch Version**, **OpenSearch Upgrade Available**                                                    | DevOps / Patch       | **Medium**         | Legacy versions may miss CVE patches, vector indexing performance or DoS protections              |
| 9     | **Zone Fault Tolerance**            | **OpenSearch Zone Awareness Disabled**                                                                      | Runtime / HA         | **Medium**         | Outage risk affecting vector search if AZ goes down                                               |
| 10    | **Node Stability**                  | **Dedicated Master Not Enabled**, **Desired Instance Type** not optimized                                   | Runtime / Stability  | **Medium**         | Vector-heavy workloads (ANN/knn, cosine similarity) are resource-intensive                        |
| 11    | **CNAS-3: IAM Over-Permission**     | Unscoped access to vector APIs by internal services                                                         | Provision            | **High**           | Could allow misuse of vector indexes, especially with knn\_vector exposed endpoints               |
| 12    | **CNAS-5: Unencrypted Secrets**     | CLI config stored with plaintext endpoint/keys (linked to CVE-2021-44833)                                   | Dev                  | **High**           | Exploitable during lateral movement or code repo leakage                                          |
| 13    | **CNAS-6: Insecure Network Policy** | Public endpoint exposed or internal traffic not restricted (ACLs, SGs)                                      | Runtime / Network    | **High**           | Embedding store vulnerable to vector scraping, brute search attacks                               |
| 14    | **Vector-Specific Threat**          | 🔐 **Malicious Embedding Insertion** (custom attack)                                                        | Ingest / Runtime     | **High**           | Poisoning vector store via adversarial embeddings affecting similarity behavior or search results |
| 15    | **Unmonitored Access Pattern**      | Lack of behavioral analytics or query pattern analysis                                                      | Runtime              | **Medium**         | Unusual usage of semantic APIs could signal abuse but goes undetected                             |
| 16    | **Static TLS / Cipher Config**      | TLS version/ciphers hardcoded or outdated                                                                   | Runtime / Network    | **Medium**         | Insecure transport encryption risks                                                               |



---

#### 🧠 DynamoDB – Vulnerability Mapping

| **#** | **Category**                      | **Misconfiguration / Weakness**                            | **Phase**              | **Risk**       | **Mapped CWE**                                      | **Context / Reason**                                                                   |
| ----- | --------------------------------- | ---------------------------------------------------------- | ---------------------- | -------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------- |
| 1     | **Encryption**                    | **Enable At Rest Encryption disabled**                     | Provision              | **High**       | CWE-311: Missing Encryption of Sensitive Data       | Embedding metadata, user-session IDs, PII, etc., could be stored without protection    |
| 2     | **Encryption**                    | **Table Customer Key not used** (no CMK)                   | Provision              | **High**       | CWE-312: Cleartext Storage of Sensitive Information | Without CMK, unable to enforce stricter access or audit control over encrypted keys    |
| 3     | **Encryption**                    | **DynamoDB Accelerator Cluster Encryption** disabled       | Provision / Runtime    | **Medium**     | CWE-311: Missing Encryption                         | DAX is an in-memory cache — without encryption, sensitive cached data is exposed       |
| 4     | **Recovery/Backup**               | **Enable Recovery / DynamoDB Continuous Backups Disabled** | Runtime                | **Medium**     | CWE-212: Improper Removal of Sensitive Data         | No backup = no recovery = data loss in attack or accidental deletion                   |
| 5     | **Recovery/Backup**               | **DynamoDB Table Backup Exists = ❌**                       | Runtime                | **Medium**     | CWE-710: Improper Adherence to Expected Conventions | Absence of backups breaks standard high-availability expectations                      |
| 6     | **Destructive Action Protection** | **DynamoDB Deletion Protection Not Enabled**               | Runtime                | **High**       | CWE-693: Protection Mechanism Failure               | Allows malicious or accidental table deletion without MFA or workflow gating           |
| 7     | **Data Loss / Logging**           | **DynamoDB Empty Table**                                   | Runtime                | **Low–Medium** | CWE-200: Exposure of Sensitive Information          | May indicate accidental overwrite or injection attacks where original data got wiped   |
| 8     | **Metadata Tagging**              | **DynamoDB Table Has Tags = ❌**                            | Provision / Governance | **Low**        | CWE-284: Improper Access Control                    | Lack of tagging can affect access policies, governance, cost controls                  |
| 9     | **Key Management**                | **Table Customer Key Not Used (CMK)**                      | Provision              | **High**       | CWE-256: Plaintext Storage of a Password            | Similar risk if encryption is default (AWS-managed), but not auditable or restrictable |


---

#### 🧠 API Gateway – Vulnerability Mapping
| **#** | **Category**                      | **Misconfiguration / Weakness**                  | **Phase**   | **Risk**     | **Mapped CWE**                                     | **Context / Reason**                                                               |
| ----- | --------------------------------- | ------------------------------------------------ | ----------- | ------------ | -------------------------------------------------- | ---------------------------------------------------------------------------------- |
| 1     | **Authentication**                | **API Gateway Authorization not enabled**        | Runtime     | **Critical** | CWE-284: Improper Access Control                   | Unauthenticated API allows public invocation of Lambda functions                   |
| 2     | **Authentication**                | **API Gateway V2 Authorization not enabled**     | Runtime     | **Critical** | CWE-287: Improper Authentication                   | Especially critical for HTTP APIs (V2) — allows unauthorized access to bot backend |
| 3     | **Transport Security**            | **Custom Domain TLS Version < 1.2**              | Provision   | **High**     | CWE-327: Use of a Broken or Risky Crypto Algorithm | Weak TLS versions enable MITM or downgrade attacks                                 |
| 4     | **Transport Security**            | **Use Secure TLS Policy not enforced**           | Provision   | **High**     | CWE-326: Inadequate Encryption Strength            | Allows weak cipher negotiation on TLS handshakes                                   |
| 5     | **Access Control**                | **No Public Access restrictions on API Gateway** | Runtime     | **Critical** | CWE-200: Exposure of Sensitive Information         | Without IP whitelisting/resource policy, APIs can be publicly abused               |
| 6     | **Access Control**                | **Default Endpoint Not Disabled**                | Runtime     | **High**     | CWE-668: Exposure of Internal Resource             | Exposes an additional invoke path bypassing auth layers                            |
| 7     | **Traffic Protection**            | **API Gateway WAF Not Enabled**                  | Runtime     | **High**     | CWE-693: Allocation of Resources Without Limits    | No protection against brute force or bot-based LLM abuse                           |
| 8     | **Traffic Protection**            | **API Gateway Client Certificate not required**  | Runtime     | **Medium**   | CWE-295: Improper Certificate Validation           | No mTLS — less secure in internal service-to-service communication                 |
| 9     | **Input Validation**              | **API Gateway Request Validation not enabled**   | Runtime     | **High**     | CWE-20: Improper Input Validation                  | No protection from malformed payloads or prompt injection                          |
| 10    | **Input Validation**              | **API Gateway Content Encoding not enforced**    | Runtime     | **Medium**   | CWE-444: Improper Encoding or Escaping of Output   | May allow content-type abuse or header smuggling                                   |
| 11    | **Monitoring & Audit**            | **Access Logging not enabled**                   | Runtime     | **Medium**   | CWE-778: Insufficient Logging                      | Loss of traceability and request history                                           |
| 12    | **Monitoring & Audit**            | **API Gateway V2 Access Logging not enabled**    | Runtime     | **Medium**   | CWE-778                                            | Misses deeper log insights for HTTP APIs                                           |
| 13    | **Monitoring & Audit**            | **Detailed CloudWatch Metrics disabled**         | Runtime     | **Medium**   | CWE-1191: Inadequate Monitoring                    | Prevents alerting on spike/failure patterns                                        |
| 14    | **Monitoring & Audit**            | **Enable Tracing not configured**                | Runtime     | **Medium**   | CWE-1173: Improper Debugging Information           | Limits end-to-end visibility through Lambda and beyond                             |
| 15    | **Caching / Security**            | **Stage-Level Cache Encryption not enabled**     | Provision   | **Medium**   | CWE-311: Missing Encryption of Sensitive Data      | If response caching is enabled, encryption must protect any cached sensitive data  |
| 16    | **Caching / Efficiency**          | **Enable Cache disabled**                        | Runtime     | Low–Medium   |                                                    | Reduces performance; context-dependent for dynamic vs static endpoints             |
| 17    | **Key Management / Cert Hygiene** | **Certificate Rotation not enabled**             | Maintenance | **Medium**   | CWE-321: Use of Hard-coded Cryptographic Key       | Long-lived certs can lead to compromise if not rotated                             |


---

#### 🧠 Amazon Bedrock – Vulnerability Mapping

| **#** | **Category**                   | **Misconfiguration / Weakness**                           | **Phase**   | **Risk**     | **Mapped CWE**                                     | **Context / Reason**                                                                                  |
| ----- | ------------------------------ | --------------------------------------------------------- | ----------- | ------------ | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| 1     | **Audit / Observability**      | **Bedrock Model Invocation Logging Disabled**             | Runtime     | **High**     | CWE-778: Insufficient Logging                      | Disables visibility into prompt activity — prevents detection of abuse, LLM jailbreaks, or data leaks |
| 2     | **Model Security**             | **Private Custom Model Not Configured**                   | Provision   | **High**     | CWE-200: Exposure of Sensitive Information         | Custom models deployed without network isolation may expose endpoints to unauthorized inference       |
| 3     | **Model Deployment**           | **Custom Model Not In VPC**                               | Provision   | **High**     | CWE-668: Exposure of Internal Resource             | Makes models accessible without private routing or firewall — vulnerable to exfiltration              |
| 4     | **Encryption / Data Security** | **Custom Model Encryption Disabled**                      | Provision   | **High**     | CWE-311: Missing Encryption of Sensitive Data      | Leaves model weights or parameters unencrypted in storage, risking IP and leakage                     |
| 5     | **Tagging / Governance**       | **Custom Model Has No Tags**                              | Governance  | **Low**      | CWE-284: Improper Access Control                   | Without tags, model cannot be properly governed or scoped in IAM, budgets, or monitoring              |
| 6     | **GenAI Pipeline Security**    | **Notebook Direct Internet Access Enabled**               | Runtime     | **High**     | CWE-668 / CWE-200                                  | Internet-exposed notebooks (e.g., SageMaker Studio) can be hijacked or used to poison model pipelines |
| 7     | **GenAI Pipeline Security**    | **Notebook Instance Not In VPC**                          | Provision   | **High**     | CWE-284 / CWE-732: Incorrect Permission Assignment | Not isolating notebooks risks both training data and model staging leakage                            |
| 8     | **Training Data Protection**   | **Notebook Data Not Encrypted**                           | Runtime     | **High**     | CWE-311: Missing Encryption of Sensitive Data      | Can lead to extraction of confidential embeddings or fine-tuning corpora                              |
| 9     | **Model Training Threats**     | **\[AML.T0020] Training Data Poisoning**                  | Development | **Critical** | CWE-20: Improper Input Validation                  | Poor input validation or review on training sets can introduce backdoors or sabotage model behavior   |
| 10    | **Info Disclosure / Recon**    | **\[AML.CS0006] Info Disclosure via Prompts or Metadata** | Runtime     | **High**     | CWE-200 / CWE-359: Exposure of Private Information | Sensitive responses can leak internal instructions, embeddings, system prompts, etc.                  |
| 11    | **Availability / DoS**         | **\[AML.CS0016] LLM Denial of Service (prompt spamming)** | Runtime     | **Medium**   | CWE-400: Uncontrolled Resource Consumption         | Prompt loops or oversized inputs can choke model invocations or cause billing spikes                  |


---

#### 🧠 ECS (Container) – Vulnerability Mapping

| **#** | **Category**                   | **Misconfiguration / Weakness**                           | **Phase**   | **Risk**     | **Mapped CWE**                                     | **Context / Reason**                                                                                  |
| ----- | ------------------------------ | --------------------------------------------------------- | ----------- | ------------ | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| 1     | **Audit / Observability**      | **Bedrock Model Invocation Logging Disabled**             | Runtime     | **High**     | CWE-778: Insufficient Logging                      | Disables visibility into prompt activity — prevents detection of abuse, LLM jailbreaks, or data leaks |
| 2     | **Model Security**             | **Private Custom Model Not Configured**                   | Provision   | **High**     | CWE-200: Exposure of Sensitive Information         | Custom models deployed without network isolation may expose endpoints to unauthorized inference       |
| 3     | **Model Deployment**           | **Custom Model Not In VPC**                               | Provision   | **High**     | CWE-668: Exposure of Internal Resource             | Makes models accessible without private routing or firewall — vulnerable to exfiltration              |
| 4     | **Encryption / Data Security** | **Custom Model Encryption Disabled**                      | Provision   | **High**     | CWE-311: Missing Encryption of Sensitive Data      | Leaves model weights or parameters unencrypted in storage, risking IP and leakage                     |
| 5     | **Tagging / Governance**       | **Custom Model Has No Tags**                              | Governance  | **Low**      | CWE-284: Improper Access Control                   | Without tags, model cannot be properly governed or scoped in IAM, budgets, or monitoring              |
| 6     | **GenAI Pipeline Security**    | **Notebook Direct Internet Access Enabled**               | Runtime     | **High**     | CWE-668 / CWE-200                                  | Internet-exposed notebooks (e.g., SageMaker Studio) can be hijacked or used to poison model pipelines |
| 7     | **GenAI Pipeline Security**    | **Notebook Instance Not In VPC**                          | Provision   | **High**     | CWE-284 / CWE-732: Incorrect Permission Assignment | Not isolating notebooks risks both training data and model staging leakage                            |
| 8     | **Training Data Protection**   | **Notebook Data Not Encrypted**                           | Runtime     | **High**     | CWE-311: Missing Encryption of Sensitive Data      | Can lead to extraction of confidential embeddings or fine-tuning corpora                              |
| 9     | **Model Training Threats**     | **\[AML.T0020] Training Data Poisoning**                  | Development | **Critical** | CWE-20: Improper Input Validation                  | Poor input validation or review on training sets can introduce backdoors or sabotage model behavior   |
| 10    | **Info Disclosure / Recon**    | **\[AML.CS0006] Info Disclosure via Prompts or Metadata** | Runtime     | **High**     | CWE-200 / CWE-359: Exposure of Private Information | Sensitive responses can leak internal instructions, embeddings, system prompts, etc.                  |
| 11    | **Availability / DoS**         | **\[AML.CS0016] LLM Denial of Service (prompt spamming)** | Runtime     | **Medium**   | CWE-400: Uncontrolled Resource Consumption         | Prompt loops or oversized inputs can choke model invocations or cause billing spikes                  |


---

### 🌲 5.2 Mapping Threats to Vulnerabilities and Misconfigurations (Threat Trees)

This subsection visualizes how each previously identified threat scenario is mapped to known vulnerabilities and misconfigurations in the Lambda function. By creating a **Threat Tree**, we uncover how different categories of risks (e.g., privilege escalation, remote code execution, denial of service) are realized through combinations of misconfigurations, outdated components, and poor deployment hygiene.

Threat trees are instrumental in understanding:
- The **logical structure** of how a threat could materialize,
- The **pathways** an attacker could follow, and
- How each vulnerability links to an exploit scenario.

#### 🖼️ Lambda Threat Tree Visualization

![Lambda Threat Tree](/PASTA/images/threat_tree_lambda_enhanced.png)

> **Figure**: Threat Tree representing threat categories and related Lambda vulnerabilities.

---

---

#### 🔍Threat Tree Explanation – Lambda Orchestrator

The root of this threat tree is the critical risk: **“Compromise of the Lambda Orchestrator”**, which plays a central role in processing, coordination, and downstream interactions with other microservices and AI components.

This compromise may manifest through a variety of attacker goals, each driven by a distinct class of vulnerabilities or misconfigurations across different **phases of the application lifecycle** and within varied **runtime environments** (e.g., CI/CD, runtime, provisioning):

---

### 🔐 Privilege Escalation
**Lifecycle Phase**: Provisioning  
**Environment**: Deployment  
These risks originate from overly broad permissions or insufficient trust boundaries:
- **Over-permissioned IAM roles** (`CWE-284`): Lambdas with `*` actions or `sts:AssumeRole` are prime targets for privilege escalation.
- **CVE-2024-37293** (`CWE-266`): Auto-deployment of Lambda with elevated access can lead to CI/CD abuse and misuse of roles.
- **SourceArn not restricted**: Trigger-based Lambdas without `SourceArn` limits allow untrusted invocation paths, bypassing access control layers.

---

### 💥 Remote Code Execution (RCE)
**Lifecycle Phase**: Build / Development  
**Environment**: Runtime  
Vulnerabilities that allow attackers to execute arbitrary commands:
- **CVE-2019-10777** (`CWE-78`): Unvalidated `FunctionName` input leads to OS command injection in build scripts or runtime logic.
- **Event injection** (`CNAS-2`): Crafted JSON via API Gateway exploits loose validation, leading to logic abuse or unauthorized code execution.

---

### 🧯 Denial of Service (DoS)
**Lifecycle Phase**: Runtime  
**Environment**: Public Internet / API  
DoS stems from inefficient processing or missing safeguards:
- **CVE-2018-7560** (`CWE-20`): ReDoS using malformed multipart input overwhelms regex parsers.
- **No concurrency/time limits**: Absence of these limits enables long-running or recursive invocations, exhausting Lambda concurrency.

---

### 🕵️‍♂️ Sensitive Data Exposure
**Lifecycle Phase**: Config / Runtime  
**Environment**: Shared / Multi-tenant  
Weak secrets management and open network exposure:
- **Plaintext secrets in env vars** (`CNAS-5`, `CWE-522`): Secrets are readable in config metadata if not encrypted or managed by Secrets Manager.
- **Public access via VPC**: Lambdas with unrestricted internet access can be used as entry points or data exfiltration paths.

---

### ⚙️ Supply Chain Compromise
**Lifecycle Phase**: Build / Deploy  
**Environment**: CI/CD  
Pipeline security issues that introduce unverified or malicious code:
- **Code signing disabled**: Allows unsigned or tampered packages to be deployed.
- **Known vulnerable dependencies** (`CNAS-7`): Third-party packages included at build-time introduce known CVEs into production code.

---

### 🧾 Logging and Detection Gaps
**Lifecycle Phase**: Runtime  
**Environment**: Cloud Monitoring / Security Analytics  
Without proper monitoring, threats may go unnoticed:
- **CloudWatch alarms/tracing disabled**: Lack of metrics and tracing delays incident response.
- **Missing resource monitoring** (`CNAS-10`): No audit trail to detect anomaly patterns or post-exploit investigations.

---

This structured threat tree illustrates how **each misconfiguration or CVE can be a critical node in the attack path**, often interlinked with others, enabling **multi-stage attacks**. It underlines the importance of **contextual hardening**, **runtime observability**, and **lifecycle-aware security enforcement** in securing Lambda orchestrators within AI-centric cloud-native architectures.

---


---

#### 📌 Threat Tree – Amazon S3

![Threat Tree – Amazon S3](/PASTA/images/threat_tree_s3_enhanced.png.png)

---

#### 🔍 Threat Tree Explanation – Amazon S3

The **root node** represents the high-level threat scenario:  
**“Compromise or Abuse of Amazon S3 Data Storage”**.

This branches into multiple **threat categories**, each tied to relevant vulnerabilities and misconfigurations (referenced by their serial numbers from Stage 5.1):

---

##### 🔐 1. Unauthorized Data Access
> **Goal**: Gain unauthorized access to sensitive S3-stored data due to misconfigured access controls or weak encryption.

- **#5**: S3 buckets are publicly accessible due to missing block public access settings, exposing all data to anonymous users. *(Provision / Runtime – Critical)*
- **#6**: Insecure ACL configurations assign broader access (like `AllUsers`), enabling unintended parties to list or write to buckets. *(Provision – High)*
- **#8**: S3 encryption settings are not enforced, meaning sensitive data might be stored or transmitted unencrypted. *(Config / Runtime – High)*
- **#20**: IAM trust relationships allow principals from external AWS accounts to assume roles, enabling cross-account data access. *(Provision – High)*

---

##### 🌐 2. Insecure Data Transmission / Retrieval
> **Goal**: Intercept or retrieve unprotected data in transit or credentials stored insecurely.

- **#3**: AWS SDK behavior stores encryption metadata in plain text, potentially exposing keys if storage is breached. *(Code Logic – Medium)*
- **#4**: Jenkins plugin writes AWS credentials in plaintext on disk during build steps, risking theft from compromised CI agents. *(Provisioning – Medium)*
- **#13**: Data transmitted over HTTP rather than HTTPS allows MITM attacks to intercept sensitive payloads. *(Runtime – High)*

---

##### 🛠️ 3. Remote Execution / SSRF / XXE
> **Goal**: Execute unauthorized actions via injection techniques using malicious XML or SSRF endpoints.

- **#1**: Eclipse JGit parses untrusted XML stored in S3, enabling XML External Entity (XXE) injection during dependency management. *(Build – Medium)*
- **#2**: The `locals3` test tool exposes SSRF vectors via misconfigured endpoints accessible during automated test pipelines. *(Build / Test Tools – Medium)*

---

##### 🔄 4. Supply Chain Attacks
> **Goal**: Compromise the build pipeline through insecure plugins or artifacts that interact with S3.

- **#15**: CI/CD tools like JGit and Jenkins S3 plugins are misconfigured or outdated, exposing the build system to tampering. *(Build / CI-CD – High)*
- **#17**: Third-party build plugins with known CVEs are still used without vetting or patching, introducing backdoor risks. *(Build / CI-CD – Medium)*

---

##### 🧩 5. Data Integrity & Recovery Gaps
> **Goal**: Prevent recovery or traceability of altered/deleted data due to lack of integrity controls.

- **#7**: MFA Delete is not enabled, making it easier for attackers or automated scripts to delete critical data without strong authentication. *(Provision – High)*
- **#10**: S3 object versioning is disabled, meaning deleted or modified data can't be rolled back in the event of corruption or ransomware. *(Runtime – Medium)*

---

##### 🔍 6. Logging and Monitoring Gaps
> **Goal**: Remain undetected by exploiting lack of auditing and visibility in S3 activity.

- **#9**: Bucket logging and access logging are disabled, so unauthorized access and operational events are not auditable. *(Runtime / Compliance – Medium)*
- **#18**: Older buckets exist without monitoring tags or lifecycle policies, creating blind spots in usage and compliance monitoring. *(Runtime / Lifecycle – Medium)*

---

##### 📡 7. Attack Surface Expansion
> **Goal**: Leverage unused or misconfigured S3 features to expand attack vectors.

- **#11**: Buckets lack basic hygiene measures like tagging, DNS compliance, or lifecycle rules, making them hard to track and control. *(Management – Low)*
- **#12**: Static website hosting is enabled, which exposes public endpoints potentially exploitable for phishing or drive-by downloads. *(Runtime / Exposure – Medium)*
- **#14**: Transfer Acceleration is active without restriction, enabling abuse for exfiltration or traffic proxying. *(Runtime – Medium)*
- **#19**: Public endpoints do not enforce rate limiting or DDoS protections, increasing susceptibility to abuse or service degradation. *(Runtime – Medium)*
- **#16**: IAM policies grant broad delegation rights over S3 actions, enabling privilege abuse through over-permissive role assumptions. *(Provision / Runtime – High)*

---

#### ✅ Summary

This threat tree demonstrates how **20 unique vulnerabilities and misconfigurations** in Amazon S3 map to **7 critical attacker objectives**. These findings help prioritize remediation, improve cloud governance, and prepare for **attack path simulation** in Stage 6.

---

---

#### 📊 Threat Tree – OpenSearch Vector Store

![Threat Tree – Amazon OpenSearch](/PASTA/images/threat_tree_opensearch_enhanced_numbered.png)

---

#### 🔍 Threat Tree Explanation – Amazon OpenSearch Vector Store

The threat tree for **Amazon OpenSearch** outlines the risk of **compromise or abuse** of the vector store component, which is critical in AI-driven applications like semantic search or retrieval-augmented generation (RAG). OpenSearch often stores user-generated embeddings or proprietary data – making it a high-value target.

---

##### 🧨 Root Threat
> **“Compromise or Abuse of OpenSearch Vector Store”**  
This root represents risks stemming from insecure access, exposure of embeddings, and manipulation of vector data or configurations.

---

##### 🎯 Threat Objectives & Attack Paths

##### **T1 – Unauthorized Access**
- **Phase:** Provisioning / Runtime  
- **Environment:** Public domains, IAM misconfigurations  
Attackers may exploit:
- **[#2]** IAM authentication is disabled or misconfigured, allowing anonymous access to OpenSearch clusters without role verification. *(Critical Access Control Flaw)*
- **[#3]** Public OpenSearch endpoints are left exposed to the internet, offering unrestricted query access to anyone with the endpoint URL. *(Perimeter Misconfiguration)*
- **[#5]** Cross-account access permissions are poorly scoped, enabling unintended principals to discover or manipulate OpenSearch indexes. *(Trust Boundary Weakness)*
- **[#11]** Internal IAM roles are over-permissive, enabling lateral movement or privilege abuse within the same account. *(Least Privilege Violation)*
- **[#20]** IAM trust relationships are weakly defined, making it easier for external roles to impersonate internal access. *(Cross-Tenant Risk)*

---

##### **T2 – Sensitive Data Exposure**
- **Phase:** Storage / Network  
Embedding and vector payloads may be leaked due to:
- **[#4]** TLS is either disabled or using outdated ciphers, allowing attackers to intercept API traffic and extract embeddings in transit. *(Transport Security Flaw)*
- **[#6]** Data at rest is not encrypted using AWS KMS or other mechanisms, leaving sensitive vectors in plaintext in disk snapshots. *(At-Rest Exposure Risk)*
- **[#13]** Public network access to OpenSearch is enabled without access policies, allowing anyone to extract stored vectors via HTTP requests. *(Public Exposure Risk)*
- **[#16]** TLS configurations are static and vulnerable to protocol downgrade attacks, opening doors to man-in-the-middle interceptions. *(Downgrade Attack Surface)*

---

##### **T3 – Insecure Configuration / Credential Leakage**
- **Phase:** Build / DevOps  
Attack surface increases via:
- **[#1]** OpenSearch CLI config files (e.g., `~/.opensearch/config`) are world-readable, exposing API tokens or secrets to local adversaries or containers. *(Filesystem Permissions Misuse)*
- **[#12]** Secrets such as admin passwords or tokens are hardcoded or committed to configuration files within infrastructure code or containers. *(Secret Hygiene Failure)*

---

##### **T4 – Logging & Detection Gaps**
- **Phase:** Runtime / Compliance  
Monitoring failures hinder visibility into attacks:
- **[#7]** Audit logging is disabled, preventing any detection of unauthorized searches, vector tampering, or access violations. *(Observability Blindspot)*
- **[#15]** Behavioral analytics for search patterns or API activity is not enabled, leaving adversarial usage patterns undetected. *(Anomaly Detection Deficiency)*

---

##### **T5 – Vector Store Poisoning**
- **Phase:** Ingest / Runtime  
Attackers may manipulate search results by:
- **[#14]** Open ingestion APIs allow arbitrary embedding uploads without validation or authentication, enabling poisoning of vector space with adversarial inputs. *(Input Validation Risk)*

---

##### **T7 – Platform Hardening Gaps**
- **Phase:** Runtime / Patch / HA  
Operational weaknesses reduce resilience:
- **[#8]** OpenSearch version is outdated, with unpatched vulnerabilities that can be exploited remotely (e.g., CVEs in Lucene or plugin dependencies). *(Patch Management Gap)*
- **[#9]** Zone awareness is disabled, meaning OpenSearch lacks availability zone failover, increasing risk of full-service disruption during localized failures. *(High Availability Weakness)*
- **[#10]** Node types used in the cluster are not optimized for k-NN/ANN workloads, which can result in latency issues and missed similarity matches under load. *(Performance/Capacity Risk)*

---


---

#### 📌 Threat Tree – Amazon DynamoDB

![Threat Tree – Amazon DynamoDB](/PASTA/images/threat_tree_dynamodb_enhanced_LR.png)

---

#### 🔍 Threat Tree Explanation – Amazon DynamoDB

The **root node** represents the high-level threat scenario:  
**“Compromise or Data Loss in DynamoDB”**

This branches into multiple **threat categories**, each tied to relevant vulnerabilities and misconfigurations (referenced by their serial numbers from Stage 5.1):

---

##### 🔐 1. Encryption Weakness  
> **Goal**: Exploit weak or missing encryption to access sensitive data stored in DynamoDB or DAX.

- **#1**: At-rest encryption is disabled, leading to unprotected storage of sensitive data like PII or session tokens. *(Provision – High)*  
- **#2**: Customer-managed KMS key (CMK) not used, limiting auditability and fine-grained access control. *(Provision – High)*  
- **#3**: DynamoDB Accelerator (DAX) cache is unencrypted, exposing in-memory sensitive data. *(Provision / Runtime – Medium)*  

---

##### 🔐 2. Key Management  
> **Goal**: Exploit lack of cryptographic key isolation or CMK management to weaken data protection boundaries.

- **#9**: Default AWS-managed keys used instead of CMKs, leading to insufficient control and audit over encryption lifecycle. *(Provision – High)*  

---

##### 💾 3. Backup / Recovery Gaps  
> **Goal**: Cause irreversible data loss by exploiting weak or absent backup strategies.

- **#4**: Continuous backups are disabled, exposing the system to accidental or malicious data deletion. *(Runtime – Medium)*  
- **#5**: DynamoDB table backups are not configured at all, violating recovery and compliance requirements. *(Runtime – Medium)*  

---

##### ☢️ 4. Deletion / Destructive Action  
> **Goal**: Delete or tamper with tables due to lack of safeguards for destructive actions.

- **#6**: Deletion protection is disabled, allowing users (or attackers) to remove critical tables without warning. *(Runtime – High)*  

---

##### ⚠️ 5. Data Loss / Logging  
> **Goal**: Exploit insufficient visibility or injection flaws to wipe data silently or remain undetected.

- **#7**: DynamoDB table is empty, potentially due to injection attacks or accidental overwrites, indicating data integrity loss. *(Runtime – Low–Medium)*  

---

##### 🏷️ 6. Governance / Tagging  
> **Goal**: Exploit lack of metadata tagging for unauthorized access or billing evasion.

- **#8**: Tables lack tags, hindering cost management, automation, and access policies via IAM condition keys. *(Provision / Governance – Low)*  

---

#### ✅ Summary

This threat tree highlights how **9 distinct misconfigurations in Amazon DynamoDB** map to **6 critical attacker objectives**. These findings prioritize action areas such as **encryption enforcement**, **backup hygiene**, and **deletion protection**, helping teams build resilient, monitored, and secure DynamoDB workloads.

---


---

#### 📌 Threat Tree – Amazon API Gateway

![Threat Tree – Amazon API Gateway](/PASTA/images/threat_tree_apigateway_enhanced_LR.png)

---

#### 🔍 Threat Tree Explanation – Amazon API Gateway

The **root node** represents the high-level threat scenario:  
**“Compromise or Abuse of Amazon API Gateway APIs”**

This branches into multiple **threat categories**, each tied to relevant vulnerabilities and misconfigurations (referenced by their serial numbers from Stage 5.1):

---

##### 🔐 1. Authentication & Authorization Gaps  
> **Goal**: Exploit missing or misconfigured access controls to invoke protected APIs.

- **#1**: API Gateway authorization not enabled, allowing unauthenticated users to trigger backend Lambda functions. *(Runtime – Critical)*  
- **#2**: API Gateway V2 authorization missing for HTTP APIs, exposing serverless or bot logic to anonymous abuse. *(Runtime – Critical)*  

---

##### 🔒 2. Transport Security Misconfiguration  
> **Goal**: Exploit weak TLS configurations to perform MITM or downgrade attacks.

- **#3**: Custom domain TLS version set below 1.2, enabling insecure connections. *(Provision – High)*  
- **#4**: Secure TLS policy not enforced, allowing negotiation of weak ciphers. *(Provision – High)*  

---

##### 🚫 3. Access Control Exposure  
> **Goal**: Access internal APIs or functions due to public or legacy endpoints.

- **#5**: No public access restrictions applied via resource policies or IP allowlists. *(Runtime – Critical)*  
- **#6**: Default endpoint is not disabled, creating alternate invoke paths that may bypass authorization. *(Runtime – High)*  

---

##### 🛡️ 4. Traffic Protection & Abuse Prevention  
> **Goal**: Overload or exploit APIs through brute force, scraping, or automation.

- **#7**: AWS WAF not enabled on API Gateway, allowing abuse like prompt injection or enumeration. *(Runtime – High)*  
- **#8**: Client certificate not required, weakening mTLS-based internal communication. *(Runtime – Medium)*  

---

##### 🧹 5. Input Validation & Encoding  
> **Goal**: Send malformed requests or payloads to exploit validation gaps.

- **#9**: Request validation is not enabled, increasing risk of schema-less attacks or fuzzing payloads. *(Runtime – High)*  
- **#10**: Content encoding not enforced, enabling request smuggling or header abuse through improper parsing. *(Runtime – Medium)*  

---

##### 📊 6. Monitoring, Logging & Observability  
> **Goal**: Remain undetected by exploiting lack of logging, tracing, or metrics.

- **#11**: Access logging not enabled, obscuring request history and client identity. *(Runtime – Medium)*  
- **#12**: V2 (HTTP API) access logs not enabled, losing visibility into lightweight production APIs. *(Runtime – Medium)*  
- **#13**: CloudWatch metrics not enabled, preventing alerting on failure or usage anomalies. *(Runtime – Medium)*  
- **#14**: Tracing (e.g., X-Ray) not configured, reducing visibility across the full request lifecycle. *(Runtime – Medium)*  

---

##### 💾 7. Caching Misconfiguration  
> **Goal**: Allow sensitive response caching without adequate protection.

- **#15**: Stage-level cache encryption is disabled, risking exposure of sensitive data in cache memory. *(Provision – Medium)*  
- **#16**: Caching is disabled where applicable, degrading performance and increasing cost. *(Runtime – Low–Medium)*  
- **#17**: Cache encryption not enabled, exposing token metadata in cache layers. *(Provision – Medium)*  

---

##### 🔑 8. Certificate & Key Management  
> **Goal**: Exploit long-lived or mismanaged certificates for spoofing or replay.

- **#18**: Certificate rotation is not enabled, increasing exposure if certs are compromised. *(Maintenance – Medium)*  

---

#### ✅ Summary

This threat tree highlights how **18 unique misconfigurations and design flaws** in Amazon API Gateway map to **8 major attacker objectives**. These findings support prioritizing efforts in:

- **Authentication enforcement**
- **Secure traffic handling**
- **Cache and cert hygiene**
- **Observability and abuse detection**

Improving these areas significantly reduces the API attack surface and enables more resilient, secure serverless architectures.

---



---

#### 📌 Threat Tree – Amazon Bedrock

![Threat Tree – Amazon Bedrock](/PASTA/images/threat_tree_bedrock_enhanced_LR.png.png)

---
#### 🧠 Threat Tree – AWS Bedrock Chatbot Architecture


##### 🔐 1. Spoofing / Unauthorized Access
> **Goal**: Exploit missing network isolation or public endpoints to gain unauthorized inference access or impersonate trusted services.

- **#2 – Private Custom Model Not Configured**
  - Without a private endpoint, Bedrock-hosted models may be accessible externally.
  - **Risk**: External actors could invoke model APIs directly.
  - `Phase: Provision | Risk: High | CWE-200`

- **#3 – Custom Model Not in VPC**
  - Lack of VPC isolation makes models accessible from outside the private network.
  - **Risk**: Model APIs exposed to public internet or untrusted networks.
  - `Phase: Provision | Risk: High | CWE-668`

---

##### 🧪 2. Tampering / Poisoning
> **Goal**: Introduce malicious inputs (e.g., poisoned training data or pipeline steps) to affect model behavior.

- **#6 – Notebook Direct Internet Access Enabled**
  - Notebooks with outbound internet access can download untrusted data or execute unauthorized code.
  - **Risk**: Poisoned training corpora or dependency hijacking.
  - `Phase: Runtime | Risk: High | CWE-668 / CWE-200`

---

##### 🧾 3. Repudiation / Lack of Audit
> **Goal**: Prevent detection or accountability by disabling visibility into model usage or prompt flows.

- **#1 – Bedrock Model Invocation Logging Disabled**
  - Disables CloudWatch logs for Bedrock requests.
  - **Risk**: No traceability for prompt injection, abuse, or misuse.
  - `Phase: Runtime | Risk: High | CWE-778`

---

##### 🔍 4. Information Disclosure
> **Goal**: Leak sensitive data like embeddings, model parameters, or training data due to lack of encryption or data controls.

- **#4 – Custom Model Encryption Disabled**
  - Unencrypted model artifacts in storage (e.g., S3) can be exfiltrated.
  - **Risk**: Intellectual property theft or reverse engineering.
  - `Phase: Provision | Risk: High | CWE-311`

- **#8 – Notebook Data Not Encrypted**
  - Data used or stored in notebooks (e.g., training corpora or embeddings) is not encrypted at rest.
  - **Risk**: Sensitive corpora extraction or data leakage.
  - `Phase: Runtime | Risk: High | CWE-311`

---

##### 🧱 5. Escalation via Misconfiguration
> **Goal**: Gain broader privileges due to improper scoping or resource isolation failures.

- **#7 – Notebook Instance Not in VPC**
  - Notebooks outside VPC can access AWS resources with broad permissions.
  - **Risk**: Privilege escalation or lateral movement.
  - `Phase: Provision | Risk: High | CWE-284 / CWE-732`

---

## 🛡️ Stage 6 : Attack Modeling


This document covers **Step 6: Attack Modeling** from the [PASTA](https://owasp.org/www-community/Threat_Modeling) (Process for Attack Simulation and Threat Analysis) methodology. This step builds on insights from earlier stages to **simulate real-world attack scenarios**, helping identify how threats can materialize into actual exploits against critical assets.

---

### 🔁 Recap: PASTA Stage Flow Leading to Attack Modeling

| Step | Title                                  | Purpose |
|------|----------------------------------------|---------|
| 1    | **Define the Objectives**              | Understand business and security goals |
| 2    | **Define the Technical Scope**         | Map out the architecture and components |
| 3    | **Application Decomposition**          | Identify data flows, trust boundaries, and system interactions |
| 4    | **Threat Analysis**                    | Identify and classify relevant threats and threat agents |
| 5    | **Vulnerability & Weakness Analysis**  | Discover system and application vulnerabilities |
| 6    | **Attack Modeling**                    | Simulate how attackers could exploit the system |
| 7    | (Next) **Risk and Impact Analysis**    | Quantify risk and prioritize mitigations |

---

### 🎯 Step 6: Purpose of Attack Modeling

The goal of this stage is to simulate **how an attacker could exploit identified vulnerabilities** and interact with the system to compromise assets. This is done by logically modeling attack steps, mapping vectors, and identifying exploit paths.

Attack modeling provides the **"attacker's perspective"**, turning earlier data into actionable security insights and testing artifacts.

---

### 👥 Stakeholders and Consumers

| Role               | Purpose of Consumption                                |
|--------------------|--------------------------------------------------------|
| Red Team / Pentesters | Simulate real-world attacks and validate security posture |
| Developers         | Understand how vulnerabilities can be exploited        |
| Security Architects| Strengthen security design, control placement          |
| Risk Analysts      | Score risk based on modeled attack scenarios           |

---

### 🛠️ Techniques and Artifacts Used

- **Attack Trees** for structured threat logic
- **Trust Boundaries** and **Control Zones** for scoping
- **Known Attack Libraries**: MITRE ATT&CK, OWASP Top 10, CAPEC
- Optional: Kill Chains, STRIDE mapping for cross-validation

---

### 📦 Outputs and Deliverables

- Modeled **attack trees** per threat scenario
- List of **mapped attack vectors** per system component
- Detailed **exploit paths** with decision logic
- Foundation for pen testing, mitigation, and risk quantification


---


### 🔶 Step 6.1 – Identify the Application Attack Surface

This step focuses on identifying and documenting the **application attack surface** — all the points where an attacker may interact with the system, directly or indirectly. Understanding the attack surface is crucial for determining **where threats can manifest**, and which assets or entry points may be exploited in later stages of an attack.

#### 🧭 Purpose

The goal is to:

- Map **entry and interaction points** across the application
- Define what’s **exposed**, to whom, and under what conditions
- Highlight areas where **untrusted input** enters the system
- Establish **trust boundaries** between services and users
- Identify **control gaps** or over-permissioned components

---

#### 📍 Identified Attack Surface

| **Asset / Component**     | **Attack Surface Element**                     | **Exposed To**             | **Security Notes**                                                                 |
| ------------------------- | ---------------------------------------------- | -------------------------- | ---------------------------------------------------------------------------------- |
| **ECS (UI frontend)**     | User prompt submission via frontend → ECS HTTP | **External users**         | Accepts unstructured input; primary injection point for prompt manipulation        |
| **API Gateway**           | Internal API endpoint (ECS → Lambda)           | **Internal only**          | May be abused from inside VPC; risks include token replay or request fuzzing       |
| **Lambda (Orchestrator)** | Coordinates input flow → DynamoDB, OpenSearch, Bedrock | **Internal services**    | High-value target; over-permissioned IAM role could enable lateral movement        |
| **S3 (Document Bucket)**  | Stores user-uploaded PDFs                      | **Internal via Lambda**    | Poisoned files could affect downstream ML/LLM processing via embedded payloads     |
| **OpenSearch**            | Vector query API via SDK                       | **Lambda only**            | Vulnerable to index poisoning or vector tampering if ACLs fail                     |
| **Bedrock (Claude 3)**    | Generative AI model API for prompt response    | **Lambda only**            | Prompt injection could manipulate LLM behavior or exfiltrate data                  |
| **DynamoDB**              | Stores chat/session state                      | **Lambda only**            | Poor session isolation or token re-use could lead to unauthorized access           |
| **IAM Roles / STS**       | Lambda role with broad service permissions     | **AWS IAM trust policies** | Misconfigured trust relationships can lead to privilege escalation or role abuse   |
| **CloudWatch / Logging**  | Logging visibility (metrics, traces, logs)     | **Admin-only**             | Lack of granular logging may create visibility blind spots for threat detection    |

---

#### 🔐 Trust Boundaries and Exposure Types

The system consists of multiple **trust boundaries** that determine exposure:

- **External boundary**: Between untrusted users and ECS (UI)
- **Internal API boundary**: ECS → API Gateway → Lambda
- **Service interaction boundary**: Lambda’s communication with AWS services (Bedrock, OpenSearch, DynamoDB)
- **Cloud infrastructure boundary**: IAM roles, STS trust, and monitoring controls

---

### 🔶 Step 6.2 – Derive Attack Trees for Threats and Assets

We build **attack trees** to model attacker strategies and logic. Each tree includes:

- **Attacker goals** (e.g., privilege escalation, data theft)
- **Sequence of actions** that could lead to successful compromise

![rag_attack_tree_large_spacing](https://github.com/user-attachments/assets/2bc562e8-009a-4ccb-95f0-b8673afb7a62)

---
<details>
  <summary><strong>1. PROMPT INJECTION VIA RAG CONTEXT POLLUTION</strong></summary>

  <img width="1205" height="289" alt="compact_subtree_1_prompt_injection" src="https://github.com/user-attachments/assets/8e577c6b-5120-4afb-86af-336ff00aa029" />


  <details>
    <summary><strong>1.1 Embedding Poisoning via User Input</strong></summary>
    <img width="1053" height="1203" alt="deep_subtree_1_1_embedding_poisoning_expanded" src="https://github.com/user-attachments/assets/535d8a0b-6419-4a78-b841-375801e47f5e" />


  </details>

  <details>
    <summary><strong>1.2 Retrieval Ranking Manipulation</strong></summary>
    <img width="1006" height="1020" alt="deep_subtree_1_2_retrieval_ranking" src="https://github.com/user-attachments/assets/fb9f6bba-37d4-4b7f-8ff6-b2f41f55048c" />

  </details>

  <details>
    <summary><strong>1.3 Prompt Injection via Context Stitching</strong></summary>
    <img width="1105" height="1020" alt="deep_subtree_1_3_context_stitching" src="https://github.com/user-attachments/assets/ec6c6017-5f54-4e39-9b8a-5619757a9e82" />
  </details>


</details>

---
<details>
  <summary><strong>2. TOKEN REPLAY AND API ABUSE VIA GATEWAY</strong></summary>

  <img width="783" height="289" alt="subtree_2_token_replay_gateway_abuse (1)" src="https://github.com/user-attachments/assets/32c48be5-0783-4160-8fcb-3a74ee0a83f8" />



  <details>
    <summary><strong>2.1 Token Replay via Frontend or Intercept</strong></summary>
    <img width="1233" height="1203" alt="deep_subtree_2_1_token_replay" src="https://github.com/user-attachments/assets/f326a94e-383f-4423-930b-ea87ba1a0e55" />


  </details>

  <details>
    <summary><strong>2.2 API Gateway Misconfiguration</strong></summary>
    <img width="1546" height="1020" alt="deep_subtree_2_2_api_gateway_misconfig" src="https://github.com/user-attachments/assets/3cee6808-02e4-4158-be00-59a737de758b" />

  </details>

</details>

---
<details>
  <summary><strong>3. VECTOR INDEX POISONING IN OPENSEARCH</strong></summary>
  <img width="1762" height="336" alt="main_category_3_vector_index_poisoning" src="https://github.com/user-attachments/assets/fced456d-a5b3-4b41-b803-c8f590964df7" />

  <details>
    <summary><strong>3.1 Poisoned Vector Ingestion</strong></summary>
    <img width="1139" height="1020" alt="deep_subtree_3_1_poisoned_vector_ingestion" src="https://github.com/user-attachments/assets/a71b1c3d-3f66-4834-b5b8-5468e9eacac8" />
  </details>

  <details>
    <summary><strong>3.2 Vector Manipulation Post-Ingestion</strong></summary>
    <img width="819" height="1020" alt="deep_subtree_3_2_vector_post_ingestion" src="https://github.com/user-attachments/assets/9dc031ce-ddcf-472f-ab10-91210db56ffb" />

  </details>

  <details>
    <summary><strong> 3.3 Retrieval Misrouting & Multi-Tenant Querying</strong></summary>
    <img width="1027" height="1020" alt="deep_subtree_3_3_retrieval_misrouting" src="https://github.com/user-attachments/assets/56082c97-c54a-4815-bdc1-ea21eabcdac3" />

  </details>

</details>

---
<details>
  <summary><strong>4. LLM RESPONSE SPOOFING IN TRANSIT</strong></summary>
  <img width="1378" height="336" alt="main_category_4_llm_response_spoofing" src="https://github.com/user-attachments/assets/143627e0-0351-4ad8-9fb4-81d2c34a86f0" />

  <details>
    <summary><strong>4.1 TLS Downgrade or Misconfiguration Attack</strong></summary>
    <img width="925" height="1020" alt="deep_subtree_4_1_tls_downgrade" src="https://github.com/user-attachments/assets/c9666edc-4ba5-484f-a6c8-439e7ca9b2b2" />

  </details>

  <details>
    <summary><strong>4.2 Client-Side Spoofing via Web Interception</strong></summary>
    <img width="1318" height="1020" alt="deep_subtree_4_2_client_side_spoofing" src="https://github.com/user-attachments/assets/30c9960f-f188-4613-8673-bc57398f5f92" />
  </details>

</details>

---
<details>
  <summary><strong>5. OVER-PERMISSIONED LAMBDA ENABLING INSECURE OPERATIONS</strong></summary>
  <img width="3041" height="1068" alt="rag_attack_subtree_lambda_overpermissioned" src="https://github.com/user-attachments/assets/a0a71d78-7fef-4e12-9265-0c4040b7cba4" />

  <details>
    <summary><strong>5.1 Privilege Escalation</strong></summary>
    <img width="317" height="973" alt="compact_subtree_5_1_1_only" src="https://github.com/user-attachments/assets/d5a1fd7c-7a77-40c9-9077-b142a736a4da" />


      
  </details>

  <details>
    <summary><strong>5.2 DynamoDB Unauthorized Access</strong></summary>
    <img width="1362" height="655" alt="compact_subtree_5_2_dynamodb_access" src="https://github.com/user-attachments/assets/3199b19a-70a6-426a-a6aa-6ffefb3b3201" />

  </details>

  <details>
    <summary><strong>5.3 Invoke Bedrock with Malicious Prompt</strong></summary>
    <img width="1429" height="655" alt="compact_subtree_5_3_bedrock_malicious_prompt" src="https://github.com/user-attachments/assets/c4550948-b48a-461f-ad67-07c8b02a4c9c" />

  </details>

  <details>
    <summary><strong>5.4 Persistence in Lambda Runtime</strong></summary>
    <img width="1101" height="655" alt="compact_subtree_5_4_lambda_persistence" src="https://github.com/user-attachments/assets/45bca27d-b941-46fb-a0c6-362a593bb7e4" />
  </details>

</details>

---

### 🔶 Step 6.3 – Map Attack Vectors to Attack Tree Nodes

Each node in the attack tree is enriched with **real-world attack vectors**, such as:

- 🧰 **Credential Abuse** (e.g., token replay, hardcoded secrets)  
- 🧰 **Injection Techniques** (e.g., prompt injection, payload manipulation)  
- 🧰 **Infrastructure Attacks** (e.g., OpenSearch poisoning, SSRF)  
- 🧰 **Cloud Misconfigurations** (e.g., over-permissioned roles)  
- 🧰 **API Abuse** (e.g., rate bypass, schema fuzzing)  

Sources like **MITRE ATT&CK** and **MITRE Cloud Matrix**  are referenced to ensure relevance.

---

### 🔶 Step 6.4 – Identify Exploits and Attack Paths

Finally, we identify **complete exploit chains** and how they traverse the system, including:

- Entry → Lateral Movement → Privilege Escalation → Impact  
- Chain of events mapped from **initial vector** to **final asset compromise**
- Multiple attacker paths per scenario, including alternate or fallback methods

These paths become the basis for:

- Penetration Testing playbooks  
- Risk scoring (Likelihood × Impact)  
- Control design and mitigation planning  


