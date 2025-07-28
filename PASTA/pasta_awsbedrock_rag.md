
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

| #  | Category              | Vulnerability / CWE                                      | Phase            | Risk Level     | Detailed Explanation (Threat Actions / Exploitation)                                                                                                                                                                  |
| -- | --------------------- | -------------------------------------------------------- | ---------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1  | IAM Misconfiguration  | **Lambda Admin Privileges** (AquaSec) <br> CWE-250       | Provision        | High           | Overly permissive IAM roles like `lambda:*` or `*:*` enable adversaries to perform privilege escalation, pivot laterally using **AssumeRole**, or manipulate other AWS services.                                      |
| 2  | CI/CD Configuration   | **CVE-2024-37293** <br> CWE-266                          | Provision        | High           | Insecure versions of AWS ADF (<4.0.0) allow abuse of deployment pipelines, letting attackers inject malicious automation steps and potentially **gain unauthorized access** or escalate privileges during deployment. |
| 3  | Code Injection        | **CVE-2019-10777** <br> CWE-78                           | Build            | Critical (9.8) | Exploitable via unvalidated `npm` scripts—malicious inputs or compromised dependencies allow **command injection**, enabling remote code execution in build environments or during deployment.                        |
| 4  | Input Validation      | **CVE-2018-7560** <br> CWE-1333                          | Runtime          | High (7.5)     | Improper input regex validation leads to **ReDoS (Regex Denial of Service)** — attackers send crafted multipart requests to overload regex-based parsers, crashing or degrading system performance.                   |
| 5  | Secrets Management    | CWE-256                                                  | Config / Runtime | High           | Secrets (API keys, tokens) stored in plaintext environment variables can be harvested by an attacker with minimal access, leading to **unauthorized access** or **lateral movement**.                                 |
| 6  | Supply Chain Security | Lack of Code Signing <br> CWE-347                        | Build / Deploy   | Medium         | Unsigned code or containers can be tampered with—attackers could insert **malicious payloads** that are deployed without detection, especially in a CI/CD pipeline.                                                   |
| 7  | IAM Role Abuse        | No Unique IAM Role <br> CWE-266                          | Provision        | High           | Shared IAM roles among multiple services or users make it hard to trace activity and allow **privilege abuse**, especially if one component is compromised and can impersonate others.                                |
| 8  | Network Exposure      | Public Lambda / Internet-Exposed <br> CWE-306            | Runtime / Config | High           | Exposed Lambda endpoints are reachable over the internet — attackers may exploit open APIs to brute-force, scan, or deliver payloads (DoS, SSRF, or abuse).                                                           |
| 9  | Runtime Obsolescence  | Use of outdated runtime (e.g., Python 2.7) <br> CWE-1104 | Build / Deploy   | High           | Older runtimes no longer receive patches; attackers can exploit **known unpatched vulnerabilities** to gain access or crash the function.                                                                             |
| 10 | Dependency Risk       | Vulnerable Libraries (CNAS-7) <br> CWE-1104              | Build            | High           | Use of outdated or vulnerable packages (e.g., NLP libraries) can be exploited via **payload injection, memory corruption**, or **sandbox escapes** if input is unsanitized.                                           |
| 11 | Runtime Controls      | Missing Concurrency/Timeouts <br> CWE-770                | Runtime          | Medium         | Functions without concurrency limits or timeout settings are vulnerable to **Denial of Wallet (DoW)** attacks where attackers invoke long-running functions to incur high cloud costs.                                |
| 12 | Permission Scope      | No SourceArn Restriction <br> CWE-732                    | Provision        | High           | If a Lambda permission (like S3 event trigger) lacks `SourceArn` restriction, **any source** can trigger the function, enabling abuse or **unauthorized invocation**.                                                 |
| 13 | Attack Surface Bloat  | Multipart Parser Overhead <br> CWE-1333                  | Build / Runtime  | Medium         | Large or unused dependency trees (e.g., file parsers) increase **attack surface** and risk of ReDoS attacks or **indirect dependency exploits**.                                                                      |
| 14 | CI/CD Supply Chain    | Untrusted Layers / Images <br> CWE-829                   | Build            | Medium         | Use of unverified or stale base images can introduce **malware, backdoors**, or vulnerabilities during container build.                                                                                               |
| 15 | Input Exploitation    | API Event Injection <br> CWE-20                          | Runtime          | High           | Malicious crafted JSON sent via API Gateway can manipulate logic, **bypass auth**, or trigger unintended function behavior (e.g., SSRF, code path injection, or IAM abuse).                                           |


---


#### 🧠 S3 – Vulnerability Mapping

| **#** | **Category**               | **Vulnerability / CVE / CWE**                                                                                   | **Phase**            | **Risk**     | **Details / Context**                                                                   |
| ----- | -------------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------- | ------------ | --------------------------------------------------------------------------------------- |
| 1     | XXE / Data Injection       | **CVE-2025-4949** / **CWE-611, CWE-827** – Eclipse JGit & XML manifest in S3                                    | Build (DevOps)       | Medium (6.8) | The vulnerability lies in how Eclipse JGit, a Java-based Git implementation widely used in CI/CD pipelines, handles XML configuration files. When the CI/CD system (such as Jenkins or AWS CodePipeline) fetches a project from an S3 bucket that contains a maliciously crafted XML manifest, it may invoke the vulnerable XML parser in JGit without proper validation. This leads to an XXE (XML External Entity) injection. An attacker can use external entity references in XML to exfiltrate sensitive data from the build server, perform server-side request forgery (SSRF), or read arbitrary files (e.g., /etc/passwd). The exploitation affects the DevOps toolchain during the build phase, putting at risk the build environment, credentials, internal network exposure, and artifact integrity.                        |
| 2     | Secrets / Encryption       | **CVE-2022-2582** / **CWE-326** – AWS S3 Crypto SDK storing metadata in plaintext                               | Code Logic           | Medium (4.3) | This vulnerability impacts applications using the AWS S3 Encryption Client SDK (Crypto SDK) for encrypting and storing objects in S3. The SDK version affected fails to securely encrypt encryption context metadata—which includes key identifiers and algorithm hints—leaving them exposed in plaintext in the object’s metadata headers. While the data payload is encrypted, this leaked metadata can assist attackers in cryptanalysis, identifying which KMS keys are being used, or mounting privilege escalation or targeted decryption attempts if key compromise happens. If an attacker has read access to S3 (e.g., through IAM misconfiguration), they can gather metadata across objects to map encryption schemes. This threatens the data confidentiality posture of applications depending on S3 and KMS for secure storage.                        |
| 3     | Credential Exposure        | **CVE-2022-43426** / **CWE-256** – Jenkins AWS S3 plugin storing AWS creds in plaintext                         | Provisioning (CI/CD) | Medium (5.3) | Jenkins AWS S3 plugin stores AWS credentials in plaintext within configuration files; attackers with access to the Jenkins filesystem or job configs can extract these secrets and use them to gain unauthorized access to AWS services.                               |
| 4     | Public Access Risk         | **S3 Bucket Public Access Block**, **No Public Buckets**, **CWE-732**                        | Provision / Runtime  | Critical     | By default, S3 buckets can be made publicly accessible via bucket policies or ACLs unless Public Access Block settings are explicitly enabled. Without enforcement of BlockPublicAcls and BlockPublicPolicy, misconfigured buckets may allow unauthenticated access to sensitive data or enable data exfiltration through anonymous read/write operations. This exposure poses significant risks to the confidentiality and integrity of data assets.            |                                         |
| 5     | Policy Gaps                | **Block Public Policy**, **Require MFA Delete**, **CloudTrail Bucket Delete Policy**,**CWE-732**                           | Provision            | High         | When key preventive S3 bucket policies such as BlockPublicPolicy, RequireMFADelete, and restrictive Delete permissions (e.g., for CloudTrail log buckets) are not configured, it creates a policy gap. Attackers who gain access—via compromised IAM credentials or misconfigured roles—can exploit this by modifying or deleting log data (CloudTrail), disabling versioning, or deleting backup/data buckets. This can result in data loss, log evasion, or ransomware-style attacks where critical audit logs are wiped or access is hijacked. Without explicit deny or MFA-based protection, such actions often go undetected and are difficult to recover from.              |
| 6     | Encryption Missing         | **Enable Bucket Encryption**, **S3 Bucket Encryption Enforcement**, **Encryption Customer Key**, **In Transit**,**CWE-311/312** | Config / Runtime     | High         | When S3 buckets do not have default encryption enabled (e.g., SSE-S3, SSE-KMS, or SSE-C), or if encryption in transit (e.g., via HTTPS/TLS) is not enforced, sensitive data may be stored or transmitted in plaintext or with weak cryptographic protections. Additionally, not using customer-managed KMS keys (CMKs) may limit key rotation and access control. Attackers who gain access to storage or intercept network traffic (e.g., via misconfigured VPC, proxy, or endpoint) can exploit this weakness to exfiltrate or tamper with unprotected data, undermining confidentiality, compliance, and audit integrity.|
| 7    | Attack Surface Expansion   | **S3 Transfer Acceleration Enabled** without rate limiting ,**CWE-668/770**                                                  | Runtime              | Medium       | Enabling S3 Transfer Acceleration allows access to S3 buckets over Amazon CloudFront’s global edge locations, improving performance. However, if this feature is enabled without rate limiting or logging, it can be abused by an adversary for high-speed, stealthy data exfiltration. It increases the attack surface by allowing global entry points to the S3 bucket, potentially bypassing expected network restrictions and expanding exposure to unauthorized or excessive access.                                             |
| 8    | CI/CD Supply Chain Risk    |Use of plugins/tools (JGit, Jenkins S3) storing credentials or pushing unvalidated XML **CWE-502**             | Build / CI/CD        | High         | Use of insecure or unvalidated CI/CD plugins and tools—such as JGit (for Git operations) or Jenkins S3 plugin—can expose the build pipeline to supply chain attacks. Risks include storing AWS credentials in plaintext, parsing untrusted XML manifests, or executing injected scripts. Attackers can exploit these tools to perform credential theft, logic manipulation, or malicious artifact injection, ultimately compromising the integrity of deployments or poisoning downstream environments.                                       |
| 9    | Improper Access Delegation | Over-permissive IAM policies granting full access to S3 buckets ,**CWE-269/CWE-732/CWE-284**                                   | Provision / Runtime  | High         | IAM roles or policies that grant full or wildcard access to S3 buckets (e.g., s3:* on *) allow users or services to perform any action on any bucket. This misconfiguration can be exploited by an attacker—especially after initial access—to pivot across services, read sensitive data, delete logs, or exfiltrate knowledge base documents. Such delegation gaps are a critical enabler of lateral movement, privilege escalation, and data breach incidents within cloud environments. |                                            
| 10    | Weak IAM Trust Policies    | **No explicit trust boundaries for cross-account access** ,   **CWE-732/CWE-940**                                                 | Provision            | High         | IAM roles with poorly scoped or missing trust policies (e.g., Principal: "*", or unrestricted sts:AssumeRole from unknown external accounts) can lead to unauthorized cross-account access. In a multi-account architecture, such weak trust boundaries can be exploited by malicious or compromised third parties to assume roles and perform actions within your environment, including reading from or writing to S3 buckets, altering pipelines, or exfiltrating sensitive data. Proper scoping of Principal, usage of Condition blocks (e.g., aws:SourceAccount, aws:SourceArn), and cross-account governance are critical to mitigate these risks.                           |



---

#### 🧠 Opensearch (vector db) – Vulnerability Mapping

| **#** | **Category**                        | **Vulnerability / CWE / Misconfiguration**                                                                  | **Phase**            | **Risk**           | **Details / Context**                                                                             |
| ----- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------- | ------------------ | ------------------------------------------------------------------------------------------------- |
| 1     | **Insecure Local Config**           | **CVE-2021-44833** / **CWE-276** – AWS OpenSearch CLI `config.yaml` file readable/executable by all users   | Dev Env (Build)      | **Critical (9.8)** | The AWS OpenSearch CLI (opensearch-cli) stores credentials and API tokens in a local config.yaml file, which is world-readable and executable by default (chmod 777). This misconfiguration allows any local user or process on the development machine or CI runner to access OpenSearch credentials, leading to lateral movement or privilege escalation. In shared or multi-user environments, this represents a critical exposure of authentication data, potentially allowing an attacker to modify or exfiltrate OpenSearch indexes and mappings. Proper file permission hygiene and secret management (e.g., using AWS Secrets Manager) are required to mitigate this.                            |
| 2     | **IAM Misuse / Privilege**          | **OpenSearch IAM Authentication not enforced** ,**CWE-269/CWE-284**                                                            | Provision            | **High**           | When IAM-based authentication is not enforced for OpenSearch, any internal or external entity with network access to the OpenSearch endpoint may be able to interact with index APIs, including search, write, or delete operations. Without proper IAM roles, policies, or SigV4 authentication enforcement, the service becomes vulnerable to unauthorized data manipulation, exfiltration, or service abuse. In a Bedrock-based RAG pipeline, this could allow attackers to poison or tamper with the knowledge index used by the chatbot, severely affecting output reliability and security.          |                                 |
| 3     | **Insecure Transport Layer**        | **OpenSearch HTTPS Only Disabled**, **OpenSearch TLS Version (Outdated)** ,**CWE-319/CWE-326**                                  | Runtime / Network    | **High**           | If HTTPS-only access is disabled or the OpenSearch domain allows outdated TLS versions (e.g., TLS 1.0/1.1), it exposes vector index communications to man-in-the-middle (MITM) attacks or protocol downgrade exploits. This can lead to unauthorized observation or tampering of RAG enrichment queries or retrieved data from the vector DB. In a secure Bedrock pipeline, this undermines the integrity and confidentiality of semantic search results. Enforcing modern TLS (1.2/1.3) and HTTPS-only policies is critical to secure data in transit.                                    |
| 4     | **Improper Access Isolation**       | **Domain Cross Account Access** without restriction ,**CWE-732/CWE-642**                                                        | Runtime / IAM Config | **High**           | When OpenSearch domains are configured to allow cross-account access without fine-grained restrictions (e.g., missing aws:SourceAccount, aws:SourceArn, or overly permissive resource policies), it may permit external AWS accounts to access or query the entire embedding corpus. In the context of a Bedrock RAG architecture, this can result in data leakage, unauthorized inference, or tampering with the vector store used by the chatbot. Proper isolation using IAM trust policies and domain access policies is essential to enforce tenant or boundary separation.                    |
| 5     | **Lack of Encryption**              | **OpenSearch Encryption Enabled**, **Encrypted Domain**, **CMK Encryption**, **Node to Node Encryption**,**CWE-311**    | Storage / Network    | **High**           | If encryption at rest (e.g., EBS-backed domain data), node-to-node encryption, or CMK (Customer Managed Key) encryption is not enabled, OpenSearch may expose sensitive embeddings — including proprietary knowledge base vectors or user query traces — to unauthorized access. Similarly, lacking encryption in transit can leak data during replication or cross-AZ communications. This poses significant risk to the integrity and confidentiality of the RAG pipeline supporting Amazon Bedrock. Enforcing both at-rest and in-transit encryption is essential for secure vector storage and transfer.          |
| 6     | **Version Drift**                   | **OpenSearch Version**, **OpenSearch Upgrade Available** ,**CWE-1104**                                                  | DevOps / Patch       | **Medium**         | Running legacy or unsupported versions of OpenSearch can expose the system to unpatched CVEs, reduced vector indexing performance, and lack of modern protections against query-based DoS attacks or memory handling flaws. Without regular version reviews and upgrades, your Bedrock RAG setup may inherit vulnerabilities or miss out on stability and optimization improvements critical to semantic search performance. Maintain update hygiene through automated checks and staged upgrades.              |                    
| 7    | **CNAS-3: IAM Over-Permission**     | Unscoped access to vector APIs by internal services,**CWE-732/CWE-284**                                                      | Provision            | **High**           | When internal services (e.g., Lambda, Bedrock components) are granted unscoped or wildcard permissions (such as es:ESHttp* on all OpenSearch domains or indices), they may unintentionally gain access to sensitive vector index APIs — particularly endpoints like knn_vector. This can lead to unauthorized queries, data tampering, or even index deletion. In RAG-based architectures, over-permissioned access can compromise knowledge integrity and expose sensitive semantic embeddings. Enforcing least privilege IAM policies with scoped actions and resources is essential.               |
| 8    | **CNAS-6: Insecure Network Policy** | Public endpoint exposed or internal traffic not restricted (ACLs, SGs),**CWE-200/CWE-284**                                     | Runtime / Network    | **High**           | When OpenSearch domains are configured with public endpoints or lack network-level restrictions (e.g., misconfigured security groups or missing VPC access policies), they become vulnerable to vector scraping, brute-force similarity queries, or enumeration attacks. In a RAG-based architecture, this could lead to leakage of sensitive embeddings or knowledge base content through repeated queries. Enforcing private access endpoints, network ACLs, and strict security group rules is essential to reduce the OpenSearch exposure surface.                                 |
| 9    | **Vector-Specific Threat**          | 🔐 **Malicious Embedding Insertion** (custom attack)  ,**CWE-707**                                                      | Ingest / Runtime     | **High**           | Attackers may inject adversarial embeddings into the OpenSearch vector store during document ingestion (e.g., via poisoned PDFs, manipulated data payloads, or API misuse). These embeddings are crafted to disrupt ANN (Approximate Nearest Neighbor) similarity logic, causing the RAG chatbot to return irrelevant, misleading, or even harmful responses. This vector poisoning attack undermines semantic accuracy and trust, particularly when input data is user-submitted or loosely validated. Secure ingestion pipelines, embedding validation, and outlier detection are critical mitigations. |

---

#### 🧠 DynamoDB – Vulnerability Mapping

| **#** | **Category**                        | **Vulnerability / CWE / Misconfiguration**                                                                  | **Phase**            | **Risk**           | **Details / Context**                                                                             |
| ----- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------- | ------------------ | ------------------------------------------------------------------------------------------------- |
| 1 | **Encryption** | **DynamoDB At-Rest Encryption Disabled** ,**CWE-311** | **Provision** | **High**   | If **at-rest encryption** is disabled for DynamoDB, sensitive data such as **user session tokens, chat history, PII, or user preferences** may be stored in plaintext on disk. This creates a risk of unauthorized access through backup compromise, snapshot leaks, or internal threat actors. In a Bedrock RAG-enhanced chatbot, where DynamoDB enriches LLM responses with user-specific context, **unencrypted data may expose behavioral insights, identity details, or usage patterns**, violating data protection policies. AWS KMS-based encryption (default or CMK) should always be enabled to mitigate this. |
| 2 | **Encryption** | **DynamoDB Accelerator (DAX) Encryption Disabled** ,**CWE-311**/**CWE-319** | **Provision / Runtime** | **Medium** | If **DAX cluster encryption at rest and in transit** is disabled, sensitive user data cached in memory — such as **chat history, session tokens, or personalization context** — is vulnerable to exposure. In a Bedrock-enhanced chatbot pipeline, attackers with lateral access to DAX nodes or network-level interception may **dump memory or sniff traffic**, leading to **session hijacking or data leakage**. Enabling DAX encryption helps protect transient session-level context stored in cache from runtime threats. |
| 3 | **Recovery / Backup** | **DynamoDB Backup & Recovery Disabled** <br> **CWE-212** (Improper Removal of Sensitive Data), **CWE-710** (Improper Adherence to Expected Conventions) | **Runtime** | **Medium** | If **Point-In-Time Recovery (PITR)** and **on-demand backups** are not enabled for DynamoDB, the system lacks the ability to restore user data — such as **chat history, session state, or personalization context** — after malicious deletion, corruption, or accidental changes. While not directly exploitable, this weakness **amplifies the impact** of other attacks (e.g., IAM misuse, data poisoning) by **removing rollback capability**. In RAG-driven chat applications, this can result in **permanent loss of user interaction state**, affecting user trust and service continuity. Enabling continuous backups is essential for post-incident recovery and operational resilience. |
| 4 | **Query Injection** | **DynamoDB PartiQL Injection**,**CWE-89** (Improper Neutralization of Special Elements Used in an SQL Command) | **Ingest / Search** | **High**   | DynamoDB supports **PartiQL**, a SQL-like query language. If user input is passed into PartiQL expressions without proper sanitization or parameterization, attackers can craft **injection payloads** (e.g., `' OR '1'='1`) to bypass logic, alter query behavior, or access unauthorized records. In a Bedrock-based RAG chatbot, if user search terms or filter conditions are dynamically embedded in PartiQL statements (e.g., via Lambda), this can lead to **data exposure or privilege escalation**. Validation and parameterized queries are essential mitigation controls. |


---

#### 🧠 API Gateway – Vulnerability Mapping
| **#** | **Category**                        | **Vulnerability / CWE / Misconfiguration**                                                                  | **Phase**            | **Risk**           | **Details / Context**                                                                             |
| ----- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------- | ------------------ | ------------------------------------------------------------------------------------------------- |
| 1 | **Authentication** | **API Gateway Authorization Not Enabled (REST & HTTP APIs)** <br> **CWE-284** (Improper Access Control) <br> **CWE-287** (Improper Authentication) | **Runtime** | **Critical** | In both **REST APIs (V1)** and **HTTP APIs (V2)**, if authorization mechanisms such as IAM auth, Lambda authorizers, or Cognito JWT validation are not properly enabled, the API Gateway allows unauthenticated access to backend Lambda functions. While users accessing the chatbot via ECS (Streamlit app) are unaware of the API version, the risk is architectural. For **REST APIs**, lack of IAM or Lambda authorizers means any entity can invoke critical backend routes. For **HTTP APIs**, lack of **native JWT validation** (e.g., via Cognito or OIDC) exposes lightweight endpoints to unauthorized external invocation. This can lead to **data leakage, abuse of compute, or manipulation of chat interactions** in Bedrock workflows. |
| 2 | **Transport Security** | **Custom Domain TLS Version < 1.2** <br> **CWE-327: Use of a Broken or Risky Crypto Algorithm** | Provision | **High**   | When API Gateway is exposed via a custom domain using TLS versions below 1.2 (e.g., TLS 1.0/1.1), it becomes susceptible to downgrade attacks, MITM, or protocol vulnerabilities like POODLE and BEAST. This allows adversaries on compromised networks (e.g., open Wi-Fi) to intercept or manipulate data in transit.   |
| 3 | **Transport Security** | **Use Secure TLS Policy Not Enforced** <br> **CWE-326: Inadequate Encryption Strength**         | Provision | **High**   | Even with TLS 1.2+, if a secure TLS policy is not enforced in API Gateway, the handshake can permit weak or deprecated cipher suites (e.g., RC4, 3DES). This creates an opportunity for attackers to exploit weak encryption during the handshake, potentially decrypting sensitive traffic between ECS and API Gateway. |
| 4 | **Access Control** | **No Public Access Restrictions on API Gateway** <br> **CWE-200: Exposure of Sensitive Information** | Runtime | **Critical** | API Gateway lacks IP-based restrictions (e.g., allowlists), WAF rules, or resource-based policies. Without these, any user on the internet can invoke API endpoints — including invoking unauthenticated or rate-unlimited paths. This leaves the backend (e.g., Lambda or vector enrichment logic) vulnerable to abuse, brute-force, or scraping. |
| 5 | **Access Control** | **Default Endpoint Not Disabled** <br> **CWE-668: Exposure of Internal Resource**                    | Runtime | **High**     | If a custom domain for the API is secured (e.g., with Cognito or IP filtering), but the **default `execute-api` endpoint** is still enabled, attackers can bypass those protections by directly invoking the default URL. This silent backdoor exposes the same routes through an unprotected path, breaking defense-in-depth posture.             |
| 6 | **Traffic Protection** | **API Gateway WAF Not Enabled** <br> **CWE-693: Allocation of Resources Without Limits**          | Runtime | **High**   | Without AWS WAF attached to API Gateway, there are no protections against high-volume requests, brute-force attempts, or bot-based abuse targeting LLM endpoints. This exposes backend services (e.g., Lambda or Bedrock inference) to resource exhaustion or misuse.                                          |
| 7 | **Traffic Protection** | **API Gateway Client Certificate Not Required** <br> **CWE-295: Improper Certificate Validation** | Runtime | **Medium** | API Gateway does not enforce mTLS (mutual TLS) by requiring client-side certificates during HTTPS communication. In internal-to-internal service communication (e.g., ECS → API Gateway), this weakens service identity validation and makes man-in-the-middle attacks easier in misconfigured or shared VPCs. |
| 8  | **Input Validation** | **API Gateway Request Validation Not Enabled** <br> **CWE-20: Improper Input Validation**               | Runtime | **High**   | Without request validation at the API Gateway layer (e.g., validating request body, headers, or query strings), malformed or malicious input can reach downstream services. This increases the risk of prompt injection in LLMs, malformed requests crashing the orchestrator, or unexpected logic execution. |
| 9 | **Input Validation**  | **API Gateway Content Encoding Not Enforced** <br> **CWE-444: Improper Encoding or Escaping of Output** | Runtime | **Medium** | Lack of strict enforcement of accepted content-types or encodings (e.g., gzip, JSON only) may allow attackers to smuggle headers, bypass parsers, or trigger content-type confusion in backend Lambda functions — increasing chances of injection, logic bypass, or denial-of-service.                        |
| 10 | **Caching / Security**            | **Stage-Level Cache Encryption Not Enabled** <br> **CWE-311: Missing Encryption of Sensitive Data** | Provision   | **Medium** | When stage-level caching is enabled in API Gateway, unencrypted responses may be stored in plaintext. This can expose sensitive data (e.g., session info, tokens, user context) in cache if accessed or dumped via misconfiguration or compromise.                            |
| 11 | **Key Management / Cert Hygiene** | **Certificate Rotation Not Enabled** <br> **CWE-321: Use of Hard-coded Cryptographic Key**          | Maintenance | **Medium** | TLS certificates for custom domains in API Gateway, if not rotated regularly, become long-lived secrets. If leaked, they could be exploited for spoofing, interception, or unauthorized access. This risk is amplified in multi-tenant environments or shared infrastructure. |

---

#### 🧠 Amazon Bedrock – Vulnerability Mapping

| **#** | **Category**                        | **Vulnerability / CWE / Misconfiguration**                                                                  | **Phase**            | **Risk**           | **Details / Context**                                                                             |
| ----- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------- | ------------------ | ------------------------------------------------------------------------------------------------- |
| 1 | **Audit / Observability** | **Bedrock Model Invocation Logging Disabled** <br> **CWE-778: Insufficient Logging** | Runtime | **High**   | When invocation logging for Amazon Bedrock is disabled, prompt inputs, model outputs, and invocation metadata are not recorded. This limits visibility into malicious usage, prompt injection attempts, or LLM misuse — weakening forensic capability and incident response posture. |
| 2 | Availability / DoS | **LLM Denial of Service (Prompt Spamming)** <br> Referenced from MITRE ATLAS \[AML.CS0016] <br> **CWE-400: Uncontrolled Resource Consumption** | Runtime | **Medium** | Continuous or looped prompt submissions, oversized payloads, or adversarial queries can overload Bedrock model invocations (e.g., Claude 3), leading to degraded performance or unexpected cost escalation. Additionally, prompt poisoning attacks may force the model to ignore safety filters, leak environment variables, or engage in unintended logic behavior. |



---

#### 🧠 ECS (Container) – Vulnerability Mapping

| **#** | **Category**                        | **Vulnerability / CWE / Misconfiguration**                                                                  | **Phase**            | **Risk**           | **Details / Context**                                                                             |
| ----- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------- | ------------------ | ------------------------------------------------------------------------------------------------- |
| 1     | **Component Supply Chain Risk** | **CWE-1104: Use of Unmaintained Third-Party Component**<br>- **CWE-79: XSS in Streamlit (CVE-2023-27494)** <br>- **CWE-22: Path Traversal in Streamlit Components (CVE-2022-35918)** | Image + Runtime | **High** | The application uses outdated versions of Streamlit and related components (as defined in `requirements.txt`), which include critical unpatched vulnerabilities:<br><br>**1. Reflected XSS (CVE-2023-27494):** Allows attackers to execute malicious scripts via crafted URLs, leading to session or token theft.<br><br>**2. Path Traversal (CVE-2022-35918):** Exploits weaknesses in custom Streamlit components to access sensitive files from within the container file system.<br><br>These vulnerabilities are introduced due to the lack of secure dependency management, failing to pin safe versions and missing upgrade hygiene, ultimately affecting both image integrity and runtime behavior. |
| 2    | **Vulnerable Native Binaries** | **CWE-119: Buffer Overflow / Memory Corruption**<br>-**CWE-134(Use of Externally-Controlled Format String)** <br>-**CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')** <br>-            | Image     | **High**   | Vulnerable native binaries in the base image (e.g., glibc, bash) may expose the container to memory corruption attacks such as buffer overflows (CWE-119), format string exploits (CWE-134), or command injection (CWE-78). These flaws can be exploited through insecure system calls or shell invocations within the application (e.g., os.system(), subprocess), potentially allowing attackers to execute arbitrary commands, escalate privileges inside the container, or crash the runtime environment.
| 3     | **CI/CD Role Overprivilege** | **CWE-250: Execution with Unnecessary Privileges** | Build     | **High** | CI/CD roles used during the build process (e.g., AWS CodeBuild, GitHub Actions) have wildcard or overly permissive IAM policies (e.g., `ecr:*`, `ecs:*`). An internal or compromised actor can misuse these roles to overwrite trusted images in ECR, alter ECS task definitions, or inject malicious code into the app (e.g., XSS, command injection in Streamlit components). Exploitation occurs during the build phase, potentially compromising downstream deployments. |   
| 4 | **Insecure Docker Instructions** | **CWE-276: Incorrect Default Permissions** | Build | **Medium** | Insecure use of Dockerfile instructions such as COPY and RUN without setting file-level permissions results in default read/write access. Sensitive scripts or config files copied during image build may be accessible at runtime. If an attacker gains access to the container filesystem, they can read or modify these files, leading to potential privilege escalation or persistence. Misconfiguration occurs at build time; exploitation typically happens at runtime. |
| 5 | **Container Runs as Root** | **CWE-250: Execution with Unnecessary Privileges** | Image (Runtime) | **High** | The container is configured to run as the default root user due to the absence of a USER directive in the Dockerfile or lack of explicit runtime override. If an attacker gains access to the container, root-level privileges allow high-impact actions such as accessing sensitive ENV variables, exfiltrating credentials from metadata endpoints, modifying runtime files, or installing persistence mechanisms. Exploitation can be carried out by internal or external actors during runtime. |
|6    | **Public ECR Repository** | **CWE-732: Incorrect Permission Assignment for Critical Resource** | Registry  | **High** | The ECR repository is misconfigured as public, allowing unauthenticated users to pull container images. Adversaries can reverse-engineer the image contents to discover sensitive logic, exposed environment variables (`.env`), hardcoded credentials, internal API endpoints, or even cloud resource identifiers like S3 buckets or database names. This increases the risk of targeted attacks, code exploitation, or data exfiltration based on internal knowledge gleaned from image analysis. |
|7 | **No Cleanup / Retention Policy** | **CWE-770: Allocation of Resources Without Limits or Throttling** | Registry | **Low** | The registry lacks a defined cleanup or image retention policy, leading to uncontrolled image accumulation. This increases the storage cost, clutters the image space with outdated or test builds, and makes it harder to monitor and secure the supply chain. Attackers may exploit this by uploading large or malicious images to exhaust storage limits or by hiding backdoors in old images that are no longer actively scanned or deployed but remain accessible. |
                                    
---

## 🛡️ Stage 6 : Attack Modeling


This document covers **Step 6: Attack Modeling** from the [PASTA](https://owasp.org/www-community/Threat_Modeling) (Process for Attack Simulation and Threat Analysis) methodology. This step builds on insights from earlier stages to **simulate real-world attack scenarios**, helping identify how threats can materialize into actual exploits against critical assets.

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

<img width="3908" height="1452" alt="root_node" src="https://github.com/user-attachments/assets/06787bbc-b60f-4561-a505-0086a11ea613" />

---
<details>
  <summary><strong>1.TOKEN REPLAY AND API ABUSE VIA GATEWAY</strong></summary>

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
  <summary><strong>2.LLM RESPONSE SPOOFING IN TRANSIT</strong></summary>
  <img width="1741" height="337" alt="4 0_LLM_RESPONSE_SPOOFING" src="https://github.com/user-attachments/assets/478d9c66-82ba-49e0-b0b3-0ddd53fb4a67" />



  <details>
    <summary><strong>2.1  API Gateway Transport Layer Exploitation</strong></summary>
   <img width="1269" height="2775" alt="4 1 1_api_gateway_tls_attack_path" src="https://github.com/user-attachments/assets/16282daf-b808-457a-9686-701075b9958a" />



  </details>

  <details>
    <summary><strong>2.2 Lambda Response Manipulation</strong></summary>
    <img width="1322" height="1816" alt="4 2 1_lambda_attack_path" src="https://github.com/user-attachments/assets/1259fb37-a631-49b2-86f6-3a551e235581" />

  </details>

   <details>
    <summary><strong>2.3 ECS (UI) Based Client-Side Spoofing</strong></summary>
    <img width="1127" height="868" alt="4 3 1_ECS_frontend_response_spoof" src="https://github.com/user-attachments/assets/bf714269-0067-4ae5-856d-a6beb0f10e4f" />
  </details>

</details>

---
<details>
  <summary><strong>3.OVER-PERMISSIONED LAMBDA ENABLING INSECURE OPERATIONS</strong></summary>
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


