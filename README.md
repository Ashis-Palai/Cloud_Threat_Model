# ☁️ CLOUD THREAT MODELING

This project focuses on performing threat modeling on a modern cloud-native application hosted on AWS. The application is an **AWS Bedrock-based RAG (Retrieval-Augmented Generation) Chatbot**, which leverages several managed services such as Amazon Bedrock, ECS Fargate, API Gateway, Lambda, S3, Vector db and Amazon DynamoDB.

### 📌 Architecture Overview
The chatbot architecture handles user interactions via a Streamlit UI running on ECS Fargate. These inputs are processed through API Gateway and AWS Lambda to interact with data sources and LLMs such as Anthropic Claude 3 via Amazon Bedrock. A knowledge base is maintained using Amazon OpenSearch and embeddings from Amazon Titan, with data persisted in Amazon S3 and DynamoDB.

Please refer to the diagram in the \`architecture/\` folder for a full visual reference.

### 🎯 Project Goal
The main goal of this Threat Modeling (TM) project is to:

- Identify security threats in the architecture
- Apply threat modeling concepts using multiple tools:
  - **OWASP Threat Dragon**
  - **PyTM (Python-based threat modeling)**
- Use recognized TM methodologies:
  - **STRIDE**
  - **PASTA (Process for Attack Simulation and Threat Analysis)**

This multi-method approach demonstrates the application of theoretical and practical TM skills on real-world cloud infrastructure.
