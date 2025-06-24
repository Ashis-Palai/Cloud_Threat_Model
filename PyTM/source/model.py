
#!/usr/bin/env python3

from pytm import TM, Boundary, Actor, Lambda, Server, Datastore, Dataflow, Process

tm = TM("AWS Bedrock Chatbot RAG Architecture - Finalized")
tm.description = "Threat model for RAG chatbot using AWS Bedrock, ECS Fargate, API Gateway, Titan, OpenSearch, and S3-based document enrichment."

# === Trust Boundaries ===
internet = Boundary("Internet")
vpc = Boundary("AWS Customer VPC")
aws_managed = Boundary("AWS Managed Services")

# === External Actor ===
user = Actor("User")
user.inBoundary = internet

# === VPC Components ===
streamlit_ui = Process("Streamlit UI")
streamlit_ui.inBoundary = vpc

ecs_fargate = Server("ECS Fargate Backend")
ecs_fargate.inBoundary = vpc

api_gateway = Server("API Gateway")
api_gateway.inBoundary = vpc

lambda_orchestrator = Lambda("Lambda Orchestrator")
lambda_orchestrator.inBoundary = vpc

dynamodb = Datastore("DynamoDB (Chat Sessions)")
dynamodb.inBoundary = vpc

s3_bucket = Datastore("Amazon S3 (Knowledge Docs)")
s3_bucket.inBoundary = vpc  # Now placed in customer VPC

# === AWS Managed Components ===
bedrock_llm = Server("Amazon Bedrock (Claude 3 LLM)")
bedrock_llm.inBoundary = aws_managed

titan_embedder = Process("Titan Embedding Engine")
titan_embedder.inBoundary = aws_managed

opensearch = Datastore("Amazon OpenSearch Vector DB")
opensearch.inBoundary = aws_managed

# === Dataflows (Bidirectional unless stated) ===
Dataflow(user, streamlit_ui, "User initiates chat via browser")
Dataflow(streamlit_ui, ecs_fargate, "UI calls backend ECS")
Dataflow(ecs_fargate, api_gateway, "REST call to API Gateway")
Dataflow(api_gateway, lambda_orchestrator, "Invoke Lambda function")

Dataflow(lambda_orchestrator, dynamodb, "Retrieve session context")
Dataflow(dynamodb, lambda_orchestrator, "Return session history")

# Dataflow(lambda_orchestrator, s3_bucket, "Fetch documents from S3")
# NOTE: S3 → Knowledge Base is unidirectional only
Dataflow(s3_bucket, titan_embedder, "Send documents for embedding (Unidirectional)")
Dataflow(titan_embedder, opensearch, "Store vector embeddings")

Dataflow(lambda_orchestrator, titan_embedder, "Request embeddings for input")
Dataflow(opensearch, lambda_orchestrator, "Retrieve vector matches for context")
Dataflow(lambda_orchestrator, opensearch, "Send vector query")

Dataflow(lambda_orchestrator, bedrock_llm, "Send prompt to Claude 3")
Dataflow(bedrock_llm, lambda_orchestrator, "Receive LLM response")

Dataflow(lambda_orchestrator, dynamodb, "Write updated session state")

# Response path follows reverse flow
Dataflow(lambda_orchestrator, api_gateway, "Send response back to API Gateway")
Dataflow(api_gateway, ecs_fargate, "Pass response to ECS")
Dataflow(ecs_fargate, streamlit_ui, "Render chatbot response")

# === Finalize Threat Model ===
if __name__ == "__main__":
    tm.process()



