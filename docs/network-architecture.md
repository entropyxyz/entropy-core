# Entropy Network Architecture

This document provides a high-level overview of the Entropy network architecture using diagrams.

## System Overview

```mermaid
graph TB
    subgraph "Entropy Network"
        subgraph "Threshold Signature Servers"
            TSS1[Alice TSS]
            TSS2[Bob TSS]
            TSS3[Charlie TSS]
            TSS4[Dave TSS]
        end
        
        subgraph "Substrate Chain"
            SC[Entropy Chain]
        end
        
        subgraph "Client Applications"
            CA1[Client 1]
            CA2[Client 2]
        end
    end
    
    TSS1 <-->|Threshold Signing| TSS2
    TSS1 <-->|Threshold Signing| TSS3
    TSS2 <-->|Threshold Signing| TSS3
    TSS4 <-->|Threshold Signing| TSS1
    
    TSS1 <-->|Chain Interaction| SC
    TSS2 <-->|Chain Interaction| SC
    TSS3 <-->|Chain Interaction| SC
    TSS4 <-->|Chain Interaction| SC
    
    CA1 <-->|Signature Requests| SC
    CA2 <-->|Signature Requests| SC
```

## Key Share Distribution

```mermaid
graph LR
    subgraph "Initial Setup"
        DKG[Distributed Key Generation]
        KS1[Key Share 1]
        KS2[Key Share 2]
        KS3[Key Share 3]
    end
    
    subgraph "TSS Nodes"
        TSS1[Alice TSS]
        TSS2[Bob TSS]
        TSS3[Charlie TSS]
    end
    
    DKG -->|Generates| KS1
    DKG -->|Generates| KS2
    DKG -->|Generates| KS3
    
    KS1 -->|Distributed to| TSS1
    KS2 -->|Distributed to| TSS2
    KS3 -->|Distributed to| TSS3
```

## Reshare Process

```mermaid
sequenceDiagram
    participant C as Chain
    participant T1 as TSS1
    participant T2 as TSS2
    participant T3 as TSS3
    participant T4 as TSS4
    
    C->>T1: Reshare Request
    C->>T2: Reshare Request
    C->>T3: Reshare Request
    C->>T4: Reshare Request
    
    T1->>T2: Share Contribution
    T1->>T3: Share Contribution
    T1->>T4: Share Contribution
    
    T2->>T1: Share Contribution
    T2->>T3: Share Contribution
    T2->>T4: Share Contribution
    
    T3->>T1: Share Contribution
    T3->>T2: Share Contribution
    T3->>T4: Share Contribution
    
    T4->>T1: Share Contribution
    T4->>T2: Share Contribution
    T4->>T3: Share Contribution
    
    T1->>C: New Key Share
    T2->>C: New Key Share
    T3->>C: New Key Share
    T4->>C: New Key Share
```

## Signature Generation Process

```mermaid
sequenceDiagram
    participant C as Client
    participant SC as Substrate Chain
    participant T1 as TSS1
    participant T2 as TSS2
    participant T3 as TSS3
    
    C->>SC: Signature Request
    SC->>T1: Request Partial Signature
    SC->>T2: Request Partial Signature
    SC->>T3: Request Partial Signature
    
    T1->>SC: Partial Signature
    T2->>SC: Partial Signature
    T3->>SC: Partial Signature
    
    SC->>SC: Combine Signatures
    SC->>C: Final Signature
```

## Network Security Model

```mermaid
graph TB
    subgraph "Security Boundaries"
        subgraph "TSS Network"
            TSS1[Alice TSS]
            TSS2[Bob TSS]
            TSS3[Charlie TSS]
        end
        
        subgraph "Chain Network"
            SC[Entropy Chain]
        end
        
        subgraph "Client Network"
            C1[Client 1]
            C2[Client 2]
        end
    end
    
    TSS1 <-->|Encrypted| TSS2
    TSS1 <-->|Encrypted| TSS3
    TSS2 <-->|Encrypted| TSS3
    
    TSS1 <-->|Secure RPC| SC
    TSS2 <-->|Secure RPC| SC
    TSS3 <-->|Secure RPC| SC
    
    C1 <-->|HTTPS| SC
    C2 <-->|HTTPS| SC
```

## Component Interaction

```mermaid
graph LR
    subgraph "TSS Components"
        API[API Layer]
        KV[Key-Value Store]
        DKG[DKG Module]
        SIG[Signing Module]
    end
    
    subgraph "External"
        CHAIN[Substrate Chain]
        CLIENTS[Clients]
    end
    
    API <-->|Internal| KV
    API <-->|Internal| DKG
    API <-->|Internal| SIG
    
    API <-->|External| CHAIN
    API <-->|External| CLIENTS
    
    DKG <-->|Key Management| KV
    SIG <-->|Key Access| KV
``` 