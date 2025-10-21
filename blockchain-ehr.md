# Blockchain Strategy for EHR Management

A technical roadmap and MVP plan for a blockchain-based EHR access system.

## Building the Minimum Viable Product: A Technical Roadmap

### MVP Philosophy: Start Minimal, Scale Systematically

Based on successful implementations (particularly Pampattiwar 2025 and Singh 2024) and lessons from the 38% that achieved deployment, this section provides a **concrete, actionable roadmap** for build[...]  

**Core Principle:** Your MVP should solve **one critical problem** extremely well, not attempt comprehensive EHR replacement.

---

### Phase 1: MVP Scope Definition (Week 1-2)

#### **The One Problem to Solve**

Based on market analysis and successful implementations, the highest-value MVP is:

**"Patient-Controlled Access to Medical Records Across Providers"**

**Why This Problem:**
1. **High pain point**: Patients can't easily share records between providers
2. **Clear value**: Reduces duplicate tests, improves care coordination
3. **Regulatory alignment**: HIPAA and GDPR both mandate patient control
4. **Technically achievable**: Doesn't require full EHR replacement
5. **Measurable**: Can track time savings, cost reductions, user satisfaction

**Out of Scope for MVP:**
- ❌ Full EHR functionality (diagnosis, treatment planning, billing)
- ❌ Integration with medical devices/IoT sensors
- ❌ AI-powered analytics
- ❌ Insurance claims processing
- ❌ Prescription management

**In Scope for MVP:**
- ✅ Upload medical records (PDF, DICOM, HL7 messages)
- ✅ Secure storage with encryption
- ✅ Patient grants/revokes provider access
- ✅ Immutable audit trail of who accessed what when
- ✅ Basic provider verification
- ✅ Export records in standard formats

---

### Phase 2: Technical Architecture (Week 2-4)

#### **Architecture Overview**

```text
┌─────────────────────────────────────────────────────────────┐
│                        USER LAYER                           │
│  ┌──────────┐  ┌──────────┐  ┌─────────────┐                │
│  │ Patient  │  │ Provider │  │   Admin     │                │
│  │   App    │  │   Portal │  │  Dashboard  │                │
│  └──────────┘  └──────────┘  └─────────────┘                │
└────────────┬─────────────┬──────────────┬─────────────────-─┘
             │             │              │
             ▼             ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│                    API GATEWAY LAYER                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Request Validation │ Auth │ Rate Limiting │ Logging │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────┬─────────────┬──────────────┬──────────────────┘
             │             │              │
             ▼             ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│                   BUSINESS LOGIC LAYER                      │
│  ┌───────────┐  ┌────────────┐  ┌──────────────┐            │
│  │  Access   │  │   Record   │  │   Consent    │            │
│  │  Control  │  │ Management │  │  Management  │            │
│  └───────────┘  └────────────┘  └──────────────┘            │
└────────────┬─────────────┬──────────────┬──────────────────┘
             │             │              │
             ▼             ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│                   BLOCKCHAIN LAYER                        │
│  ┌──────────────────────────────────────────────────────┐ │
│  │    Hyperledger Fabric (Permissioned Blockchain)      │ │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────────┐  │ │
│  │  │  Access  │  │  Audit   │  │  Smart Contracts   │  │ │
│  │  │  Ledger  │  │   Log    │  │  (Chaincode)       │  │ │
│  │  └──────────┘  └──────────┘  └────────────────────┘    │
│  └──────────────────────────────────────────────────────┘ │
└────────────┬─────────────┬──────────────┬──────────────────┘
             │             │              │
             ▼             ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│                    STORAGE LAYER                            │
│  ┌────────────┐  ┌────────────┐  ┌─────────────────────┐    │
│  │   IPFS     │  │  Postgres  │  │   AWS S3 (Backup)   │    │
│  │ (Off-chain)│  │(Metadata)  │  │   (Encrypted)       │    │
│  └────────────┘  └────────────┘  └─────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

### Technology Stack Rationale

Based on successful implementations and requirements analysis:

| Layer | Technology | Rationale | Alternative |
|-------|------------|-----------|-------------|
| Blockchain Platform | Hyperledger Fabric 2.5+ | Permissioned (meets HIPAA)<br>• High throughput (3,000+ TPS)<br>• Modular architecture<br>• 81% of healthcare implementations use it | •Polygon [...] |
| Smart Contracts | Go (Fabric Chaincode) | • Official Fabric language<br>• Performance<br>• Type safety | Node.js (easier development) |
| Off-Chain Storage | IPFS (InterPlanetary File System) | • Decentralized<br>• Content-addressable<br>• No single point of failure | AWS S3 (simpler, but centralized) |
| Database | PostgreSQL 15+ | • ACID compliance<br>• JSON support<br>• Mature, reliable | MongoDB (if document flexibility needed) |
| API Layer | Node.js + Express | • Fast development<br>• Large ecosystem<br>• Good for I/O-heavy workloads | Python FastAPI (better typing) |
| Frontend | React + TypeScript | • Component reusability<br>• Strong typing<br>• Industry standard | Vue.js (simpler learning curve) |
| Authentication | OAuth 2.0 + JWT | • Industry standard<br>• Federated identity support | Auth0/Okta (managed service) |
| Encryption | AES-256 (data at rest)<br>TLS 1.3 (data in transit) | • HIPAA compliant<br>• Industry standard | ChaCha20 (faster, equally secure) |

---

### Phase 3: Core Components Implementation (Week 4-12)

### Component 1: Soulbound Token (SBT) Identity System

Based on Singh 2024 implementation, use SBTs for non-transferable patient identities.

**Implementation:**

```solidity
// Smart Contract (Solidity for concept; adapt to Fabric Chaincode)
contract PatientIdentitySBT {
    struct PatientIdentity {
        string patientID;           // Unique patient identifier
        string publicKeyHash;       // Hash of patient's public key
        address walletAddress;      // Patient's blockchain wallet
        uint256 issuedTimestamp;    // When SBT was issued
        string[] guardianAddresses; // Recovery guardians
        bool isActive;              // Can be revoked if compromised
    }
    
    mapping(address => PatientIdentity) public patients;
    
    // Issue SBT (can only be called by verified healthcare provider)
    function issuePatientSBT(
        address patientWallet,
        string memory patientID,
        string memory publicKeyHash,
        string[] memory guardians
    ) public onlyVerifiedProvider {
        require(!patients[patientWallet].isActive, "SBT already exists");
        
        patients[patientWallet] = PatientIdentity({
            patientID: patientID,
            publicKeyHash: publicKeyHash,
            walletAddress: patientWallet,
            issuedTimestamp: block.timestamp,
            guardianAddresses: guardians,
            isActive: true
        });
        
        emit SBTIssued(patientWallet, patientID);
    }
    
    // SBTs are non-transferable (core feature)
    function transfer(address to) public pure {
        revert("SBTs are non-transferable");
    }
}
```

### Key Features:

• **Non-transferable:** Patient identity cannot be sold/transferred  
• **Recovery mechanism:** Guardians can help recover access if private key lost  
• **Verifiable:** Any provider can verify patient identity on-chain  
• **Privacy-preserving:** Only hash of patient data on-chain, not PII  
  
### GDPR Compliance:

• **Right to erasure:** SBT can be marked "inactive" on-chain; all off-chain data deleted  
• **Data minimization:** Only identifier hash on-chain  
• **Purpose limitation:** SBT used solely for authentication  

### Component 2: Access Control Smart Contract

Based on Pampattiwar 2025's "context-sensitive rule engine":

```go
// Hyperledger Fabric Chaincode (Go)
package main

import (
    "encoding/json"
    "fmt"
    "time"
    
    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type AccessControlContract struct {
    contractapi.Contract
}

type AccessRequest struct {
    RequestID      string    `json:"requestID"`
    ProviderID     string    `json:"providerID"`
    PatientID      string    `json:"patientID"`
    RecordHash     string    `json:"recordHash"`      // Hash of off-chain record
    RequestedDate  time.Time `json:"requestedDate"`
    ExpiryDate     time.Time `json:"expiryDate"`      // Time-limited access
    Status         string    `json:"status"`          // Pending/Approved/Denied
    ApprovedDate   time.Time `json:"approvedDate"`
    Purpose        string    `json:"purpose"`         // Treatment/Research/etc.
}

// Provider requests access to patient record
func (c *AccessControlContract) RequestAccess(
    ctx contractapi.TransactionContextInterface,
    providerID string,
    patientID string,
    recordHash string,
    purpose string,
    durationDays int,
) error {
    // Verify provider is registered
    providerExists, err := c.VerifyProvider(ctx, providerID)
    if err != nil || !providerExists {
        return fmt.Errorf("provider not verified: %s", providerID)
    }
    
    // Create access request
    requestID := generateRequestID(providerID, patientID, time.Now())
    request := AccessRequest{
        RequestID:     requestID,
        ProviderID:    providerID,
        PatientID:     patientID,
        RecordHash:    recordHash,
        RequestedDate: time.Now(),
        ExpiryDate:    time.Now().AddDate(0, 0, durationDays),
        Status:        "Pending",
        Purpose:       purpose,
    }
    
    requestJSON, err := json.Marshal(request)
    if err != nil {
        return err
    }
    
    // Store on blockchain
    return ctx.GetStub().PutState(requestID, requestJSON)
}

// Patient approves/denies access request
func (c *AccessControlContract) RespondToAccessRequest(
    ctx contractapi.TransactionContextInterface,
    requestID string,
    approved bool,
) error {
    // Retrieve request
    requestJSON, err := ctx.GetStub().GetState(requestID)
    if err != nil {
        return fmt.Errorf("failed to read request: %s", err.Error())
    }
    if requestJSON == nil {
        return fmt.Errorf("request does not exist: %s", requestID)
    }
    
    var request AccessRequest
    err = json.Unmarshal(requestJSON, &request)
    if err != nil {
        return err
    }
    
    // Verify caller is the patient
    // (In production: verify digital signature)
    
    // Update status
    if approved {
        request.Status = "Approved"
        request.ApprovedDate = time.Now()
    } else {
        request.Status = "Denied"
    }
    
    requestJSON, err = json.Marshal(request)
    if err != nil {
        return err
    }
    
    // Update blockchain
    err = ctx.GetStub().PutState(requestID, requestJSON)
    if err != nil {
        return err
    }
    
    // Emit event for off-chain systems
    ctx.GetStub().SetEvent("AccessRequestResolved", requestJSON)
    
    return nil
}

// Verify if provider has active access to record
func (c *AccessControlContract) VerifyAccess(
    ctx contractapi.TransactionContextInterface,
    providerID string,
    patientID string,
    recordHash string,
) (bool, error) {
    // Query all access requests for this provider-patient-record combination
    queryString := fmt.Sprintf(
        `{"selector":{"providerID":"%s","patientID":"%s","recordHash":"%s","status":"Approved"}}`,
        providerID, patientID, recordHash,
    )
    
    resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
    if err != nil {
        return false, err
    }
    defer resultsIterator.Close()
    
    // Check if any approved access exists and is not expired
    for resultsIterator.HasNext() {
