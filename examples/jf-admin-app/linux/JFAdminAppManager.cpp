/*
 *
 *    Copyright (c) 2024 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "JFAdminAppManager.h"

#include "Options.h"

#include <app-common/zap-generated/attributes/Accessors.h>
#include <app/clusters/general-diagnostics-server/general-diagnostics-server.h>
#include <app/clusters/software-diagnostics-server/software-diagnostics-server.h>
#include <app/clusters/switch-server/switch-server.h>
#include <app/server/Server.h>
#include <app/util/attribute-storage.h>
#include <controller/CHIPCluster.h>
#include <controller/ExampleOperationalCredentialsIssuer.h>
#include <platform/PlatformManager.h>

#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/ConcreteAttributePath.h>
#include <app/server/JointFabricDatastorage.h>
#include <app/server/Server.h>
#include <lib/support/TestGroupData.h>
#include <lib/support/logging/CHIPLogging.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::Controller;
using namespace chip::Credentials;
using namespace chip::DeviceLayer;
using namespace chip::TLV;

using KeySet = GroupDataProvider::KeySet;

namespace {
static constexpr uint16_t kAdminCATIdenifier            = 0xFFFF;
static constexpr uint16_t kAnchorDatastoreCATIdentifier = 0xFFFC;

/* demo: fixed for the moment */
NodeId jfControllerNodeId = 500;

static constexpr uint16_t failSafeTimerPeriod = 15; // seconds

static constexpr char kOperationalCredentialsIntermediateIssuerKeypairStorage[] = "ExampleOpCredsICAKey0";
static constexpr char kOperationalCredentialsRootCertificateStorage[]           = "ExampleCARootCert0";
static constexpr char kOperationalCredentialsIntermediateCertificateStorage[]   = "ExampleCAIntermediateCert0";
static constexpr char kJFFabricID[]                                             = "FabricID0";
} // namespace

CHIP_ERROR JFAdminAppManager::Init(Server & server, OperationalCredentialsDelegate & opCredentialsDelegate,
                                   PersistentStorage & storage)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    mServer                 = &server;
    mCASESessionManager     = server.GetCASESessionManager();
    mOpCredentials          = &opCredentialsDelegate;
    mControllerPKI          = &storage;
    mJointFabricDatastorage = &(mServer->GetJointFabricDatastorage());

    return err;
}

void JFAdminAppManager::HandleCommissioningCompleteEvent(NodeId peerNodeId, FabricIndex accessingFabricIndex)
{
    VerifyOrReturn(mAnchorSet == false);

    CATValues cats;

    if (mServer->GetFabricTable().FetchCATs(accessingFabricIndex, cats) == CHIP_NO_ERROR)
    {
        /* JFA has Administrator CAT and Anchor/Datastore CAT
         * when first commissioned in its fabric
         */
        if (cats.ContainsIdentifier(kAdminCATIdenifier) && cats.ContainsIdentifier(kAnchorDatastoreCATIdentifier))
        {
            mInitialFabricIndex = accessingFabricIndex;
            mInitialAdminNodeId = peerNodeId;
            mAnchorSet          = true;
        }
    }
}

void JFAdminAppManager::HandleJointFabricCommissioningCompleteEvent(NodeId peerNodeId, FabricIndex accessingFabricIndex)
{
    CATValues cats;

    if (mServer->GetFabricTable().FetchCATs(accessingFabricIndex, cats) == CHIP_NO_ERROR)
    {
        /* after JCM, JFA receives an Administrator CAT */
        if (cats.ContainsIdentifier(kAdminCATIdenifier))
        {
            mJointFabricIndex    = accessingFabricIndex;
            mJointFabricVendorId = mServer->GetFabricTable().FindFabricWithIndex(accessingFabricIndex)->GetVendorId();
        }
    }

    if ((mInitialFabricIndex != kUndefinedFabricIndex) && (mJointFabricIndex != kUndefinedFabricIndex))
    {
        ChipLogProgress(Test, "HandleCommissioningCompleteEvent: TriggerJFOnboardingForNextNode state machine");

        mAnchorAdminScopedNodeId = ScopedNodeId(peerNodeId, mJointFabricIndex);
        TriggerJFOnboardingForNextNode();
    }
    else
    {
        ChipLogProgress(Test, "HandleCommissioningCompleteEvent: Couldn't identify mInitialFabricIndex and mJointFabricIndex.");
    }
}

void JFAdminAppManager::TriggerJFOnboardingForNextNode()
{
    NodeId pendingNodeId          = kUndefinedNodeId;
    bool deletedPendingNodesExist = false;

    auto mNodeInformationEntries = mJointFabricDatastorage->GetNodeInformationEntries();

    for (auto & nodeInformationEntry : mNodeInformationEntries)
    {
        if (nodeInformationEntry.commissioningStatusEntry.state == JointFabricDatastore::DatastoreStateEnum::kCommitted)
        {
            mJointFabricDatastorage->SetNode(nodeInformationEntry.nodeID, JointFabricDatastore::DatastoreStateEnum::kDeletePending);
            pendingNodeId = nodeInformationEntry.nodeID;
            break;
        }
        else if (!deletedPendingNodesExist &&
                 nodeInformationEntry.commissioningStatusEntry.state == JointFabricDatastore::DatastoreStateEnum::kDeletePending)
        {
            deletedPendingNodesExist = true;
        }
    }

    if (pendingNodeId != kUndefinedNodeId)
    {
        mPendingScopedNodeId = ScopedNodeId(pendingNodeId, mInitialFabricIndex);
        ConnectToNode(mPendingScopedNodeId, kReissueOperationalIdentity);
    }
    else if (!deletedPendingNodesExist)
    {
        ChipLogProgress(Test, "All Nodes have now updated NOCs chaining up to the cross-signed ICAC!");

        /* TODO: add it inside the state machine */
        UpdateOperationalIdentifyForController();
    }
    else
    {
        ChipLogError(Test, "Error while updating NOCs for some of the devices.");

        for (auto & nodeInformationEntry : mNodeInformationEntries)
        {
            if (nodeInformationEntry.commissioningStatusEntry.state == JointFabricDatastore::DatastoreStateEnum::kDeletePending)
            {
                NodeId kDeletePendingNode = nodeInformationEntry.nodeID;

                ChipLogError(Test, "Node ID of device with kDeletePending status: 0x" ChipLogFormatX64,
                             ChipLogValueX64(kDeletePendingNode));
            }
        }
    }
}

void JFAdminAppManager::ConnectToNode(ScopedNodeId scopedNodeId, OnConnectedAction onConnectedAction)
{
    VerifyOrDie(mServer != nullptr);

    if ((scopedNodeId.GetFabricIndex() == kUndefinedFabricIndex) || (scopedNodeId.GetNodeId() == kUndefinedNodeId))
    {
        ChipLogError(DeviceLayer, "Invalid node location!");
        return;
    }

    // Set the action to take once connection is successfully established
    mOnConnectedAction = onConnectedAction;

    ChipLogDetail(Test, "Establishing session to node ID 0x" ChipLogFormatX64 " on fabric index %d",
                  ChipLogValueX64(scopedNodeId.GetNodeId()), scopedNodeId.GetFabricIndex());

    mCASESessionManager->FindOrEstablishSession(scopedNodeId, &mOnConnectedCallback, &mOnConnectionFailureCallback);
}

void JFAdminAppManager::OnConnected(void * context, Messaging::ExchangeManager & exchangeMgr, const SessionHandle & sessionHandle)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);
    jfAdminCore->mSessionHolder.Grab(sessionHandle);

    ChipLogProgress(Test, "OnConnected: successful");

    jfAdminCore->mExchangeMgr = &exchangeMgr;

    switch (jfAdminCore->mOnConnectedAction)
    {
    case kReadNodeLabel: {
        jfAdminCore->ReadNodeLabel();
        break;
    }

    case kSendAddPendingNode: {
        jfAdminCore->SendAddPendingNode();
        break;
    }
    case kReissueOperationalIdentity: {
        jfAdminCore->SendArmFailSafeTimer();
        break;
    }
    case kSendCommissioningComplete: {
        jfAdminCore->SendCommissioningComplete();
        break;
    }
    case kSendRefreshNode: {
        jfAdminCore->SendRefreshNode();
        break;
    }

    default:
        break;
    }
}

CHIP_ERROR JFAdminAppManager::ReadNodeLabel()
{
    ChipLogProgress(Test, "ReadNodeLabel: invoke cluster command.");
    using TypeInfo = BasicInformation::Attributes::NodeLabel::TypeInfo;

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.ReadAttribute<TypeInfo>(this, OnReadSuccessResponse, OnReadFailureResponse);
}

CHIP_ERROR JFAdminAppManager::SendAddPendingNode()
{
    JointFabricDatastore::Commands::AddPendingNode::Type request;

    request.nodeID       = mPendingScopedNodeId.GetNodeId();
    request.friendlyName = friendlyNameCharSpan;

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(Test, "SendAddPendingNode: invoke cluster command.");
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.InvokeCommand(request, this, OnAddPendingNodeResponse, OnAddPendingNodeFailure);
}

CHIP_ERROR JFAdminAppManager::SendRefreshNode()
{
    JointFabricDatastore::Commands::RefreshNode::Type request;

    request.nodeID = mPendingScopedNodeId.GetNodeId();

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(Test, "SendRefreshNode: invoke cluster command.");
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.InvokeCommand(request, this, OnRefreshNodeResponse, OnRefreshFailure);
}

CHIP_ERROR JFAdminAppManager::SendArmFailSafeTimer()
{
    uint64_t breadcrumb = static_cast<uint64_t>(kReissueOperationalIdentity);
    GeneralCommissioning::Commands::ArmFailSafe::Type request;
    request.expiryLengthSeconds = failSafeTimerPeriod;
    request.breadcrumb          = breadcrumb;

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(Test, "SendArmFailSafeTimer: invoke cluster command.");
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.InvokeCommand(request, this, OnArmFailSafeTimerResponse, OnArmFailSafeTimerFailure);
}

CHIP_ERROR JFAdminAppManager::SendCSRRequest()
{
    OperationalCredentials::Commands::CSRRequest::Type request;
    uint8_t csrNonce[kCSRNonceLength];

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    Crypto::DRBG_get_bytes(csrNonce, sizeof(csrNonce));
    request.CSRNonce = csrNonce;

    ChipLogProgress(Test, "SendCSRRequest: invoke cluster command.");
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.InvokeCommand(request, this, OnOperationalCertificateSigningRequest, OnCSRFailureResponse);
}

CHIP_ERROR JFAdminAppManager::SendAddTrustedRootCertificate()
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    OperationalCredentials::Commands::AddTrustedRootCertificate::Type request;
    uint8_t pendingRCAC[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan pendingRCACSpan{ pendingRCAC };

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    err = mServer->GetFabricTable().FetchRootCert(this->mJointFabricIndex, pendingRCACSpan);
    if (err != CHIP_NO_ERROR || !pendingRCACSpan.size())
    {
        ChipLogProgress(Test, "SendAddTrustedRootCertificate: Error while fetching the JF RCAC!");
        return err;
    }
    request.rootCACertificate = pendingRCACSpan;

    ChipLogProgress(Test, "SendAddTrustedRootCertificate: invoke cluster command.");
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.InvokeCommand(request, this, OnRootCertSuccessResponse, OnRootCertFailureResponse);
}

CHIP_ERROR JFAdminAppManager::SendAddNOC()
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    OperationalCredentials::Commands::AddNOC::Type request;
    uint8_t pendingICAC[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan pendingICACSpan{ pendingICAC };

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    /* get ICAC */
    err = mServer->GetFabricTable().FetchICACert(this->mJointFabricIndex, pendingICACSpan);
    if (err != CHIP_NO_ERROR || !pendingICACSpan.size())
    {
        ChipLogProgress(Test, "SendAddNOC: Error while fetching the JF ICAC.");
        return err;
    }

    request.NOCValue         = Span(this->mPendingNOCSpan.data(), this->mPendingNOCSpan.size());
    request.ICACValue        = MakeOptional(Span(pendingICACSpan.data(), pendingICACSpan.size()));
    request.IPKValue         = chip::GroupTesting::DefaultIpkValue::GetDefaultIpk();
    request.caseAdminSubject = NodeIdFromCASEAuthTag(0xFFFF'0001);
    request.adminVendorId    = this->mJointFabricVendorId;

    ChipLogProgress(Test, "SendAddNOC: invoke cluster command.");
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.InvokeCommand(request, this, OnOperationalCertificateAddResponse, OnAddNOCFailureResponse);

    return CHIP_NO_ERROR;
}

CHIP_ERROR JFAdminAppManager::SendCommissioningComplete()
{
    GeneralCommissioning::Commands::CommissioningComplete::Type request;

    if (!mExchangeMgr)
    {
        return CHIP_ERROR_UNINITIALIZED;
    }

    ChipLogProgress(Test, "SendCommissioningComplete: invoke cluster command.");
    Controller::ClusterBase cluster(*mExchangeMgr, mSessionHolder.Get().Value(), kRootEndpointId);
    return cluster.InvokeCommand(request, this, OnCommissioningCompleteResponse, OnCommissioningCompleteFailure);
}

void JFAdminAppManager::DisconnectFromNode()
{
    auto optionalSessionHandle = mSessionHolder.Get();
    if (optionalSessionHandle.HasValue())
    {
        if (optionalSessionHandle.Value()->IsActiveSession())
        {
            optionalSessionHandle.Value()->AsSecureSession()->MarkAsDefunct();
        }
    }
    mSessionHolder.Release();
}

CHIP_ERROR JFAdminAppManager::UpdateOperationalIdentifyForController()
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    const char * chipToolKvs = nullptr;
    Crypto::P256SerializedKeypair serializedICACKey;
    uint16_t ICACKeySize = static_cast<uint16_t>(serializedICACKey.Capacity());

    /* CHIPCert format for Anchor CA */
    uint8_t anchorCA[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan anchorCASpan{ anchorCA };

    /* DER format for Anchor CA */
    uint8_t anchorCADer[Credentials::kMaxDERCertLength] = { 0 };
    MutableByteSpan anchorCADerSpan{ anchorCADer };

    /* CHIPCert format for cross-signed ICAC */
    uint8_t icac[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan icacSpan{ icac };

    /* DER format for cross-signed ICAC */
    uint8_t icacDer[Credentials::kMaxDERCertLength] = { 0 };
    MutableByteSpan icacDerSpan{ icacDer };

    /* required for extracting the NOC Fabric ID */
    uint8_t JFNoc[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan JFNocSpan{ JFNoc };
    uint8_t JFNocDer[Credentials::kMaxDERCertLength] = { 0 };
    MutableByteSpan JFNocDerSpan{ JFNocDer };
    ChipDN JFNocDn;
    uint64_t dnFabricIDJFNoc;
    std::string fabricIDString;

    /* initialize JFC storage */
    chipToolKvs = JointFabricDeviceOptions::GetInstance().chipToolKvs;
    err         = mControllerJFPKIStorage.Init("beta", chipToolKvs ? chipToolKvs : "/tmp/");
    SuccessOrExit(err);

    /* extract RCAC */
    err = mServer->GetFabricTable().FetchRootCert(mJointFabricIndex, anchorCASpan);
    SuccessOrExit(err);

    err = ConvertChipCertToX509Cert(anchorCASpan, anchorCADerSpan);
    SuccessOrExit(err);

    /* extract ICAC */
    err = mServer->GetFabricTable().FetchICACert(mJointFabricIndex, icacSpan);
    SuccessOrExit(err);

    err = ConvertChipCertToX509Cert(icacSpan, icacDerSpan);
    SuccessOrExit(err);

    /* write Anchor CA in JFC storage */
    err = mControllerJFPKIStorage.SyncSetKeyValue(kOperationalCredentialsRootCertificateStorage, anchorCADerSpan.data(),
                                                  static_cast<uint16_t>(anchorCADerSpan.size()));
    SuccessOrExit(err);

    /* write cross-signed ICAC in JFC storage */
    err = mControllerJFPKIStorage.SyncSetKeyValue(kOperationalCredentialsIntermediateCertificateStorage, icacDerSpan.data(),
                                                  static_cast<uint16_t>(icacDerSpan.size()));
    SuccessOrExit(err);

    /* write public-private key pair of the cross-signed ICAC in JFC storage */
    err = mControllerPKI->SyncGetKeyValue(kOperationalCredentialsIntermediateIssuerKeypairStorage, serializedICACKey.Bytes(),
                                          ICACKeySize);
    serializedICACKey.SetLength(ICACKeySize);
    SuccessOrExit(err);

    err = mControllerJFPKIStorage.SyncSetKeyValue(kOperationalCredentialsIntermediateIssuerKeypairStorage,
                                                  serializedICACKey.Bytes(), ICACKeySize);

    /* extract JF NOC: needed for Matter Operational Certificate DN attribute for fabric identifier */
    err = mServer->GetFabricTable().FetchNOCCert(mJointFabricIndex, JFNocSpan);
    SuccessOrExit(err);

    err = ConvertChipCertToX509Cert(JFNocSpan, JFNocDerSpan);
    SuccessOrExit(err);

    JFNocDn = ChipDN{};
    err     = ExtractSubjectDNFromX509Cert(JFNocDerSpan, JFNocDn);
    SuccessOrExit(err);

    err = JFNocDn.GetCertFabricId(dnFabricIDJFNoc);
    SuccessOrExit(err);

    /* save FabricID that needs to be used inside the NOCs generated by JFC */
    fabricIDString = std::to_string(dnFabricIDJFNoc);
    err =
        mControllerJFPKIStorage.SyncSetKeyValue(kJFFabricID, fabricIDString.c_str(), static_cast<uint16_t>(fabricIDString.size()));
    SuccessOrExit(err);

    /* save the NodeID that should be used by the JF-onboarded Controller */
    err = mControllerJFPKIStorage.SetLocalNodeId(jfControllerNodeId);
    SuccessOrExit(err);

exit:
    return err;
}

void JFAdminAppManager::OnConnectionFailure(void * context, const ScopedNodeId & peerId, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogError(Test, "Failed to establish connection to 0x" ChipLogFormatX64 " on fabric index %d",
                 ChipLogValueX64(peerId.GetNodeId()), peerId.GetFabricIndex());

    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnReadSuccessResponse(void * context,
                                              const BasicInformation::Attributes::NodeLabel::TypeInfo::DecodableType nodeLabel)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    size_t sizeToCopy               = 0;

    VerifyOrDie(jfAdminCore != nullptr);

    memset(jfAdminCore->friendlyNameBuffer, 0, sizeof(jfAdminCore->friendlyNameBuffer));

    sizeToCopy =
        (nodeLabel.size() > sizeof(jfAdminCore->friendlyNameBuffer)) ? sizeof(jfAdminCore->friendlyNameBuffer) : nodeLabel.size();
    memcpy(jfAdminCore->friendlyNameBuffer, nodeLabel.data(), sizeToCopy);
    jfAdminCore->friendlyNameCharSpan = CharSpan(jfAdminCore->friendlyNameBuffer, sizeToCopy);

    jfAdminCore->DisconnectFromNode();
    jfAdminCore->ConnectToNode(jfAdminCore->mAnchorAdminScopedNodeId, kSendAddPendingNode);
}

void JFAdminAppManager::OnReadFailureResponse(void * context, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogError(Test, "OnReadFailureResponse!");

    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnAddPendingNodeResponse(void * context, const chip::app::DataModel::NullObjectType &)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogProgress(Test, "OnAddPendingNodeResponse!");

    /* disconnect from the Anchor Administrator */
    jfAdminCore->DisconnectFromNode();

    /* start device onboarding into JF */
    jfAdminCore->ConnectToNode(jfAdminCore->mPendingScopedNodeId, kReissueOperationalIdentity);
}

void JFAdminAppManager::OnAddPendingNodeFailure(void * context, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogError(Test, "OnAddPendingNodeFailure!");

    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnArmFailSafeTimerResponse(
    void * context, const app::Clusters::GeneralCommissioning::Commands::ArmFailSafeResponse::DecodableType & data)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogProgress(Test, "OnArmFailSafeTimerResponse, errorCode=%u", to_underlying(data.errorCode));

    jfAdminCore->SendCSRRequest();
}

void JFAdminAppManager::OnArmFailSafeTimerFailure(void * context, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogError(Test, "OnArmFailSafeTimerFailure!");
    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnOperationalCertificateSigningRequest(
    void * context, const OperationalCredentials::Commands::CSRResponse::DecodableType & data)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    uint8_t icac[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan ICACSpan{ icac };

    uint8_t ownJFNoc[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan ownJFNocSpan{ ownJFNoc };
    uint8_t ownJFNocDer[Credentials::kMaxDERCertLength] = { 0 };
    MutableByteSpan ownJFNocDerSpan{ ownJFNocDer };
    ChipDN ownJFNocDn;
    uint64_t dnFabricIDJFNoc;

    uint8_t icacDer[Credentials::kMaxDERCertLength] = { 0 };
    MutableByteSpan ICACDerSpan{ icacDer };

    uint8_t noc[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan nocSpan{ noc };

    uint8_t nocDer[Credentials::kMaxDERCertLength] = { 0 };
    MutableByteSpan nocDerSpan{ nocDer };

    TLVReader reader;
    TLVType containerType;

    ByteSpan csrSpan;

    ChipLogProgress(Test, "OnOperationalCertificateSigningRequest!");

    /* extract CSR from the CSRResponse */
    reader.Init(data.NOCSRElements);
    if (reader.GetType() == kTLVType_NotSpecified)
    {
        err = reader.Next();
        SuccessOrExit(err);
    }
    err = reader.Expect(kTLVType_Structure, AnonymousTag());
    SuccessOrExit(err);

    err = reader.EnterContainer(containerType);
    SuccessOrExit(err);

    err = reader.Next(kTLVType_ByteString, TLV::ContextTag(1));
    SuccessOrExit(err);

    csrSpan = Span(reader.GetReadPoint(), reader.GetLength());
    reader.ExitContainer(containerType);

    /* extract ICAC */
    err = jfAdminCore->mServer->GetFabricTable().FetchICACert(jfAdminCore->mJointFabricIndex, ICACSpan);
    SuccessOrExit(err);

    /* extract JF NOC: needed for Matter Operational Certificate DN attribute for fabric identifier */
    err = jfAdminCore->mServer->GetFabricTable().FetchNOCCert(jfAdminCore->mJointFabricIndex, ownJFNocSpan);
    SuccessOrExit(err);

    err = ConvertChipCertToX509Cert(ownJFNocSpan, ownJFNocDerSpan);
    SuccessOrExit(err);

    ownJFNocDn = ChipDN{};
    err        = ExtractSubjectDNFromX509Cert(ownJFNocDerSpan, ownJFNocDn);
    SuccessOrExit(err);

    err = ownJFNocDn.GetCertFabricId(dnFabricIDJFNoc);
    SuccessOrExit(err);

    jfAdminCore->mOpCredentials->SetNodeIdForNextNOCRequest(jfAdminCore->mPendingScopedNodeId.GetNodeId());
    jfAdminCore->mOpCredentials->SetFabricIdForNextNOCRequest(dnFabricIDJFNoc);

    err = ConvertChipCertToX509Cert(ICACSpan, ICACDerSpan);
    SuccessOrExit(err);

    err = jfAdminCore->mOpCredentials->SignNOC(ICACDerSpan, csrSpan, nocDerSpan);
    SuccessOrExit(err);

    err = ConvertX509CertToChipCert(nocDerSpan, nocSpan);
    SuccessOrExit(err);

    CopySpanToMutableSpan(nocSpan, jfAdminCore->mPendingNOCSpan);

exit:
    if (CHIP_NO_ERROR == err)
    {
        jfAdminCore->SendAddTrustedRootCertificate();
    }
    else
    {
        ChipLogError(Test, "Error during OnOperationalCertificateSigningRequest");
        jfAdminCore->DisconnectFromNode();
        jfAdminCore->TriggerJFOnboardingForNextNode();
    }
}

void JFAdminAppManager::OnCSRFailureResponse(void * context, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogProgress(Test, "OnCSRFailureResponse!");
    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnRootCertSuccessResponse(void * context, const chip::app::DataModel::NullObjectType &)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogProgress(Test, "OnRootCertSuccessResponse!");

    jfAdminCore->SendAddNOC();
}

void JFAdminAppManager::OnRootCertFailureResponse(void * context, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogError(Test, "OnRootCertFailureResponse!");
    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnOperationalCertificateAddResponse(
    void * context, const OperationalCredentials::Commands::NOCResponse::DecodableType & data)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    err = ConvertFromOperationalCertStatus(data.statusCode);

    ChipLogProgress(Test, "OnOperationalCertificateAddResponse: %s!", ErrorStr(err));

    jfAdminCore->DisconnectFromNode();

    if (CHIP_NO_ERROR == err)
    {
        /* switch to JF fabric from now: Commissioning Complete requests/response commands */
        jfAdminCore->mPendingScopedNodeId =
            ScopedNodeId(jfAdminCore->mPendingScopedNodeId.GetNodeId(), jfAdminCore->mJointFabricIndex);
        jfAdminCore->ConnectToNode(jfAdminCore->mPendingScopedNodeId, kSendCommissioningComplete);
    }
    else
    {
        jfAdminCore->TriggerJFOnboardingForNextNode();
    }
}

void JFAdminAppManager::OnAddNOCFailureResponse(void * context, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogError(Test, "OnAddNOCFailureResponse!");
    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnCommissioningCompleteResponse(
    void * context, const GeneralCommissioning::Commands::CommissioningCompleteResponse::DecodableType & data)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);
    jfAdminCore->DisconnectFromNode();

    ChipLogProgress(Test, "OnCommissioningCompleteResponse, Code=%u", to_underlying(data.errorCode));

    /* CommissioningCompleteResponse has errors, proceed with JF onboarding another node */
    if (data.errorCode != GeneralCommissioning::CommissioningErrorEnum::kOk)
    {
        jfAdminCore->TriggerJFOnboardingForNextNode();
    }
    else
    {
        // jfAdminCore->ConnectToNode(jfAdminCore->mAnchorAdminScopedNodeId, kSendRefreshNode);
        /* node is marked as kCommitted on JFA, remove it from the local Datastore */
        jfAdminCore->mJointFabricDatastorage->RemoveNode(jfAdminCore->mPendingScopedNodeId.GetNodeId());
        jfAdminCore->TriggerJFOnboardingForNextNode();
    }
}

void JFAdminAppManager::OnCommissioningCompleteFailure(void * context, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogError(Test, "Received failure response %s\n", chip::ErrorStr(error));
    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnRefreshNodeResponse(void * context, const chip::app::DataModel::NullObjectType &)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogProgress(Test, "OnRefreshNodeResponse!");

    /* node is marked as kCommitted on JFA, remove it from the local Datastore */
    jfAdminCore->mJointFabricDatastorage->RemoveNode(jfAdminCore->mPendingScopedNodeId.GetNodeId());

    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

void JFAdminAppManager::OnRefreshFailure(void * context, CHIP_ERROR error)
{
    JFAdminAppManager * jfAdminCore = static_cast<JFAdminAppManager *>(context);
    VerifyOrDie(jfAdminCore != nullptr);

    ChipLogError(Test, "OnRefreshNodeFailure!");
    jfAdminCore->DisconnectFromNode();
    jfAdminCore->TriggerJFOnboardingForNextNode();
}

CHIP_ERROR JFAdminAppManager::ConvertFromOperationalCertStatus(OperationalCredentials::NodeOperationalCertStatusEnum err)
{
    using OperationalCredentials::NodeOperationalCertStatusEnum;
    switch (err)
    {
    case NodeOperationalCertStatusEnum::kOk:
        return CHIP_NO_ERROR;
    case NodeOperationalCertStatusEnum::kInvalidPublicKey:
        return CHIP_ERROR_INVALID_PUBLIC_KEY;
    case NodeOperationalCertStatusEnum::kInvalidNodeOpId:
        return CHIP_ERROR_WRONG_NODE_ID;
    case NodeOperationalCertStatusEnum::kInvalidNOC:
        return CHIP_ERROR_UNSUPPORTED_CERT_FORMAT;
    case NodeOperationalCertStatusEnum::kMissingCsr:
        return CHIP_ERROR_INCORRECT_STATE;
    case NodeOperationalCertStatusEnum::kTableFull:
        return CHIP_ERROR_NO_MEMORY;
    case NodeOperationalCertStatusEnum::kInvalidAdminSubject:
        return CHIP_ERROR_INVALID_ADMIN_SUBJECT;
    case NodeOperationalCertStatusEnum::kFabricConflict:
        return CHIP_ERROR_FABRIC_EXISTS;
    case NodeOperationalCertStatusEnum::kLabelConflict:
        return CHIP_ERROR_INVALID_ARGUMENT;
    case NodeOperationalCertStatusEnum::kInvalidFabricIndex:
        return CHIP_ERROR_INVALID_FABRIC_INDEX;
    case NodeOperationalCertStatusEnum::kUnknownEnumValue:
        // Is this a reasonable value?
        return CHIP_ERROR_CERT_LOAD_FAILED;
    }

    return CHIP_ERROR_CERT_LOAD_FAILED;
}
