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

#pragma once

#include <AppMain.h>
#include <controller/ExampleOperationalCredentialsIssuer.h>
#include <controller/ExamplePersistentStorage.h>

namespace chip {

class JFAdminAppManager
{
public:
    JFAdminAppManager() : mOnConnectedCallback(OnConnected, this), mOnConnectionFailureCallback(OnConnectionFailure, this) {}

    CHIP_ERROR Init(Server & server, chip::Controller::OperationalCredentialsDelegate & opCredentialsDelegate,
                    PersistentStorage & storage);
    void HandleCommissioningCompleteEvent(chip::NodeId peerNodeId, chip::FabricIndex accessingFabricIndex);
    void HandleJointFabricCommissioningCompleteEvent(chip::NodeId peerNodeId, chip::FabricIndex accessingFabricIndex);

private:
    // Various actions to take when OnConnected callback is called
    enum OnConnectedAction
    {
        kReadNodeLabel = 0,
        kSendAddPendingNode,
        kReissueOperationalIdentity,
        kSendCommissioningComplete,
        kSendRefreshNode,
    };

    void ConnectToNode(chip::ScopedNodeId scopedNodeId, OnConnectedAction onConnectedAction);
    CHIP_ERROR ReadNodeLabel();
    CHIP_ERROR SendArmFailSafeTimer();
    CHIP_ERROR SendAddTrustedRootCertificate();
    CHIP_ERROR SendCSRRequest();
    CHIP_ERROR SendAddPendingNode();
    CHIP_ERROR SendRefreshNode();
    CHIP_ERROR SendAddNOC();
    CHIP_ERROR SendCommissioningComplete();

    void TriggerJFOnboardingForNextNode();
    void DisconnectFromNode();

    CHIP_ERROR UpdateOperationalIdentifyForController();

    static void OnConnected(void * context, Messaging::ExchangeManager & exchangeMgr, const SessionHandle & sessionHandle);
    static void OnConnectionFailure(void * context, const ScopedNodeId & peerId, CHIP_ERROR error);
    Callback::Callback<OnDeviceConnected> mOnConnectedCallback;
    Callback::Callback<OnDeviceConnectionFailure> mOnConnectionFailureCallback;

    static void
    OnReadSuccessResponse(void * context,
                          const app::Clusters::BasicInformation::Attributes::NodeLabel::TypeInfo::DecodableType nodeLabel);
    static void OnReadFailureResponse(void * context, CHIP_ERROR error);

    static void OnAddPendingNodeResponse(void * context, const chip::app::DataModel::NullObjectType &);
    static void OnAddPendingNodeFailure(void * context, CHIP_ERROR error);

    static void
    OnArmFailSafeTimerResponse(void * context,
                               const app::Clusters::GeneralCommissioning::Commands::ArmFailSafeResponse::DecodableType & data);
    static void OnArmFailSafeTimerFailure(void * context, CHIP_ERROR error);

    static void OnOperationalCertificateSigningRequest(
        void * context, const app::Clusters::OperationalCredentials::Commands::CSRResponse::DecodableType & data);
    static void OnCSRFailureResponse(void * context, CHIP_ERROR error);

    static void OnRootCertSuccessResponse(void * context, const chip::app::DataModel::NullObjectType &);
    static void OnRootCertFailureResponse(void * context, CHIP_ERROR error);

    static void OnAddNOCFailureResponse(void * context, CHIP_ERROR error);
    static void
    OnOperationalCertificateAddResponse(void * context,
                                        const app::Clusters::OperationalCredentials::Commands::NOCResponse::DecodableType & data);

    static void OnCommissioningCompleteResponse(
        void * context, const app::Clusters::GeneralCommissioning::Commands::CommissioningCompleteResponse::DecodableType & data);
    static void OnCommissioningCompleteFailure(void * context, CHIP_ERROR error);

    static void OnRefreshNodeResponse(void * context, const chip::app::DataModel::NullObjectType &);
    static void OnRefreshFailure(void * context, CHIP_ERROR error);

    static CHIP_ERROR ConvertFromOperationalCertStatus(app::Clusters::OperationalCredentials::NodeOperationalCertStatusEnum err);

    OnConnectedAction mOnConnectedAction                              = kReissueOperationalIdentity;
    Server * mServer                                                  = nullptr;
    app::JointFabricDatastorage * mJointFabricDatastorage             = nullptr;
    CASESessionManager * mCASESessionManager                          = nullptr;
    chip::Controller::OperationalCredentialsDelegate * mOpCredentials = nullptr;
    PersistentStorage * mControllerPKI                                = nullptr;

    NodeId mInitialAdminNodeId      = kUndefinedNodeId;
    FabricIndex mInitialFabricIndex = kUndefinedFabricIndex;
    FabricIndex mJointFabricIndex   = kUndefinedFabricIndex;
    VendorId mJointFabricVendorId   = NotSpecified;

    /* information about the node that receives updated NOC from JFA.
     * updated NOC chains up to the cross-signed ICAC
     */
    ScopedNodeId mPendingScopedNodeId;
    Messaging::ExchangeManager * mExchangeMgr = nullptr;
    SessionHolder mSessionHolder;

    /* friendlyName for the pendingNode */
    char friendlyNameBuffer[16] = { 0 };
    CharSpan friendlyNameCharSpan;

    /* demo: NodeID of JFA-A */
    ScopedNodeId mAnchorAdminScopedNodeId;

    uint8_t mPendingNOCBuffer[Credentials::kMaxCHIPCertLength] = { 0 };
    MutableByteSpan mPendingNOCSpan{ mPendingNOCBuffer };

    /* NOC reissuance for JFC */
    PersistentStorage mControllerJFPKIStorage;

    bool mAnchorSet = false;
};

} // namespace chip
