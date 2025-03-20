/*
 *
 *    Copyright (c) 2025 Project CHIP Authors
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

/****************************************************************************
 * @file
 * @brief Implementation for the Joint Fabric Administrator Cluster
 ***************************************************************************/

#include "joint-fabric-administrator-server.h"

#include <access/AccessControl.h>
#include <app-common/zap-generated/attributes/Accessors.h>
#include <app-common/zap-generated/ids/Attributes.h>
#include <app/AttributeAccessInterface.h>
#include <app/AttributeAccessInterfaceRegistry.h>
#include <app/CommandHandler.h>
#include <app/ConcreteCommandPath.h>
#include <app/EventLogging.h>
#include <app/InteractionModelEngine.h>
#include <app/ReadPrepareParams.h>
#include <app/reporting/reporting.h>
#include <app/server/Dnssd.h>
#include <app/server/Server.h>
#include <app/util/attribute-storage.h>
#include <credentials/CHIPCert.h>
#include <credentials/CertificationDeclaration.h>
#include <credentials/DeviceAttestationConstructor.h>
#include <credentials/DeviceAttestationCredsProvider.h>
#include <credentials/FabricTable.h>
#include <credentials/GroupDataProvider.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/CHIPSafeCasts.h>
#include <lib/core/PeerId.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/ScopedBuffer.h>
#include <lib/support/TestGroupData.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>
#include <platform/CommissionableDataProvider.h>
#include <string.h>
#include <tracing/macros.h>

using namespace chip;
using namespace chip::Transport;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::JointFabricAdministrator;
using namespace chip::Controller;
using namespace chip::Credentials;
using namespace chip::Crypto;
using namespace chip::Protocols::InteractionModel;

namespace JointFabricAdministratorCluster = chip::app::Clusters::JointFabricAdministrator;

extern uint64_t gCaseAdminSubject;

namespace {
prepareCredentialsIssuerCallbackType gPrepareCredentialsIssuerCallback = nullptr;
OperationalCredentialsDelegate * gCredentialsIssuer                    = nullptr;
} // namespace

void SetPrepareCredentialsIssuerCallback(prepareCredentialsIssuerCallbackType prepareCredentialsIssuerCallback)
{
    gPrepareCredentialsIssuerCallback = prepareCredentialsIssuerCallback;
}

void SetOperationalCredentialsIssuer(OperationalCredentialsDelegate * provider)
{
    gCredentialsIssuer = provider;
}

class JointFabricAdministratorAttrAccess : public AttributeAccessInterface
{
public:
    JointFabricAdministratorAttrAccess() :
        AttributeAccessInterface(Optional<EndpointId>::Missing(), JointFabricAdministratorCluster::Id)
    {}

    CHIP_ERROR Read(const ConcreteReadAttributePath & aPath, AttributeValueEncoder & aEncoder) override;
    CHIP_ERROR Write(const ConcreteDataAttributePath & aPath, AttributeValueDecoder & aDecoder) override;

    FabricIndex GetAdministratorFabricIndex() { return mAdministratorFabricIndex; }

private:
    CHIP_ERROR ReadAdministratorFabricIndex(AttributeValueEncoder & aEncoder);
    CHIP_ERROR WriteAdministratorFabricIndex(AttributeValueDecoder & aDecoder);

    FabricIndex mAdministratorFabricIndex = kUndefinedFabricId;
};

JointFabricAdministratorAttrAccess gJointFabricAdministratorAttrAccess;

CHIP_ERROR JointFabricAdministratorAttrAccess::Read(const ConcreteReadAttributePath & aPath, AttributeValueEncoder & aEncoder)
{
    VerifyOrDie(aPath.mClusterId == JointFabricAdministratorCluster::Id);

    switch (aPath.mAttributeId)
    {
    case JointFabricAdministrator::Attributes::AdministratorFabricIndex::Id: {
        return ReadAdministratorFabricIndex(aEncoder);
    }
    default:
        break;
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR JointFabricAdministratorAttrAccess::Write(const ConcreteDataAttributePath & aPath, AttributeValueDecoder & aDecoder)
{
    VerifyOrDie(aPath.mClusterId == JointFabricAdministratorCluster::Id);

    switch (aPath.mAttributeId)
    {
    case JointFabricAdministrator::Attributes::AdministratorFabricIndex::Id: {
        return WriteAdministratorFabricIndex(aDecoder);
    }
    default:
        break;
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR JointFabricAdministratorAttrAccess::ReadAdministratorFabricIndex(AttributeValueEncoder & aEncoder)
{
    return aEncoder.Encode(mAdministratorFabricIndex);
}

CHIP_ERROR JointFabricAdministratorAttrAccess::WriteAdministratorFabricIndex(AttributeValueDecoder & aDecoder)
{
    FabricIndex administratorFabricIndex = kUndefinedFabricIndex;
    ReturnErrorOnFailure(aDecoder.Decode(administratorFabricIndex));
    mAdministratorFabricIndex = administratorFabricIndex;

    ChipLogProgress(Zcl, "JointFabricAdministrator: AdministratorFabricIndex set to %d", mAdministratorFabricIndex);

    return CHIP_NO_ERROR;
}

namespace {

void SendAddICACResponse(app::CommandHandler * commandObj, const ConcreteCommandPath & path, ICACResponseStatusEnum status)
{
    Commands::ICACResponse::Type payload;
    payload.statusCode = status;
    commandObj->AddResponse(path, payload);
}

CHIP_ERROR CreateAccessControlEntryForNewFabricAdministrator(const Access::SubjectDescriptor & subjectDescriptor,
                                                             FabricIndex fabricIndex)
{
    uint64_t subject       = gCaseAdminSubject;
    NodeId subjectAsNodeID = static_cast<NodeId>(subject);

    if (!IsOperationalNodeId(subjectAsNodeID) && !IsCASEAuthTag(subjectAsNodeID))
    {
        return CHIP_ERROR_INVALID_ADMIN_SUBJECT;
    }

    Access::AccessControl::Entry entry;
    ReturnErrorOnFailure(Access::GetAccessControl().PrepareEntry(entry));
    ReturnErrorOnFailure(entry.SetFabricIndex(fabricIndex));
    ReturnErrorOnFailure(entry.SetPrivilege(Access::Privilege::kAdminister));
    ReturnErrorOnFailure(entry.SetAuthMode(Access::AuthMode::kCase));
    ReturnErrorOnFailure(entry.AddSubject(nullptr, subject));
    CHIP_ERROR err = Access::GetAccessControl().CreateEntry(&subjectDescriptor, fabricIndex, nullptr, entry);

    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Zcl, "OpCreds: Failed to add administrative node ACL entry: %" CHIP_ERROR_FORMAT, err.Format());
        return err;
    }

    ChipLogProgress(Zcl, "OpCreds: ACL entry created for Fabric index 0x%x CASE Admin Subject 0x" ChipLogFormatX64,
                    static_cast<unsigned>(fabricIndex), ChipLogValueX64(subject));

    return CHIP_NO_ERROR;
}

} // namespace

void MatterJointFabricAdministratorPluginServerInitCallback()
{
    ChipLogProgress(DataManagement, "JointFabricAdministrator: initializing");
    AttributeAccessInterfaceRegistry::Instance().Register(&gJointFabricAdministratorAttrAccess);
}

bool emberAfJointFabricAdministratorClusterICACCSRRequestCallback(
    chip::app::CommandHandler * commandObj, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::JointFabricAdministrator::Commands::ICACCSRRequest::DecodableType & commandData)
{
    MATTER_TRACE_SCOPE("ICACCSRRequest", "JointFabricAdministrator");

    ChipLogProgress(Zcl, "JointFabricAdministrator: Received a ICACCSRRequest command");

    // Flush acks before really slow work
    commandObj->FlushAcksRightAwayOnSlowCommand();

    auto finalStatus = Status::Failure;
    CHIP_ERROR err   = CHIP_ERROR_INVALID_ARGUMENT;

    // TODO: Fabric Table Vendor ID Verification against AdministratorFabricIndex of Commissioner

    {
        Commands::ICACCSRResponse::Type response;

        uint8_t icaCsr[Crypto::kMAX_CSR_Buffer_Size] = { 0 };
        MutableByteSpan icaCsrSpan{ icaCsr };

        if (gPrepareCredentialsIssuerCallback == nullptr)
        {
            err = CHIP_ERROR_INTERNAL;
            VerifyOrExit(gPrepareCredentialsIssuerCallback != nullptr, finalStatus = Status::Failure);
        }
        if (gCredentialsIssuer == nullptr)
        {
            err = CHIP_ERROR_INTERNAL;
            VerifyOrExit(gCredentialsIssuer != nullptr, finalStatus = Status::Failure);
        }

        err = gPrepareCredentialsIssuerCallback();
        VerifyOrExit(err == CHIP_NO_ERROR, finalStatus = Status::Failure);

        err = gCredentialsIssuer->ObtainIcaCsr(icaCsrSpan);
        VerifyOrExit(err == CHIP_NO_ERROR && icaCsrSpan.size() > 0, finalStatus = Status::Failure);

        response.icaccsr = icaCsrSpan;

        ChipLogProgress(Zcl, "JointFabricAdministrator: ICACCSRRequest successful.");
        finalStatus = Status::Success;
        commandObj->AddResponse(commandPath, response);
    }

exit:
    if (finalStatus != Status::Success)
    {
        commandObj->AddStatus(commandPath, finalStatus);
        ChipLogError(Zcl,
                     "JointFabricAdministrator: Failed ICACCSRRequest request with IM error 0x%02x (err = %" CHIP_ERROR_FORMAT ")",
                     to_underlying(finalStatus), err.Format());
    }

    return true;
}

bool emberAfJointFabricAdministratorClusterAddICACCallback(
    chip::app::CommandHandler * commandObj, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::JointFabricAdministrator::Commands::AddICAC::DecodableType & commandData)
{
    MATTER_TRACE_SCOPE("AddICAC", "JointFabricAdministrator");
    auto & ICACValue = commandData.ICACValue;

    NodeId nodeId;
    FabricId fabricId;
    VendorId adminVendorId = VendorId::NotSpecified;

    auto addICACResponse     = ICACResponseStatusEnum::kOk;
    auto nonDefaultStatus    = Status::Success;
    auto * groupDataProvider = Credentials::GetGroupDataProvider();
    CHIP_ERROR err           = CHIP_NO_ERROR;
    FabricIndex fabricIndex  = 0;
    Credentials::GroupDataProvider::KeySet keyset;

    const FabricInfo * newFabricInfo = nullptr;
    auto & fabricTable               = Server::GetInstance().GetFabricTable();
    auto & failSafeContext           = Server::GetInstance().GetFailSafeContext();

    uint8_t compressed_fabric_id_buffer[sizeof(uint64_t)];
    MutableByteSpan compressed_fabric_id(compressed_fabric_id_buffer);

    ChipLogProgress(Zcl, "JointFabricAdministrator: Received a AddICAC command");

    VerifyOrExit(ICACValue.size() <= Credentials::kMaxCHIPCertLength, nonDefaultStatus = Status::InvalidCommand);

    // Flush acks before really slow work
    commandObj->FlushAcksRightAwayOnSlowCommand();

    {
        // TODO: Remove this, maybe accept IPK via this command
        ByteSpan defaultIpkSpan = chip::GroupTesting::DefaultIpkValue::GetDefaultIpk();

        uint8_t nocCsr[Crypto::kMAX_CSR_Buffer_Size] = { 0 };
        MutableByteSpan nocCsrSpan{ nocCsr };

        uint8_t nocBuf[Credentials::kMaxDERCertLength] = { 0 };
        MutableByteSpan nocSpan{ nocBuf };

        uint8_t nocChipBuf[Credentials::kMaxCHIPCertLength] = { 0 };
        MutableByteSpan nocChipSpan{ nocChipBuf };

        uint8_t administratorNocChipBuf[Credentials::kMaxCHIPCertLength] = { 0 };
        MutableByteSpan administratorNocChipSpan{ administratorNocChipBuf };

        uint8_t previousNocChipBuf[Credentials::kMaxCHIPCertLength] = { 0 };
        MutableByteSpan previousNocChipSpan{ previousNocChipBuf };

        uint8_t icaDerCert[Credentials::kMaxDERCertLength] = { 0 };
        MutableByteSpan icaDerCertSpan{ icaDerCert };

        uint8_t rootChipBuf[Credentials::kMaxCHIPCertLength] = { 0 };
        MutableByteSpan rootChipSpan{ rootChipBuf };

        err = fabricTable.FetchRootCert(commandObj->GetAccessingFabricIndex(), rootChipSpan);
        VerifyOrExit(err == CHIP_NO_ERROR && rootChipSpan.size() > 0, nonDefaultStatus = Status::Failure);

        err = fabricTable.FetchNOCCert(gJointFabricAdministratorAttrAccess.GetAdministratorFabricIndex(), administratorNocChipSpan);
        VerifyOrExit(err == CHIP_NO_ERROR && administratorNocChipSpan.size() > 0, nonDefaultStatus = Status::Failure);

        err = fabricTable.FetchNOCCert(commandObj->GetAccessingFabricIndex(), previousNocChipSpan);
        VerifyOrExit(err == CHIP_NO_ERROR && previousNocChipSpan.size() > 0, nonDefaultStatus = Status::Failure);

        newFabricInfo = fabricTable.FindFabricWithIndex(commandObj->GetAccessingFabricIndex());
        VerifyOrExit(newFabricInfo != nullptr, nonDefaultStatus = Status::Failure);

        adminVendorId = newFabricInfo->GetVendorId();
        VerifyOrExit(adminVendorId != VendorId::NotSpecified, nonDefaultStatus = Status::Failure);

        fabricTable.RevertPendingFabricData();

        failSafeContext.SetCsrRequestForUpdateNoc(false);

        err = fabricTable.AllocatePendingOperationalKey(MakeOptional(commandObj->GetAccessingFabricIndex()), nocCsrSpan);
        VerifyOrExit(err == CHIP_NO_ERROR && nocCsrSpan.size() > 0, nonDefaultStatus = Status::Failure);

        err = fabricTable.AddNewPendingTrustedRootCert(rootChipSpan);
        VerifyOrExit(err != CHIP_ERROR_NO_MEMORY, nonDefaultStatus = Status::ResourceExhausted);

        failSafeContext.SetAddTrustedRootCertInvoked();

        if (gCredentialsIssuer == nullptr)
        {
            err = CHIP_ERROR_INTERNAL;
            VerifyOrExit(gCredentialsIssuer != nullptr, nonDefaultStatus = Status::Failure);
        }

        CATValues cats = kUndefinedCATs;
        err            = ExtractCATsFromOpCert(administratorNocChipSpan, cats);
        VerifyOrExit(err == CHIP_NO_ERROR, nonDefaultStatus = Status::Failure);
        err = ExtractNodeIdFabricIdFromOpCert(previousNocChipSpan, &nodeId, &fabricId);
        VerifyOrExit(err == CHIP_NO_ERROR, nonDefaultStatus = Status::Failure);

        ChipLogProgress(Zcl, "JointFabricAdministrator: Node Id for Next NOC Request: 0x" ChipLogFormatX64,
                        ChipLogValueX64(nodeId));
        ChipLogProgress(Zcl, "JointFabricAdministrator: Fabric Id for Next NOC Request: 0x" ChipLogFormatX64,
                        ChipLogValueX64(fabricId));

        gCredentialsIssuer->SetNodeIdForNextNOCRequest(nodeId);
        gCredentialsIssuer->SetFabricIdForNextNOCRequest(fabricId);
        gCredentialsIssuer->SetCATValuesForNextNOCRequest(cats);

        err = ConvertChipCertToX509Cert(ICACValue, icaDerCertSpan);
        VerifyOrExit(err == CHIP_NO_ERROR && icaDerCertSpan.size() > 0, nonDefaultStatus = Status::Failure);

        err = gCredentialsIssuer->SignNOC(icaDerCertSpan, nocCsrSpan, nocSpan);
        VerifyOrExit(err == CHIP_NO_ERROR && nocSpan.size() > 0, nonDefaultStatus = Status::Failure);

        err = ConvertX509CertToChipCert(nocSpan, nocChipSpan);
        VerifyOrExit(err == CHIP_NO_ERROR && nocChipSpan.size() > 0, nonDefaultStatus = Status::Failure);

        err = fabricTable.AddNewPendingFabricWithOperationalKeystore(nocChipSpan, ICACValue, adminVendorId, &fabricIndex);
        VerifyOrExit(err == CHIP_NO_ERROR, addICACResponse = ICACResponseStatusEnum::kInvalidICAC);

        newFabricInfo = fabricTable.FindFabricWithIndex(fabricIndex);
        VerifyOrExit(newFabricInfo != nullptr, nonDefaultStatus = Status::Failure);

        // Set the Identity Protection Key (IPK)
        // The IPK SHALL be the operational group key under GroupKeySetID of 0
        keyset.keyset_id                = Credentials::GroupDataProvider::kIdentityProtectionKeySetId;
        keyset.policy                   = GroupKeyManagement::GroupKeySecurityPolicyEnum::kTrustFirst;
        keyset.num_keys_used            = 1;
        keyset.epoch_keys[0].start_time = 0;
        memcpy(keyset.epoch_keys[0].key, defaultIpkSpan.data(), defaultIpkSpan.size());

        err = newFabricInfo->GetCompressedFabricIdBytes(compressed_fabric_id);
        VerifyOrExit(err == CHIP_NO_ERROR, nonDefaultStatus = Status::Failure);

        err = groupDataProvider->SetKeySet(fabricIndex, compressed_fabric_id, keyset);
        VerifyOrExit(err == CHIP_NO_ERROR, addICACResponse = ICACResponseStatusEnum::kInvalidICAC);

        // Creating the initial ACL must occur after the PASE session has adopted the fabric index
        // (see above) so that the concomitant event, which is fabric scoped, is properly handled.
        err = CreateAccessControlEntryForNewFabricAdministrator(commandObj->GetSubjectDescriptor(), fabricIndex);
        VerifyOrExit(err != CHIP_ERROR_INTERNAL, nonDefaultStatus = Status::Failure);
        VerifyOrExit(err == CHIP_NO_ERROR, addICACResponse = ICACResponseStatusEnum::kInvalidICAC);

        failSafeContext.SetAddNocCommandInvoked(fabricIndex);

        ChipLogProgress(Zcl, "JointFabricAdministrator: Joint Fabric Index: %" PRIu8, fabricIndex);
    }

    // We might have a new operational identity, so we should start advertising
    // it right away.  Also, we need to withdraw our old operational identity.
    // So we need to StartServer() here.
    app::DnssdServer::Instance().StartServer();

exit:
    // We have an ICAC response
    if (nonDefaultStatus == Status::Success)
    {
        SendAddICACResponse(commandObj, commandPath, addICACResponse);
        // Failed to add ICAC
        if (addICACResponse != ICACResponseStatusEnum::kOk)
        {
            ChipLogError(Zcl, "JointFabricAdministrator: Failed AddICAC (err=%" CHIP_ERROR_FORMAT ") with JointFabric error %d",
                         err.Format(), to_underlying(addICACResponse));
        }
        // Success
        else
        {
            ChipLogProgress(Zcl, "JointFabricAdministrator: AddICAC successful.");
        }
    }
    // No ICAC response - Failed constraints
    else
    {
        commandObj->AddStatus(commandPath, nonDefaultStatus);
        ChipLogError(Zcl, "JointFabricAdministrator: Failed AddICAC request with IM error 0x%02x", to_underlying(nonDefaultStatus));
    }

    return true;
}

bool emberAfJointFabricAdministratorClusterOpenJointCommissioningWindowCallback(
    chip::app::CommandHandler * commandObj, const chip::app::ConcreteCommandPath & commandPath,
    const chip::app::Clusters::JointFabricAdministrator::Commands::OpenJointCommissioningWindow::DecodableType & commandData)
{
    MATTER_TRACE_SCOPE("OpenJointCommissioningWindow", "JointFabricAdministrator");
    auto commissioningTimeout = System::Clock::Seconds16(commandData.commissioningTimeout);
    auto & pakeVerifier       = commandData.PAKEPasscodeVerifier;
    auto & discriminator      = commandData.discriminator;
    auto & iterations         = commandData.iterations;
    auto & salt               = commandData.salt;

    Optional<AdministratorCommissioning::StatusCode> status = Optional<AdministratorCommissioning::StatusCode>::Missing();
    Status globalStatus                                     = Status::Success;
    Spake2pVerifier verifier;

    ChipLogProgress(Zcl, "Received command to open joint commissioning window");

    FabricIndex fabricIndex       = commandObj->GetAccessingFabricIndex();
    const FabricInfo * fabricInfo = Server::GetInstance().GetFabricTable().FindFabricWithIndex(fabricIndex);
    auto & failSafeContext        = Server::GetInstance().GetFailSafeContext();
    auto & commissionMgr          = Server::GetInstance().GetCommissioningWindowManager();

    VerifyOrExit(fabricInfo != nullptr, status.Emplace(AdministratorCommissioning::StatusCode::kPAKEParameterError));
    VerifyOrExit(failSafeContext.IsFailSafeFullyDisarmed(), status.Emplace(AdministratorCommissioning::StatusCode::kBusy));

    VerifyOrExit(!commissionMgr.IsCommissioningWindowOpen(), status.Emplace(AdministratorCommissioning::StatusCode::kBusy));
    VerifyOrExit(iterations >= kSpake2p_Min_PBKDF_Iterations,
                 status.Emplace(AdministratorCommissioning::StatusCode::kPAKEParameterError));
    VerifyOrExit(iterations <= kSpake2p_Max_PBKDF_Iterations,
                 status.Emplace(AdministratorCommissioning::StatusCode::kPAKEParameterError));
    VerifyOrExit(salt.size() >= kSpake2p_Min_PBKDF_Salt_Length,
                 status.Emplace(AdministratorCommissioning::StatusCode::kPAKEParameterError));
    VerifyOrExit(salt.size() <= kSpake2p_Max_PBKDF_Salt_Length,
                 status.Emplace(AdministratorCommissioning::StatusCode::kPAKEParameterError));
    VerifyOrExit(commissioningTimeout <= commissionMgr.MaxCommissioningTimeout(), globalStatus = Status::InvalidCommand);
    VerifyOrExit(commissioningTimeout >= commissionMgr.MinCommissioningTimeout(), globalStatus = Status::InvalidCommand);
    VerifyOrExit(discriminator <= kMaxDiscriminatorValue, globalStatus = Status::InvalidCommand);

    VerifyOrExit(verifier.Deserialize(pakeVerifier) == CHIP_NO_ERROR,
                 status.Emplace(AdministratorCommissioning::StatusCode::kPAKEParameterError));
    VerifyOrExit(commissionMgr.OpenJointCommissioningWindow(commissioningTimeout, discriminator, verifier, iterations, salt,
                                                            fabricIndex, fabricInfo->GetVendorId()) == CHIP_NO_ERROR,
                 status.Emplace(AdministratorCommissioning::StatusCode::kPAKEParameterError));
    ChipLogProgress(Zcl, "Commissioning window is now open");

exit:
    if (status.HasValue())
    {
        ChipLogError(Zcl, "Failed to open joint commissioning window. Cluster status 0x%02x", to_underlying(status.Value()));
        commandObj->AddClusterSpecificFailure(commandPath, to_underlying(status.Value()));
    }
    else
    {
        if (globalStatus != Status::Success)
        {
            ChipLogError(Zcl, "Failed to open joint commissioning window. Global status " ChipLogFormatIMStatus,
                         ChipLogValueIMStatus(globalStatus));
        }
        commandObj->AddStatus(commandPath, globalStatus);
    }

    return true;
}

// TODO
bool emberAfJointFabricAdministratorClusterTransferAnchorRequestCallback(
    chip::app::CommandHandler *, chip::app::ConcreteCommandPath const &,
    chip::app::Clusters::JointFabricAdministrator::Commands::TransferAnchorRequest::DecodableType const &)
{
    return true;
}

// TODO
bool emberAfJointFabricAdministratorClusterTransferAnchorCompleteCallback(
    chip::app::CommandHandler *, chip::app::ConcreteCommandPath const &,
    chip::app::Clusters::JointFabricAdministrator::Commands::TransferAnchorComplete::DecodableType const &)
{
    return true;
}

JointFabricAdministratorServer JointFabricAdministratorServer::sJointFabricAdministratorServerInstance;

JointFabricAdministratorServer & JointFabricAdministratorServer::GetInstance()
{
    return sJointFabricAdministratorServerInstance;
}

void JointFabricAdministratorServer::ReadJointFabricInfo(Messaging::ExchangeManager & exchangeMgr,
                                                         const SessionHandle & sessionHandle)
{
    AttributePathParams readPaths[5];
    readPaths[0] = AttributePathParams(kRootEndpointId, Descriptor::Id, Descriptor::Attributes::DeviceTypeList::Id);
    readPaths[1] = AttributePathParams(kRootEndpointId, Descriptor::Id, Descriptor::Attributes::ServerList::Id);
    readPaths[2] = AttributePathParams(kRootEndpointId, Descriptor::Id, Descriptor::Attributes::ClientList::Id);
    readPaths[3] = AttributePathParams(kRootEndpointId, Descriptor::Id, Descriptor::Attributes::PartsList::Id);
    // all endpoints
    readPaths[4] =
        AttributePathParams(JointFabricAdministrator::Id, JointFabricAdministrator::Attributes::AdministratorFabricIndex::Id);

    InteractionModelEngine * engine = InteractionModelEngine::GetInstance();
    ReadPrepareParams readParams(sessionHandle);
    readParams.mpAttributePathParamsList    = readPaths;
    readParams.mAttributePathParamsListSize = 5;

    auto readInfo = Platform::MakeUnique<JointFabricReadInfo>(engine, &exchangeMgr, *this, ReadClient::InteractionType::Read);
    VerifyOrReturn(readInfo != nullptr);

    CHIP_ERROR err = readInfo->readClient.SendRequest(readParams);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Zcl, "Failed to read Joint Fabric Info");
        return;
    }
    mJointFabricReadInfo = std::move(readInfo);
}

void JointFabricAdministratorServer::OnAttributeData(const ConcreteDataAttributePath & aPath, TLV::TLVReader * apData,
                                                     const StatusIB & aStatus)
{
    VerifyOrReturn((aPath.mClusterId == Descriptor::Id || aPath.mClusterId == JointFabricAdministrator::Id) &&
                   !aStatus.IsFailure());

    switch (aPath.mAttributeId)
    {
    case Descriptor::Attributes::PartsList::Id:
        if (DataModel::Decode(*apData, mJointFabricReadInfo->partsList) != CHIP_NO_ERROR)
        {
            ChipLogError(Zcl, "Failed to read Joint Fabric Info: PartsList");
        }
        break;
    case JointFabricAdministrator::Attributes::AdministratorFabricIndex::Id:
        if (DataModel::Decode(*apData, mJointFabricReadInfo->administratorFabricIndex) != CHIP_NO_ERROR)
        {
            ChipLogError(Zcl, "Failed to read Joint Fabric Info: AdministratorFabricIndex");
        }
        break;
    default:
        break;
    }
}

void JointFabricAdministratorServer::OnDone(ReadClient * apReadClient)
{
    FabricIndex administratorFabricIndex = mJointFabricReadInfo->administratorFabricIndex;
    mJointFabricReadInfo                 = nullptr;

    (void) administratorFabricIndex;
}
