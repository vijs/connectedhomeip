/*
 *    Copyright (c) 2022 Project CHIP Authors
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

#include "JCMAdministrator.h"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/InteractionModelEngine.h>
#include <controller/JCMAdministrator.h>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>

using namespace ::chip;
using namespace ::chip::app;
using namespace chip::app::Clusters;
using chip::app::ReadClient;

namespace chip {
namespace Controller {

JCMAdministrator::JCMAdministrator()
{
    mJCMAdministratorCompleteCallback = nullptr;
}

CHIP_ERROR JCMAdministrator::Start(DeviceProxy * proxy, chip::Callback::Callback<JCMAdministratorCompleteCallback> * callback)
{
    VerifyOrReturnError(proxy != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(callback != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    mNextStage                        = JCMAdministratorStage::kStarted;
    mJCMAdministratorCompleteCallback = callback;
    mDeviceProxy                      = proxy;

    AdvanceStage(JCMAdministratorCompletionResult::kSuccess);

    return CHIP_NO_ERROR;
}

void JCMAdministrator::PerformVendorIDVerificationProcedure()
{
    ChipLogProgress(Controller, "Performing Vendor ID Verification Procedure");

    // TODO: Implement the Vendor ID verification procedure

    AdvanceStage(JCMAdministratorCompletionResult::kSuccess);
}

void JCMAdministrator::SendICACSRRequest()
{
    MATTER_TRACE_SCOPE("SendICACSRRequest", "JCMAdministrator");
    ChipLogDetail(Controller, "Sending JointFabric request to %p device", device);
    VerifyOrReturnError(device != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    JointFabricAdministrator::Commands::ICACCSRRequest::Type request;

    ReturnErrorOnFailure(
        SendCommissioningCommand(device, request, OnICACCSRResponse, OnJointFabricFailureResponse, kRootEndpointId, timeout));
    ChipLogDetail(Controller, "Sent JointFabric request, waiting for the JointFabric Information");

    return CHIP_NO_ERROR;
}

void JCMAdministrator::OnDeviceICACSignature(void * context, CHIP_ERROR status, const ByteSpan & icac)
{
    MATTER_TRACE_SCOPE("OnDeviceICACSignature", "JCMAdministrator");
    JCMAdministrator * commissioner = static_cast<JCMAdministrator *>(context);

    ChipLogProgress(Controller, "Received callback from the CA for NOC Issuer signature. Status %s", ErrorStr(status));
    if (status == CHIP_NO_ERROR && commissioner->mState != State::Initialized)
    {
        status = CHIP_ERROR_INCORRECT_STATE;
    }
    if (status != CHIP_NO_ERROR)
    {
        ChipLogError(Controller, "Failed in signing NOC Issuer. Error %s", ErrorStr(status));
    }

    CommissioningDelegate::CommissioningReport report;
    report.Set<JointIcaCertificate>(JointIcaCertificate(icac));
    commissioner->CommissioningStageComplete(status, report);
}

void JCMAdministrator::ProcessICACCSRResponse()
{
    MATTER_TRACE_SCOPE("OnICACCSRResponse", "JCMAdministrator");
    ChipLogProgress(Controller, "Received JointFabric Information from the device");
    JCMAdministrator * commissioner = reinterpret_cast<JCMAdministrator *>(context);

    CommissioningDelegate::CommissioningReport report;
    report.Set<ICACCSRResponse>(ICACCSRResponse(data.icaccsr));
    commissioner->CommissioningStageComplete(CHIP_NO_ERROR, report);

    MATTER_TRACE_SCOPE("SignICAC", "JCMAdministrator");
    VerifyOrReturnError(mState == State::Initialized, CHIP_ERROR_INCORRECT_STATE);

    ChipLogProgress(Controller, "Joint Fabric: Signing Device's NOC Issuer");

    mOperationalCredentialsDelegate->SetNodeIdForNextNOCRequest(proxy->GetDeviceId());

    if (mFabricIndex != kUndefinedFabricIndex)
    {
        mOperationalCredentialsDelegate->SetFabricIdForNextNOCRequest(GetFabricId());
    }

    return mOperationalCredentialsDelegate->SignICAC(icaCsr, &mDeviceSignICACCallback);

    AdvanceStage(JCMAdministratorCompletionResult::kSuccess);
}

void JCMAdministrator::OnICACertFailureResponse(void * context, CHIP_ERROR error)
{
    MATTER_TRACE_SCOPE("OnICACertFailureResponse", "JCMAdministrator");
    ChipLogProgress(Controller, "Device failed to receive the ICA certificate Response: %s", chip::ErrorStr(error));
    JCMAdministrator * commissioner = static_cast<JCMAdministrator *>(context);
    commissioner->CommissioningStageComplete(error);
}

void JCMAdministrator::OnJointFabricFailureResponse(void * context, CHIP_ERROR error)
{
    MATTER_TRACE_SCOPE("OnJointFabricFailureResponse", "JCMAdministrator");
    ChipLogProgress(Controller, "Device failed to receive the Joint ICA: %s", chip::ErrorStr(error));
    JCMAdministrator * commissioner = reinterpret_cast<JCMAdministrator *>(context);
    commissioner->CommissioningStageComplete(error);
}

void JCMAdministrator::SendAddICACRequest()
{
    MATTER_TRACE_SCOPE("SendICAC", "JCMAdministrator");
    VerifyOrReturnError(device != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    ChipLogProgress(Controller, "Sending ICA certificate to the device");

    JointFabricAdministrator::Commands::AddICAC::Type request;
    request.ICACValue = icac;

    ReturnErrorOnFailure(
        SendCommissioningCommand(device, request, OnICACertSuccessResponse, OnICACertFailureResponse, kRootEndpointId, timeout));

    ChipLogProgress(Controller, "Sent ICA certificate to the device");

    return CHIP_NO_ERROR;

    AdvanceStage(JCMAdministratorCompletionResult::kSuccess);
}

void JCMAdministrator::ProcessAddICACResponse()
{
    MATTER_TRACE_SCOPE("OnICACertSuccessResponse", "JCMAdministrator");
    ChipLogProgress(Controller, "Device confirmed that it has received the ICA certificate");
    JCMAdministrator * commissioner = static_cast<JCMAdministrator *>(context);
    CHIP_ERROR err                  = CHIP_NO_ERROR;

    err = ConvertFromICACResponseStatus(data.statusCode);
    SuccessOrExit(err);

    commissioner->CommissioningStageComplete(CHIP_NO_ERROR);

exit:
    if (err != CHIP_NO_ERROR)
    {
        ChipLogProgress(Controller, "SendICAC failed with error %s", ErrorStr(err));
        commissioner->CommissioningStageComplete(err);
    }

    AdvanceStage(JCMAdministratorCompletionResult::kSuccess);
}

void JCMAdministrator::AdvanceStage(JCMAdministratorCompletionResult result)
{
    if (result != JCMAdministratorCompletionResult::kSuccess)
    {
        // Handle error
        ChipLogError(Controller, "Error in JCM Administrator Commissioning: %d", static_cast<int>(result));
        mJCMAdministratorCompleteCallback->mCall(mJCMAdministratorCompleteCallback->mContext, nullptr, result);
        return;
    }

    switch (mNextStage)
    {
    case chip::Controller::JCMAdministratorStage::kStarted:
        mNextStage = JCMAdministratorStage::kPerformingVendorIDVerificationProcedure;
        PerformVendorIDVerificationProcedure();
        break;
    case JCMAdministratorStage::kPerformingVendorIDVerificationProcedure:
        mNextStage = JCMAdministratorStage::kSendingICACSRRequest;
        SendICACSRRequest();
        break;
    case JCMAdministratorStage::kSendingICACSRRequest:
        mNextStage = JCMAdministratorStage::kProcessingICACCSRResponse;
        ProcessICACCSRResponse();
        break;
    case JCMAdministratorStage case JCMAdministratorStage::kProcessingICACCSRResponse:
        mNextStage = JCMAdministratorStage::kSendingAddICACRequest;
        SendAddICACRequest();
        break;
    case JCMAdministratorStage::kSendingAddICACRequest:
        mNextStage = JCMAdministratorStage::kProcessingAddICACResponse;
        ProcessAddICACResponse();
        break;
    case JCMAdministratorStage::kProcessingAddICACResponse:
        mNextStage = JCMAdministratorStage::kCompleteCommissioning;
        CompleteCommissioning();
        break;
    case JCMAdministratorStage::kCompleteCommissioning:
        ChipLogProgress(Controller, "Joint Commissioning Method completed successfully");
        mNextStage = JCMAdministratorStage::kIdle;
        mJCMAdministratorCompleteCallback->mCall(mJCMAdministratorCompleteCallback->mContext, result);
        break;
    default:
        ChipLogError(Controller, "Invalid state in OnDone: %d", static_cast<int>(mNextStage));
        mJCMAdministratorCompleteCallback->mCall(mJCMAdministratorCompleteCallback->mContext, nullptr,
                                                 JCMAdministratorCompletionResult::kInternalError);
        break;
    }
}

} // namespace Controller
} // namespace chip
