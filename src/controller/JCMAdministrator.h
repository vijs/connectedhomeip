/*
 *
 *    Copyright (c) 2021-2024 Project CHIP Authors
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

#include <app/ClusterStateCache.h>
#include <app/DeviceProxy.h>
#include <app/ReadClient.h>
#include <lib/core/CHIPCallback.h>
#include <lib/core/CHIPError.h>
#if CONFIG_DEVICE_LAYER
#include <platform/CHIPDeviceLayer.h>
#endif
namespace chip {

namespace Controller {

enum class JCMAdministratorCompletionResult : uint16_t
{
    kSuccess = 0,

    kNotAnAdministrator = 100,
    // TODO: Add more JCM trust verification errors

    kNoMemory = 700,

    kInvalidArgument = 800,

    kInternalError = 900,

    kNotImplemented = 0xFFFFU,
};

struct JCMAdministratorCompletionError
{
    JCMAdministratorCompletionError(JCMAdministratorCompletionResult result) : mResult(result) {}
    JCMAdministratorCompletionResult mResult;
};

enum JCMAdministratorStage : uint8_t
{
    kIdle,
    kStarted,
    kPerformingVendorIDVerificationProcedure,
    kSendingICACSRRequest,
    kProcessingICACCSRResponse,
    kSendingAddICACRequest,
    kProcessingAddICACResponse,
    kCompleteCommissioning,
};

typedef void (*JCMAdministratorCompleteCallback)(void * context, JCMAdministratorCompletionResult result);

class JCMAdministrator
{
public:
    JCMAdministrator();
    ~JCMAdministrator() {};
    CHIP_ERROR Start(DeviceProxy * device, chip::Callback::Callback<JCMAdministratorCompleteCallback> * callback);

private:
    // Move to next JCM administrator step
    void AdvanceStage(JCMAdministatorCompletionResult result);

    // JCM administrator steps
    void PerformVendorIDVerificationProcedure();
    void SendICACSRRequest();
    void ProcessICACCSRResponse();
    void SendAddICACRequest();
    void ProcessAddICACResponse();

    chip::Callback::Callback<JCMAdministratorCompleteCallback> * mJCMAdministratorCompleteCallback;
    JCMAdministratorStage mNextStage = JCMAdministratorStage::kIdle;
    DeviceProxy * mDeviceProxy       = nullptr;
};

} // namespace Controller
} // namespace chip
