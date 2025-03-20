/*
 *    Copyright (c) 2025 Project CHIP Authors
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

#include <lib/core/CHIPError.h>
#include <lib/core/CHIPVendorIdentifiers.hpp>
#include <lib/support/DLLUtil.h>

namespace chip {
namespace Controller {

/**
 * A delegate that can be notified of progress as a JCM Trust check proceeds.
 */
class DLL_EXPORT DeviceJCMTrustCheckDelegate
{
public:
    virtual ~DeviceJCMTrustCheckDelegate() {}

    virtual void OnJCMTrustCheckComplete(CHIP_ERROR error) {}

    virtual bool OnAskUserForConsentToOnboardVendorIdToEcosystemFabric(VendorId vendorId) { return false; }
};

} // namespace Controller
} // namespace chip
