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
#include <AppMain.h>

#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/ConcreteAttributePath.h>
#include <app/clusters/joint-fabric-administrator-server/joint-fabric-administrator-server.h>
#include <app/server/Server.h>
#include <controller/ExampleOperationalCredentialsIssuer.h>
#include <controller/ExamplePersistentStorage.h>
#include <lib/support/logging/CHIPLogging.h>

#include <platform/DeviceInstanceInfoProvider.h>
#include <string>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::DeviceLayer;
using namespace chip::Controller;

namespace {

ExampleOperationalCredentialsIssuer gOpCredsIssuer;
PersistentStorage gControllerPKIStorage;

CHIP_ERROR OnPrepareCredentialsIssuer()
{
    const char * chipToolKvs = JointFabricDeviceOptions::GetInstance().chipToolKvs;
    ReturnErrorOnFailure(gControllerPKIStorage.Init("alpha", chipToolKvs ? chipToolKvs : "/tmp/"));
    ReturnErrorOnFailure(gOpCredsIssuer.Initialize(gControllerPKIStorage));

    return CHIP_NO_ERROR;
}

CHIP_ERROR PrepareJointFabricCluster()
{
    SetOperationalCredentialsIssuer(&gOpCredsIssuer);
    SetPrepareCredentialsIssuerCallback(OnPrepareCredentialsIssuer);
    return CHIP_NO_ERROR;
}

class ExampleDeviceInstanceInfoProvider : public DeviceInstanceInfoProvider
{
public:
    void Init(DeviceInstanceInfoProvider * defaultProvider) { mDefaultProvider = defaultProvider; }

    CHIP_ERROR GetVendorName(char * buf, size_t bufSize) override { return mDefaultProvider->GetVendorName(buf, bufSize); }
    CHIP_ERROR GetVendorId(uint16_t & vendorId) override { return mDefaultProvider->GetVendorId(vendorId); }
    CHIP_ERROR GetProductName(char * buf, size_t bufSize) override { return mDefaultProvider->GetProductName(buf, bufSize); }
    CHIP_ERROR GetProductId(uint16_t & productId) override { return mDefaultProvider->GetProductId(productId); }
    CHIP_ERROR GetPartNumber(char * buf, size_t bufSize) override { return mDefaultProvider->GetPartNumber(buf, bufSize); }
    CHIP_ERROR GetProductURL(char * buf, size_t bufSize) override { return mDefaultProvider->GetPartNumber(buf, bufSize); }
    CHIP_ERROR GetProductLabel(char * buf, size_t bufSize) override { return mDefaultProvider->GetProductLabel(buf, bufSize); }
    CHIP_ERROR GetSerialNumber(char * buf, size_t bufSize) override { return mDefaultProvider->GetSerialNumber(buf, bufSize); }
    CHIP_ERROR GetManufacturingDate(uint16_t & year, uint8_t & month, uint8_t & day) override
    {
        return mDefaultProvider->GetManufacturingDate(year, month, day);
    }
    CHIP_ERROR GetHardwareVersion(uint16_t & hardwareVersion) override
    {
        return mDefaultProvider->GetHardwareVersion(hardwareVersion);
    }
    CHIP_ERROR GetHardwareVersionString(char * buf, size_t bufSize) override
    {
        return mDefaultProvider->GetHardwareVersionString(buf, bufSize);
    }
    CHIP_ERROR GetRotatingDeviceIdUniqueId(MutableByteSpan & uniqueIdSpan) override
    {
        return mDefaultProvider->GetRotatingDeviceIdUniqueId(uniqueIdSpan);
    }
    CHIP_ERROR GetProductFinish(Clusters::BasicInformation::ProductFinishEnum * finish) override
    {
        return mDefaultProvider->GetProductFinish(finish);
    }
    CHIP_ERROR GetProductPrimaryColor(Clusters::BasicInformation::ColorEnum * primaryColor) override
    {
        return mDefaultProvider->GetProductPrimaryColor(primaryColor);
    }

    // TODO: Add new JointFabric Key to ConfigurationManager
    CHIP_ERROR GetJointFabricMode(uint8_t & jointFabricMode) override
    {
        jointFabricMode = 1;
        return CHIP_NO_ERROR;
    }

private:
    DeviceInstanceInfoProvider * mDefaultProvider;
};

JFAdminAppManager sJFAdminAppManager;

} // namespace

void MatterPostAttributeChangeCallback(const chip::app::ConcreteAttributePath & attributePath, uint8_t type, uint16_t size,
                                       uint8_t * value)
{}

void EventHandler(const DeviceLayer::ChipDeviceEvent * event, intptr_t arg)
{
    (void) arg;

    if (event->Type == DeviceLayer::DeviceEventType::kJointFabricCommissioningComplete)
    {
        sJFAdminAppManager.HandleJointFabricCommissioningCompleteEvent(event->CommissioningComplete.nodeId,
                                                                       event->CommissioningComplete.fabricIndex);
    }
    else if (event->Type == DeviceLayer::DeviceEventType::kCommissioningComplete)
    {
        sJFAdminAppManager.HandleCommissioningCompleteEvent(event->CommissioningComplete.nodeId,
                                                            event->CommissioningComplete.fabricIndex);
    }
}

ExampleDeviceInstanceInfoProvider gExampleDeviceInstanceInfoProvider;

void ApplicationInit()
{
    ChipLogProgress(Test, "ApplicationInit");

    auto * defaultProvider = GetDeviceInstanceInfoProvider();
    if (defaultProvider != &gExampleDeviceInstanceInfoProvider)
    {
        gExampleDeviceInstanceInfoProvider.Init(defaultProvider);
        SetDeviceInstanceInfoProvider(&gExampleDeviceInstanceInfoProvider);
    }

    PrepareJointFabricCluster();

    sJFAdminAppManager.Init(Server::GetInstance(), gOpCredsIssuer, gControllerPKIStorage);

    DeviceLayer::PlatformMgrImpl().AddEventHandler(EventHandler, 0);
}

void ApplicationShutdown()
{
    ChipLogProgress(Test, "ApplicationShutdown");
}

int main(int argc, char * argv[])
{
    VerifyOrDie(ChipLinuxAppInit(argc, argv, JointFabricDeviceOptions::GetOptions()) == 0);

    ChipLinuxAppMainLoop();

    return 0;
}
