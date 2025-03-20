/**
 *
 *    Copyright (c) 2024 Project CHIP Authors
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

#include <app-common/zap-generated/cluster-objects.h>
#include <app/ReadClient.h>
#include <controller/OperationalCredentialsDelegate.h>
#include <lib/core/DataModelTypes.h>
#include <lib/support/CHIPMem.h>

typedef CHIP_ERROR (*prepareCredentialsIssuerCallbackType)(void);

void SetPrepareCredentialsIssuerCallback(prepareCredentialsIssuerCallbackType prepareCredentialsIssuerCallback);
void SetOperationalCredentialsIssuer(chip::Controller::OperationalCredentialsDelegate * provider);

class JointFabricAdministratorServer : public chip::app::ReadClient::Callback
{
public:
    static JointFabricAdministratorServer & GetInstance(void);

    void ReadJointFabricInfo(chip::Messaging::ExchangeManager & exchangeMgr, const chip::SessionHandle & sessionHandle);

    // ReadClient::Callback functions
    void OnAttributeData(const chip::app::ConcreteDataAttributePath & aPath, chip::TLV::TLVReader * apData,
                         const chip::app::StatusIB & aStatus);
    void OnDone(chip::app::ReadClient * apReadClient) override;

private:
    JointFabricAdministratorServer() {}

    struct JointFabricReadInfo
    {
        JointFabricReadInfo(chip::app::InteractionModelEngine * apImEngine, chip::Messaging::ExchangeManager * apExchangeMgr,
                            chip::app::ReadClient::Callback & apCallback, chip::app::ReadClient::InteractionType aInteractionType) :
            readClient(apImEngine, apExchangeMgr, apCallback, aInteractionType)
        {}
        chip::app::Clusters::JointFabricAdministrator::Attributes::AdministratorFabricIndex::TypeInfo::DecodableType
            administratorFabricIndex;
        chip::app::Clusters::Descriptor::Attributes::PartsList::TypeInfo::DecodableType partsList;
        chip::app::ReadClient readClient;
    };

    chip::Platform::UniquePtr<JointFabricReadInfo> mJointFabricReadInfo;

    static JointFabricAdministratorServer sJointFabricAdministratorServerInstance;
};
