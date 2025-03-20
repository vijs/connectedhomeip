/*
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
#include <lib/core/CHIPPersistentStorageDelegate.h>
#include <lib/core/CHIPVendorIdentifiers.hpp>
#include <lib/core/NodeId.h>
#include <vector>

namespace chip {
namespace app {

/**
 * A struct which extends the DatastoreNodeInformationEntry type with FriendlyName buffer reservation.
 */
struct GenericDatastoreNodeInformationEntry : public Clusters::JointFabricDatastore::Structs::DatastoreNodeInformationEntry::Type
{
    GenericDatastoreNodeInformationEntry(NodeId nodeId = 0, FabricIndex fabricId = 0,
                                         Clusters::JointFabricDatastore::DatastoreStateEnum state =
                                             Clusters::JointFabricDatastore::DatastoreStateEnum::kUnknownEnumValue,
                                         Optional<CharSpan> label = NullOptional)
    {
        Set(nodeId, fabricId, state, label);
    }

    GenericDatastoreNodeInformationEntry(const GenericDatastoreNodeInformationEntry & op) { *this = op; }

    GenericDatastoreNodeInformationEntry & operator=(const GenericDatastoreNodeInformationEntry & op)
    {
        Set(op.nodeID, op.fabricIndex, op.commissioningStatusEntry.state, MakeOptional(op.friendlyName));
        return *this;
    }

    void Set(NodeId nodeId, FabricIndex fabricId, Clusters::JointFabricDatastore::DatastoreStateEnum state,
             Optional<CharSpan> label = NullOptional)
    {
        SetFabricIndex(fabricId);
        this->nodeID                         = nodeId;
        this->commissioningStatusEntry.state = state;
        Set(label);
    }

    void Set(Optional<CharSpan> label = NullOptional)
    {
        if (label.HasValue())
        {
            memset(mFriendlyNameBuffer, 0, sizeof(mFriendlyNameBuffer));
            if (label.Value().size() > sizeof(mFriendlyNameBuffer))
            {
                memcpy(mFriendlyNameBuffer, label.Value().data(), sizeof(mFriendlyNameBuffer));
                this->friendlyName = CharSpan(mFriendlyNameBuffer, sizeof(mFriendlyNameBuffer));
            }
            else
            {
                memcpy(mFriendlyNameBuffer, label.Value().data(), label.Value().size());
                this->friendlyName = CharSpan(mFriendlyNameBuffer, label.Value().size());
            }
        }
        else
        {
            this->friendlyName = CharSpan();
        }
    }

private:
    static constexpr size_t kFriendlyNameMaxSize = 32u;

    char mFriendlyNameBuffer[kFriendlyNameMaxSize];
};

class JointFabricDatastorage
{
public:
    static JointFabricDatastorage & GetInstance()
    {
        static JointFabricDatastorage sInstance;
        return sInstance;
    }

    CHIP_ERROR SetAnchorNodeId(NodeId anchorNodeId)
    {
        mAnchorNodeId = anchorNodeId;
        return CHIP_NO_ERROR;
    }
    NodeId GetAnchorNodeId() { return mAnchorNodeId; }

    CHIP_ERROR SetAnchorVendorId(VendorId anchorVendorId)
    {
        mAnchorVendorId = anchorVendorId;
        return CHIP_NO_ERROR;
    }
    VendorId GetAnchorVendorId() { return mAnchorVendorId; }

    CHIP_ERROR AddPendingNode(FabricIndex fabricId, NodeId nodeId, const CharSpan & friendlyName);
    CHIP_ERROR UpdateNode(NodeId nodeId, const CharSpan & friendlyName);
    CHIP_ERROR RemoveNode(NodeId nodeId);
    CHIP_ERROR RefreshNode(NodeId nodeId);

    CHIP_ERROR SetNode(NodeId nodeId, Clusters::JointFabricDatastore::DatastoreStateEnum state);
    CHIP_ERROR RefreshGroupKeySet(NodeId nodeId);
    CHIP_ERROR RefreshACLList(NodeId nodeId);

    CHIP_ERROR AddGroupKeySetEntry(uint16_t groupKeySetId);
    CHIP_ERROR AddGroupKeySetEntry(Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type & groupKeySet);
    bool IsGroupKeySetEntryPresent(uint16_t groupKeySetId);
    CHIP_ERROR RemoveGroupKeySetEntry(uint16_t groupKeySetId);
    CHIP_ERROR UpdateGroupKeySetEntry(Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type & groupKeySet);

    CHIP_ERROR RefreshNodes(Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type & groupKeySet);

    CHIP_ERROR AddAdmin(Clusters::JointFabricDatastore::Structs::DatastoreAdministratorInformationEntry::Type & adminId);
    bool IsAdminEntryPresent(NodeId nodeId);
    CHIP_ERROR UpdateAdmin(NodeId nodeId, CharSpan friendlyName, ByteSpan icac);
    CHIP_ERROR RemoveAdmin(NodeId nodeId);

    const std::vector<Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type> & GetGroupKeySetList()
    {
        return mGroupKeySetList;
    }
    const std::vector<GenericDatastoreNodeInformationEntry> & GetNodeInformationEntries() { return mNodeInformationEntries; }
    const std::vector<Clusters::JointFabricDatastore::Structs::DatastoreAdministratorInformationEntry::Type> & GetAdminEntries()
    {
        return mAdminEntries;
    }

    /**
     * Used to notify of changes in the node list and more TODO.
     */
    class Listener
    {
    public:
        virtual ~Listener() = default;

        /**
         * Notifies of a change in the node list.
         */
        virtual void MarkNodeListChanged() = 0;

    private:
        Listener * mNext = nullptr;

        friend class JointFabricDatastorage;
    };

    /**
     * Add a listener to be notified of changes in the Joint Fabric Datastorage.
     *
     * @param [in] listener  The listener to add.
     */
    void AddListener(Listener & listener);

    /**
     * Remove a listener from being notified of changes in the Joint Fabric Datastorage
     *
     * @param [in] listener  The listener to remove.
     */
    void RemoveListener(Listener & listener);

private:
    static constexpr size_t kMaxNodes = 32;

    NodeId mAnchorNodeId     = kUndefinedNodeId;
    VendorId mAnchorVendorId = VendorId::NotSpecified;

    std::vector<GenericDatastoreNodeInformationEntry> mNodeInformationEntries;
    std::vector<Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type> mGroupKeySetList;
    std::vector<Clusters::JointFabricDatastore::Structs::DatastoreAdministratorInformationEntry::Type> mAdminEntries;

    Listener * mListeners = nullptr;

    CHIP_ERROR IsNodeIDInDatastore(NodeId nodeId, size_t & index);
};

} // namespace app
} // namespace chip
