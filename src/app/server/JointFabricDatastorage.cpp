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

#include <app/server/JointFabricDatastorage.h>

namespace chip {
namespace app {

void JointFabricDatastorage::AddListener(Listener & listener)
{
    if (mListeners == nullptr)
    {
        mListeners     = &listener;
        listener.mNext = nullptr;
        return;
    }

    for (Listener * l = mListeners; /**/; l = l->mNext)
    {
        if (l == &listener)
        {
            return;
        }

        if (l->mNext == nullptr)
        {
            l->mNext       = &listener;
            listener.mNext = nullptr;
            return;
        }
    }
}

void JointFabricDatastorage::RemoveListener(Listener & listener)
{
    if (mListeners == &listener)
    {
        mListeners     = listener.mNext;
        listener.mNext = nullptr;
        return;
    }

    for (Listener * l = mListeners; l != nullptr; l = l->mNext)
    {
        if (l->mNext == &listener)
        {
            l->mNext       = listener.mNext;
            listener.mNext = nullptr;
            return;
        }
    }
}

CHIP_ERROR JointFabricDatastorage::AddPendingNode(FabricIndex fabricId, NodeId nodeId, const CharSpan & friendlyName)
{
    VerifyOrReturnError(mNodeInformationEntries.size() < kMaxNodes, CHIP_ERROR_NO_MEMORY);

    mNodeInformationEntries.push_back(GenericDatastoreNodeInformationEntry(
        nodeId, fabricId, Clusters::JointFabricDatastore::DatastoreStateEnum::kPending, MakeOptional(friendlyName)));

    for (Listener * listener = mListeners; listener != nullptr; listener = listener->mNext)
    {
        listener->MarkNodeListChanged();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR JointFabricDatastorage::UpdateNode(NodeId nodeId, const CharSpan & friendlyName)
{
    for (auto & entry : mNodeInformationEntries)
    {
        if (entry.nodeID == nodeId)
        {
            entry.Set(MakeOptional(friendlyName));

            for (Listener * listener = mListeners; listener != nullptr; listener = listener->mNext)
            {
                listener->MarkNodeListChanged();
            }

            return CHIP_NO_ERROR;
        }
    }

    return CHIP_ERROR_KEY_NOT_FOUND;
}

CHIP_ERROR JointFabricDatastorage::RemoveNode(NodeId nodeId)
{
    for (auto it = mNodeInformationEntries.begin(); it != mNodeInformationEntries.end(); ++it)
    {
        if (it->nodeID == nodeId)
        {
            mNodeInformationEntries.erase(it);

            for (Listener * listener = mListeners; listener != nullptr; listener = listener->mNext)
            {
                listener->MarkNodeListChanged();
            }

            return CHIP_NO_ERROR;
        }
    }

    return CHIP_ERROR_KEY_NOT_FOUND;
}

CHIP_ERROR JointFabricDatastorage::RefreshNode(NodeId nodeId)
{
    // 1. && 2.
    ReturnErrorOnFailure(SetNode(nodeId, Clusters::JointFabricDatastore::DatastoreStateEnum::kPending));

    // 3. TODO: Read the PartsList of the Descriptor cluster from the Node.

    // 4.
    ReturnErrorOnFailure(RefreshGroupKeySet(nodeId));

    // 5.
    ReturnErrorOnFailure(RefreshACLList(nodeId));

    // 6.
    ReturnErrorOnFailure(SetNode(nodeId, Clusters::JointFabricDatastore::DatastoreStateEnum::kCommitted));

    for (Listener * listener = mListeners; listener != nullptr; listener = listener->mNext)
    {
        listener->MarkNodeListChanged();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR JointFabricDatastorage::SetNode(NodeId nodeId, Clusters::JointFabricDatastore::DatastoreStateEnum state)
{
    size_t index = 0;
    ReturnErrorOnFailure(IsNodeIDInDatastore(nodeId, index));
    mNodeInformationEntries[index].commissioningStatusEntry.state = state;
    return CHIP_NO_ERROR;
}

CHIP_ERROR JointFabricDatastorage::IsNodeIDInDatastore(NodeId nodeId, size_t & index)
{
    for (auto & entry : mNodeInformationEntries)
    {
        if (entry.nodeID == nodeId)
        {
            index = static_cast<size_t>(&entry - &mNodeInformationEntries[0]);
            return CHIP_NO_ERROR;
        }
    }

    return CHIP_ERROR_KEY_NOT_FOUND;
}

CHIP_ERROR JointFabricDatastorage::RefreshGroupKeySet(NodeId nodeId)
{
    size_t index = 0;
    ReturnErrorOnFailure(IsNodeIDInDatastore(nodeId, index));

    for (auto & it : mNodeInformationEntries[index].nodeKeySetList)
    {
        if (it.statusEntry.state == Clusters::JointFabricDatastore::DatastoreStateEnum::kPending)
        {
            ReturnErrorOnFailure(AddGroupKeySetEntry(it.groupKeySetId));
            const_cast<Clusters::JointFabricDatastore::Structs::DatastoreNodeKeyEntry::Type &>(it).statusEntry.state =
                Clusters::JointFabricDatastore::DatastoreStateEnum::kCommitted;
        }
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR JointFabricDatastorage::AddGroupKeySetEntry(uint16_t groupKeySetId)
{
    VerifyOrReturnError(mGroupKeySetList.size() < kMaxNodes, CHIP_ERROR_NO_MEMORY);

    Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type entry;
    entry.groupKeySetID = groupKeySetId;

    mGroupKeySetList.push_back(entry);

    return CHIP_NO_ERROR;
}

CHIP_ERROR JointFabricDatastorage::AddGroupKeySetEntry(Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type & groupKeySet)
{
    VerifyOrReturnError(IsGroupKeySetEntryPresent(groupKeySet.groupKeySetID) == false, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(mGroupKeySetList.size() < kMaxNodes, CHIP_ERROR_NO_MEMORY);

    mGroupKeySetList.push_back(groupKeySet);

    return CHIP_NO_ERROR;
}

bool JointFabricDatastorage::IsGroupKeySetEntryPresent(uint16_t groupKeySetId)
{
    for (auto & entry : mGroupKeySetList)
    {
        if (entry.groupKeySetID == groupKeySetId)
        {
            return true;
        }
    }

    return false;
}

CHIP_ERROR JointFabricDatastorage::RemoveGroupKeySetEntry(uint16_t groupKeySetId)
{
    for (auto it = mGroupKeySetList.begin(); it != mGroupKeySetList.end(); ++it)
    {
        if (it->groupKeySetID == groupKeySetId)
        {
            mGroupKeySetList.erase(it);
            return CHIP_NO_ERROR;
        }
    }

    return CHIP_ERROR_KEY_NOT_FOUND;
}

CHIP_ERROR
JointFabricDatastorage::UpdateGroupKeySetEntry(Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type & groupKeySet)
{
    for (auto & entry : mGroupKeySetList)
    {
        if (entry.groupKeySetID == groupKeySet.groupKeySetID)
        {
            bool field_updated =
                memcmp(&entry, &groupKeySet, sizeof(Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type)) == 0;
            entry = groupKeySet;

            if (field_updated)
            {
                RefreshNodes(groupKeySet);
            }

            return CHIP_NO_ERROR;
        }
    }

    return CHIP_ERROR_KEY_NOT_FOUND;
}

CHIP_ERROR JointFabricDatastorage::RefreshNodes(Clusters::GroupKeyManagement::Structs::GroupKeySetStruct::Type & groupKeySet)
{
    for (auto & entry : mNodeInformationEntries)
    {
        for (auto & it : entry.nodeKeySetList)
        {
            if (it.groupKeySetId == groupKeySet.groupKeySetID)
            {
                const_cast<Clusters::JointFabricDatastore::Structs::DatastoreNodeKeyEntry::Type &>(it).statusEntry.state =
                    Clusters::JointFabricDatastore::DatastoreStateEnum::kPending;

                // TODO: Update the node with the new group key set

                const_cast<Clusters::JointFabricDatastore::Structs::DatastoreNodeKeyEntry::Type &>(it).statusEntry.state =
                    Clusters::JointFabricDatastore::DatastoreStateEnum::kCommitted;
            }
        }
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR
JointFabricDatastorage::AddAdmin(Clusters::JointFabricDatastore::Structs::DatastoreAdministratorInformationEntry::Type & adminId)
{
    VerifyOrReturnError(IsAdminEntryPresent(adminId.nodeID) == false, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(mAdminEntries.size() < kMaxNodes, CHIP_ERROR_NO_MEMORY);

    mAdminEntries.push_back(adminId);

    return CHIP_NO_ERROR;
}

bool JointFabricDatastorage::IsAdminEntryPresent(NodeId nodeId)
{
    for (auto & entry : mAdminEntries)
    {
        if (entry.nodeID == nodeId)
        {
            return true;
        }
    }

    return false;
}

CHIP_ERROR JointFabricDatastorage::UpdateAdmin(NodeId nodeId, CharSpan friendlyName, ByteSpan icac)
{
    for (auto & entry : mAdminEntries)
    {
        if (entry.nodeID == nodeId)
        {
            entry.friendlyName = friendlyName;
            entry.icac         = icac;
            return CHIP_NO_ERROR;
        }
    }

    return CHIP_ERROR_KEY_NOT_FOUND;
}

CHIP_ERROR JointFabricDatastorage::RemoveAdmin(NodeId nodeId)
{
    for (auto it = mAdminEntries.begin(); it != mAdminEntries.end(); ++it)
    {
        if (it->nodeID == nodeId)
        {
            mAdminEntries.erase(it);
            return CHIP_NO_ERROR;
        }
    }

    return CHIP_ERROR_KEY_NOT_FOUND;
}

CHIP_ERROR
JointFabricDatastorage::RefreshACLList(NodeId nodeId)
{
    size_t index = 0;
    ReturnErrorOnFailure(IsNodeIDInDatastore(nodeId, index));

    for (auto & it : mNodeInformationEntries[index].ACLList)
    {
        if (it.statusEntry.state == Clusters::JointFabricDatastore::DatastoreStateEnum::kPending)
        {
            // TODO: Add it.aclEntry to the ACL list
            const_cast<Clusters::JointFabricDatastore::Structs::DatastoreACLEntry::Type &>(it).statusEntry.state =
                Clusters::JointFabricDatastore::DatastoreStateEnum::kCommitted;
        }
    }

    return CHIP_NO_ERROR;
}

} // namespace app
} // namespace chip
