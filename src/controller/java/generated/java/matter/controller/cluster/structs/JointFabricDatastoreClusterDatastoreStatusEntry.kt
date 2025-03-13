/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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
package matter.controller.cluster.structs

import matter.controller.cluster.*
import matter.tlv.ContextSpecificTag
import matter.tlv.Tag
import matter.tlv.TlvReader
import matter.tlv.TlvWriter

class JointFabricDatastoreClusterDatastoreStatusEntry(
  val state: UByte,
  val updateTimestamp: ULong?,
) {
  override fun toString(): String = buildString {
    append("JointFabricDatastoreClusterDatastoreStatusEntry {\n")
    append("\tstate : $state\n")
    append("\tupdateTimestamp : $updateTimestamp\n")
    append("}\n")
  }

  fun toTlv(tlvTag: Tag, tlvWriter: TlvWriter) {
    tlvWriter.apply {
      startStructure(tlvTag)
      put(ContextSpecificTag(TAG_STATE), state)
      if (updateTimestamp != null) {
        put(ContextSpecificTag(TAG_UPDATE_TIMESTAMP), updateTimestamp)
      } else {
        putNull(ContextSpecificTag(TAG_UPDATE_TIMESTAMP))
      }
      endStructure()
    }
  }

  companion object {
    private const val TAG_STATE = 0
    private const val TAG_UPDATE_TIMESTAMP = 1

    fun fromTlv(
      tlvTag: Tag,
      tlvReader: TlvReader,
    ): JointFabricDatastoreClusterDatastoreStatusEntry {
      tlvReader.enterStructure(tlvTag)
      val state = tlvReader.getUByte(ContextSpecificTag(TAG_STATE))
      val updateTimestamp =
        if (!tlvReader.isNull()) {
          tlvReader.getULong(ContextSpecificTag(TAG_UPDATE_TIMESTAMP))
        } else {
          tlvReader.getNull(ContextSpecificTag(TAG_UPDATE_TIMESTAMP))
          null
        }

      tlvReader.exitContainer()

      return JointFabricDatastoreClusterDatastoreStatusEntry(state, updateTimestamp)
    }
  }
}
