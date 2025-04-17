/*
 *
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

#include "Options.h"

using namespace chip;
using namespace chip::ArgParser;

namespace {
JointFabricDeviceOptions gJointFabricDeviceOptions;

// Follow the code style of command line arguments in case we need to add more options in the future.
enum
{
    kDeviceOption_ChipToolKvs = 0x2000,
};

OptionDef sJointFabricDeviceOptionDefs[] = { { "chip-tool-kvs", kArgumentRequired, kDeviceOption_ChipToolKvs }, {} };

const char * sJointFabricDeviceOptionHelp = "  --chip-tool-kvs <filepath>\n"
                                            "       A file to sync Key Value Store items with chip-tool.\n"
                                            "\n";

bool HandleOption(const char * aProgram, OptionSet * aOptions, int aIdentifier, const char * aName, const char * aValue)
{
    bool retval = true;

    switch (aIdentifier)
    {
    case kDeviceOption_ChipToolKvs:
        JointFabricDeviceOptions::GetInstance().chipToolKvs = aValue;
        break;
    default:
        PrintArgError("%s: INTERNAL ERROR: Unhandled option: %s\n", aProgram, aName);
        retval = false;
        break;
    }

    return (retval);
}

OptionSet sJointFabricDeviceOptions = { HandleOption, sJointFabricDeviceOptionDefs, "JOINT FABRIC OPTIONS",
                                        sJointFabricDeviceOptionHelp };
} // namespace

JointFabricDeviceOptions & JointFabricDeviceOptions::GetInstance()
{
    return gJointFabricDeviceOptions;
}

OptionSet * JointFabricDeviceOptions::GetOptions()
{
    return &sJointFabricDeviceOptions;
}
