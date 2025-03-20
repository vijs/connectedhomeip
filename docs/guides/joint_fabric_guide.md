# Joint Fabric Guide

-   [Fabric Synchronization Guide](#fabric-synchronization-guide)
    -   [Joint Fabric Example Applications](#joint-fabric-example-applications)
    -   [Run Joint Fabric Demo on UNIX](#run-fabric-sync-demo-on-rp4)

## Joint Fabric Example Applications

chip-tool and all-cluster-app example applications are provided to demonstrate
Joint Fabric feature. You can find them in the examples.

chip-tool example app implements the Ecosystems A and B Commissioner role and
communicates with the all-clusters-app on the other side, facilitating the Joint
Fabric process.

all-clusters-app example app implements the Ecosystems A and B Admin and
demonstrates the end-to-end Joint Fabric feature.

Joint Fabric can be triggered from chip-tool's side. The chip-tool takes on the
Commissioner role. The all-clusters-app, who receives the new ICA signed by the
Anchor Fabric Root CA, assumes the Commissionee role.

### Building the Example Application

-   Building the chip-tool Application

    [chip-tool](https://github.com/project-chip/connectedhomeip/tree/master/examples/chip-tool/README.md)

*   Building the all-clusters-app Application

    [all-clusters-app](https://github.com/project-chip/connectedhomeip/tree/master/examples/all-clusters-app/linux/README.md)

    > Add the following argument to gn: `--args='chip_enable_joint_fabric=true'`

## Run Joint Fabric Demo on UNIX

### Prepare filesystem and clear previous cached data

```
# Reset key storage
rm -rf /tmp/chip_*
rm -rf /tmp/jf-kvs
mkdir -p /tmp/jf-kvs/all-clusters-app
mkdir -p /tmp/jf-kvs/chip-tool
mkdir -p /tmp/jf-kvs/secondary-chip-tool
```

### Run Ecosystem B Admin (all-clusters-app B)

```
./out/host/chip-all-clusters-app --capabilities 0x4 --discriminator 1261 --passcode 110220033 \
    --KVS /tmp/jf-kvs/all-clusters-app/acs-app --chip-tool-kvs /tmp/jf-kvs/chip-tool
```

### Run Ecosystem B Controller (chip-tool B) and issue a B NOC Chain to Ecosystem's B Admin

From a new console, run a chip-tool interactive shell and start by pairing a new
device with an Anchor CAT:

```
./out/host/chip-tool interactive start --storage-directory /tmp/jf-kvs/chip-tool
> pairing onnetwork 1 110220033 --anchor 1
```

Ensure pairing was successful by reading Ecosystem B Admin Serial Number:

```
> basicinformation read serial-number 1 0
```

Check that the AdministratorFabricIndex was set by the previous joint fabric
anchor pairing:

```
> jointfabricadministrator read administrator-fabric-index 1 0
```

Should be set to 1 since we're starting from a completely fresh session.

### Run Ecosystem A Admin (all-clusters-app A)

Run Ecosystem A preferrably on a different device than the one used to run
Ecosystem B apps - Let's call Device A. Also prepare filesystem and clear
previous cached data as instructed above.

```
./out/host/chip-all-clusters-app --capabilities 0x4 --discriminator 1262 --passcode 110220044 \
    --KVS /tmp/jf-kvs/all-clusters-app/secondary-acs-app --chip-tool-kvs /tmp/jf-kvs/secondary-chip-tool
```

### Run Ecosystem A Controller (chip-tool A) and issue a A NOC Chain to Ecosystem's A Admin

From a new console on Device A, pair new device:

```
./out/host/chip-tool interactive start --storage-directory /tmp/jf-kvs/secondary-chip-tool
> pairing onnetwork 3 110220044 --anchor 1
```

Ensure pairing was successful by reading Ecosystem A Admin Serial Number:

```
> basicinformation read serial-number 3 0
```

Check that the AdministratorFabricIndex was set by the previous joint fabric
anchor pairing:

```
> jointfabricadministrator read administrator-fabric-index 3 0
```

Should be set to 1 since we're starting from a completely fresh session.

### Open new Pairing Window on Ecosystem B

Return to Device B and use chip-tool to open a new pairing window on Ecosystem B
Admin.

So other ecosystem can initiate Joint Fabric, run this:

```
> pairing open-commissioning-window 1 1 400 1000 1261 --joint-fabric 1
```

### Run Ecosystem A Controller (chip-tool A) using Joint Commissioning Method (JCM)

This controller will issue Ecosystem B a new A NOC Chain. Right after it will
initiate a Joint Fabric exchange in order to provide all-clusters-app B with a
new ICA signed by A's Root CA.

In a new console:

```
> pairing onnetwork-joint-fabric 2 <pin-code that was set by the new commissioning window>
```

Ensure pairing was successful by reading Ecosystem B Admin Serial Number:

```
> basicinformation read serial-number 2 0
```
