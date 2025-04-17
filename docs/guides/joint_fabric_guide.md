# Joint Fabric Guide

-   [Joint Fabric Example Applications](#joint-fabric-example-applications)
-   [Run Joint Fabric Demo on UNIX](#run-fabric-sync-demo-on-rp4)

## Joint Fabric Example Applications

chip-tool and jf-admin-app example applications are provided to demonstrate
Joint Fabric feature. You can find them in the examples.

chip-tool example app implements the Ecosystems A and B Commissioner role and
communicates with the jf-admin-app on the other side, facilitating the Joint
Fabric process.

jf-admin-app example app implements the Ecosystems A and B Admin and
demonstrates the end-to-end Joint Fabric feature.

Joint Fabric can be triggered from chip-tool's side. The chip-tool takes on the
Commissioner role. The jf-admin-app, who receives the new ICA signed by the
Anchor Fabric Root CA, assumes the Commissionee role.

### Building the Example Application

-   Building the chip-tool Application

    [chip-tool](https://github.com/project-chip/connectedhomeip/tree/master/examples/chip-tool/README.md)

*   Building the jf-admin-app Application

    [jf-admin-app](https://github.com/project-chip/connectedhomeip/tree/master/examples/all-clusters-app/linux/README.md)

*   Building the all-clusters-app Application

    [all-clusters-app](https://github.com/project-chip/connectedhomeip/tree/master/examples/all-clusters-app/linux/README.md)

## Run Joint Fabric Demo on UNIX

### Prepare filesystem and clear previous cached data

```
$ # Reset key storage
$ rm -rf /tmp/chip_*
$ rm -rf /tmp/jf-*
```

### Run Lighting App B (all-clusters-app B) on Machine 1

```
$ ./out/host/chip-all-clusters-app --discriminator 1260 --passcode 110220022
```

### Run Ecosystem B Admin (jf-admin-app B) on Machine 2

```
$ ./out/host/chip-jf-admin-app --discriminator 1261 --passcode 110220033
```

### Run Ecosystem B Controller (chip-tool B) on Machine 2 (same as jf-admin-app B) and issue a B NOC Chain to Ecosystem's B Admin

From a new console, run a chip-tool interactive shell and start by pairing a new
device with an Anchor CAT:

```
$ ./out/host/chip-tool interactive start
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

### Pair Lighting App B to Ecosystem B.

From the same chip-tool interactive shell we just opened previously, let's pair
a new device to the ecosystem and then add it to the Joint Fabric Datastorage on
NodeId 1 -> jf-admin-app B.

```
> pairing onnetwork 10 110220022
> jointfabricdatastore add-pending-node 10 eco-b-lamp 1 0
> jointfabricdatastore refresh-node 10 1 0
> accesscontrol read acl 10 0
> accesscontrol write acl '[{"fabricIndex": 0, "privilege": 5, "authMode": 2, "subjects": [112233], "targets": null}, {"fabricIndex": 0, "privilege": 5, "authMode": 2, "subjects": [1], "targets": null}]' 10 0
```

### Run Ecosystem A Admin (jf-admin-app A) on Machine 3

Run Ecosystem A on a different device than the one used to run Ecosystem B
apps - Let's call Device A. Also prepare filesystem and clear previous cached
data as instructed above.

```
$ ./out/host/jf-admin-app --discriminator 1262 --passcode 110220044
```

### Run Ecosystem A Controller (chip-tool A) on Machine 3 (same as jf-admin-app A) and issue a A NOC Chain to Ecosystem's A Admin

From a new console on Device A, pair new device:

```
$ ./out/host/chip-tool interactive start
> pairing onnetwork 3 110220044 --anchor 1 --commissioner-case-auth-tags 0xFFFF0001
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
> payload parse-setup-payload <code-from-result-above>
```

### Run Ecosystem A Controller (chip-tool A) using Joint Commissioning Method (JCM)

This controller will issue Ecosystem B a new A NOC Chain. Right after it will
initiate a Joint Fabric exchange in order to provide all-clusters-app B with a
new ICA signed by A's Root CA.

Trigger JCM Flow to joint commission jf-admin-app B:

```
> pairing onnetwork-joint-fabric 2 <new-pin> --case-auth-tags 0xFFFF0001 --commissioner-case-auth-tags 0xFFFF0001
```

Ensure pairing was successful by reading Ecosystem B Admin Serial Number:

```
> basicinformation read serial-number 2 0
```

### Test that Ecosystem A Controller can access Ecosystem B Lamp given the new Joint Fabric chain

In the Ecosystem A Controller (chip-tool A) console with an open interactive
shell:

```
> basicinformation read serial-number 10 0
```
