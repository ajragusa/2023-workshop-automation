Tune host settings https://hmntsharma.github.io/cisco-xrd/base_setup/#clone-the-xrd-tools-repository

Set mgmt address in the config (instead of automatically assigning) as XRd has a bug and a container keeps its old address if it's been assigned a new address. containerlab is non-deterministic when assigning mgmt IPs.

Review the `Makefile` in `Getting_Started`

`make gen` to generate lab topologies based on `workshop.clab.yml.j2`. This currently creates 30 labs, set via `gen-topo.py`.  
`make deploy` to start up all 30 labs. This will take some time but should complete without error.  
`make destroy` to tear down all labs.  
`make inspect` to output lab info (this show local IPs, not port bindings)  
`make container` to build new lab container based on `Containerfile`  

You can also run `containerlab` commands directly but they need to be run as root or via `sudo`.

You can probably use the output of `sudo containerlab inspect -t workshop1.clab.yml -f json` to create something similar to the `containerlab inspect` table output that displays the port bindings. i.e., use this to generate workshop instructions.
