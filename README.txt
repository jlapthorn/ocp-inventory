OCP CLI Inventory Toolkit (v3)
------------------------------

Python requirements:
- Python 3.6+ (Python 3.7+ recommended)

Toolkit contents:
- ocp_inventory_cli_v3.py    : Collects inventory and analysis data from a single OpenShift cluster
- combine_ocp_outputs_v3.py  : Combines multiple cluster output folders into consolidated CSV reports

Public release highlights in v3:
- Structured CSV/JSON outputs replace most text-only reporting
- New estate combiner for multi-cluster analysis
- Environment Pre-Checks validate Python, oc CLI, login session, cluster API reachability, and basic read access
- summary.json added for machine-readable automation/integration
- collection_summary.csv records API call status per cluster
- Replay support when raw JSON is captured in full mode
- SHA-256 integrity manifest and integrity report for evidence validation
- AI accelerator detection added (for example NVIDIA GPU, AMD GPU, Gaudi, FPGA resource keys)
- Subscription sizing signals added:
  - Worker CPU Capacity (Cores)
  - Worker CPU Allocatable (Cores)
  - Estimated Core-Pairs (Heuristic)
  - AI Accelerator Add-on Signal
- OpenShift Virtualization VM export retained (best-effort)
- DR posture, Platform Plus, managed-service, and workload signals retained as heuristic evidence

This toolkit collects OpenShift cluster inventory data including:
- Node roles, capacity, allocatable CPU/memory, topology, and billable-node signals
- Installed operator subscriptions and channels
- Add-on evidence (ACS / ACM / ODF / Quay) with ACTIVE vs HISTORICAL best-effort status
- Cluster version, platform type, managed-service indicators, and deployment signals
- DR posture heuristic and workload activity signals
- AI accelerator resources exposed on nodes
- VM inventory when OpenShift Virtualization resources are available

Output files (per cluster run):
- nodes.csv
- accelerators.csv
- operators.csv
- addons.csv
- cluster_summary.csv
- collection_summary.csv
- summary.json
- (optional) workload_evidence.csv        [deep/full mode]
- (optional) infra_compliance.csv         [deep/full mode]
- (optional) virtualization_vms.csv       [when accessible]
- (optional) raw_json/                    [full mode]
- hash.txt
- integrity_report.txt

REQUIREMENTS:
- Python 3.6+
- Access to the `oc` CLI and appropriate RBAC to read cluster resources

AUTHENTICATION OPTIONS
----------------------

1) Recommended (Token-based):
   Obtain a token from the OpenShift console:
     User menu -> Copy login command -> Display token
   Then run:
     python3 ocp_inventory_cli_v3.py --server https://api.<cluster>:6443 --token <sha256~...>

2) Username/password (only if supported by the cluster OAuth provider):
     python3 ocp_inventory_cli_v3.py --server https://api.<cluster>:6443 --username <user>
   You will be prompted for the password.

3) Already logged in (SSO / existing oc session):
   If 'oc whoami' succeeds and your current context server matches --server,
   the script will skip login automatically.

RUN MODES
---------
Default mode:
- Fast collection of core inventory data
- Produces nodes, operators, add-ons, cluster summary, collection summary, and summary.json by default
  python3 ocp_inventory_cli_v3.py --server https://api.<cluster>:6443 --token <sha256~...>

Deep analysis:
- Adds workload evidence and infrastructure workload analysis
- Uses a longer timeout for cluster-wide pod collection on larger environments
  python3 ocp_inventory_cli_v3.py --server https://api.<cluster>:6443 --token <sha256~...> --mode deep

Full evidence mode:
- Adds raw JSON captures for replay, audit support, or engineering review
  python3 ocp_inventory_cli_v3.py --server https://api.<cluster>:6443 --token <sha256~...> --mode full

Replay mode:
- Rebuild reports from a prior full-mode output folder without re-querying the cluster API
  python3 ocp_inventory_cli_v3.py --replay ./OCP_Inventory_<clusterID>_<timestamp>

Optional packaging control:
- Skip automatic ZIP packaging and keep only the output folder
  python3 ocp_inventory_cli_v3.py --server https://api.<cluster>:6443 --token <sha256~...> --mode full --no-zip

COMBINING MULTIPLE CLUSTERS
---------------------------
Place cluster output folders under a parent directory, then run:
  python3 combine_ocp_outputs_v3.py --input ./cluster_outputs

Combined outputs include:
- combined_nodes.csv
- combined_accelerators.csv
- combined_operators.csv
- combined_addons.csv
- combined_cluster_summary.csv
- combined_vms.csv                    [if VM data exists]
- combined_infra_compliance.csv       [if present]
- combined_workload_evidence.csv        [present when source runs used deep/full mode]
- combined_collection_summary.csv
- combiner_run_log.csv

PLATFORM TYPE / EDITION DETECTION
---------------------------------
Platform type and edition-related outputs are signals-based and may report:
- Self-Managed OpenShift (OCP)
- OpenShift Kubernetes Engine (OKE) signals
- Managed service indicators (for example ROSA / ARO / OSD)
- Platform Plus indicators based on detected add-ons

These outputs are intended to support customer discussions and analysis.

BARE-METAL SOCKET / CORE COLLECTION
-----------------------------------
This toolkit does not automatically collect physical socket counts.

To collect subscription-relevant hardware details for bare-metal deployments,
run the following per node:
  oc debug node/<node-name> -- chroot /host lscpu | grep -E 'Socket|Core'

NOTES
-----
- DR posture, Platform Plus, workload activity, and infrastructure compliance outputs are heuristic signals.
- Operator install timestamps are best-effort based on available metadata.
- ProviderID may be empty on on-premises or UPI clusters without cloud provider integration.
- AI accelerator reporting is based on node resource exposure and is intended as an evidence signal, not a final entitlement determination.
- Subscription conclusions should always be validated against purchased entitlements and the current Red Hat subscription guide.
- The login command uses oc with --insecure-skip-tls-verify to reduce failures on clusters using self-signed or privately signed certificates.

TYPICAL WORKFLOW
----------------
1) Run the inventory script on each cluster:
     python3 ocp_inventory_cli_v3.py --server https://api.<cluster>:6443 --token <sha256~...>

2) Collect the generated ZIP file from each cluster output folder.

3) Combine all runs:
     python3 combine_ocp_outputs_v3.py --input ./all_cluster_runs

SUPPORT / TROUBLESHOOTING
-------------------------
If troubleshooting is required, please provide:
- collection_summary.csv
- summary.json
- combiner_run_log.csv   [if combining multiple clusters]

These files contain the primary diagnostics needed to review the collection results.
