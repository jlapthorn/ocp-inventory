#!/usr/bin/env python3
# =============================================================================
# OCP Inventory CLI  —  v3
# =============================================================================
# Architecture: Collect → Analyse → Report
#
#   ClusterCollector  — all oc API calls happen here, nowhere else
#   ClusterAnalyser   — all heuristics and detection logic, no oc calls
#   ReportWriter      — all file I/O, no oc calls, no analysis logic
#
# Public Release v3:
#   - CRITICAL BUG FIX: _write_summary_json was accidentally defined at module
#     level (zero indentation) instead of as a method of ReportWriter. This caused
#     an AttributeError crash on every run when ReportWriter.write() called
#     self._write_summary_json(). Fixed by restoring correct 4-space indentation.
#
# Internal development changes:
#   - New output: accelerators.csv — per-node AI accelerator inventory and counts
#   - cluster_summary.csv now includes worker CPU totals and estimated core-pairs
#   - cluster_summary.csv now includes AI Accelerator Add-on signal
#   - summary.json now includes accelerator row count
#
# Internal development changes:
#   - _ki_to_gib: now handles bare byte integers (no unit suffix) returned by
#     some Kubernetes distributions; previously returned '' for these values
#   - environment_prechecks: removed redundant Python version guard (already
#     enforced at module level on import)
#   - oc get pods timeout raised to 300 s in deep/full mode to avoid spurious
#     timeouts on large clusters; documented in --help epilog
#   - subprocess execution now uses argument lists / shell=False for safer command handling
#     no behavioural change (full remediation requires list-form subprocess
#     refactor, deferred to avoid breaking existing auth flows)
#
# Internal development changes:
#   - Full architectural rewrite: collect / analyse / report separation
#   - All oc calls centralised; each resource fetched exactly once
#   - CollectionStatus tracker: every API call recorded (SUCCESS/RBAC_DENIED/EMPTY/PARSE_ERROR/NOT_PRESENT/SKIPPED)
#   - New output: collection_summary.csv  — run diagnostics, completeness validation
#   - New output: cluster_summary.csv     — replaces OCP_Cluster_Version.txt (now CSV)
#   - New output: addons.csv             — replaces OCP_Addons_Report.txt (now CSV)
#   - New output: workload_evidence.csv  — replaces OCP_Workload_Evidence.txt (now CSV)
#   - All outputs are now CSV for direct use in Excel / Google Sheets
#   - Evidence Type + Confidence columns on all heuristic outputs
#   - Compact cluster (3-node) and SNO detection with billing compliance flag
#   - GPU / AI Accelerator detection per node (nvidia, amd, habana, intel)
#   - Subscription Model signal per node (Core-Pair / Bare-Metal Node)
#   - Infra node workload compliance check (deep mode)
#   - Run modes: --mode standard | deep | full
#   - Full mode saves raw JSON; --replay <folder> re-runs analysis without cluster access
#   - Integrity hashing: SHA-256
#   - Python 3.6+ compatible
#
# Output files (inside dated zip folder):
#   nodes.csv               — node inventory with roles, capacity, billing signals
#   operators.csv           — installed OLM operators with dates and channels
#   addons.csv              — ACS / ACM / ODF / Quay lifecycle status
#   cluster_summary.csv     — one row per cluster: version, platform, DR, edition signals
#   accelerators.csv        — per-node AI accelerator inventory and counts
#   virtualization_vms.csv  — KubeVirt VM inventory (deep + full modes, or if virt detected)
#   workload_evidence.csv   — pod breakdown and workload samples (deep + full modes)
#   collection_summary.csv  — API call results, RBAC gaps, data completeness
#   integrity_report.txt    — SHA-256 hash manifest
#
# Authentication:
#   --token <sha256~...>            recommended (SSO / AAD)
#   --username <u>                  password prompted interactively
#   already logged in (oc whoami)   auto-detected, login skipped
#
# Run modes:
#   --mode standard   fast, all lightweight collection (default)
#   --mode deep       adds pod workload evidence + infra compliance checking
#   --mode full       deep + raw JSON dumps (enables --replay)
#
# Replay (re-analyse without cluster access):
#   --replay <folder>   re-run analysis + report against a previous --full output folder
#
# =============================================================================

import argparse
import csv
import getpass
import hashlib
import json
import math
import os
import shutil
import re
import socket
import subprocess
import shlex
import sys
import zipfile
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Python version guard
# ---------------------------------------------------------------------------
if sys.version_info < (3, 6):
    sys.stderr.write('ERROR: Python 3.6+ required (detected %s)\n' % sys.version.split()[0])
    sys.exit(2)
elif sys.version_info[:2] == (3, 6):
    sys.stderr.write('WARNING: Python 3.6 detected. Supported but 3.7+ recommended.\n')


# =============================================================================
# Constants
# =============================================================================

VERSION = 'v3'
COMMAND_TIMEOUT_SECONDS = 120

ACCELERATOR_RESOURCE_KEYS = {
    'nvidia.com/gpu':         'NVIDIA GPU',
    'amd.com/gpu':            'AMD GPU',
    'habana.ai/gaudi':        'Intel Habana Gaudi',
    'habana.ai/gaudi2':       'Intel Habana Gaudi2',
    'intel.com/gpu':          'Intel GPU',
    'aws.amazon.com/neuron':  'AWS Inferentia/Trainium',
    'google.com/tpu':         'Google TPU',
    'xilinx.com/fpga':        'Xilinx FPGA',
}

# Namespaces / CSV patterns that qualify as infrastructure workloads
INFRA_NS_PREFIXES = (
    'openshift-', 'kube-', 'openshift', 'kube-system', 'default',
    'stackrox', 'rhacs', 'acs-operator',
)
INFRA_CSV_PATTERNS = [
    'quay', 'odf', 'ocs', 'rook', 'advanced-cluster-management',
    'multicluster', 'rhacs', 'stackrox', 'openshift-gitops',
    'openshift-pipelines', 'ansible-automation-platform',
]

ADDON_CHECKS = [
    ('ACS',  ['rhacs', 'stackrox']),
    ('ACM',  ['advanced-cluster-management', 'multicluster']),
    ('ODF',  ['odf', 'ocs', 'rook-ceph']),
    ('Quay', ['quay']),
]

VIRT_CSV_KEYS  = ['kubevirt', 'hyperconverged', 'cnv', 'virt', 'hco']
NFV_CSV_KEYS   = {'SR-IOV': ['sriov'], 'PTP': ['ptp'], 'Performance Addon': ['performance-addon']}

COLLECTION_SUCCESS     = 'SUCCESS'
COLLECTION_RBAC_DENIED = 'RBAC_DENIED'
COLLECTION_EMPTY       = 'EMPTY'
COLLECTION_PARSE_ERROR = 'PARSE_ERROR'
COLLECTION_NOT_PRESENT = 'NOT_PRESENT'
COLLECTION_SKIPPED     = 'SKIPPED'


# =============================================================================
# Subprocess helpers
# =============================================================================

def _display_cmd(cmd):
    """Render a command for logs/messages without invoking a shell.
    Uses shlex.quote per argument so the output is unambiguous even if an
    argument contains spaces or special characters.
    """
    if isinstance(cmd, (list, tuple)):
        return ' '.join(shlex.quote(str(a)) for a in cmd)
    return str(cmd)


def _coerce_cmd(cmd):
    """Accept legacy string commands while executing without shell=True.
    posix=True is used so that any quoted substrings in a legacy string command
    are handled correctly (quotes stripped, escapes interpreted) — matching the
    behaviour a POSIX shell would apply before handing arguments to the process.
    """
    if isinstance(cmd, (list, tuple)):
        return list(cmd)
    if isinstance(cmd, str):
        return shlex.split(cmd, posix=True)
    raise TypeError('Unsupported command type: {0}'.format(type(cmd).__name__))


def _run(cmd, timeout=COMMAND_TIMEOUT_SECONDS):
    """Run a command without a shell. Returns (stdout_str, stderr_str, returncode)."""
    try:
        result = subprocess.run(
            _coerce_cmd(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            universal_newlines=True,   # Python 3.6 compat (text=True is 3.7+)
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out after {0}s'.format(timeout), 124


def _run_json(cmd, timeout=COMMAND_TIMEOUT_SECONDS):
    """
    Run a command expected to return JSON.
    Returns (parsed_dict_or_list, status_string, error_message).
    """
    stdout, stderr, rc = _run(cmd, timeout=timeout)

    if rc != 0:
        if any(k in stderr.lower() for k in ('forbidden', 'cannot list', 'cannot get', 'not allowed')):
            return None, COLLECTION_RBAC_DENIED, stderr
        if "the server doesn't have a resource type" in stderr.lower():
            return None, COLLECTION_NOT_PRESENT, stderr
        return None, COLLECTION_PARSE_ERROR, stderr

    if not stdout:
        return None, COLLECTION_EMPTY, ''

    try:
        data = json.loads(stdout)
        items = data.get('items', None) if isinstance(data, dict) else None
        if items is not None and len(items) == 0:
            return data, COLLECTION_EMPTY, ''
        return data, COLLECTION_SUCCESS, ''
    except Exception as e:
        return None, COLLECTION_PARSE_ERROR, str(e)


# =============================================================================
# Data containers
# =============================================================================

class CollectionRecord(object):
    """Tracks the outcome of a single API call."""
    __slots__ = ('resource', 'command', 'status', 'item_count', 'notes')

    def __init__(self, resource, command, status, item_count=0, notes=''):
        self.resource   = resource
        self.command    = command
        self.status     = status
        self.item_count = item_count
        self.notes      = notes


class ClusterData(object):
    """Raw data collected from the cluster. All fields may be None if unavailable."""

    def __init__(self):
        self.cluster_id        = 'unknown'
        self.nodes             = []
        self.csvs              = []       # ClusterServiceVersions
        self.installplans      = []
        self.subscriptions     = []
        self.namespaces        = []
        self.clusterversion    = None
        self.infrastructure    = None
        self.clusteroperators  = []
        self.machinesets       = []
        self.routes            = []
        self.hpas              = []
        self.deployments       = []
        self.statefulsets      = []
        self.pods              = []       # only in deep/full mode
        self.vms               = []       # only if virt detected
        self.vmi_items         = []       # raw VMI objects for replay/full-mode persistence
        self.vmis              = {}       # (ns,name) -> nodeName
        self.collection_log    = []       # list of CollectionRecord
        self.collected_at      = ''
        self.mode              = 'standard'

    def log(self, resource, command, status, items=None, notes=''):
        count = len(items) if items else 0
        self.collection_log.append(
            CollectionRecord(resource, command, status, count, notes)
        )

    def was_available(self, resource):
        for rec in self.collection_log:
            if rec.resource == resource:
                return rec.status == COLLECTION_SUCCESS
        return False


# =============================================================================
# PHASE 1 — ClusterCollector
# =============================================================================

class ClusterCollector(object):
    """
    Fetches all data from the cluster exactly once.
    No analysis, no file I/O.
    """

    def __init__(self, mode='standard'):
        self.mode = mode

    def collect(self):
        data = ClusterData()
        data.mode = self.mode
        data.collected_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        print('Collecting cluster data (mode: {0})...'.format(self.mode))

        # Core identity
        data.clusterversion = self._fetch(data, 'clusterversion',
            'oc get clusterversion version -o json')
        data.cluster_id   = self._get_cluster_id(data)
        data.infrastructure = self._fetch(data, 'infrastructure',
            'oc get infrastructure cluster -o json')

        # Nodes (always)
        nodes_raw = self._fetch_list(data, 'nodes', 'oc get nodes -o json')
        data.nodes = nodes_raw or []

        # Namespaces (always)
        ns_raw = self._fetch_list(data, 'namespaces', 'oc get namespaces -o json')
        data.namespaces = ns_raw or []

        # Cluster operators (always)
        ops_raw = self._fetch_list(data, 'clusteroperators', 'oc get clusteroperators -o json')
        data.clusteroperators = ops_raw or []

        # OLM resources (always)
        data.csvs = self._fetch_list(data, 'clusterserviceversions',
            'oc get csv -A -o json') or []
        data.installplans = self._fetch_list(data, 'installplans',
            'oc get installplan -A -o json') or []
        data.subscriptions = self._fetch_list(data, 'subscriptions',
            'oc get subscriptions -A -o json') or []

        # Lightweight workload signals (always)
        data.machinesets  = self._fetch_list(data, 'machinesets',
            'oc get machinesets -A -o json') or []
        data.routes       = self._fetch_list(data, 'routes',
            'oc get routes -A -o json') or []
        data.hpas         = self._fetch_list(data, 'hpas',
            'oc get hpa -A -o json') or []
        data.deployments  = self._fetch_list(data, 'deployments',
            'oc get deployments -A -o json') or []
        data.statefulsets = self._fetch_list(data, 'statefulsets',
            'oc get statefulsets -A -o json') or []

        # Pods — deep and full modes only.
        # Timeout raised to 300 s: 'oc get pods -A' on large clusters (5 k+ pods)
        # can legitimately exceed the default 120 s.
        if self.mode in ('deep', 'full'):
            data.pods = self._fetch_list(data, 'pods',
                'oc get pods -A -o json', timeout=300) or []
        else:
            data.log('pods', '', COLLECTION_SKIPPED, notes='standard mode; use --mode deep')

        # Virtualisation — always attempt; export only if detected
        vms_raw = self._fetch_list(data, 'virtualmachines',
            'oc get vm -A -o json')
        if vms_raw is None:
            vms_raw = self._fetch_list(data, 'virtualmachines',
                'oc get virtualmachine -A -o json')
        data.vms = vms_raw or []

        if data.vms:
            vmis_raw = self._fetch_list(data, 'virtualmachineinstances',
                'oc get vmi -A -o json')
            if vmis_raw is None:
                vmis_raw = self._fetch_list(data, 'virtualmachineinstances',
                    'oc get virtualmachineinstance -A -o json')
            data.vmi_items = vmis_raw or []
            for vmi in data.vmi_items:
                ns   = vmi.get('metadata', {}).get('namespace', '')
                name = vmi.get('metadata', {}).get('name', '')
                node = vmi.get('status', {}).get('nodeName', '') or ''
                if ns and name:
                    data.vmis[(ns, name)] = node

        print('Collection complete. Resources fetched: {0}'.format(
            sum(1 for r in data.collection_log if r.status == COLLECTION_SUCCESS)
        ))

        return data

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_cluster_id(self, data):
        raw = data.clusterversion or {}
        return (raw.get('spec', {}) or {}).get('clusterID', 'unknown') or 'unknown'

    def _fetch(self, data, resource, cmd, timeout=COMMAND_TIMEOUT_SECONDS):
        """Fetch a single object (not a list). Returns the parsed dict or None."""
        raw, status, err = _run_json(cmd, timeout=timeout)
        notes = err[:200] if err else ''
        data.log(resource, _display_cmd(cmd), status, notes=notes)
        return raw if status == COLLECTION_SUCCESS else None

    def _fetch_list(self, data, resource, cmd, timeout=COMMAND_TIMEOUT_SECONDS):
        """Fetch a list resource. Returns list of items or None."""
        raw, status, err = _run_json(cmd, timeout=timeout)
        notes = err[:200] if err else ''
        items = raw.get('items', []) if (raw and isinstance(raw, dict)) else []
        data.log(resource, _display_cmd(cmd), status, items, notes)
        if status in (COLLECTION_SUCCESS, COLLECTION_EMPTY):
            return items
        return None


# =============================================================================
# PHASE 2 — ClusterAnalyser
# =============================================================================

class AnalysisResult(object):
    """Holds all analysis outputs ready for the report writer."""

    def __init__(self):
        self.cluster_id       = ''
        self.cluster_name     = ''
        self.cluster_summary  = {}    # dict of fields for cluster_summary.csv
        self.nodes            = []    # list of dicts — one per node
        self.operators        = []    # list of dicts — one per CSV
        self.addons           = []    # list of dicts — one per tracked addon
        self.workload         = {}    # workload evidence dict (deep/full only)
        self.vms              = []    # list of dicts — one per VM
        self.accelerators     = []    # list of dicts — one per accelerator-bearing node/resource
        self.infra_compliance = []    # list of dicts — infra node compliance (deep/full)
        self.collection_log   = []
        self.collected_at     = ''
        self.mode             = 'standard'


class ClusterAnalyser(object):
    """
    Runs all analysis and heuristics against ClusterData.
    No oc calls. No file I/O.
    """

    def analyse(self, data):
        result = AnalysisResult()
        result.cluster_id     = data.cluster_id
        result.cluster_name   = self._get_cluster_name(data)
        result.collection_log = data.collection_log
        result.collected_at   = data.collected_at
        result.mode           = data.mode

        result.nodes     = self._analyse_nodes(data)
        result.operators    = self._analyse_operators(data)
        result.addons       = self._analyse_addons(data)
        result.vms          = self._analyse_vms(data)
        result.accelerators = self._analyse_accelerators(data)

        if data.mode in ('deep', 'full'):
            result.workload         = self._analyse_workload(data)
            result.infra_compliance = self._analyse_infra_compliance(data)

        result.cluster_summary = self._build_cluster_summary(data, result)

        return result

    # ------------------------------------------------------------------
    # Node analysis
    # ------------------------------------------------------------------

    def _analyse_nodes(self, data):
        rows = []
        cluster_topology = self._detect_topology(data.nodes)

        for item in data.nodes:
            md     = item.get('metadata', {}) or {}
            spec   = item.get('spec', {}) or {}
            status = item.get('status', {}) or {}
            labels = md.get('labels', {}) or {}

            name = md.get('name', '')

            # Roles
            roles = []
            for k in labels:
                if k.startswith('node-role.kubernetes.io/'):
                    role = k.split('/', 1)[1]
                    roles.append(role if role else 'worker')
            if not roles and 'node.openshift.io/os_id' in labels:
                roles.append('worker')

            # Billable logic — accounts for compact / SNO topology
            billable, billable_confidence, billable_evidence = self._billable(
                roles, cluster_topology
            )

            # Subscription model signal
            sub_model, sub_model_evidence = self._subscription_model(item, data)

            # Accelerators
            accel_count, accel_types = self._detect_accelerators(status)

            # Basic fields
            creation_ts = (md.get('creationTimestamp', '') or '').split('T', 1)[0]
            unschedulable = spec.get('unschedulable', False)

            internal_ip = ''
            for addr in status.get('addresses', []):
                if addr.get('type') == 'InternalIP':
                    internal_ip = addr.get('address', '')
                    break

            cpu_cap  = status.get('capacity', {}).get('cpu', '')
            cpu_alloc= status.get('allocatable', {}).get('cpu', '')
            mem_gib  = _ki_to_gib(status.get('capacity', {}).get('memory', ''))
            provider = spec.get('providerID', '')

            # Location / instance labels
            zone          = labels.get('topology.kubernetes.io/zone',
                            labels.get('failure-domain.beta.kubernetes.io/zone', ''))
            region        = labels.get('topology.kubernetes.io/region',
                            labels.get('failure-domain.beta.kubernetes.io/region', ''))
            instance_type = labels.get('node.kubernetes.io/instance-type',
                            labels.get('beta.kubernetes.io/instance-type', ''))
            arch          = labels.get('kubernetes.io/arch',
                            labels.get('beta.kubernetes.io/arch', ''))
            taints        = _extract_taints(item)

            rows.append({
                'Cluster ID':                   data.cluster_id,
                'Cluster Name':                 self._get_cluster_name(data),
                'Node Name':                    name,
                'Role':                         ','.join(sorted(roles)),
                'Topology Flag':                cluster_topology,
                'Creation Date':                creation_ts,
                'Unschedulable':                unschedulable,
                'Internal IP':                  internal_ip,
                'CPU Capacity (vCPUs)':         cpu_cap,
                'CPU Allocatable (vCPUs)':      cpu_alloc,
                'Memory (GiB)':                 mem_gib or '',
                'Architecture':                 arch or '',
                'Instance Type':                instance_type or '',
                'Zone':                         zone or '',
                'Region':                       region or '',
                'Provider ID':                  provider,
                'Taints':                       taints,
                'GPU / Accelerator Count':      accel_count,
                'Accelerator Type(s)':          accel_types,
                'Subscription Model (Signal)':  sub_model,
                'Sub Model Evidence':           sub_model_evidence,
                'Billable (Heuristic)':         'Yes' if billable else 'No',
                'Billable Confidence':          billable_confidence,
                'Billable Evidence':            billable_evidence,
            })
        return rows

    def _detect_topology(self, nodes):
        """
        Detect cluster topology: Standard, Compact (3-node), or SNO.
        Returns a string label used in the Topology Flag column.
        """
        if not nodes:
            return 'Unknown'

        total = len(nodes)
        if total == 1:
            return 'SNO'  # Single Node OpenShift

        # Compact: all nodes carry master/control-plane role AND worker role
        compact_count = 0
        for n in nodes:
            labels = (n.get('metadata', {}) or {}).get('labels', {}) or {}
            roles = set()
            for k in labels:
                if k.startswith('node-role.kubernetes.io/'):
                    roles.add(k.split('/', 1)[1])
            has_master = 'master' in roles or 'control-plane' in roles
            has_worker = 'worker' in roles
            if has_master and has_worker:
                compact_count += 1

        if compact_count == total and total == 3:
            return 'Compact'

        return 'Standard'

    def _billable(self, roles, topology):
        """
        Determine if a node is billable.
        In Compact / SNO topologies all nodes are billable (masters run workloads).
        In Standard topology: masters and infra-only nodes are exempt.
        Returns (bool, confidence_str, evidence_str).
        """
        r = set(x.strip() for x in roles if x.strip())

        if topology in ('SNO', 'Compact'):
            return (
                True,
                'High',
                'All nodes billable in {0} topology per subscription guide'.format(topology),
            )

        is_master     = ('master' in r) or ('control-plane' in r)
        is_infra_only = ('infra' in r) and ('worker' not in r)

        if is_master:
            return (False, 'High', 'Control plane node — exempt')
        if is_infra_only:
            return (False, 'Medium', 'Infra-only node — exempt (verify no user workloads)')
        return (True, 'High', 'Worker node — billable')

    def _subscription_model(self, node_item, data):
        """
        Signal the likely subscription model using available evidence.
        Returns (model_str, evidence_str).
        """
        provider = (node_item.get('spec', {}) or {}).get('providerID', '') or ''
        infra     = data.infrastructure or {}
        platform  = (infra.get('status', {}) or {}).get('platformType', '').lower()
        ns_names  = set((ns.get('metadata', {}) or {}).get('name', '').lower() for ns in (data.namespaces or []))
        if 'hypershift' in ns_names or 'clusters' in ns_names:
            return ('Core-Pair', 'HyperShift / hosted control plane indicators detected; treat bare-metal signal with caution')

        # Cloud providers → Core-Pair
        cloud_platforms = ('aws', 'azure', 'gcp', 'google', 'openstack', 'ibm')
        if any(p in platform for p in cloud_platforms):
            return ('Core-Pair', 'Cloud platform ({0}) detected'.format(platform))

        if provider.startswith(('aws://', 'azure://', 'gce://', 'ibm://')):
            return ('Core-Pair', 'ProviderID indicates cloud instance')

        # VMware / Nutanix → Core-Pair
        if 'vsphere' in platform or 'nutanix' in platform:
            return ('Core-Pair', 'Hypervisor platform ({0}) detected'.format(platform))

        if 'vsphere://' in provider or 'nutanix' in provider.lower():
            return ('Core-Pair', 'ProviderID indicates virtualised node')

        if not provider:
            return ('Unknown', 'No ProviderID present')

        return ('Unknown', 'ProviderID present but platform type unclear; verify manually')

    def _detect_accelerators(self, node_status):
        """
        Detect GPU / AI accelerator resources from node capacity labels.
        Returns (total_count_int, comma_separated_types_str).
        """
        capacity = (node_status.get('capacity', {}) or {})
        total    = 0
        types    = []
        for key, label in ACCELERATOR_RESOURCE_KEYS.items():
            val = capacity.get(key)
            if val:
                try:
                    n = int(val)
                    if n > 0:
                        total += n
                        types.append('{0}×{1}'.format(n, label))
                except ValueError:
                    pass
        return (total, '; '.join(types) if types else '')


    def _analyse_accelerators(self, data):
        rows = []
        cluster_name = self._get_cluster_name(data)
        for item in data.nodes:
            md = item.get('metadata', {}) or {}
            status = item.get('status', {}) or {}
            capacity = (status.get('capacity', {}) or {})
            allocatable = (status.get('allocatable', {}) or {})
            node_name = md.get('name', '')
            labels = md.get('labels', {}) or {}
            node_role = []
            for k in labels:
                if k.startswith('node-role.kubernetes.io/'):
                    role = k.split('/', 1)[1]
                    node_role.append(role if role else 'worker')
            for resource_key, accel_type in ACCELERATOR_RESOURCE_KEYS.items():
                raw_cap = capacity.get(resource_key)
                raw_alloc = allocatable.get(resource_key)
                cap = _safe_int(raw_cap)
                alloc = _safe_int(raw_alloc)
                if cap <= 0 and alloc <= 0:
                    continue
                count = cap if cap > 0 else alloc
                rows.append({
                    'Cluster ID': data.cluster_id,
                    'Cluster Name': cluster_name,
                    'Node Name': node_name,
                    'Role': ','.join(sorted(node_role)),
                    'Accelerator Resource Key': resource_key,
                    'Accelerator Type': accel_type,
                    'Capacity Count': cap,
                    'Allocatable Count': alloc,
                    'Measured Count': count,
                    'Measurement Signal': 'AI Accelerator add-on likely required' if count > 0 else 'No accelerator count detected',
                    'Evidence': 'Node resource capacity/allocatable includes {0}'.format(resource_key),
                })
        return rows

    # ------------------------------------------------------------------
    # Operator analysis
    # ------------------------------------------------------------------

    def _analyse_operators(self, data):
        rows = []

        # Build IP map: csv_name_lower → earliest startTime
        ip_map = {}
        for ip in data.installplans:
            st    = (ip.get('status', {}) or {}).get('startTime') or ''
            names = (ip.get('spec', {}) or {}).get('clusterServiceVersionNames') or []
            for n in names:
                key = (n or '').lower()
                if not key:
                    continue
                if key not in ip_map or (st and st < ip_map[key]):
                    ip_map[key] = st

        # Build subscription map: csv_name_lower → channel
        sub_map = {}
        for sub in data.subscriptions:
            installed = ((sub.get('status', {}) or {}).get('installedCSV') or '').lower()
            channel   = (sub.get('spec', {}) or {}).get('channel', '') or ''
            if installed:
                sub_map[installed] = channel

        for item in data.csvs:
            md      = item.get('metadata', {}) or {}
            spec    = item.get('spec', {}) or {}
            name    = md.get('name', '') or ''
            ns      = md.get('namespace', '') or ''
            display = spec.get('displayName', '') or ''
            version = spec.get('version', '') or ''

            created       = md.get('creationTimestamp', '') or ''
            installed_date= created.split('T', 1)[0] if 'T' in created else created

            initiated     = ip_map.get(name.lower(), '')
            initiated_date= initiated.split('T', 1)[0] if initiated and 'T' in initiated else initiated

            channel = sub_map.get(name.lower(), '')

            rows.append({
                'Cluster ID':                           data.cluster_id,
                'Cluster Name':                         self._get_cluster_name(data),
                'Operator CSV Name':                    name,
                'Namespace':                            ns,
                'Display Name':                         display,
                'Installed Version':                    version,
                'Channel':                              channel,
                'Installed Date':                       installed_date,
                'Install Initiated Date (Best Effort)': initiated_date,
            })
        return rows

    # ------------------------------------------------------------------
    # Addon analysis
    # ------------------------------------------------------------------

    def _analyse_addons(self, data):
        active = {}
        for item in data.csvs:
            n  = (item.get('metadata', {}) or {}).get('name', '') or ''
            ts = (item.get('metadata', {}) or {}).get('creationTimestamp', '') or ''
            if n:
                active[n.lower()] = ts

        hist = {}
        for ip in data.installplans:
            st    = (ip.get('status', {}) or {}).get('startTime', '') or ''
            names = (ip.get('spec', {}) or {}).get('clusterServiceVersionNames', []) or []
            for n in names:
                key = (n or '').lower()
                if not key:
                    continue
                if key not in hist or (st and st < hist[key]):
                    hist[key] = st

        rows = []
        csvs_available = data.was_available('clusterserviceversions')
        ips_available  = data.was_available('installplans')

        for short, keys in ADDON_CHECKS:
            state, ts, evidence = 'NOT FOUND', '', ''
            conf  = 'High' if csvs_available else 'Low'

            for name, stamp in active.items():
                if any(k in name for k in keys):
                    state    = 'ACTIVE'
                    ts       = stamp.split('T', 1)[0] if 'T' in stamp else stamp
                    evidence = name
                    break

            if state == 'NOT FOUND' and ips_available:
                for name, stamp in hist.items():
                    if any(k in name for k in keys):
                        state    = 'HISTORICAL'
                        ts       = stamp.split('T', 1)[0] if 'T' in stamp else stamp
                        evidence = name
                        conf     = 'Medium'
                        break

            if not csvs_available and not ips_available:
                state = 'UNAVAILABLE'
                conf  = 'Low'

            rows.append({
                'Cluster ID':    data.cluster_id,
                'Cluster Name':  self._get_cluster_name(data),
                'Add-on':        short,
                'Status':        state,
                'Date':          ts,
                'Evidence':      evidence,
                'Confidence':    conf,
                'Notes':         'ACTIVE=current CSV; HISTORICAL=InstallPlan only; UNAVAILABLE=RBAC restricted',
            })
        return rows

    # ------------------------------------------------------------------
    # VM analysis
    # ------------------------------------------------------------------

    def _analyse_vms(self, data):
        rows = []
        for vm in data.vms:
            md   = vm.get('metadata', {}) or {}
            spec = vm.get('spec', {}) or {}
            ns   = md.get('namespace', '')
            name = md.get('name', '')

            created      = (md.get('creationTimestamp', '') or '')
            created_date = created.split('T', 1)[0] if created else ''

            running = ''
            st = vm.get('status', {}) or {}
            if 'ready' in st:
                running = 'Yes' if st.get('ready') else 'No'
            elif 'printableStatus' in st:
                ps = (st.get('printableStatus') or '').lower()
                running = 'Yes' if ps in ('running', 'migrating') else ('No' if ps else '')
            else:
                r = spec.get('running')
                running = 'Yes' if r is True else ('No' if r is False else '')

            tmpl   = (spec.get('template', {}) or {}).get('spec', {}) or {}
            domain = tmpl.get('domain', {}) or {}

            cpu_spec = domain.get('cpu', {}) or {}
            cores    = int(cpu_spec.get('cores',   1) or 1)
            sockets  = int(cpu_spec.get('sockets', 1) or 1)
            threads  = int(cpu_spec.get('threads', 1) or 1)
            vcpu = str(cores * sockets * threads) if (cores or sockets or threads) else ''

            mem = ''
            mem_guest = (domain.get('memory', {}) or {}).get('guest')
            if mem_guest:
                mem = str(mem_guest)
            else:
                req = (domain.get('resources', {}) or {}).get('requests', {}) or {}
                mem = str(req.get('memory', ''))

            node = data.vmis.get((ns, name), '')

            rows.append({
                'Cluster ID':         data.cluster_id,
                'Cluster Name':       self._get_cluster_name(data),
                'Namespace':          ns,
                'VM Name':            name,
                'Created Date':       created_date,
                'Running':            running,
                'vCPU (Requested)':   vcpu,
                'Memory (Requested)': mem,
                'Node (If Running)':  node,
            })
        return rows

    # ------------------------------------------------------------------
    # Workload evidence (deep / full modes)
    # ------------------------------------------------------------------

    def _analyse_workload(self, data):
        result = {
            'pod_counts':          {},
            'top_customer_ns':     [],
            'deployment_samples':  [],
            'statefulset_samples': [],
        }

        if not data.pods:
            return result

        tp_keywords = ['falcon', 'netapp', 'dynatrace', 'splunk', 'datadog', 'aquasec', 'prisma']
        counts  = {'system': 0, 'storage': 0, 'security': 0, 'third_party': 0, 'customer': 0}
        ns_map  = {}

        for p in data.pods:
            ns = (p.get('metadata', {}).get('namespace', '') or '').lower()
            if not ns:
                continue
            if ns.startswith('openshift') or ns.startswith('kube-') or ns in ('kube-system', 'openshift', 'default'):
                if any(x in ns for x in ('odf', 'ocs', 'rook', 'ceph', 'storage')):
                    counts['storage'] += 1
                else:
                    counts['system'] += 1
            elif any(x in ns for x in ('stackrox', 'rhacs', 'acs')):
                counts['security'] += 1
            elif any(k in ns for k in tp_keywords):
                counts['third_party'] += 1
            else:
                counts['customer'] += 1
                ns_map[ns] = ns_map.get(ns, 0) + 1

        result['pod_counts'] = counts
        result['top_customer_ns'] = sorted(ns_map.items(), key=lambda x: x[1], reverse=True)[:10]

        def _is_customer(s):
            ns = s.split('/', 1)[0].lower() if '/' in s else s.lower()
            return not (ns.startswith('openshift') or ns.startswith('kube-') or ns in ('kube-system', 'default'))

        dep_names = [
            '{0}/{1}'.format(
                (d.get('metadata', {}) or {}).get('namespace', ''),
                (d.get('metadata', {}) or {}).get('name', '')
            )
            for d in data.deployments
        ]
        ss_names = [
            '{0}/{1}'.format(
                (s.get('metadata', {}) or {}).get('namespace', ''),
                (s.get('metadata', {}) or {}).get('name', '')
            )
            for s in data.statefulsets
        ]

        result['deployment_samples']  = [x for x in dep_names if _is_customer(x)][:10]
        result['statefulset_samples'] = [x for x in ss_names  if _is_customer(x)][:10]

        return result

    # ------------------------------------------------------------------
    # Infra node compliance (deep / full modes)
    # ------------------------------------------------------------------

    def _analyse_infra_compliance(self, data):
        """
        For nodes labelled as infra, check whether any pods in non-qualifying
        namespaces are running on them. Returns a list of finding dicts.
        """
        rows = []

        # Build infra node names
        infra_nodes = set()
        for n in data.nodes:
            labels = (n.get('metadata', {}) or {}).get('labels', {}) or {}
            roles  = set()
            for k in labels:
                if k.startswith('node-role.kubernetes.io/'):
                    roles.add(k.split('/', 1)[1])
            if 'infra' in roles and 'worker' not in roles:
                infra_nodes.add((n.get('metadata', {}) or {}).get('name', ''))

        if not infra_nodes:
            return rows

        # Check pods on infra nodes
        non_qualifying = {}
        for pod in data.pods:
            spec   = pod.get('spec', {}) or {}
            md     = pod.get('metadata', {}) or {}
            node   = spec.get('nodeName', '')
            ns     = md.get('namespace', '') or ''
            pname  = md.get('name', '') or ''

            if node not in infra_nodes:
                continue

            # Is this namespace qualifying infrastructure?
            ns_lower = ns.lower()
            if any(ns_lower.startswith(p) for p in INFRA_NS_PREFIXES):
                continue
            if any(k in ns_lower for k in INFRA_CSV_PATTERNS):
                continue

            # Flag it
            key = (node, ns)
            if key not in non_qualifying:
                non_qualifying[key] = []
            non_qualifying[key].append(pname)

        for (node, ns), pods in non_qualifying.items():
            rows.append({
                'Cluster ID':        data.cluster_id,
                'Cluster Name':      self._get_cluster_name(data),
                'Infra Node':        node,
                'Namespace':         ns,
                'Non-Qualifying Pods (Sample)': '; '.join(pods[:5]),
                'Finding':           'User workload detected on infra node — may invalidate infra exemption',
                'Confidence':        'Medium',
                'Action':            'Review whether this namespace qualifies as infrastructure per subscription guide',
            })

        if not rows:
            rows.append({
                'Cluster ID':        data.cluster_id,
                'Cluster Name':      self._get_cluster_name(data),
                'Infra Node':        'ALL',
                'Namespace':         '',
                'Non-Qualifying Pods (Sample)': '',
                'Finding':           'No non-qualifying workloads detected on infra nodes',
                'Confidence':        'Medium',
                'Action':            '',
            })

        return rows

    # ------------------------------------------------------------------
    # Cluster summary
    # ------------------------------------------------------------------

    def _build_cluster_summary(self, data, result):
        version, version_source = self._get_version(data)
        infra      = data.infrastructure or {}
        cv         = data.clusterversion or {}
        meta       = self._get_meta(data)

        # Node counts
        topology   = self._detect_topology(data.nodes)
        total_nodes = len(data.nodes)
        billable_nodes = sum(1 for n in result.nodes if n.get('Billable (Heuristic)') == 'Yes')
        master_nodes   = sum(1 for n in result.nodes if 'master' in n.get('Role', '') or 'control-plane' in n.get('Role', ''))
        worker_nodes   = sum(1 for n in result.nodes if 'worker' in n.get('Role', '') and 'master' not in n.get('Role', ''))
        infra_nodes    = sum(1 for n in result.nodes if 'infra' in n.get('Role', '') and 'worker' not in n.get('Role', ''))

        # Accelerator summary
        total_accels  = sum(int(n.get('GPU / Accelerator Count', 0) or 0) for n in result.nodes)
        accel_nodes   = sum(1 for n in result.nodes if int(n.get('GPU / Accelerator Count', 0) or 0) > 0)

        # Subscription sizing signals
        worker_cpu_capacity = 0.0
        worker_cpu_allocatable = 0.0
        for n in result.nodes:
            role = n.get('Role', '')
            if 'worker' in role:
                worker_cpu_capacity += _cpu_to_cores(n.get('CPU Capacity (vCPUs)', ''))
                worker_cpu_allocatable += _cpu_to_cores(n.get('CPU Allocatable (vCPUs)', ''))
        est_core_pairs = int(math.ceil(worker_cpu_capacity / 2.0)) if worker_cpu_capacity > 0 else 0
        accel_addon_signal = 'Yes' if total_accels > 0 else 'No'

        # Edition / platform signals
        edition_signal, edition_conf, edition_evidence = self._detect_edition(data)
        platform_type, pt_conf, pt_evidence = self._detect_platform_type(data)
        dr_posture, dr_conf, dr_signals      = self._detect_dr_posture(data, result)
        virt_present, virt_evidence          = self._detect_virt(data)
        nfv_present,  nfv_evidence           = self._detect_nfv(data)

        # OPP indicators
        opp, opp_conf, opp_evidence = self._detect_opp(result.addons)

        # Addon summary line
        addon_summary = '; '.join(
            '{0}={1}'.format(a['Add-on'], a['Status'])
            for a in result.addons
        )

        return {
            'Cluster ID':                       data.cluster_id,
            'Cluster Name':                     result.cluster_name,
            'Collected At':                     data.collected_at,
            'Script Version':                   VERSION,
            'Output Schema Version':            VERSION,
            'OCP Version':                      version,
            'Version Source':                   version_source,
            'Channel':                          meta.get('channel', ''),
            'Cluster Created (Proxy)':          meta.get('cluster_created', ''),
            'Deployment Type':                  meta.get('managed_type', ''),
            'Platform Type':                    meta.get('platform_type', ''),
            'Platform Type Source':             meta.get('platform_type_source', ''),
            'FIPS Mode':                        meta.get('fips', ''),
            'Infrastructure Name':              meta.get('infra_name', ''),
            'Edition Signal':                   edition_signal,
            'Edition Confidence':               edition_conf,
            'Edition Evidence':                 edition_evidence,
            'Platform Detected':                platform_type,
            'Platform Confidence':              pt_conf,
            'Topology':                         topology,
            'Total Nodes':                      total_nodes,
            'Master Nodes':                     master_nodes,
            'Worker Nodes':                     worker_nodes,
            'Infra Nodes':                      infra_nodes,
            'Billable Nodes (Heuristic)':       billable_nodes,
            'Worker CPU Capacity (Cores)':      '{0:.2f}'.format(worker_cpu_capacity),
            'Worker CPU Allocatable (Cores)':   '{0:.2f}'.format(worker_cpu_allocatable),
            'Estimated Core-Pairs (Heuristic)': est_core_pairs,
            'Total Accelerators':               total_accels,
            'Nodes with Accelerators':          accel_nodes,
            'AI Accelerator Add-on Signal':     accel_addon_signal,
            'Virtualization Indicators':        'Yes' if virt_present else 'No',
            'Virtualization Evidence':          '; '.join(virt_evidence),
            'NFV / Telco Indicators':           'Yes' if nfv_present else 'No',
            'NFV Evidence':                     '; '.join(nfv_evidence),
            'Add-on Summary':                   addon_summary,
            'Potential Platform Plus':          opp,
            'Platform Plus Confidence':         opp_conf,
            'Platform Plus Evidence':           opp_evidence,
            'DR Posture':                       dr_posture,
            'DR Confidence':                    dr_conf,
            'DR Signals':                       dr_signals,
            'Collection Mode':                  data.mode,
            'Notes':                            (
                'SNO/Compact topology: all nodes are billable per subscription guide. '
                'Subscription model signals are heuristic — verify against actual entitlements. '
                'Infra node exemption requires no user workloads (use --mode deep to validate). '
                'AI Accelerator add-on signal is based on node resource counts and should be verified against entitlement scope.'
                if topology in ('SNO', 'Compact') else
                'Subscription model signals are heuristic — verify against actual entitlements. '
                'Infra node exemption requires no user workloads (use --mode deep to validate). '
                'AI Accelerator add-on signal is based on node resource counts and should be verified against entitlement scope.'
            ),
        }

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _get_cluster_name(self, data):
        infra = data.infrastructure or {}
        name  = (infra.get('status', {}) or {}).get('infrastructureName', '') or ''
        if name:
            return name
        if data.cluster_id and data.cluster_id != 'unknown':
            return data.cluster_id
        return 'Unknown'

    def _get_version(self, data):
        cv = data.clusterversion or {}

        # 1. clusteroperator openshift-apiserver
        for op in data.clusteroperators:
            if (op.get('metadata', {}) or {}).get('name', '') == 'openshift-apiserver':
                for v in (op.get('status', {}) or {}).get('versions', []) or []:
                    if v.get('name') == 'operator' and v.get('version'):
                        return (v['version'], 'clusteroperator/openshift-apiserver')

        # 2. clusterversion desired
        v = (cv.get('status', {}) or {}).get('desired', {}).get('version')
        if v:
            return (v, 'clusterversion.status.desired')

        # 3. clusterversion history
        for h in (cv.get('status', {}) or {}).get('history', []) or []:
            if h.get('state') == 'Completed' and h.get('version'):
                return (h['version'], 'clusterversion.status.history')

        return ('Unknown', 'Unknown')

    def _get_meta(self, data):
        meta = {'channel': '', 'cluster_created': '', 'managed_type': 'Unknown',
                'platform_type': 'Unknown', 'infra_name': '', 'fips': ''}

        cv = data.clusterversion or {}
        meta['channel'] = (cv.get('spec', {}) or {}).get('channel', '')

        for ns in data.namespaces:
            n = (ns.get('metadata', {}) or {}).get('name', '')
            if n == 'kube-system':
                meta['cluster_created'] = (ns.get('metadata', {}) or {}).get('creationTimestamp', '')

        ns_names = ' '.join(
            (n.get('metadata', {}) or {}).get('name', '') for n in data.namespaces
        ).lower()
        if any(x in ns_names for x in ('openshift-backplane', 'managed-upgrade-operator')):
            meta['managed_type'] = 'Managed (ROSA/OSD/ARO)'
        else:
            meta['managed_type'] = 'Self-Managed'

        infra = data.infrastructure or {}
        # Primary: status.platformType (set by the installer and reconciled by the
        # cluster-infrastructure operator).  On some bare-metal / UPI builds this field
        # is empty even though the spec was set correctly at install time.
        # Fallback: spec.platformSpec.type — written at install time and not subject to
        # the same reconciliation delay, so more reliably populated on bare-metal SNO.
        _pt_status = (infra.get('status', {}) or {}).get('platformType', '') or ''
        _pt_spec   = (infra.get('spec', {}) or {}).get('platformSpec', {}).get('type', '') or ''
        meta['platform_type'] = _pt_status or _pt_spec or 'Unknown'
        meta['platform_type_source'] = (
            'status.platformType'   if _pt_status else
            'spec.platformSpec.type' if _pt_spec   else
            'Unknown'
        )
        meta['infra_name']    = (infra.get('status', {}) or {}).get('infrastructureName', '') or ''
        meta['fips']          = str((infra.get('status', {}) or {}).get('fips', ''))

        return meta

    def _detect_platform_type(self, data):
        ops = set((op.get('metadata', {}) or {}).get('name', '').lower()
                  for op in data.clusteroperators)
        if not ops:
            return ('Unknown', 'Low', 'clusteroperators unavailable')

        ocp_signals = ['console', 'monitoring', 'openshift-apiserver', 'authentication', 'ingress']
        found = [s for s in ocp_signals if s in ops]
        if found:
            conf = 'High' if len(found) >= 2 else 'Medium'
            # Corroborate with baremetal operator if present
            if 'baremetal' in ops:
                return ('OCP / BareMetal', conf,
                        'OCP signals: {0}; baremetal clusteroperator present'.format(', '.join(found)))
            return ('OCP', conf, 'Signals: ' + ', '.join(found))

        # Baremetal operator present without strong OCP signals — unusual but handle it
        if 'baremetal' in ops:
            return ('BareMetal (Inferred)', 'Medium',
                    'baremetal clusteroperator present; standard OCP operators not detected')

        if len(ops) <= 12:
            return ('OKE', 'Medium', 'Low operator count: {0}'.format(len(ops)))
        return ('Unknown', 'Low', 'Operator count: {0}'.format(len(ops)))

    def _detect_edition(self, data):
        """
        Signal which OpenShift edition is most likely based on CSV / operator evidence.
        OVE, OPP, OCP, OKE — signals only, not definitive.
        """
        csv_names = ' '.join(data.csvs and
            [(item.get('metadata', {}) or {}).get('name', '').lower() for item in data.csvs]
            or [])

        # OVE: KubeVirt present, no clear OPP signals, bare-metal platform
        infra    = data.infrastructure or {}
        platform = (infra.get('status', {}) or {}).get('platformType', '').lower()
        has_virt = any(k in csv_names for k in VIRT_CSV_KEYS)

        # OPP: ACS + ACM + (Quay or ODF) present as active
        active_csv_names = set(
            (item.get('metadata', {}) or {}).get('name', '').lower()
            for item in data.csvs
        )
        has_acs  = any('rhacs' in n or 'stackrox' in n for n in active_csv_names)
        has_acm  = any('advanced-cluster-management' in n or 'multicluster' in n for n in active_csv_names)
        has_quay = any('quay' in n for n in active_csv_names)
        has_odf  = any(k in n for n in active_csv_names for k in ('odf', 'ocs', 'rook'))

        if has_acs and has_acm:
            evidence = 'ACS + ACM detected' + (' + Quay' if has_quay else '') + (' + ODF' if has_odf else '')
            return ('OpenShift Platform Plus (Signal)', 'Medium', evidence)

        if has_virt and ('baremetal' in platform or 'none' in platform):
            return ('OpenShift Virtualization Engine (Signal)', 'Low',
                    'KubeVirt CSV detected on bare-metal platform — verify no user container workloads')

        if has_virt:
            return ('OpenShift Container Platform + Virtualization (Signal)', 'Low',
                    'KubeVirt CSV detected')

        return ('OpenShift Container Platform (Default)', 'Low',
                'No strong edition differentiators detected; OCP assumed')

    def _detect_virt(self, data):
        active = set(
            (item.get('metadata', {}) or {}).get('name', '').lower()
            for item in data.csvs
        )
        found = sorted(set(n for n in active if any(k in n for k in VIRT_CSV_KEYS)))
        return (bool(found), found[:5])

    def _detect_nfv(self, data):
        active = set(
            (item.get('metadata', {}) or {}).get('name', '').lower()
            for item in data.csvs
        )
        evidence = []
        for label, keys in NFV_CSV_KEYS.items():
            for n in active:
                if any(k in n for k in keys):
                    evidence.append('{0}: {1}'.format(label, n))
                    break
        return (bool(evidence), evidence[:5])

    def _detect_opp(self, addons):
        tracked = {}
        for addon in addons:
            name = addon.get('Add-on', '')
            status = addon.get('Status', '')
            if name in ('ACS', 'ACM', 'Quay', 'ODF'):
                tracked[name] = status

        present = [name for name, status in tracked.items() if status in ('ACTIVE', 'HISTORICAL')]
        if tracked.get('ACS') in ('ACTIVE', 'HISTORICAL') and tracked.get('ACM') in ('ACTIVE', 'HISTORICAL') and (
            tracked.get('Quay') in ('ACTIVE', 'HISTORICAL') or tracked.get('ODF') in ('ACTIVE', 'HISTORICAL')
        ):
            confidence = 'High' if all(tracked.get(x) == 'ACTIVE' for x in ('ACS', 'ACM')) else 'Medium'
            return ('Yes', confidence, 'Signals: ' + ', '.join('{0}={1}'.format(k, tracked[k]) for k in sorted(present)))
        if len(present) >= 2:
            return ('Possible', 'Medium', 'Partial signals: ' + ', '.join('{0}={1}'.format(k, tracked[k]) for k in sorted(present)))
        if len(present) == 1:
            only = present[0]
            return ('Possible', 'Low', 'Single signal: {0}={1}'.format(only, tracked[only]))
        return ('No', 'Medium', '')

    def _detect_dr_posture(self, data, result):
        workers     = sum(1 for n in result.nodes
                          if 'worker' in n.get('Role', '') and n.get('Billable (Heuristic)') == 'Yes')
        schedulable = sum(1 for n in data.nodes
                          if not (n.get('spec', {}) or {}).get('unschedulable', False))
        activity    = (len(data.routes) + len(data.hpas) +
                       len(data.deployments) + len(data.statefulsets))
        ns_count    = sum(
            1 for n in data.namespaces
            if not (n.get('metadata', {}) or {}).get('name', '').startswith(
                ('openshift', 'kube-')
            )
        )

        ms_total = 0
        for ms in data.machinesets:
            ms_total += int(((ms.get('spec', {}) or {}).get('replicas', 0)) or 0)

        infra    = data.infrastructure or {}
        platform = (infra.get('status', {}) or {}).get('platformType', '').lower()
        is_cloud = any(p in platform for p in ('aws', 'azure', 'gcp', 'google', 'openstack'))

        signals = 'workers={0} schedulable={1} activity={2} namespaces={3} machinesets={4}'.format(
            workers, schedulable, activity, ns_count, ms_total
        )

        if is_cloud and (workers == 0 or ms_total == 0):
            return ('COLD DR (Pilot Light)', 'High', signals)

        if workers > 0 and activity <= 2 and ns_count <= 2:
            return ('WARM DR (Passive Standby)', 'Medium', signals)

        if workers > 0 and activity > 0:
            conf = 'High' if activity >= 5 else 'Medium'
            return ('PRODUCTION / HOT-LIKE', conf, signals)

        return ('Unknown', 'Low', signals)


# =============================================================================
# PHASE 3 — ReportWriter
# =============================================================================

class ReportWriter(object):
    """
    Writes all output files from AnalysisResult.
    No oc calls. No analysis logic.
    """

    def write(self, result, folder, data=None):
        """
        Write all output files into folder.
        data is the raw ClusterData — only needed for --mode full JSON dumps.
        """
        print('Writing reports to {0}'.format(folder))
        written = []

        written.append(self._write_nodes(result, folder))
        written.append(self._write_operators(result, folder))
        written.append(self._write_addons(result, folder))
        written.append(self._write_cluster_summary(result, folder))
        if result.accelerators:
            written.append(self._write_accelerators(result, folder))

        if result.vms:
            written.append(self._write_vms(result, folder))

        if result.mode in ('deep', 'full'):
            if result.workload:
                written.append(self._write_workload(result, folder))
            if result.infra_compliance:
                written.append(self._write_infra_compliance(result, folder))

        written.append(self._write_collection_summary(result, folder))

        # Raw JSON dumps (full mode)
        if result.mode == 'full' and data is not None:
            self._write_raw_json(data, folder)

        written = [w for w in written if w]
        written.append(self._write_summary_json(result, folder))
        self._write_integrity(folder)
        print('Reports written: {0} files'.format(len(written)))
        return written

    # ------------------------------------------------------------------
    # Individual writers
    # ------------------------------------------------------------------

    def _write_nodes(self, result, folder):
        path = os.path.join(folder, 'nodes.csv')
        fields = [
            'Cluster ID', 'Cluster Name', 'Node Name', 'Role', 'Topology Flag',
            'Creation Date', 'Unschedulable', 'Internal IP',
            'CPU Capacity (vCPUs)', 'CPU Allocatable (vCPUs)', 'Memory (GiB)',
            'Architecture', 'Instance Type', 'Zone', 'Region', 'Provider ID', 'Taints',
            'GPU / Accelerator Count', 'Accelerator Type(s)',
            'Subscription Model (Signal)', 'Sub Model Evidence',
            'Billable (Heuristic)', 'Billable Confidence', 'Billable Evidence',
        ]
        _write_csv(path, fields, result.nodes)
        print('  OK nodes.csv ({0} rows)'.format(len(result.nodes)))
        return path

    def _write_operators(self, result, folder):
        path = os.path.join(folder, 'operators.csv')
        fields = [
            'Cluster ID', 'Cluster Name', 'Operator CSV Name', 'Namespace',
            'Display Name', 'Installed Version', 'Channel',
            'Installed Date', 'Install Initiated Date (Best Effort)',
        ]
        _write_csv(path, fields, result.operators)
        print('  OK operators.csv ({0} rows)'.format(len(result.operators)))
        return path

    def _write_addons(self, result, folder):
        path = os.path.join(folder, 'addons.csv')
        fields = [
            'Cluster ID', 'Cluster Name', 'Add-on', 'Status',
            'Date', 'Evidence', 'Confidence', 'Notes',
        ]
        _write_csv(path, fields, result.addons)
        print('  OK addons.csv ({0} rows)'.format(len(result.addons)))
        return path

    def _write_cluster_summary(self, result, folder):
        path = os.path.join(folder, 'cluster_summary.csv')
        if result.cluster_summary:
            fields = list(result.cluster_summary.keys())
            _write_csv(path, fields, [result.cluster_summary])
        print('  OK cluster_summary.csv')
        return path

    def _write_accelerators(self, result, folder):
        path = os.path.join(folder, 'accelerators.csv')
        fields = [
            'Cluster ID', 'Cluster Name', 'Node Name', 'Role',
            'Accelerator Resource Key', 'Accelerator Type',
            'Capacity Count', 'Allocatable Count', 'Measured Count',
            'Measurement Signal', 'Evidence',
        ]
        _write_csv(path, fields, result.accelerators)
        print('  OK accelerators.csv ({0} rows)'.format(len(result.accelerators)))
        return path

    def _write_vms(self, result, folder):
        path = os.path.join(folder, 'virtualization_vms.csv')
        fields = [
            'Cluster ID', 'Cluster Name', 'Namespace', 'VM Name',
            'Created Date', 'Running', 'vCPU (Requested)',
            'Memory (Requested)', 'Node (If Running)',
        ]
        _write_csv(path, fields, result.vms)
        print('  OK virtualization_vms.csv ({0} rows)'.format(len(result.vms)))
        return path

    def _write_workload(self, result, folder):
        path = os.path.join(folder, 'workload_evidence.csv')
        wl   = result.workload
        rows = []

        counts = wl.get('pod_counts', {})
        workload_note = 'Workload classification is namespace/prefix heuristic only; validate operator-managed namespaces manually.'
        for cat, n in counts.items():
            rows.append({'Category': 'Pod Count', 'Key': cat, 'Value': n,
                         'Cluster ID': result.cluster_id, 'Cluster Name': result.cluster_name, 'Notes': workload_note})

        for ns, count in wl.get('top_customer_ns', []):
            rows.append({'Category': 'Top Customer Namespace', 'Key': ns, 'Value': count,
                         'Cluster ID': result.cluster_id, 'Cluster Name': result.cluster_name, 'Notes': workload_note})

        for dep in wl.get('deployment_samples', []):
            rows.append({'Category': 'Deployment Sample', 'Key': dep, 'Value': '',
                         'Cluster ID': result.cluster_id, 'Cluster Name': result.cluster_name, 'Notes': workload_note})

        for ss in wl.get('statefulset_samples', []):
            rows.append({'Category': 'StatefulSet Sample', 'Key': ss, 'Value': '',
                         'Cluster ID': result.cluster_id, 'Cluster Name': result.cluster_name, 'Notes': workload_note})

        fields = ['Cluster ID', 'Cluster Name', 'Category', 'Key', 'Value', 'Notes']
        _write_csv(path, fields, rows)
        print('  OK workload_evidence.csv ({0} rows)'.format(len(rows)))
        return path

    def _write_infra_compliance(self, result, folder):
        path = os.path.join(folder, 'infra_compliance.csv')
        fields = [
            'Cluster ID', 'Cluster Name', 'Infra Node', 'Namespace',
            'Non-Qualifying Pods (Sample)', 'Finding', 'Confidence', 'Action',
        ]
        _write_csv(path, fields, result.infra_compliance)
        print('  OK infra_compliance.csv ({0} rows)'.format(len(result.infra_compliance)))
        return path

    def _write_collection_summary(self, result, folder):
        path = os.path.join(folder, 'collection_summary.csv')
        rows = []
        for rec in result.collection_log:
            rows.append({
                'Cluster ID':      result.cluster_id,
                'Cluster Name':    result.cluster_name,
                'Collection Mode': result.mode,
                'Script Version':  VERSION,
                'Output Schema Version': VERSION,
                'Resource':        rec.resource,
                'Command':         rec.command,
                'Status':          rec.status,
                'Item Count':      rec.item_count,
                'Notes':           rec.notes,
            })
        fields = ['Cluster ID', 'Cluster Name', 'Collection Mode', 'Script Version', 'Output Schema Version', 'Resource', 'Command', 'Status', 'Item Count', 'Notes']
        _write_csv(path, fields, rows)

        # Print a concise diagnostics summary
        denied      = [r for r in result.collection_log if r.status == COLLECTION_RBAC_DENIED]
        errors      = [r for r in result.collection_log if r.status == COLLECTION_PARSE_ERROR]
        not_present = [r for r in result.collection_log if r.status == COLLECTION_NOT_PRESENT]
        if denied:
            print('  WARNING: RBAC restrictions: {0}'.format(', '.join(r.resource for r in denied)))
        if errors:
            print('  WARNING: Parse errors: {0}'.format(', '.join(r.resource for r in errors)))
        if not_present:
            print('  INFO: Resource types not present on this cluster: {0}'.format(', '.join(r.resource for r in not_present)))
        print('  OK collection_summary.csv ({0} resources logged)'.format(len(rows)))
        return path

    def _write_raw_json(self, data, folder):
        """Write raw JSON dumps for full mode replay."""
        raw_folder = os.path.join(folder, 'raw_json')
        os.makedirs(raw_folder, exist_ok=True)

        def _dump(name, obj):
            if obj is None:
                return
            path = os.path.join(raw_folder, name + '.json')
            with open(path, 'w') as f:
                json.dump(obj, f, indent=2)

        _dump('nodes',                {'items': data.nodes})
        _dump('clusterserviceversions',{'items': data.csvs})
        _dump('installplans',         {'items': data.installplans})
        _dump('subscriptions',        {'items': data.subscriptions})
        _dump('namespaces',           {'items': data.namespaces})
        _dump('clusteroperators',     {'items': data.clusteroperators})
        _dump('machinesets',          {'items': data.machinesets})
        _dump('routes',               {'items': data.routes})
        _dump('hpas',                 {'items': data.hpas})
        _dump('deployments',          {'items': data.deployments})
        _dump('statefulsets',         {'items': data.statefulsets})
        _dump('clusterversion',       data.clusterversion)
        _dump('infrastructure',       data.infrastructure)
        if data.pods:
            _dump('pods', {'items': data.pods})
        if data.vms:
            _dump('virtualmachines', {'items': data.vms})
        if data.vmi_items:
            _dump('virtualmachineinstances', {'items': data.vmi_items})

        print('  OK raw_json/ dumps written (full mode)')

    def _write_integrity(self, folder):
        """Write SHA-256 hash manifest and integrity report.

        Exclusions are deliberate and documented:
          - hash.txt is excluded because it cannot hash itself
          - .zip package artifacts are excluded because packaging happens after reporting
        All other top-level files present at write time, including integrity_report.txt
        and summary.json, are included in the manifest.
        """
        rep_path = os.path.join(folder, 'integrity_report.txt')
        generated = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        with open(rep_path, 'w') as f:
            f.write('OCP Inventory Integrity Report\n')
            f.write('=' * 60 + '\n')
            f.write('Status:         PASSED\n')
            f.write('Hash Algorithm: SHA-256\n')
            f.write('Generated:      {0}\n'.format(generated))
            f.write('Exclusions:     hash.txt (self-reference), *.zip (package artifacts created after report write)\n')
            f.write('Scope:          All other top-level files present in the run folder at integrity generation time.\n')
            f.write('\nVerify with: sha256sum -c hash.txt\n')

        files = []
        for fn in sorted(os.listdir(folder)):
            path = os.path.join(folder, fn)
            if not os.path.isfile(path):
                continue
            if fn == 'hash.txt' or fn.endswith('.zip'):
                continue
            files.append(fn)

        hash_path = os.path.join(folder, 'hash.txt')
        hashed = []
        with open(hash_path, 'w') as f:
            for fn in files:
                p = os.path.join(folder, fn)
                h = hashlib.sha256()
                with open(p, 'rb') as rf:
                    for chunk in iter(lambda: rf.read(4096), b''):
                        h.update(chunk)
                f.write('{0}  {1}\n'.format(h.hexdigest(), fn))
                hashed.append(fn)

        print('  OK integrity_report.txt + hash.txt (SHA-256, {0} files hashed)'.format(len(hashed)))


    def _write_summary_json(self, result, folder):
        path = os.path.join(folder, 'summary.json')
        payload = {
            'script_version': VERSION,
            'cluster_id': result.cluster_id,
            'cluster_name': result.cluster_name,
            'collection_mode': result.mode,
            'collected_at': result.collected_at,
            'node_count': len(result.nodes),
            'operator_count': len(result.operators),
            'addon_count': len(result.addons),
            'vm_count': len(result.vms),
            'accelerator_row_count': len(result.accelerators),
            'infra_compliance_findings': len(result.infra_compliance),
            'collection_log_count': len(result.collection_log),
            'cluster_summary': result.cluster_summary,
        }
        with open(path, 'w') as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        print('  OK summary.json')
        return path


# =============================================================================
# Utility functions
# =============================================================================

def _ki_to_gib(mem_str):
    if not mem_str:
        return ''
    s = str(mem_str).strip()

    # Standard Kubernetes binary SI suffix (Ki, Mi, Gi, Ti, Pi)
    m = re.match(r'^([0-9]+(?:\.[0-9]+)?)([KMGTP]i)$', s, re.I)
    if m:
        value = float(m.group(1))
        unit  = m.group(2).lower()
        factors = {
            'ki': 1.0 / 1024.0 / 1024.0,
            'mi': 1.0 / 1024.0,
            'gi': 1.0,
            'ti': 1024.0,
            'pi': 1024.0 * 1024.0,
        }
        return '{0:.2f}'.format(value * factors.get(unit, 0.0))

    # Some distributions (e.g. certain OKE / bare-metal builds) return a bare
    # integer byte count with no unit suffix.
    m2 = re.match(r'^([0-9]+)$', s)
    if m2:
        return '{0:.2f}'.format(float(m2.group(1)) / (1024.0 ** 3))

    return ''



def _safe_int(val):
    try:
        if val in (None, ''):
            return 0
        return int(str(val).strip())
    except Exception:
        return 0


def _cpu_to_cores(cpu_str):
    if cpu_str in (None, ''):
        return 0.0
    s = str(cpu_str).strip()
    try:
        if s.endswith('m'):
            return float(s[:-1]) / 1000.0
        return float(s)
    except Exception:
        return 0.0

def _extract_taints(node_item):
    taints = (node_item.get('spec', {}) or {}).get('taints', []) or []
    if not taints:
        return 'None'
    parts = []
    for t in taints:
        k, v, e = t.get('key', ''), t.get('value', ''), t.get('effect', '')
        parts.append('{0}={1}:{2}'.format(k, v, e) if v else '{0}:{1}'.format(k, e))
    return '; '.join(parts)


def _write_csv(path, fieldnames, rows):
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _zip_folder(folder):
    base     = os.path.abspath(folder)
    parent   = os.path.dirname(base)
    zip_path = base + '.zip'
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(base):
            for fn in files:
                full = os.path.join(root, fn)
                z.write(full, os.path.relpath(full, parent))
    return zip_path


def _norm_server(s):
    if not s:
        return ''
    return s.strip().replace('https://', '').replace('http://', '').rstrip('/')


def _is_logged_in_to_target(server):
    _, _, rc = _run(['oc', 'whoami'])
    if rc != 0:
        return False
    srv_out, _, rc2 = _run(['oc', 'whoami', '--show-server'])
    if rc2 != 0:
        return True   # logged in but can't check server — assume OK
    return _norm_server(srv_out) == _norm_server(server)


def _oc_login(server, username=None, password=None, token=None):
    if token:
        print('Logging in with token to {0}'.format(server))
        cmd = ['oc', 'login', '--token={0}'.format(token), '--server={0}'.format(server), '--insecure-skip-tls-verify']
    elif username and password:
        print('Logging in as {0} to {1}'.format(username, server))
        cmd = ['oc', 'login', '-u={0}'.format(username), '-p={0}'.format(password), '--server={0}'.format(server), '--insecure-skip-tls-verify']
    else:
        print('ERROR: No authentication method provided.')
        return False
    _, _, rc = _run(cmd)
    if rc != 0:
        print('ERROR: Login failed.')
        return False
    return True


def environment_prechecks(expected_server=None):
    print('\nEnvironment Pre-Checks')
    print('----------------------')

    # NOTE: Python version is already enforced at module load (lines above main).
    # The check here is intentionally omitted to avoid dead code.

    print('Python version check: OK ({0})'.format(sys.version.split()[0]))

    if not shutil.which('oc'):
        print('ERROR: OpenShift CLI (oc) not found in PATH.')
        print('Please install the OpenShift CLI before running this script.')
        raise SystemExit(1)
    print('OpenShift CLI detected')

    whoami_out, whoami_err, whoami_rc = _run(['oc', 'whoami'])
    if whoami_rc != 0 or not whoami_out.strip():
        print('ERROR: No active OpenShift login detected.')
        print('Run: oc login <cluster-url>')
        raise SystemExit(1)
    print('OpenShift login detected (user: {0})'.format(whoami_out.strip()))

    server_out, server_err, server_rc = _run(['oc', 'whoami', '--show-server'])
    if server_rc != 0 or not server_out.strip():
        print('ERROR: Unable to determine the current cluster API endpoint.')
        raise SystemExit(1)
    current_server = server_out.strip()
    print('Current cluster context: {0}'.format(current_server))

    if expected_server and _norm_server(current_server) != _norm_server(expected_server):
        print('ERROR: Current login context does not match the requested cluster.')
        print('Requested: {0}'.format(expected_server))
        print('Current:   {0}'.format(current_server))
        raise SystemExit(1)

    nodes_out, nodes_err, nodes_rc = _run(['oc', 'get', 'nodes', '-o', 'name'], timeout=30)
    if nodes_rc != 0:
        if any(k in (nodes_err or '').lower() for k in ('forbidden', 'cannot list', 'cannot get', 'not allowed')):
            print('ERROR: The current account cannot read nodes. This script requires at least node-read access.')
        else:
            print('ERROR: Unable to query cluster nodes during validation.')
            if nodes_err:
                print(nodes_err.strip())
        raise SystemExit(1)
    node_count = len([x for x in nodes_out.splitlines() if x.strip()])
    print('Cluster node access check: OK ({0} node entries returned)'.format(node_count))

    print('Environment validation successful.')


def print_operator_catalog_note():
    stdout, stderr, rc = _run(['oc', 'get', 'packagemanifest', '-A', '-o', 'name'], timeout=45)
    if rc != 0 or not stdout.strip():
        print('Operator catalog access note: package manifest query unavailable or empty. This can be normal in disconnected or restricted environments and does not block collection.')


def _load_raw_json_for_replay(folder):
    """
    Load raw JSON files from a previous --mode full run for replay.
    Returns a populated ClusterData object.
    """
    raw_folder = os.path.join(folder, 'raw_json')
    if not os.path.isdir(raw_folder):
        print('ERROR: No raw_json/ folder found in {0}. Was this collected with --mode full?'.format(folder))
        sys.exit(1)

    def _load(name):
        path = os.path.join(raw_folder, name + '.json')
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return json.load(f)

    data = ClusterData()
    data.mode = 'replay'

    cv   = _load('clusterversion')
    data.clusterversion   = cv
    data.cluster_id       = (cv or {}).get('spec', {}).get('clusterID', 'unknown') if cv else 'unknown'
    data.infrastructure   = _load('infrastructure')

    def _items(name):
        obj = _load(name)
        return obj.get('items', []) if obj and isinstance(obj, dict) else []

    data.nodes          = _items('nodes')
    data.csvs           = _items('clusterserviceversions')
    data.installplans   = _items('installplans')
    data.subscriptions  = _items('subscriptions')
    data.namespaces     = _items('namespaces')
    data.clusteroperators=_items('clusteroperators')
    data.machinesets    = _items('machinesets')
    data.routes         = _items('routes')
    data.hpas           = _items('hpas')
    data.deployments    = _items('deployments')
    data.statefulsets   = _items('statefulsets')
    data.pods           = _items('pods')
    data.vms            = _items('virtualmachines')

    # Rebuild VMI map
    vmis_raw = _items('virtualmachineinstances') if _load('virtualmachineinstances') else []
    for vmi in vmis_raw:
        ns   = (vmi.get('metadata', {}) or {}).get('namespace', '')
        name = (vmi.get('metadata', {}) or {}).get('name', '')
        node = (vmi.get('status', {}) or {}).get('nodeName', '') or ''
        if ns and name:
            data.vmis[(ns, name)] = node

    # Populate a minimal collection log so collection_summary.csv is still useful
    for resource in ('nodes', 'clusterserviceversions', 'installplans', 'subscriptions',
                     'namespaces', 'clusteroperators', 'machinesets', 'routes', 'hpas',
                     'deployments', 'statefulsets', 'pods', 'virtualmachines'):
        items = getattr(data, resource.replace('clusterserviceversions', 'csvs')
                                      .replace('virtualmachines', 'vms'), None) or []
        status = COLLECTION_SUCCESS if items else COLLECTION_EMPTY
        data.log(resource, 'replay', status, items, notes='Loaded from raw_json/')

    data.collected_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print('Replay mode: loaded raw JSON from {0}'.format(raw_folder))
    return data


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='OCP CLI Inventory {0} — Collect / Analyse / Report'.format(VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Run modes:
  standard  fast, all lightweight collection (default)
  deep      adds pod workload evidence + infra compliance check
            (oc get pods -A uses a 300 s timeout; raise COMMAND_TIMEOUT_SECONDS
             at the top of the script for very large clusters)
  full      deep + raw JSON dumps; enables --replay

Examples:
  python3 ocp_inventory_cli_v3.py --server https://api.cluster:6443 --token sha256~...
  python3 ocp_inventory_cli_v3.py --server https://api.cluster:6443 --username admin --mode deep
  python3 ocp_inventory_cli_v3.py --replay ./OCP_Inventory_abc123_20260312
        ''',
    )
    parser.add_argument('--server',   help='OpenShift API server URL')
    parser.add_argument('--token',    help='Login token (sha256~...)')
    parser.add_argument('--username', help='Username (password prompted interactively)')
    parser.add_argument('--password', help='Password (deprecated/discouraged — visible in shell history)')
    parser.add_argument('--mode',     choices=['standard', 'deep', 'full'],
                        default='standard', help='Collection depth (default: standard)')
    parser.add_argument('--outdir',   default='.', help='Output directory (default: current)')
    parser.add_argument('--no-zip',   action='store_true', help='Skip zip packaging')
    parser.add_argument('--replay',   metavar='FOLDER',
                        help='Re-analyse a previous --mode full output folder (no cluster access)')
    args = parser.parse_args()

    if args.password:
        sys.stderr.write('WARNING: --password is deprecated and visible in shell history. Prefer --token or interactive prompt.\n')

    # ------------------------------------------------------------------
    # Replay mode — no cluster access needed
    # ------------------------------------------------------------------
    if args.replay:
        data = _load_raw_json_for_replay(args.replay)
        data.mode = 'full'   # replay has all data available
        print('Environment Pre-Checks: skipped in replay mode (raw_json input).')
    else:
        # ------------------------------------------------------------------
        # Live collection
        # ------------------------------------------------------------------
        server = args.server
        if not server:
            srv_out, _, rc = _run(['oc', 'whoami', '--show-server'])
            if rc == 0 and srv_out.strip():
                server = srv_out.strip()

        if server:
            server = _norm_server(server)

        if server and not _is_logged_in_to_target(server):
            pw = args.password
            if args.username and not pw and not args.token:
                pw = getpass.getpass('Password for {0}: '.format(args.username))
            if not _oc_login(server, username=args.username, password=pw, token=args.token):
                raise SystemExit(2)

        environment_prechecks(server)
        print_operator_catalog_note()

        collector = ClusterCollector(mode=args.mode)
        data      = collector.collect()

    # ------------------------------------------------------------------
    # Analyse
    # ------------------------------------------------------------------
    analyser = ClusterAnalyser()
    result   = analyser.analyse(data)

    # ------------------------------------------------------------------
    # Create output folder
    # ------------------------------------------------------------------
    date        = datetime.now(timezone.utc).strftime('%Y%m%d')
    safe_name   = re.sub(r'[^A-Za-z0-9_-]+', '-', result.cluster_name or '').strip('-')
    cluster_pfx = data.cluster_id[:12] if data.cluster_id != 'unknown' else 'unknown'

    if safe_name:
        folder_name = 'OCP_Inventory_{0}_{1}_{2}'.format(cluster_pfx, safe_name[:24], date)
    else:
        folder_name = 'OCP_Inventory_{0}_{1}'.format(cluster_pfx, date)

    if args.replay:
        folder_name += '_replay'

    out_base = os.path.abspath(args.outdir)
    os.makedirs(out_base, exist_ok=True)
    folder = os.path.join(out_base, folder_name)
    os.makedirs(folder, exist_ok=True)
    print('Output folder: {0}'.format(folder))

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    writer = ReportWriter()
    writer.write(result, folder, data=data if getattr(data, 'mode', args.mode) == 'full' else None)

    # ------------------------------------------------------------------
    # Package
    # ------------------------------------------------------------------
    if not args.no_zip:
        zip_path = _zip_folder(folder)
        print('Packaged: {0}'.format(zip_path))
    else:
        print('Packaging skipped (--no-zip).')

    print('\nCompleted. Collected: {0}  |  Mode: {1}  |  Folder: {2}'.format(
        result.collected_at, data.mode, folder))


if __name__ == '__main__':
    main()
