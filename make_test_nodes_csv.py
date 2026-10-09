#!/usr/bin/env python3
"""
make_test_nodes_csv.py  —  v3

Generate a synthetic combined_nodes.csv for exercising billable_report_v3.py
without touching a real cluster.

The output matches the schema combine_ocp_outputs_v3.py writes, including the
Run Folder / Source Format / Schema Version columns it appends.

The 'Billable (Heuristic)' column is filled in the way the Red Hat collector
fills it -- that is, an infra node that also carries the worker role is marked
'Yes'. That is deliberate: it gives the report's reclassification logic
something to disagree with, which is the behaviour worth testing.

Clusters are shaped to cover the branches the report cares about:
  - infra nodes tainted NoSchedule            -> exempt, High confidence
  - infra nodes tainted NoExecute             -> exempt, High confidence
  - infra nodes with no taint                 -> exempt, Medium confidence
  - infra nodes tainted PreferNoSchedule      -> exempt, Medium (does not block)
  - infra nodes with no worker role           -> exempt
  - cordoned nodes, GPU nodes, mixed sizes    -> table rendering and totals

Usage:
  python3 make_test_nodes_csv.py
  python3 make_test_nodes_csv.py -o clusters/test_nodes.csv --seed 7
  python3 make_test_nodes_csv.py --clusters 8
"""

import argparse
import csv
import random
import sys
import uuid
from datetime import datetime, timedelta

SCHEMA = [
    'Cluster ID', 'Cluster Name', 'Node Name', 'Role', 'Topology Flag',
    'Creation Date', 'Unschedulable', 'Internal IP', 'CPU Capacity (vCPUs)',
    'CPU Allocatable (vCPUs)', 'Memory (GiB)', 'Architecture', 'Instance Type',
    'Zone', 'Region', 'Provider ID', 'Taints', 'GPU / Accelerator Count',
    'Accelerator Type(s)', 'Subscription Model (Signal)', 'Sub Model Evidence',
    'Billable (Heuristic)', 'Billable Confidence', 'Billable Evidence',
    'Run Folder', 'Source Format', 'Schema Version',
]

INFRA_TAINT_KEY = 'node-role.kubernetes.io/infra'
MASTER_TAINT = 'node-role.kubernetes.io/master:NoSchedule'

# Per-platform flavour: instance types as (name, vCPUs, GiB).
PLATFORMS = {
    'AWS': {
        'region': 'us-east-2',
        'zones': ['us-east-2a', 'us-east-2b', 'us-east-2c'],
        'master': ('m6a.xlarge', 4, 15.27),
        'worker': ('m6a.4xlarge', 16, 61.46),
        'infra': ('m6a.2xlarge', 8, 30.67),
        'gpu': ('g5.4xlarge', 16, 61.46),
        'provider': 'aws:///{zone}/i-{hex:017x}',
        'host': 'ip-{a}-{b}-{c}-{d}.{region}.compute.internal',
        'model': ('Core-Pair', 'ProviderID indicates cloud instance'),
    },
    'Azure': {
        'region': 'westeurope',
        'zones': ['westeurope-1', 'westeurope-2', 'westeurope-3'],
        'master': ('Standard_D4s_v5', 4, 15.31),
        'worker': ('Standard_D16s_v5', 16, 61.75),
        'infra': ('Standard_D8s_v5', 8, 30.84),
        'gpu': ('Standard_NC24ads_A100_v4', 24, 212.4),
        'provider': 'azure:///subscriptions/{uuid}/vm-{hex:08x}',
        'host': '{cluster}-node-{index:02d}',
        'model': ('Core-Pair', 'Cloud platform (azure) detected'),
    },
    'VSphere': {
        'region': '',
        'zones': ['', '', ''],
        'master': ('', 8, 31.27),
        'worker': ('', 16, 62.73),
        'infra': ('', 8, 31.27),
        'gpu': ('', 16, 125.5),
        'provider': 'vsphere://{uuid}',
        'host': '{cluster}-{role}-{index:02d}.lab.example.com',
        'model': ('Core-Pair', 'Hypervisor platform (vsphere) detected'),
    },
    'BareMetal': {
        'region': '',
        'zones': ['rack-a', 'rack-b', 'rack-c'],
        'master': ('', 32, 125.4),
        'worker': ('', 64, 502.1),
        'infra': ('', 32, 251.0),
        'gpu': ('', 64, 1004.2),
        'provider': '',
        'host': '{cluster}-{role}-{index:02d}.dc.example.com',
        'model': ('Bare-Metal Node', 'No ProviderID present'),
    },
}

ACCELERATORS = ['nvidia.com/gpu', 'amd.com/gpu', 'habana.ai/gaudi']

# (name suffix, platform, workers, infra, infra taint effect, infra keeps
#  worker role, gpu workers, cordoned workers)
CLUSTER_SHAPES = [
    ('prod-emea',   'AWS',       6, 3, 'NoSchedule',       True,  0, 0),
    ('prod-amer',   'Azure',     8, 3, 'NoExecute',        True,  2, 1),
    ('stage-core',  'VSphere',   4, 2, None,               True,  0, 0),
    ('dev-sandbox', 'AWS',       3, 2, 'PreferNoSchedule', True,  0, 1),
    ('edge-dc1',    'BareMetal', 5, 3, 'NoSchedule',       False, 0, 0),
    ('ai-training', 'AWS',       4, 3, 'NoSchedule',       True,  4, 0),
    ('prod-apac',   'Azure',     7, 3, 'NoSchedule',       True,  0, 2),
    ('qa-shared',   'VSphere',   5, 2, 'NoSchedule',       True,  1, 0),
]


def collector_verdict(roles, topology):
    """
    Reproduce ocp_inventory_cli_v3._billable, bug and all, so the generated
    data looks like something the real collector produced.
    """
    r = set(roles)
    if topology in ('SNO', 'Compact'):
        return ('Yes', 'High',
                'All nodes billable in {0} topology per subscription guide'.format(topology))
    if 'master' in r or 'control-plane' in r:
        return ('No', 'High', 'Control plane node — exempt')
    if 'infra' in r and 'worker' not in r:
        return ('No', 'Medium', 'Infra-only node — exempt (verify no user workloads)')
    return ('Yes', 'High', 'Worker node — billable')


def build_node(rng, cluster, platform_name, role_list, index, kind,
               taint=None, cordoned=False, gpus=0):
    plat = PLATFORMS[platform_name]
    instance, vcpus, mem = plat[kind]
    zone = rng.choice(plat['zones'])

    host = plat['host'].format(
        a=10, b=rng.randint(0, 3), c=rng.randint(0, 63), d=rng.randint(2, 250),
        region=plat['region'], cluster=cluster['name'],
        role=role_list[0].replace('control-plane', 'master'), index=index)

    provider = ''
    if plat['provider']:
        provider = plat['provider'].format(
            zone=zone, hex=rng.getrandbits(68), uuid=str(uuid.UUID(int=rng.getrandbits(128))))

    # Allocatable is capacity less kubelet/system reservation.
    alloc = '{0}m'.format(int(vcpus * 1000 - 500))

    created = cluster['created'] + timedelta(days=rng.randint(0, 20))
    model, model_evidence = plat['model']
    verdict, confidence, evidence = collector_verdict(role_list, cluster['topology'])

    accel_type = ''
    if gpus:
        accel_type = rng.choice(ACCELERATORS)

    return {
        'Cluster ID': cluster['id'],
        'Cluster Name': cluster['name'],
        'Node Name': host,
        'Role': ','.join(sorted(role_list)),
        'Topology Flag': cluster['topology'],
        'Creation Date': created.strftime('%Y-%m-%d'),
        'Unschedulable': 'True' if cordoned else 'False',
        'Internal IP': '10.{0}.{1}.{2}'.format(
            rng.randint(0, 3), rng.randint(0, 63), rng.randint(2, 250)),
        'CPU Capacity (vCPUs)': str(vcpus),
        'CPU Allocatable (vCPUs)': alloc,
        'Memory (GiB)': '{0:.2f}'.format(mem),
        'Architecture': 'amd64',
        'Instance Type': instance,
        'Zone': zone,
        'Region': plat['region'],
        'Provider ID': provider,
        'Taints': taint or 'None',
        'GPU / Accelerator Count': str(gpus),
        'Accelerator Type(s)': accel_type,
        'Subscription Model (Signal)': model,
        'Sub Model Evidence': model_evidence,
        'Billable (Heuristic)': verdict,
        'Billable Confidence': confidence,
        'Billable Evidence': evidence,
        'Run Folder': 'OCP_Inventory_{0}_{1}_{2}'.format(
            cluster['id'][:13], cluster['name'], cluster['created'].strftime('%Y%m%d')),
        'Source Format': 'v3',
        'Schema Version': 'v3',
    }


def build_cluster(rng, shape, base_date):
    (suffix, platform_name, n_workers, n_infra, infra_effect,
     infra_keeps_worker, n_gpu, n_cordoned) = shape

    cluster = {
        'id': str(uuid.UUID(int=rng.getrandbits(128))),
        'name': 'cluster-{0}'.format(suffix),
        'topology': 'Standard',
        'created': base_date - timedelta(days=rng.randint(30, 400)),
    }

    rows = []
    index = 0

    # Three control plane nodes, always.
    for _ in range(3):
        index += 1
        rows.append(build_node(rng, cluster, platform_name,
                               ['control-plane', 'master'], index, 'master',
                               taint=MASTER_TAINT))

    # Workers, some of them GPU-bearing, some cordoned.
    for i in range(n_workers):
        index += 1
        is_gpu = i < n_gpu
        rows.append(build_node(
            rng, cluster, platform_name, ['worker'], index,
            'gpu' if is_gpu else 'worker',
            cordoned=(i < n_cordoned),
            gpus=rng.choice([1, 2, 4]) if is_gpu else 0))

    # Infra nodes. Real machine sets derived from the worker template leave the
    # worker role in place, so that is the default here.
    infra_roles = ['infra', 'worker'] if infra_keeps_worker else ['infra']
    if infra_effect:
        infra_taint = '{0}=reserved:{1}'.format(INFRA_TAINT_KEY, infra_effect)
    else:
        infra_taint = None

    for _ in range(n_infra):
        index += 1
        rows.append(build_node(rng, cluster, platform_name, infra_roles,
                               index, 'infra', taint=infra_taint))

    return rows


def main():
    parser = argparse.ArgumentParser(
        description='Generate a synthetic combined_nodes.csv for testing '
                    'billable_report_v3.py.')
    parser.add_argument('-o', '--output', default='clusters/test_combined_nodes.csv',
                        help='Output CSV path (default: %(default)s)')
    parser.add_argument('--clusters', type=int, default=6,
                        help='How many clusters to generate, 1-{0} (default: %(default)s)'
                             .format(len(CLUSTER_SHAPES)))
    parser.add_argument('--seed', type=int, default=20261009,
                        help='Random seed, for reproducible output (default: %(default)s)')
    args = parser.parse_args()

    if not 1 <= args.clusters <= len(CLUSTER_SHAPES):
        parser.error('--clusters must be between 1 and {0}'.format(len(CLUSTER_SHAPES)))

    rng = random.Random(args.seed)
    base_date = datetime(2026, 10, 9)

    rows = []
    for shape in CLUSTER_SHAPES[:args.clusters]:
        rows.extend(build_cluster(rng, shape, base_date))

    with open(args.output, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=SCHEMA)
        writer.writeheader()
        writer.writerows(rows)

    # Summarise what was written, so the expected numbers are visible up front.
    print('Wrote {0}'.format(args.output))
    print('  {0} cluster(s), {1} node(s)\n'.format(args.clusters, len(rows)))

    header = '  {0:<22} {1:>3} {2:>3} {3:>3} {4:>3}  {5}'
    print(header.format('CLUSTER', 'CP', 'WRK', 'INF', 'GPU', 'INFRA TAINT'))
    for shape in CLUSTER_SHAPES[:args.clusters]:
        suffix, platform_name, n_workers, n_infra, effect, keeps_worker, n_gpu, _ = shape
        taint = effect or 'none'
        if not keeps_worker:
            taint += ' (infra role only)'
        print(header.format('cluster-' + suffix, 3, n_workers, n_infra, n_gpu, taint))

    print('\nTest it with:')
    print('  python3 billable_report_v3.py --input {0}'.format(args.output))
    return 0


if __name__ == '__main__':
    sys.exit(main())
