#!/usr/bin/env python3
"""
billable_report_v3.py  —  v3

Produce a PDF report of billable items from one or more OCP CLI Inventory run
folders (the OCP_Inventory_<id>_<cluster>_<date> directories written by
ocp_inventory_cli_v3.py).

The report answers the subscription question directly:
  - how many nodes in the cluster are billable
  - which nodes they are, and why each one counts
  - which nodes are exempt, and on what evidence
  - the core-pair sizing signal that follows from the billable footprint
  - which billable add-ons / Platform Plus signals were detected

Reads (per run folder, all optional except nodes.csv):
  nodes.csv            — per-node billable verdict, roles, CPU, accelerators
  cluster_summary.csv  — cluster-level counts and sizing signals
  summary.json         — same signals, machine-readable (used as a fallback)
  addons.csv           — ACS / ACM / ODF / Quay detection
  operators.csv        — installed operator subscriptions

Billable verdicts are read from the 'Billable (Heuristic)' column when present.
For legacy (v2.x) outputs without that column the verdict is re-derived from
Role + Topology using the same rules as ocp_inventory_cli_v3.py:
  - SNO / Compact topology : every node is billable (masters run workloads)
  - Standard topology      : control-plane exempt, infra-only exempt, workers billable

Usage:
  python3 billable_report_v3.py OCP_Inventory_<id>_<cluster>_<date>
  python3 billable_report_v3.py run_a run_b run_c -o estate_billable.pdf
  python3 billable_report_v3.py --input ./all_runs

Requires: reportlab  (pip install reportlab)
"""

import argparse
import csv
import json
import math
import os
import sys
from datetime import datetime

SCRIPT_VERSION = 'v3'

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph,
                                    SimpleDocTemplate, Spacer, Table,
                                    TableStyle)
    HAVE_REPORTLAB = True
except ImportError:
    HAVE_REPORTLAB = False

# ---------------------------------------------------------------------------
# Palette — restrained, prints legibly in mono
# ---------------------------------------------------------------------------

INK        = colors.HexColor('#1f2933')
MUTED      = colors.HexColor('#5c6b7a')
RULE       = colors.HexColor('#c9d2da')
BAND       = colors.HexColor('#f2f5f7')
HEAD_BG    = colors.HexColor('#2f3e4e')
BILLABLE   = colors.HexColor('#9a3412')
EXEMPT     = colors.HexColor('#2f6f4f')

ADDON_NAMES = ('ACS', 'ACM', 'ODF', 'Quay')

# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------


def read_csv_rows(path):
    """Return a list of dict rows, or [] if the file is missing/unreadable."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', newline='', encoding='utf-8-sig') as fh:
            return [row for row in csv.DictReader(fh) if any(
                (v or '').strip() for v in row.values())]
    except Exception as exc:
        sys.stderr.write('WARNING: could not read {0}: {1}\n'.format(path, exc))
        return []


def read_json(path):
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception as exc:
        sys.stderr.write('WARNING: could not read {0}: {1}\n'.format(path, exc))
        return {}


def cpu_to_cores(cpu_str):
    """Mirror of ocp_inventory_cli_v3._cpu_to_cores — handles '16' and '15500m'."""
    if cpu_str in (None, ''):
        return 0.0
    s = str(cpu_str).strip()
    try:
        if s.endswith('m'):
            return float(s[:-1]) / 1000.0
        return float(s)
    except ValueError:
        return 0.0


def to_int(value, default=0):
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def is_run_folder(path):
    return os.path.isdir(path) and os.path.isfile(os.path.join(path, 'nodes.csv'))


def find_run_folders(paths, scan_root=None):
    """Resolve CLI arguments into a sorted list of run folders."""
    folders = []
    for p in paths:
        p = os.path.abspath(p)
        if is_run_folder(p):
            folders.append(p)
        elif os.path.isdir(p):
            # Treat as a parent directory and scan one level down.
            for name in sorted(os.listdir(p)):
                child = os.path.join(p, name)
                if is_run_folder(child):
                    folders.append(child)
        else:
            sys.stderr.write('WARNING: not a run folder or directory: {0}\n'.format(p))

    if scan_root:
        root = os.path.abspath(scan_root)
        for name in sorted(os.listdir(root)):
            child = os.path.join(root, name)
            if is_run_folder(child) and child not in folders:
                folders.append(child)

    # De-duplicate, preserve order.
    seen = set()
    unique = []
    for f in folders:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Billable analysis
# ---------------------------------------------------------------------------


def derive_billable(role, topology):
    """
    Fallback billable verdict for legacy outputs that lack the
    'Billable (Heuristic)' column. Same rules as ocp_inventory_cli_v3._billable.
    """
    roles = set(r.strip().lower() for r in (role or '').split(',') if r.strip())

    if topology in ('SNO', 'Compact'):
        return (True, 'High',
                'All nodes billable in {0} topology per subscription guide'.format(topology))

    is_master = ('master' in roles) or ('control-plane' in roles)
    is_infra_only = ('infra' in roles) and ('worker' not in roles)

    if is_master:
        return (False, 'High', 'Control plane node - exempt')
    if is_infra_only:
        return (False, 'Medium', 'Infra-only node - exempt (verify no user workloads)')
    return (True, 'High', 'Worker node - billable')


def analyse_cluster(folder):
    """Build the billable picture for a single run folder."""
    nodes = read_csv_rows(os.path.join(folder, 'nodes.csv'))
    summary_rows = read_csv_rows(os.path.join(folder, 'cluster_summary.csv'))
    summary_csv = summary_rows[0] if summary_rows else {}
    summary_json = read_json(os.path.join(folder, 'summary.json'))
    json_summary = summary_json.get('cluster_summary', {}) or {}
    addons = read_csv_rows(os.path.join(folder, 'addons.csv'))
    operators = read_csv_rows(os.path.join(folder, 'operators.csv'))

    def field(key, default=''):
        """cluster_summary.csv first, summary.json second, then the default."""
        for src in (summary_csv, json_summary):
            value = src.get(key)
            if value not in (None, ''):
                return value
        return default

    topology = field('Topology', 'Standard')
    cluster_name = field('Cluster Name') or (nodes[0].get('Cluster Name', '') if nodes else '')
    cluster_id = field('Cluster ID') or (nodes[0].get('Cluster ID', '') if nodes else '')

    billable, exempt = [], []
    derived_any = False

    for node in nodes:
        verdict = (node.get('Billable (Heuristic)') or '').strip()
        if verdict:
            is_billable = verdict.lower() == 'yes'
            confidence = node.get('Billable Confidence', '') or ''
            evidence = node.get('Billable Evidence', '') or ''
        else:
            derived_any = True
            is_billable, confidence, evidence = derive_billable(
                node.get('Role', ''), topology)

        entry = {
            'name': node.get('Node Name', '') or '(unnamed)',
            'role': node.get('Role', '') or '',
            'instance_type': node.get('Instance Type', '') or '',
            'zone': node.get('Zone', '') or '',
            'cpu_capacity': cpu_to_cores(node.get('CPU Capacity (vCPUs)', '')),
            'cpu_allocatable': cpu_to_cores(node.get('CPU Allocatable (vCPUs)', '')),
            'memory': node.get('Memory (GiB)', '') or '',
            'accelerators': to_int(node.get('GPU / Accelerator Count', 0)),
            'accelerator_types': node.get('Accelerator Type(s)', '') or '',
            'sub_model': node.get('Subscription Model (Signal)', '') or '',
            'unschedulable': (node.get('Unschedulable', '') or '').strip().lower() == 'true',
            'confidence': confidence,
            'evidence': evidence,
        }
        (billable if is_billable else exempt).append(entry)

    # Sizing. 'Worker CPU Capacity' mirrors the toolkit (any node whose role
    # contains 'worker'); billable capacity is the subscription-relevant figure
    # and differs in SNO/Compact topologies where masters are also billable.
    worker_capacity = sum(n['cpu_capacity'] for n in billable + exempt
                          if 'worker' in n['role'].lower())
    worker_allocatable = sum(n['cpu_allocatable'] for n in billable + exempt
                             if 'worker' in n['role'].lower())
    billable_capacity = sum(n['cpu_capacity'] for n in billable)

    est_core_pairs = int(math.ceil(worker_capacity / 2.0)) if worker_capacity > 0 else 0
    billable_core_pairs = int(math.ceil(billable_capacity / 2.0)) if billable_capacity > 0 else 0

    # Cross-check against the figures the collector recorded.
    reported_billable = field('Billable Nodes (Heuristic)', None)
    reported_core_pairs = field('Estimated Core-Pairs (Heuristic)', None)
    discrepancies = []
    if reported_billable not in (None, '') and to_int(reported_billable, -1) != len(billable):
        discrepancies.append(
            'Collector recorded {0} billable node(s); this report counts {1} from nodes.csv.'
            .format(reported_billable, len(billable)))
    if reported_core_pairs not in (None, '') and to_int(reported_core_pairs, -1) != est_core_pairs:
        discrepancies.append(
            'Collector recorded {0} estimated core-pair(s); recomputed value is {1}.'
            .format(reported_core_pairs, est_core_pairs))
    if derived_any:
        discrepancies.append(
            'nodes.csv has no "Billable (Heuristic)" column (legacy output); '
            'verdicts were re-derived from Role and Topology.')

    addon_rows = []
    for row in addons:
        addon_rows.append({
            'name': row.get('Add-on', '') or '',
            'status': (row.get('Status', '') or '').strip(),
            'date': row.get('Date', '') or '',
            'evidence': row.get('Evidence', '') or '',
            'confidence': row.get('Confidence', '') or '',
        })
    detected_addons = [a for a in addon_rows
                       if a['status'] and a['status'].upper() not in ('NOT FOUND', '')]

    return {
        'folder': folder,
        'cluster_name': cluster_name or os.path.basename(folder),
        'cluster_id': cluster_id,
        'topology': topology,
        'ocp_version': field('OCP Version'),
        'channel': field('Channel'),
        'platform_type': field('Platform Type'),
        'deployment_type': field('Deployment Type'),
        'edition': field('Edition Signal'),
        'edition_confidence': field('Edition Confidence'),
        'collected_at': field('Collected At'),
        'collection_mode': field('Collection Mode'),
        'notes': field('Notes'),
        'nodes_total': len(billable) + len(exempt),
        'billable': billable,
        'exempt': exempt,
        'worker_capacity': worker_capacity,
        'worker_allocatable': worker_allocatable,
        'billable_capacity': billable_capacity,
        'est_core_pairs': est_core_pairs,
        'billable_core_pairs': billable_core_pairs,
        'total_accelerators': sum(n['accelerators'] for n in billable + exempt),
        'accel_addon_signal': field('AI Accelerator Add-on Signal', 'No'),
        'addons': addon_rows,
        'detected_addons': detected_addons,
        'platform_plus': field('Potential Platform Plus', 'No'),
        'platform_plus_confidence': field('Platform Plus Confidence'),
        'platform_plus_evidence': field('Platform Plus Evidence'),
        'virtualization': field('Virtualization Indicators', 'No'),
        'operator_count': len(operators),
        'discrepancies': discrepancies,
    }


# ---------------------------------------------------------------------------
# PDF building blocks
# ---------------------------------------------------------------------------


def build_styles():
    base = getSampleStyleSheet()
    styles = {
        'title': ParagraphStyle('title', parent=base['Title'], fontName='Helvetica-Bold',
                                fontSize=20, leading=24, textColor=INK, alignment=TA_LEFT,
                                spaceAfter=2),
        'subtitle': ParagraphStyle('subtitle', parent=base['Normal'], fontSize=9.5,
                                   leading=13, textColor=MUTED),
        'h1': ParagraphStyle('h1', parent=base['Heading1'], fontName='Helvetica-Bold',
                             fontSize=14, leading=17, textColor=INK,
                             spaceBefore=12, spaceAfter=6),
        'h2': ParagraphStyle('h2', parent=base['Heading2'], fontName='Helvetica-Bold',
                             fontSize=11, leading=14, textColor=INK,
                             spaceBefore=10, spaceAfter=4),
        'body': ParagraphStyle('body', parent=base['Normal'], fontSize=9,
                               leading=12.5, textColor=INK),
        'muted': ParagraphStyle('muted', parent=base['Normal'], fontSize=8,
                                leading=11, textColor=MUTED),
        'cell': ParagraphStyle('cell', parent=base['Normal'], fontSize=7.8,
                               leading=10, textColor=INK),
        'cellhead': ParagraphStyle('cellhead', parent=base['Normal'], fontSize=7.8,
                                   leading=10, textColor=colors.white,
                                   fontName='Helvetica-Bold'),
        'big': ParagraphStyle('big', parent=base['Normal'], fontName='Helvetica-Bold',
                              fontSize=30, leading=33, textColor=BILLABLE),
        'biglabel': ParagraphStyle('biglabel', parent=base['Normal'], fontSize=8,
                                   leading=11, textColor=MUTED),
    }
    return styles


def wrappable(text):
    """Give long comma/dot separated values a sane break point inside a cell."""
    return str(text).replace(',', ', ')


def data_table(headers, rows, widths, styles, align_right=()):
    """A banded table whose cells wrap. `rows` is a list of lists of strings."""
    head = [Paragraph(h, styles['cellhead']) for h in headers]
    body = [[Paragraph(str(c), styles['cell']) for c in row] for row in rows]
    table = Table([head] + body, colWidths=widths, repeatRows=1, hAlign='LEFT')
    style = [
        ('BACKGROUND', (0, 0), (-1, 0), HEAD_BG),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, RULE),
        ('BOX', (0, 0), (-1, -1), 0.4, RULE),
    ]
    for i in range(1, len(body) + 1):
        if i % 2 == 0:
            style.append(('BACKGROUND', (0, i), (-1, i), BAND))
    for col in align_right:
        style.append(('ALIGN', (col, 0), (col, -1), 'RIGHT'))
    table.setStyle(TableStyle(style))
    return table


def kv_table(pairs, styles, key_width=42 * mm, value_width=92 * mm):
    rows = [[Paragraph('<b>{0}</b>'.format(k), styles['cell']),
             Paragraph(v if v not in (None, '') else '-', styles['cell'])]
            for k, v in pairs]
    table = Table(rows, colWidths=[key_width, value_width], hAlign='LEFT')
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    return table


def headline_block(cluster, styles):
    """The three numbers a subscription conversation starts from."""
    cells = [
        (str(len(cluster['billable'])), 'BILLABLE NODES', BILLABLE),
        (str(len(cluster['exempt'])), 'EXEMPT NODES', EXEMPT),
        (str(cluster['est_core_pairs']), 'EST. CORE-PAIRS', INK),
    ]
    row = []
    for value, label, colour in cells:
        value_style = ParagraphStyle('v', parent=styles['big'], textColor=colour)
        inner = Table([[Paragraph(value, value_style)],
                       [Paragraph(label, styles['biglabel'])]], hAlign='LEFT')
        inner.setStyle(TableStyle([
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        row.append(inner)

    table = Table([row], colWidths=[52 * mm] * 3, hAlign='LEFT')
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BACKGROUND', (0, 0), (-1, -1), BAND),
        ('BOX', (0, 0), (-1, -1), 0.4, RULE),
        ('INNERGRID', (0, 0), (-1, -1), 0.4, RULE),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    return table


def cluster_story(cluster, styles, multi_cluster):
    """Flowables for one cluster."""
    story = []
    story.append(Paragraph('Cluster: {0}'.format(cluster['cluster_name']), styles['h1']))

    story.append(kv_table([
        ('Cluster ID', cluster['cluster_id']),
        ('OCP version', '{0}  ({1})'.format(cluster['ocp_version'] or '-',
                                            cluster['channel'] or 'no channel')),
        ('Platform / deployment', '{0} / {1}'.format(cluster['platform_type'] or '-',
                                                     cluster['deployment_type'] or '-')),
        ('Topology', cluster['topology'] or '-'),
        ('Edition signal', '{0} (confidence: {1})'.format(
            cluster['edition'] or '-', cluster['edition_confidence'] or '-')),
        ('Collected at', '{0}  [mode: {1}]'.format(cluster['collected_at'] or '-',
                                                   cluster['collection_mode'] or '-')),
        ('Source folder', os.path.basename(cluster['folder'])),
    ], styles, key_width=42 * mm, value_width=150 * mm))

    story.append(Spacer(1, 8))
    story.append(headline_block(cluster, styles))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        '{0} of {1} node(s) are billable under the toolkit heuristic for '
        '{2} topology.'.format(len(cluster['billable']), cluster['nodes_total'],
                               cluster['topology'] or 'Standard'),
        styles['body']))

    if cluster['discrepancies']:
        story.append(Spacer(1, 6))
        for note in cluster['discrepancies']:
            story.append(Paragraph('! {0}'.format(note), styles['muted']))

    # --- Billable nodes -----------------------------------------------------
    story.append(Paragraph('Billable nodes', styles['h2']))
    if cluster['billable']:
        rows = []
        for n in sorted(cluster['billable'], key=lambda x: x['name']):
            rows.append([
                n['name'],
                wrappable(n['role']),
                n['instance_type'] or '-',
                '{0:.0f}'.format(n['cpu_capacity']),
                '{0:.2f}'.format(n['cpu_allocatable']),
                n['sub_model'] or '-',
                n['accelerators'] or '-',
                '{0} / {1}'.format(n['confidence'] or '-', n['evidence'] or '-'),
            ])
        story.append(data_table(
            ['Node', 'Role', 'Instance type', 'vCPU cap', 'vCPU alloc',
             'Sub model', 'Accel', 'Confidence / evidence'],
            rows,
            [62 * mm, 24 * mm, 22 * mm, 15 * mm, 16 * mm, 20 * mm, 12 * mm, 60 * mm],
            styles, align_right=(3, 4, 6)))
    else:
        story.append(Paragraph('No billable nodes identified.', styles['body']))

    # --- Exempt nodes -------------------------------------------------------
    story.append(Paragraph('Exempt nodes', styles['h2']))
    if cluster['exempt']:
        rows = []
        for n in sorted(cluster['exempt'], key=lambda x: x['name']):
            rows.append([
                n['name'], wrappable(n['role']), n['instance_type'] or '-',
                '{0:.0f}'.format(n['cpu_capacity']),
                n['confidence'] or '-', n['evidence'] or '-',
            ])
        story.append(data_table(
            ['Node', 'Role', 'Instance type', 'vCPU cap', 'Confidence', 'Exemption basis'],
            rows,
            [62 * mm, 32 * mm, 24 * mm, 16 * mm, 20 * mm, 77 * mm],
            styles, align_right=(3,)))
    else:
        story.append(Paragraph('No exempt nodes — every node in this cluster is billable.',
                               styles['body']))

    # --- Sizing -------------------------------------------------------------
    story.append(Paragraph('Core-pair sizing signal', styles['h2']))
    sizing_rows = [
        ['Worker CPU capacity (cores)', '{0:.2f}'.format(cluster['worker_capacity']),
         'Sum over nodes whose role includes "worker" — matches the collector.'],
        ['Worker CPU allocatable (cores)', '{0:.2f}'.format(cluster['worker_allocatable']),
         'Capacity less reserved system overhead; indicative only.'],
        ['Billable CPU capacity (cores)', '{0:.2f}'.format(cluster['billable_capacity']),
         'Sum over every node marked billable above.'],
        ['Estimated core-pairs (worker basis)', str(cluster['est_core_pairs']),
         'ceil(worker CPU capacity / 2) — the collector\'s headline figure.'],
        ['Estimated core-pairs (billable basis)', str(cluster['billable_core_pairs']),
         'ceil(billable CPU capacity / 2). Differs from the worker basis in '
         'SNO/Compact topologies, where control-plane nodes are also billable.'],
        ['AI accelerator add-on signal', cluster['accel_addon_signal'] or 'No',
         '{0} accelerator(s) detected across all nodes.'.format(cluster['total_accelerators'])],
    ]
    story.append(data_table(['Measure', 'Value', 'Basis'], sizing_rows,
                            [58 * mm, 24 * mm, 149 * mm], styles, align_right=(1,)))

    # --- Add-ons ------------------------------------------------------------
    story.append(Paragraph('Billable add-on signals', styles['h2']))
    if cluster['addons']:
        rows = [[a['name'], a['status'] or '-', a['date'] or '-',
                 a['confidence'] or '-', a['evidence'] or '-']
                for a in cluster['addons']]
        story.append(data_table(['Add-on', 'Status', 'First seen', 'Confidence', 'Evidence'],
                                rows, [26 * mm, 28 * mm, 24 * mm, 24 * mm, 129 * mm], styles))
    else:
        story.append(Paragraph(
            'No addons.csv in this run folder — add-on entitlement could not be assessed.',
            styles['body']))

    story.append(Spacer(1, 6))
    story.append(kv_table([
        ('Potential Platform Plus', '{0} (confidence: {1}) {2}'.format(
            cluster['platform_plus'] or 'No',
            cluster['platform_plus_confidence'] or '-',
            cluster['platform_plus_evidence'] or '')),
        ('Virtualization indicators', cluster['virtualization'] or 'No'),
        ('Installed operators', str(cluster['operator_count'])),
    ], styles, key_width=42 * mm, value_width=150 * mm))

    if cluster['notes']:
        story.append(Spacer(1, 6))
        story.append(Paragraph('Collector note: {0}'.format(cluster['notes']), styles['muted']))

    return story


def estate_story(clusters, styles):
    story = [Paragraph('Estate roll-up', styles['h1'])]
    rows = []
    for c in clusters:
        rows.append([
            c['cluster_name'], c['topology'] or '-', c['ocp_version'] or '-',
            c['platform_type'] or '-', str(c['nodes_total']),
            str(len(c['billable'])), str(len(c['exempt'])),
            '{0:.2f}'.format(c['worker_capacity']), str(c['est_core_pairs']),
            ', '.join(a['name'] for a in c['detected_addons']) or '-',
        ])
    totals = [
        'TOTAL ({0} clusters)'.format(len(clusters)), '', '', '',
        str(sum(c['nodes_total'] for c in clusters)),
        str(sum(len(c['billable']) for c in clusters)),
        str(sum(len(c['exempt']) for c in clusters)),
        '{0:.2f}'.format(sum(c['worker_capacity'] for c in clusters)),
        str(sum(c['est_core_pairs'] for c in clusters)),
        '',
    ]
    rows.append(totals)

    table = data_table(
        ['Cluster', 'Topology', 'Version', 'Platform', 'Nodes', 'Billable',
         'Exempt', 'Worker cores', 'Core-pairs', 'Add-ons detected'],
        rows,
        [42 * mm, 19 * mm, 17 * mm, 18 * mm, 14 * mm, 17 * mm, 15 * mm,
         22 * mm, 19 * mm, 48 * mm],
        styles, align_right=(4, 5, 6, 7, 8))
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, len(rows)), (-1, len(rows)), BAND),
        ('LINEABOVE', (0, len(rows)), (-1, len(rows)), 0.8, INK),
    ]))
    story.append(table)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        'Core-pair totals are a straight sum of the per-cluster estimates. They do not '
        'account for shared or pooled entitlements across the estate.', styles['muted']))
    return story


def methodology_story(styles):
    story = [Paragraph('Methodology and caveats', styles['h1'])]
    story.append(Paragraph(
        'Every figure in this report is derived from the CSV/JSON written by '
        'ocp_inventory_cli_v3.py. Nothing is queried from the cluster at report time, '
        'so the report is only as current as the run folder it was built from.',
        styles['body']))
    story.append(Spacer(1, 6))

    rules = [
        ['SNO / Compact topology', 'Every node is billable',
         'Control-plane nodes run user workloads in these topologies, so no node is exempt.'],
        ['Standard: control-plane', 'Exempt (High confidence)',
         'Nodes with the master or control-plane role.'],
        ['Standard: infra-only', 'Exempt (Medium confidence)',
         'Nodes with the infra role and not the worker role. The exemption only holds if '
         'the node runs no user workloads — run the collector with --mode deep to validate.'],
        ['Standard: worker', 'Billable (High confidence)',
         'Every remaining node, including infra-labelled nodes that also carry the worker role.'],
    ]
    story.append(data_table(['Case', 'Verdict', 'Basis'], rules,
                            [44 * mm, 44 * mm, 143 * mm], styles))

    story.append(Spacer(1, 10))
    story.append(Paragraph('Limits of this report', styles['h2']))
    for item in [
        'Billable verdicts are heuristics based on node roles and topology. They are an '
        'input to a subscription conversation, not a substitute for the entitlements '
        'recorded in your Red Hat account.',
        'Infra-node exemptions are the most common source of error. A node labelled infra '
        'that schedules any user workload is billable.',
        'Core-pair figures use CPU capacity, not allocatable, and assume no hyperthreading '
        'adjustment. Bare-metal and some virtualised platforms are subscribed on a different '
        'basis — check the Subscription Model column per node.',
        'Add-on status reflects what was visible to the collecting account. A NOT FOUND '
        'result can mean the add-on is absent or that RBAC hid it; check collection_summary.csv '
        'in the run folder for API calls that were denied.',
        'Unschedulable or cordoned nodes are still counted as billable if their role says so.',
    ]:
        story.append(Paragraph('&bull;&nbsp; {0}'.format(item), styles['body']))
        story.append(Spacer(1, 3))
    return story


def make_page_decorator(title):
    def decorate(canvas, doc):
        canvas.saveState()
        width, height = doc.pagesize
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, height - 13 * mm,
                    width - doc.rightMargin, height - 13 * mm)
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(doc.leftMargin, height - 11 * mm, title)
        canvas.drawRightString(width - doc.rightMargin, height - 11 * mm,
                               'Heuristic — verify against entitlements')
        canvas.line(doc.leftMargin, 13 * mm, width - doc.rightMargin, 13 * mm)
        canvas.drawString(doc.leftMargin, 9 * mm,
                          'billable_report_{0}'.format(SCRIPT_VERSION))
        canvas.drawRightString(width - doc.rightMargin, 9 * mm,
                               'Page {0}'.format(doc.page))
        canvas.restoreState()
    return decorate


def build_pdf(clusters, out_path, sources):
    styles = build_styles()
    generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    multi = len(clusters) > 1

    if multi:
        heading = 'OpenShift Billable Inventory Report — {0} clusters'.format(len(clusters))
    else:
        heading = 'OpenShift Billable Inventory Report — {0}'.format(clusters[0]['cluster_name'])

    doc = SimpleDocTemplate(
        out_path, pagesize=landscape(A4),
        leftMargin=14 * mm, rightMargin=14 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=heading, author='billable_report_{0}'.format(SCRIPT_VERSION),
        subject='OpenShift billable node and add-on summary')

    story = [
        Paragraph(heading, styles['title']),
        Paragraph('Generated {0} from {1} run folder(s) collected by '
                  'ocp_inventory_cli_v3.py. All verdicts are heuristic.'
                  .format(generated, len(sources)), styles['subtitle']),
        Spacer(1, 10),
    ]

    total_billable = sum(len(c['billable']) for c in clusters)
    total_nodes = sum(c['nodes_total'] for c in clusters)
    total_pairs = sum(c['est_core_pairs'] for c in clusters)
    story.append(Paragraph(
        '<b>Headline:</b> {0} billable node(s) across {1} total node(s); '
        '{2} estimated core-pair(s).'.format(total_billable, total_nodes, total_pairs),
        styles['body']))

    if multi:
        story.append(Spacer(1, 8))
        story.extend(estate_story(clusters, styles))

    for cluster in clusters:
        story.append(PageBreak())
        story.extend(cluster_story(cluster, styles, multi))

    story.append(PageBreak())
    story.extend(methodology_story(styles))

    story.append(Spacer(1, 10))
    story.append(Paragraph('Source run folders', styles['h2']))
    for src in sources:
        story.append(Paragraph(src, styles['muted']))

    decorate = make_page_decorator(heading)
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------


def print_console_summary(clusters):
    print('')
    print('Billable summary')
    print('-' * 64)
    for c in clusters:
        print('{0}'.format(c['cluster_name']))
        print('  Topology            : {0}'.format(c['topology'] or '-'))
        print('  Total nodes         : {0}'.format(c['nodes_total']))
        print('  BILLABLE NODES      : {0}'.format(len(c['billable'])))
        print('  Exempt nodes        : {0}'.format(len(c['exempt'])))
        print('  Worker CPU capacity : {0:.2f} cores'.format(c['worker_capacity']))
        print('  Est. core-pairs     : {0}'.format(c['est_core_pairs']))
        detected = ', '.join(a['name'] for a in c['detected_addons']) or 'none detected'
        print('  Add-ons             : {0}'.format(detected))
        for note in c['discrepancies']:
            print('  ! {0}'.format(note))
        print('')
    if len(clusters) > 1:
        print('-' * 64)
        print('ESTATE TOTAL billable nodes : {0}'.format(
            sum(len(c['billable']) for c in clusters)))
        print('ESTATE TOTAL core-pairs     : {0}'.format(
            sum(c['est_core_pairs'] for c in clusters)))
        print('')


def default_output_name(clusters):
    stamp = datetime.now().strftime('%Y%m%d')
    if len(clusters) == 1:
        safe = ''.join(ch if ch.isalnum() or ch in '-_' else '_'
                       for ch in clusters[0]['cluster_name'])
        return 'billable_report_{0}_{1}.pdf'.format(safe, stamp)
    return 'billable_report_estate_{0}.pdf'.format(stamp)


def main():
    parser = argparse.ArgumentParser(
        description='Produce a PDF report of billable items from OCP CLI Inventory run folders.',
        epilog='Example: python3 billable_report_v3.py OCP_Inventory_abc_cluster_20261009')
    parser.add_argument('folders', nargs='*',
                        help='One or more run folders (or parent directories containing them)')
    parser.add_argument('--input', help='Directory to scan for run folders')
    parser.add_argument('-o', '--output', help='Output PDF path (default: auto-named)')
    parser.add_argument('--no-pdf', action='store_true',
                        help='Print the console summary only; skip PDF generation')
    args = parser.parse_args()

    if not args.folders and not args.input:
        parser.error('give at least one run folder, or --input <dir> to scan')

    folders = find_run_folders(args.folders, args.input)
    if not folders:
        sys.stderr.write('ERROR: no run folders found (a run folder must contain nodes.csv)\n')
        return 2

    clusters = [analyse_cluster(f) for f in folders]
    print_console_summary(clusters)

    if args.no_pdf:
        return 0

    if not HAVE_REPORTLAB:
        sys.stderr.write(
            'ERROR: reportlab is required for PDF output.\n'
            '       Install it with:  pip install reportlab\n'
            '       Or re-run with --no-pdf for the console summary only.\n')
        return 3

    out_path = os.path.abspath(args.output or default_output_name(clusters))
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    build_pdf(clusters, out_path, folders)
    print('PDF report written to: {0}'.format(out_path))
    return 0


if __name__ == '__main__':
    sys.exit(main())
