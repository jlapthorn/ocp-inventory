#!/usr/bin/env python3
"""
combine_ocp_outputs.py  —  v3

Combine multiple OpenShift inventory run output folders into single consolidated
CSV files for analysis in Excel or Google Sheets.

Compatible with:
  - OCP CLI Inventory v3  (pure CSV outputs, preferred)
  - OCP CLI Inventory v2.4–v2.6  (legacy .txt outputs, best-effort parsing)

Public Release v3 notes:
  - read_csv: exception is now caught and logged to the run log rather than
    silently swallowed; unreadable files are flagged in combiner_run_log.csv
  - find_run_folders: output directory is excluded from the scan to prevent
    spurious warnings when --output is nested inside --input

For v3 outputs every combination is a simple row concatenation — no text parsing.
For v2.x outputs, best-effort parsing of .txt files is preserved for backwards compatibility.

Output files (written to --output folder):
  combined_nodes.csv           — all node rows across all clusters
  combined_accelerators.csv    — all AI accelerator rows across all clusters
  combined_operators.csv       — all operator rows across all clusters
  combined_addons.csv          — all add-on status rows across all clusters
  combined_cluster_summary.csv — one row per cluster (version, platform, DR, edition signals)
  combined_vms.csv             — all VM rows (only present when virt data was collected)
  combined_infra_compliance.csv— infra node compliance findings (v3 deep/full mode only)
  combined_workload_evidence.csv — workload evidence rows (v3 deep/full mode only)
  combined_collection_summary.csv — API call status per cluster (v3 only)
  combiner_run_log.csv         — what was found, processed, and skipped per run folder
"""

import argparse
import csv
import os
import re
import sys
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# File name maps
# ---------------------------------------------------------------------------

# v3 filenames
V3_FILES = {
    'nodes':               'nodes.csv',
    'accelerators':        'accelerators.csv',
    'operators':           'operators.csv',
    'addons':              'addons.csv',
    'cluster_summary':     'cluster_summary.csv',
    'vms':                 'virtualization_vms.csv',
    'infra_compliance':    'infra_compliance.csv',
    'workload_evidence':   'workload_evidence.csv',
    'collection_summary':  'collection_summary.csv',
}

# v2.x filenames (legacy)
V2_FILES = {
    'nodes':           'OCP_Nodes.csv',
    'operators':       'OCP_Operators.csv',
    'vms':             'OCP_VMs.csv',
    'cluster_version': 'OCP_Cluster_Version.txt',
    'addons_report':   'OCP_Addons_Report.txt',
}

# Markers used to detect a valid run folder
V3_MARKERS = ('cluster_summary.csv', 'nodes.csv', 'operators.csv')
V2_MARKERS = ('OCP_Cluster_Version.txt', 'OCP_Nodes.csv', 'OCP_Operators.csv')


# ---------------------------------------------------------------------------
# Folder detection
# ---------------------------------------------------------------------------

def find_run_folders(root, exclude_dirs=None):
    """
    Walk subfolders of root looking for inventory run folders.
    Handles standard layout plus up to two levels of nested extraction.
    exclude_dirs: optional set of real absolute paths to skip (e.g. the output dir).
    Returns (sorted_list_of_(path,version), warnings_list).
    """
    exclude_real = set()
    for d in (exclude_dirs or []):
        try:
            exclude_real.add(os.path.realpath(d))
        except Exception:
            pass

    folders = {}
    warnings = []
    try:
        entries = os.listdir(root)
    except Exception as e:
        print('ERROR: Cannot list input directory: {0}'.format(e))
        return [], []

    def _is_run_folder(path):
        return (
            any(os.path.exists(os.path.join(path, m)) for m in V3_MARKERS) or
            any(os.path.exists(os.path.join(path, m)) for m in V2_MARKERS)
        )

    def _detect_version(path):
        if any(os.path.exists(os.path.join(path, m)) for m in V3_MARKERS):
            return 'v3'
        return 'v2'

    def _register(path):
        real = os.path.realpath(path)
        if real in exclude_real:
            return
        folders[real] = (path, _detect_version(path))

    def _scan_nested(base, depth):
        if depth <= 0:
            return False
        try:
            inner_dirs = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
        except Exception:
            return False
        found = False
        for d in inner_dirs:
            inner = os.path.join(base, d)
            if os.path.realpath(inner) in exclude_real:
                continue
            if _is_run_folder(inner):
                _register(inner)
                found = True
            elif depth > 1:
                if _scan_nested(inner, depth - 1):
                    found = True
        return found

    for entry in entries:
        p = os.path.join(root, entry)
        if not os.path.isdir(p):
            continue
        if os.path.realpath(p) in exclude_real:
            continue
        if _is_run_folder(p):
            _register(p)
            continue
        if not _scan_nested(p, 2):
            try:
                has_subdirs = any(os.path.isdir(os.path.join(p, x)) for x in os.listdir(p))
            except Exception:
                has_subdirs = False
            if has_subdirs:
                warnings.append('Skipped folder with no recognised inventory markers: {0}'.format(p))

    return sorted(folders.values(), key=lambda x: x[0]), warnings


# ---------------------------------------------------------------------------
# CSV I/O helpers
# ---------------------------------------------------------------------------

def read_csv(path, warn_list=None):
    """
    Read a CSV file and return list of dicts.
    Returns [] on any error; appends a message to warn_list if provided.
    """
    rows = []
    try:
        with open(path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append({k: (v or '') for k, v in r.items()})
    except Exception as e:
        msg = 'Could not read {0}: {1}'.format(os.path.basename(path), e)
        if warn_list is not None:
            warn_list.append(msg)
        else:
            print('  WARNING: {0}'.format(msg))
    return rows


def write_csv(path, rows, preferred_fields=None):
    """Write rows (list of dicts) to path. Unions all field names."""
    if not rows:
        return 0

    # Build ordered field list
    seen   = set()
    fields = []
    for f in (preferred_fields or []):
        if f not in seen:
            fields.append(f)
            seen.add(f)
    for row in rows:
        for k in row:
            if k not in seen:
                fields.append(k)
                seen.add(k)

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def _infer_cluster_identity(*datasets):
    cluster_id = ''
    cluster_name = ''
    for rows in datasets:
        for row in rows or []:
            cid = (row.get('Cluster ID') or '').strip()
            cname = (row.get('Cluster Name') or '').strip()
            if cid and not cluster_id:
                cluster_id = cid
            if cname and not cluster_name:
                cluster_name = cname
            if cluster_id and cluster_name:
                return cluster_id, cluster_name
    return cluster_id, cluster_name


def _apply_cluster_identity(rows, cluster_id, cluster_name, run_folder, source_format):
    for row in rows or []:
        if cluster_id and not (row.get('Cluster ID') or '').strip():
            row['Cluster ID'] = cluster_id
        if cluster_name and not (row.get('Cluster Name') or '').strip():
            row['Cluster Name'] = cluster_name
        row.setdefault('Run Folder', os.path.basename(run_folder))
        row.setdefault('Source Format', source_format)
    return rows


# ---------------------------------------------------------------------------
# Legacy v2.x text parsers
# ---------------------------------------------------------------------------

def _read_text(path):
    try:
        with open(path, 'r') as f:
            return f.read()
    except Exception:
        return ''


def _parse_cluster_version_txt(txt, run_folder):
    """
    Parse OCP_Cluster_Version.txt (v2.x) into a dict for cluster summary row.
    Best-effort: tolerant of missing fields.
    Returns (dict, warnings_list).
    """
    d = {'Run Folder': os.path.basename(run_folder), 'Source Format': 'v2.x (txt)'}
    warnings = []

    for line in txt.splitlines():
        line = line.rstrip('\r\n')
        if line.strip().startswith('- ') or ':' not in line:
            continue
        key, _, val = line.partition(':')
        key = key.strip()
        val = val.strip()
        if key:
            d[key] = val

    patterns = {
        'DR Worker Nodes':        r'workers=(\d+)',
        'DR Schedulable Workers': r'schedulable[_=](\d+)',
        'DR Routes':              r'routes=(\d+)',
        'DR HPAs':                r'hpas=(\d+)',
        'DR MachineSet Replicas': r'machineset_replicas_total=(\d+)',
    }
    dr_hits = 0
    for field, pattern in patterns.items():
        m = re.search(pattern, txt, re.I)
        if m:
            d[field] = m.group(1)
            dr_hits += 1

    if dr_hits == 0:
        warnings.append('Legacy DR fields were not parsed from OCP_Cluster_Version.txt; format may differ from expected v2.x patterns')

    return d, warnings


def _parse_addons_report_txt(txt, cluster_id, cluster_name):
    """
    Parse OCP_Addons_Report.txt (v2.x) into rows.
    Returns list of dicts matching the v3 addons.csv column structure.
    """
    rows = []
    for line in txt.splitlines():
        line = line.strip()
        if not line.startswith('- '):
            continue
        m = re.match(r'-\s*(.+?):\s*(.+)$', line)
        if not m:
            continue

        label = m.group(1).strip()
        rest  = m.group(2).strip()
        status= rest.split()[0].upper() if rest else ''

        date = ''
        md = re.search(r'\((Installed|First seen):\s*([0-9]{4}-[0-9]{2}-[0-9]{2})', rest, re.I)
        if md:
            date = md.group(2)

        evidence = ''
        me = re.search(r'Evidence:\s*(.+)$', rest, re.I)
        if me:
            evidence = me.group(1).strip()

        rows.append({
            'Cluster ID':   cluster_id,
            'Cluster Name': cluster_name,
            'Add-on':       label,
            'Status':       status,
            'Date':         date,
            'Evidence':     evidence,
            'Confidence':   '',
            'Notes':        'Parsed from v2.x OCP_Addons_Report.txt',
        })

    return rows


# ---------------------------------------------------------------------------
# Per-folder processing
# ---------------------------------------------------------------------------

def process_v3_folder(folder, log_row):
    """Process a v3 run folder. Returns dict of {key: [rows]}."""
    result = {
        'nodes':              [],
        'accelerators':       [],
        'operators':          [],
        'addons':             [],
        'cluster_summary':    [],
        'vms':                [],
        'infra_compliance':   [],
        'workload_evidence':  [],
        'collection_summary': [],
    }
    warnings = []

    for key, filename in V3_FILES.items():
        path = os.path.join(folder, filename)
        if os.path.exists(path):
            rows = read_csv(path, warn_list=warnings)
            result[key] = rows
            log_row[filename] = 'OK ({0} rows)'.format(len(rows))
        else:
            log_row[filename] = 'not found'

    cid, cname = _infer_cluster_identity(
        result['cluster_summary'], result['nodes'], result['accelerators'], result['operators'], result['addons'],
        result['vms'], result['infra_compliance'], result['workload_evidence'], result['collection_summary']
    )
    schema_version = ''
    for row in result['cluster_summary']:
        schema_version = row.get('Script Version') or row.get('Output Schema Version') or ''
        if schema_version:
            break
    source_format = 'v3.x (csv)'
    for key in result:
        result[key] = _apply_cluster_identity(result[key], cid, cname, folder, source_format)
        for row in result[key]:
            if schema_version and 'Schema Version' not in row:
                row['Schema Version'] = schema_version
    log_row['Warnings'] = '; '.join(warnings) if warnings else ''
    return result


def process_v2_folder(folder, log_row):
    """
    Process a v2.x run folder using legacy text parsers where needed.
    Returns dict in same shape as process_v3_folder.
    """
    result = {
        'nodes':              [],
        'accelerators':       [],
        'operators':          [],
        'addons':             [],
        'cluster_summary':    [],
        'vms':                [],
        'infra_compliance':   [],
        'workload_evidence':  [],
        'collection_summary': [],
    }
    warnings = []

    for key, filename in [('nodes', 'OCP_Nodes.csv'), ('operators', 'OCP_Operators.csv'), ('vms', 'OCP_VMs.csv')]:
        path = os.path.join(folder, filename)
        if os.path.exists(path):
            rows = read_csv(path, warn_list=warnings)
            result[key] = rows
            log_row[filename] = 'OK ({0} rows)'.format(len(rows))
        else:
            log_row[filename] = 'not found'

    cv_path = os.path.join(folder, 'OCP_Cluster_Version.txt')
    cluster_id = ''
    cluster_name = ''
    if os.path.exists(cv_path):
        txt = _read_text(cv_path)
        d, parse_warnings = _parse_cluster_version_txt(txt, folder)
        warnings.extend(parse_warnings)
        cluster_id   = d.get('Cluster ID', '')
        cluster_name = d.get('Cluster Name', '')
        result['cluster_summary'] = [d]
        log_row['OCP_Cluster_Version.txt'] = 'OK (parsed)'

        ar_path = os.path.join(folder, 'OCP_Addons_Report.txt')
        if os.path.exists(ar_path):
            atxt = _read_text(ar_path)
            result['addons'] = _parse_addons_report_txt(atxt, cluster_id, cluster_name)
            log_row['OCP_Addons_Report.txt'] = 'OK ({0} rows)'.format(len(result['addons']))
        else:
            log_row['OCP_Addons_Report.txt'] = 'not found'
    else:
        log_row['OCP_Cluster_Version.txt'] = 'not found'

    cid, cname = _infer_cluster_identity(
        result['cluster_summary'], result['nodes'], result['accelerators'], result['operators'], result['addons'], result['vms'], result['workload_evidence']
    )
    source_format = 'v2.x (legacy)'
    for key in result:
        result[key] = _apply_cluster_identity(result[key], cid or cluster_id, cname or cluster_name, folder, source_format)
    log_row['Warnings'] = '; '.join(warnings)
    return result




def _finalise_log_status(log_row):
    warnings_text = (log_row.get('Warnings') or '').strip()
    current = (log_row.get('Process Status') or 'OK').strip()
    if current not in ('OK', 'WARNING', 'PARTIAL', 'ERROR'):
        current = 'OK'
        log_row['Process Status'] = current

    if not warnings_text:
        return

    if current == 'OK':
        log_row['Process Status'] = 'WARNING'

    lower = warnings_text.lower()
    if any(k in lower for k in [
        'could not read',
        'not found',
        'absent or empty',
        'skipped (no data)',
        'legacy dr fields were not parsed',
    ]):
        log_row['Process Status'] = 'PARTIAL'


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='Combine multiple OCP inventory output folders into consolidated CSVs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Compatible with OCP CLI Inventory v3 (pure CSV) and v2.4-v2.6 (legacy .txt).

Examples:
  python3 combine_ocp_outputs_v3.py --input ./runs --output ./combined
  python3 combine_ocp_outputs_v3.py   # uses script directory for both input and output
        ''',
    )
    ap.add_argument('--input',  default=None,
                    help='Folder containing run output subfolders (default: script directory)')
    ap.add_argument('--output', default=None,
                    help='Destination for combined CSVs (default: <input>/combined_outputs)')
    args = ap.parse_args()

    input_dir  = os.path.abspath(args.input  or SCRIPT_DIR)
    output_dir = os.path.abspath(args.output or os.path.join(input_dir, 'combined_outputs'))

    print('Input:  {0}'.format(input_dir))
    print('Output: {0}'.format(output_dir))

    run_folders, detection_warnings = find_run_folders(input_dir, exclude_dirs=[output_dir])
    if not run_folders:
        print('No run folders detected in: {0}'.format(input_dir))
        print('Ensure folders contain inventory output files (nodes.csv / OCP_Nodes.csv etc.)')
        sys.exit(0)

    print('Found {0} run folder(s).'.format(len(run_folders)))
    for w in detection_warnings:
        print('  WARNING: {0}'.format(w))

    # Accumulators
    all_nodes              = []
    all_accelerators       = []
    all_operators          = []
    all_addons             = []
    all_cluster_summary    = []
    all_vms                = []
    all_infra_compliance   = []
    all_workload_evidence  = []
    all_collection_summary = []
    run_log                = []

    for folder, version in run_folders:
        log_row = {
            'Run Folder':    os.path.basename(folder),
            'Full Path':     folder,
            'Format':        version,
            'Parse Mode':    'direct csv' if version == 'v3' else 'legacy parser',
            'Process Status':'OK',
            'Warnings':      '',
            'Processed At':  datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        }

        print('  Processing [{0}] {1}'.format(version, os.path.basename(folder)))

        if version == 'v3':
            data = process_v3_folder(folder, log_row)
        else:
            data = process_v2_folder(folder, log_row)

        all_nodes.extend(data['nodes'])
        all_accelerators.extend(data['accelerators'])
        all_operators.extend(data['operators'])
        all_addons.extend(data['addons'])
        all_cluster_summary.extend(data['cluster_summary'])
        all_vms.extend(data['vms'])
        all_infra_compliance.extend(data['infra_compliance'])
        all_workload_evidence.extend(data['workload_evidence'])
        all_collection_summary.extend(data['collection_summary'])
        if not data['vms']:
            log_row['virtualization_vms.csv' if version == 'v3' else 'OCP_VMs.csv'] = log_row.get('virtualization_vms.csv' if version == 'v3' else 'OCP_VMs.csv', 'skipped (no data)')
            log_row['Warnings'] = '; '.join([x for x in [log_row.get('Warnings', ''), 'VM output absent or empty'] if x])
        if version == 'v3' and not data['infra_compliance']:
            log_row['infra_compliance.csv'] = log_row.get('infra_compliance.csv', 'skipped (no data)')
        if version == 'v3' and not data['workload_evidence']:
            log_row['workload_evidence.csv'] = log_row.get('workload_evidence.csv', 'skipped (no data)')
        if version == 'v3' and not data['collection_summary']:
            log_row['collection_summary.csv'] = log_row.get('collection_summary.csv', 'skipped (no data)')

        _finalise_log_status(log_row)
        run_log.append(log_row)

    os.makedirs(output_dir, exist_ok=True)

    # Preferred column ordering mirrors v3 output conventions
    count = write_csv(
        os.path.join(output_dir, 'combined_nodes.csv'),
        all_nodes,
        preferred_fields=[
            'Cluster ID', 'Cluster Name', 'Node Name', 'Role', 'Topology Flag',
            'Creation Date', 'Unschedulable', 'Internal IP',
            'CPU Capacity (vCPUs)', 'CPU Allocatable (vCPUs)', 'Memory (GiB)',
            'Architecture', 'Instance Type', 'Zone', 'Region', 'Provider ID', 'Taints',
            'GPU / Accelerator Count', 'Accelerator Type(s)',
            'Subscription Model (Signal)', 'Sub Model Evidence',
            'Billable (Heuristic)', 'Billable Confidence', 'Billable Evidence',
        ],
    )
    print('  OK combined_nodes.csv ({0} rows)'.format(count))

    if all_accelerators:
        count = write_csv(
            os.path.join(output_dir, 'combined_accelerators.csv'),
            all_accelerators,
            preferred_fields=[
                'Cluster ID', 'Cluster Name', 'Node Name', 'Role',
                'Accelerator Resource Key', 'Accelerator Type',
                'Capacity Count', 'Allocatable Count', 'Measured Count',
                'Measurement Signal', 'Evidence', 'Run Folder', 'Source Format', 'Schema Version',
            ],
        )
        print('  OK combined_accelerators.csv ({0} rows)'.format(count))
    else:
        print('  INFO: combined_accelerators.csv skipped (no accelerator data found)')

    count = write_csv(
        os.path.join(output_dir, 'combined_operators.csv'),
        all_operators,
        preferred_fields=[
            'Cluster ID', 'Cluster Name', 'Operator CSV Name', 'Namespace',
            'Display Name', 'Installed Version', 'Channel',
            'Installed Date', 'Install Initiated Date (Best Effort)',
        ],
    )
    print('  OK combined_operators.csv ({0} rows)'.format(count))

    count = write_csv(
        os.path.join(output_dir, 'combined_addons.csv'),
        all_addons,
        preferred_fields=[
            'Cluster ID', 'Cluster Name', 'Add-on', 'Status',
            'Date', 'Evidence', 'Confidence', 'Notes',
        ],
    )
    print('  OK combined_addons.csv ({0} rows)'.format(count))

    count = write_csv(
        os.path.join(output_dir, 'combined_cluster_summary.csv'),
        all_cluster_summary,
        preferred_fields=[
            'Cluster ID', 'Cluster Name', 'Collected At',
            'OCP Version', 'Version Source', 'Channel',
            'Cluster Created (Proxy)', 'Deployment Type', 'Platform Type', 'FIPS Mode',
            'Edition Signal', 'Edition Confidence',
            'Platform Detected', 'Platform Confidence',
            'Topology', 'Total Nodes', 'Master Nodes', 'Worker Nodes',
            'Infra Nodes', 'Billable Nodes (Heuristic)',
            'Worker CPU Capacity (Cores)', 'Worker CPU Allocatable (Cores)', 'Estimated Core-Pairs (Heuristic)',
            'Total Accelerators', 'Nodes with Accelerators', 'AI Accelerator Add-on Signal',
            'Virtualization Indicators', 'NFV / Telco Indicators',
            'Add-on Summary', 'Potential Platform Plus',
            'Platform Plus Confidence', 'Platform Plus Evidence',
            'DR Posture', 'DR Confidence', 'DR Signals',
            'Collection Mode', 'Notes',
            # v2.x legacy fields (will be blank for v3 rows)
            'OpenShift Cluster Version', 'Infrastructure PlatformType',
            'DR Posture (Heuristic)', 'Hot DR Indicators Present', 'Hot DR Evidence',
            'DR Worker Nodes', 'DR Schedulable Workers', 'DR Routes', 'DR HPAs',
            'DR MachineSet Replicas', 'Run Folder', 'Source Format', 'Schema Version',
        ],
    )
    print('  OK combined_cluster_summary.csv ({0} rows)'.format(count))

    if all_vms:
        count = write_csv(
            os.path.join(output_dir, 'combined_vms.csv'),
            all_vms,
            preferred_fields=[
                'Cluster ID', 'Cluster Name', 'Namespace', 'VM Name',
                'Created Date', 'Running', 'vCPU (Requested)',
                'Memory (Requested)', 'Node (If Running)',
            ],
        )
        print('  OK combined_vms.csv ({0} rows)'.format(count))
    else:
        print('  INFO: combined_vms.csv skipped (no VM data found)')

    if all_infra_compliance:
        count = write_csv(
            os.path.join(output_dir, 'combined_infra_compliance.csv'),
            all_infra_compliance,
            preferred_fields=[
                'Cluster ID', 'Cluster Name', 'Infra Node', 'Namespace',
                'Non-Qualifying Pods (Sample)', 'Finding', 'Confidence', 'Action',
            ],
        )
        print('  OK combined_infra_compliance.csv ({0} rows)'.format(count))
    else:
        print('  INFO: combined_infra_compliance.csv skipped (no infra compliance findings)')


    if all_workload_evidence:
        count = write_csv(
            os.path.join(output_dir, 'combined_workload_evidence.csv'),
            all_workload_evidence,
            preferred_fields=[
                'Cluster ID', 'Cluster Name', 'Namespace', 'Pod Count', 'Category',
                'Notes', 'Run Folder', 'Source Format', 'Schema Version',
            ],
        )
        print('  OK combined_workload_evidence.csv ({0} rows)'.format(count))
    else:
        print('  INFO: combined_workload_evidence.csv skipped (no workload evidence found)')

    if all_collection_summary:
        count = write_csv(
            os.path.join(output_dir, 'combined_collection_summary.csv'),
            all_collection_summary,
            preferred_fields=['Cluster ID', 'Cluster Name', 'Script Version', 'Output Schema Version', 'Collection Mode', 'Resource', 'Command', 'Status', 'Item Count', 'Notes', 'Run Folder', 'Source Format', 'Schema Version'],
        )
        print('  OK combined_collection_summary.csv ({0} rows)'.format(count))
    else:
        print('  INFO: combined_collection_summary.csv skipped (no collection summaries found)')

    # Always write the run log
    count = write_csv(
        os.path.join(output_dir, 'combiner_run_log.csv'),
        run_log,
        preferred_fields=['Run Folder', 'Format', 'Parse Mode', 'Process Status', 'Warnings', 'Processed At', 'Full Path'],
    )
    print('  OK combiner_run_log.csv ({0} rows)'.format(count))

    # Summary
    print('\nCombined outputs written to: {0}'.format(output_dir))
    print('Run folders processed: {0}'.format(len(run_folders)))
    v3_count = sum(1 for _, v in run_folders if v == 'v3')
    v2_count = sum(1 for _, v in run_folders if v == 'v2')
    if v3_count:
        print('  v3 folders: {0}'.format(v3_count))
    if v2_count:
        print('  v2.x folders: {0} (legacy parsing applied)'.format(v2_count))

    files = [f for f in os.listdir(output_dir) if f.endswith('.csv')]
    print('Output files: {0}'.format(', '.join(sorted(files))))


if __name__ == '__main__':
    main()
