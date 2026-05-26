"""
Weak Function Labeler — Binary-Level Label Propagation
=======================================================
If binary is cryptojacking → ALL functions labeled malicious
If binary is benign        → ALL functions labeled benign

Run locally:
    pip install tqdm
    python function_labeler_weaklabel.py --input_dir ./combined_output --output ./labeled_functions.jsonl
"""

import json, glob, os, argparse
from pathlib import Path
from tqdm import tqdm


def process_file(path: str, min_instructions: int) -> tuple[list[dict], dict]:
    stats = {'total': 0, 'malicious': 0, 'benign': 0, 'skipped': 0, 'errors': 0}
    records = []

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)

        binary           = data.get('binary', Path(path).stem)
        binary_label     = data.get('label', 0)
        binary_label_name = data.get('label_name', 'benign')
        graphs           = data.get('graphs', [])

        # Weak labeling: inherit binary label for every function
        fn_label      = 1 if binary_label_name == 'cryptojacking' else 0
        fn_label_name = 'malicious' if fn_label == 1 else 'benign'

        for fn in graphs:
            ic = fn.get('instruction_count', 0)
            if ic < min_instructions:
                stats['skipped'] += 1
                continue

            instructions = fn.get('instructions', [])
            # Store only what GCB needs: flat asm text + metadata
            asm_text = ' \n '.join(
                f"{i['mnemonic']} {i['operands']}".strip()
                for i in instructions
            )
            if not asm_text.strip():
                stats['skipped'] += 1
                continue

            record = {
                'binary'            : binary,
                'binary_label'      : binary_label,
                'binary_label_name' : binary_label_name,
                'function'          : fn.get('function', ''),
                'entry'             : fn.get('entry', ''),
                'function_label'    : fn_label,
                'function_label_name': fn_label_name,
                'instruction_count' : ic,
                'asm_text'          : asm_text,
            }
            records.append(record)
            stats['total'] += 1
            if fn_label == 1:
                stats['malicious'] += 1
            else:
                stats['benign'] += 1

    except Exception as e:
        stats['errors'] += 1

    return records, stats


def main():
    parser = argparse.ArgumentParser(
        description='Weak function labeler — propagates binary label to all functions'
    )
    parser.add_argument('--input_dir',  required=True, help='Directory of Ghidra JSON exports')
    parser.add_argument('--output',     required=True, help='Output JSONL path')
    parser.add_argument('--min_instructions', type=int, default=10,
                        help='Skip functions with fewer than N instructions (default: 10)')
    parser.add_argument('--limit', type=int, default=None,
                        help='Process only first N files (for testing)')
    args = parser.parse_args()

    json_files = sorted(glob.glob(os.path.join(args.input_dir, '**', '*.json'), recursive=True))
    if not json_files:
        print(f"No JSON files found in {args.input_dir}")
        return
    if args.limit:
        json_files = json_files[:args.limit]

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    totals = {'total': 0, 'malicious': 0, 'benign': 0,
              'skipped': 0, 'errors': 0,
              'crypto_bins': 0, 'benign_bins': 0}

    with open(args.output, 'w', encoding='utf-8') as out:
        with tqdm(json_files, unit='file', ncols=90,
                  bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]') as pbar:
            for path in pbar:
                records, stats = process_file(path, args.min_instructions)

                for rec in records:
                    out.write(json.dumps(rec) + '\n')

                for k in ('total', 'malicious', 'benign', 'skipped', 'errors'):
                    totals[k] += stats[k]

                if records:
                    lname = records[0]['binary_label_name']
                    if lname == 'cryptojacking':
                        totals['crypto_bins'] += 1
                    else:
                        totals['benign_bins'] += 1

                pbar.set_postfix({
                    'mal': totals['malicious'],
                    'ben': totals['benign'],
                    'err': totals['errors'],
                })

    # Final stats
    total_fns = totals['total']
    mal       = totals['malicious']
    ben       = totals['benign']
    ratio     = ben // mal if mal else 0

    print(f"\n{'='*55}")
    print(f"LABELING COMPLETE")
    print(f"{'='*55}")
    print(f"Files processed     : {len(json_files):,}")
    print(f"  Cryptojacking     : {totals['crypto_bins']:,}")
    print(f"  Benign            : {totals['benign_bins']:,}")
    print(f"  Errors            : {totals['errors']:,}")
    print(f"\nFunctions labeled   : {total_fns:,}")
    print(f"  Malicious         : {mal:,} ({mal/total_fns*100:.1f}%)" if total_fns else "  Malicious : 0")
    print(f"  Benign            : {ben:,} ({ben/total_fns*100:.1f}%)" if total_fns else "  Benign    : 0")
    print(f"  Skipped (stubs)   : {totals['skipped']:,}")
    print(f"\nClass imbalance     : 1:{ratio}")
    print(f"Output              : {args.output}")
    print(f"{'='*55}")
    print(f"\nSet POS_WEIGHT = {ratio}.0 in your Stage 2 notebook")


if __name__ == '__main__':
    main()