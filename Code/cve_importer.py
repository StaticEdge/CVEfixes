# Obtaining and processing CVE json **files**
# The code is to download nvdcve zip files from NIST since 2002 to the current year,
# unzip and append all the JSON files together,
# and extracts all the entries from json files of the projects.

import datetime
import json
import os
import re
from io import BytesIO
import pandas as pd
import requests
from pathlib import Path
from zipfile import ZipFile
import ast

from extract_cwe_record import add_cwe_class,  extract_cwe
import configuration as cf
import database as db

# ---------------------------------------------------------------------------------------------------------------------

urlhead = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'
urltail = '.json.zip'
initYear = 2002
currentYear = datetime.datetime.now().year

local_zip_path = '/Users/anupaperera/Desktop/Academic/CSE/FYP/CVEfixes/Examples/nvdcve-2.0-2025.json.zip'
extract_path = Path(cf.DATA_PATH) / 'json'

# Consider only current year CVE records when sample_limit>0 for the simplified example.
if cf.SAMPLE_LIMIT > 0:
    initYear = currentYear

df = pd.DataFrame()

ordered_cve_columns = ['cve_id', 'published_date', 'last_modified_date', 'description', 'nodes', 'severity',
                       'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege',
                       'user_interaction_required',
                       'cvss2_vector_string', 'cvss2_access_vector', 'cvss2_access_complexity', 'cvss2_authentication',
                       'cvss2_confidentiality_impact', 'cvss2_integrity_impact', 'cvss2_availability_impact',
                       'cvss2_base_score',
                       'cvss3_vector_string', 'cvss3_attack_vector', 'cvss3_attack_complexity',
                       'cvss3_privileges_required',
                       'cvss3_user_interaction', 'cvss3_scope', 'cvss3_confidentiality_impact',
                       'cvss3_integrity_impact',
                       'cvss3_availability_impact', 'cvss3_base_score', 'cvss3_base_severity',
                       'exploitability_score', 'impact_score', 'ac_insuf_info',
                       'reference_json', 'problemtype_json']

cwe_columns = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']

# ---------------------------------------------------------------------------------------------------------------------

def _ensure_v1_like_structure(root_json: dict) -> dict:
    """
    Convert an NVD v2.0 top-level JSON (with 'vulnerabilities') into a
    v1.1-like dict that contains a 'CVE_Items' list so the existing
    preprocessing pipeline can continue to work with minimal changes.
    This is a best-effort mapper: it maps key fields based on the
    provided migration guide (id, sourceIdentifier, published, lastModified,
    descriptions, references, metrics, configurations).
    """
    if not isinstance(root_json, dict):
        return root_json

    # If it's already v1-like, return as-is
    if 'CVE_Items' in root_json:
        return root_json

    # If v2-style
    if 'vulnerabilities' in root_json:
        v2_list = root_json.get('vulnerabilities', [])
        cve_items = []
        for wrapper in v2_list:
            cve_item = wrapper.get('cve', {})
            item = {}

            # Top-level published / modified dates
            item['publishedDate'] = cve_item.get('published')
            item['lastModifiedDate'] = cve_item.get('lastModified')

            # Build a v1-like cve sub-dict
            cve_v1 = {}
            # Meta
            cve_v1['CVE_data_meta'] = {
                'ID': cve_item.get('id'),
                'ASSIGNER': cve_item.get('sourceIdentifier')
            }

            # Descriptions
            # v1 had description.description_data (list) ; v2 has descriptions (list)
            if 'descriptions' in cve_item:
                cve_v1['description'] = {'description_data': cve_item.get('descriptions', [])}
            else:
                cve_v1['description'] = {'description_data': []}

            # References: map list -> reference_data list
            refs = []
            for r in cve_item.get('references', []) or []:
                refs.append({
                    'url': r.get('url'),
                    'source': r.get('source')
                })
            cve_v1['references'] = {'reference_data': refs}

            # Problem type / weaknesses (best-effort)
            if 'weaknesses' in cve_item and cve_item.get('weaknesses'):
                # some v2 variants use weaknesses with description lists
                cve_v1['problemtype'] = {'problemtype_data': cve_item.get('weaknesses')}
            else:
                cve_v1['problemtype'] = {'problemtype_data': []}

            item['cve'] = cve_v1

            # Map configurations: take first configurations entry's nodes if present
            cfg = cve_item.get('configurations')
            if isinstance(cfg, list) and len(cfg) > 0 and isinstance(cfg[0], dict):
                item['configurations'] = {'nodes': cfg[0].get('nodes', [])}
            else:
                item['configurations'] = {'nodes': []}

            # Map metrics -> impact.baseMetricV3 / baseMetricV2 (best-effort)
            impact = {}
            metrics = cve_item.get('metrics', {}) or {}
            # CVSS v3.1 or v3.0
            cvss_v31 = metrics.get('cvssMetricV31') or []
            cvss_v30 = metrics.get('cvssMetricV30') or []
            if cvss_v31 or cvss_v30:
                chosen = (cvss_v31 or cvss_v30)[0]
                cvss_data = chosen.get('cvssData', {})
                bm3 = {'cvssV3': cvss_data}
                # attach scores if present
                if 'exploitabilityScore' in chosen:
                    bm3['exploitabilityScore'] = chosen.get('exploitabilityScore')
                if 'impactScore' in chosen:
                    bm3['impactScore'] = chosen.get('impactScore')
                impact['baseMetricV3'] = bm3

            # CVSS v2
            cvss_v2 = metrics.get('cvssMetricV2') or []
            if cvss_v2:
                chosen2 = cvss_v2[0]
                cvss_v2_data = chosen2.get('cvssData', {})
                impact['baseMetricV2'] = {'cvssV2': cvss_v2_data}

            item['impact'] = impact

            cve_items.append(item)

        return {'CVE_Items': cve_items}

    # Unknown structure: return input as a fallback
    return root_json


def rename_columns(name):
    """
    converts the other cases of string to snake_case, and further processing of column names.
    """
    name = name.split('.', 2)[-1].replace('.', '_')
    name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
    name = name.replace('cvss_v', 'cvss').replace('_data', '_json').replace('description_json', 'description')
    return name


def preprocess_jsons(df_in):
    """
    Flattening CVE_Items and removing the duplicates
    :param df_in: merged dataframe of all years json files
    """
    cf.logger.info('Flattening CVE items and removing the duplicates...')
    cve_items = pd.json_normalize(df_in['CVE_Items'])
    df_cve = pd.concat([df_in.reset_index(), cve_items], axis=1)

    # Removing all CVE entries which have null values in reference-data at [cve.references.reference_data] column
    df_cve = df_cve[df_cve['cve.references.reference_data'].str.len() != 0]

    # Re-ordering and filtering some redundant and unnecessary columns
    df_cve = df_cve.rename(columns={'cve.CVE_data_meta.ID': 'cve_id'})
    df_cve = df_cve.drop(
        labels=[
            'index',
            'CVE_Items',
            'cve.data_type',
            'cve.data_format',
            'cve.data_version',
            'CVE_data_type',
            'CVE_data_format',
            'CVE_data_version',
            'CVE_data_numberOfCVEs',
            'CVE_data_timestamp',
            'cve.CVE_data_meta.ASSIGNER',
            'configurations.CVE_data_version',
            'impact.baseMetricV2.cvssV2.version',
            'impact.baseMetricV2.exploitabilityScore',
            'impact.baseMetricV2.impactScore',
            'impact.baseMetricV3.cvssV3.version',
        ], axis=1, errors='ignore')

    # renaming the column names
    df_cve.columns = [rename_columns(i) for i in df_cve.columns]

    # Check and add columns if they are not present in the dataframe
    for col in ordered_cve_columns:
        if col not in df_cve.columns:
            df_cve[col] = ""

    # ordering the cve columns
    df_cve = df_cve[ordered_cve_columns]

    return df_cve

def parse_v2_weaknesses(row_val, cve_id_ref):
        """
        Parses NVD V2 'weaknesses' list to extract CWE IDs with logging.
        """
        found_cwes = set()
        
        # 1. Handle Empty/NaN
        if not row_val or pd.isna(row_val):
            # cf.logger.debug(f"[{cve_id_ref}] Weakness data is empty or NaN.")
            return ['unknown']

        # 2. Handle String Input (e.g. read from CSV/DB)
        if isinstance(row_val, str):
            try:
                row_val = ast.literal_eval(row_val)
            except (ValueError, SyntaxError) as e:
                cf.logger.warning(f"[{cve_id_ref}] FAILED to parse string literal: {row_val} | Error: {e}")
                return ['unknown']
        
        # 3. Iterate through V2 List Structure
        if isinstance(row_val, list):
            for i, entry in enumerate(row_val):
                descriptions = entry.get('description', [])
                
                # Check inside the description list
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        val = desc.get('value', '')
                        if val.startswith('CWE-'):
                            found_cwes.add(val)
                        else:
                            # Log weird values that aren't CWEs (e.g., NVD-noinfo)
                            cf.logger.debug(f"[{cve_id_ref}] entry {i}: Found non-CWE value: '{val}'")
        else:
            cf.logger.warning(f"[{cve_id_ref}] Unexpected data type: {type(row_val)}")

        # 4. Final check
        if not found_cwes:
            cf.logger.debug(f"[{cve_id_ref}] No valid CWEs found in: {row_val}")
            return ['unknown']
        
        return list(found_cwes)

def assign_cwes_to_cves(df_cve: pd.DataFrame):
    df_cwes = extract_cwe()
    # fetching CWE associations to CVE records
    cf.logger.info('Adding CWE category to CVE records...')
    df_cwes_class = df_cve[['cve_id', 'problemtype_json']].copy()
    df_cwes_class['cwe_id'] = add_cwe_class(df_cwes_class['problemtype_json'].tolist())  # list of CWE-IDs' portion

    # exploding the multiple CWEs list of a CVE into multiple rows.
    df_cwes_class = df_cwes_class.assign(
        cwe_id=df_cwes_class.cwe_id).explode('cwe_id').reset_index()[['cve_id', 'cwe_id']]
    df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
    df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')
    
    no_ref_cwes = set(list(df_cwes_class.cwe_id)).difference(set(list(df_cwes.cwe_id)))
    if len(no_ref_cwes) > 0:
        cf.logger.debug('List of CWEs from CVEs that are not associated to cwe table are as follows:')
        cf.logger.debug(no_ref_cwes)

    # Applying the assertion to cve-, cwe- and cwe_classification table.
    assert df_cwes.cwe_id.is_unique, "Primary keys are not unique in cwe records!"
    assert df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique, \
        'Primary keys are not unique in cwe_classification records!'
    assert set(list(df_cwes_class.cwe_id)).issubset(set(list(df_cwes.cwe_id))), \
        'Not all foreign keys for the cwe_classification records are present in the cwe table!'

    df_cwes = df_cwes[cwe_columns].reset_index()  # to maintain the order of the columns
    df_cwes.to_sql(name="cwe", con=db.conn, if_exists='replace', index=False)
    df_cwes_class.to_sql(name='cwe_classification', con=db.conn, if_exists='replace', index=False)
    cf.logger.info('Added cwe and cwe_classification tables')



def import_cves():
    """
    gathering CVE records by processing JSON files.
    """
    cf.logger.info('-' * 70)
    if db.table_exists('cve'):
        cf.logger.warning('The cve table already exists, loading and continuing extraction...')
        # df_cve = pd.read_sql(sql="SELECT * FROM cve", con=db.conn)
    else:
        cf.logger.warning('The cve table does not exists, extraction...')
        # for year in range(initYear, currentYear + 1):
        #     extract_target = 'nvdcve-1.1-' + str(year) + '.json'
        #     zip_file_url = urlhead + str(year) + urltail

        #     # Check if the directory already has the json file or not ?
        #     if os.path.isfile(Path(cf.DATA_PATH) / 'json' / extract_target):
        #         cf.logger.warning(f'Reusing the {year} CVE json file that was downloaded earlier...')
        #         json_file = Path(cf.DATA_PATH) / 'json' / extract_target
        #     else:
        #         # url_to_open = urlopen(zip_file_url, timeout=10)
        #         r = requests.get(zip_file_url)
        #         z = ZipFile(BytesIO(r.content))  # BytesIO keeps the file in memory
        #         json_file = z.extract(extract_target, Path(cf.DATA_PATH) / 'json')

        #     with open(json_file) as f:
        #         yearly_data = json.load(f)
        #         if year == initYear:  # initialize the df_methods by the first year data
        #             df_cve = pd.DataFrame(yearly_data)
        #         else:
        #             df_cve = df_cve.append(pd.DataFrame(yearly_data))
        #         cf.logger.info(f'The CVE json for {year} has been merged')

        # df_cve = preprocess_jsons(df_cve)
        
        
        
        
        # # Path to your specific custom file
        # json_file_path = '/Users/anupaperera/Desktop/Academic/CSE/FYP/CVEfixes/Examples/custom.json'

        # # Open the file and load it directly into df_cve
        # with open(json_file_path, 'r') as f:
        #     custom_data = json.load(f)
        #     df_cve = pd.DataFrame(custom_data)
        
        # cf.logger.info(f'Custom CVE json loaded from {json_file_path}')
        # df_cve = preprocess_jsons(df_cve)
        
        # with open(json_file) as f:
        #     yearly_data = json.load(f)
        #     # Convert v2.0 structure to v1.1-like if needed
        #     yearly_data = _ensure_v1_like_structure(yearly_data)
        #     if year == initYear:  # initialize the df_methods by the first year data
        #         df_cve = pd.DataFrame(yearly_data)
        #     else:
        #         df_cve = df_cve.append(pd.DataFrame(yearly_data))
        #     cf.logger.info(f'The CVE json for {year} has been merged')
        
        
        
        # 2. Open the local zip file directly
        with ZipFile(local_zip_path, 'r') as z:
            # Get the name of the file inside the zip (assuming there's only one relevant JSON)
            # z.namelist()[0] grabs the first filename found in the zip archive
            extract_target = z.namelist()[0]
            
            # Extract the file
            json_file = z.extract(extract_target, extract_path)
            cf.logger.info(f'Extracted {extract_target} from local zip')

        # 3. Load the JSON data
        with open(json_file) as f:
            data = json.load(f)
            data = _ensure_v1_like_structure(data)
            # Create the DataFrame directly
            df_cve = pd.DataFrame(data)
        
        df_cve = preprocess_jsons(df_cve)
        df_cve = df_cve.map(str)
        # assert df_cve.cve_id.is_unique, 'Primary keys are not unique in cve records!'
        df_cve.to_sql(name="cve", con=db.conn, if_exists="replace", index=False)
        cf.logger.info('All CVEs have been merged into the cve table')
        cf.logger.info('-' * 70)

        assign_cwes_to_cves(df_cve=df_cve)
