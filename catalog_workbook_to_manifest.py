"""Convert the approved review workbook to an import manifest without extra deps.

Usage: python catalog_workbook_to_manifest.py REVIEW.xlsx PROPOSAL.json OUTPUT.json
All Proposed/Units approvals and Decisions must be resolved first. No DB access.
"""
import json
import posixpath
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from import_lecture_catalog import validate_manifest
from lecture_catalog import number

NS = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
REL = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id'


def read_sheets(path):
    with zipfile.ZipFile(path) as z:
        strings=[]
        if 'xl/sharedStrings.xml' in z.namelist():
            strings=[''.join(x.itertext()) for x in ET.fromstring(z.read('xl/sharedStrings.xml')).findall('s:si',NS)]
        rels={x.attrib['Id']:x.attrib['Target'] for x in ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))}
        result={}
        for sheet in ET.fromstring(z.read('xl/workbook.xml')).findall('s:sheets/s:sheet',NS):
            target=rels[sheet.attrib[REL]]
            target=target.lstrip('/') if target.startswith('/') else posixpath.normpath('xl/'+target)
            rows=[]
            for row in ET.fromstring(z.read(target)).findall('s:sheetData/s:row',NS):
                cells={}
                for cell in row.findall('s:c',NS):
                    col=''.join(c for c in cell.attrib['r'] if c.isalpha())
                    value=cell.find('s:v',NS)
                    text=value.text if value is not None else ''
                    if cell.attrib.get('t')=='s': text=strings[int(text)]
                    elif cell.attrib.get('t')=='inlineStr': text=''.join(cell.find('s:is',NS).itertext())
                    cells[col]=text or ''
                rows.append(cells)
            headers=rows[0]
            records=[{header:r.get(col,'') for col,header in headers.items()} for r in rows[1:]]
            # Excel/Google Sheets can materialize styled empty rows far below a
            # table. They are not catalog records and must not block approval.
            result[sheet.attrib['name']]=[r for r in records if any(str(v).strip() for v in r.values())]
        return result


def convert(workbook, proposal):
    sheets=read_sheets(workbook)
    for name in ('Proposed','Units','Decisions'):
        sheets[name]=[row for row in sheets[name] if any(str(v).strip() for v in row.values())]
        pending=[str(i+2) for i,row in enumerate(sheets[name]) if row.get('Approval','').strip().casefold() not in ('approved','confirmed')]
        if pending:
            raise ValueError(f'{name} still has unapproved rows: {", ".join(pending[:20])}')
    data=json.loads(Path(proposal).read_text())
    sections={s['name']:s['id'] for s in data['sections']}
    folders={f['name']:f['id'] for f in data['folders']}
    original_ids={l['lecture_id'] for l in data['lectures']}
    proposed_ids={r['Lecture ID'] for r in sheets['Proposed']}
    if original_ids!=proposed_ids:
        raise ValueError('Lecture IDs were added or removed. Reconcile the source explicitly before converting.')
    units=[]
    for row in sheets['Units']:
        units.append({'id':row['Unit key'],'name':row['Unit name'],'section_id':row['Section key'],
            'order':number(row['Unit order']),'syllabus_number':number(row['Syllabus number'], None)})
    lectures=[]
    for row in sheets['Proposed']:
        lectures.append({'source_row':number(row['Source row']),'lecture_id':row['Lecture ID'],'exam_id':data['exam_id'],
            'folder_id':folders[row['Folder']],'section_id':sections[row['Section']],
            'unit_id':row['Unit key'].strip() or None, 'display_title':row['Lecture title'],
            'lecture_number':number(row['Lecture number'], None), 'order':number(row['Lecture order']),'approved':True})
    data.update(units=units,lectures=lectures,approved=True)
    validate_manifest(data)
    return data


if __name__=='__main__':
    if len(sys.argv)!=4: raise SystemExit(__doc__)
    data=convert(sys.argv[1],sys.argv[2])
    with open(sys.argv[3],'x') as output: json.dump(data,output,indent=2,ensure_ascii=False)
    print('Approved manifest created. No database changes.')
