"""
Backfill script to initialize `is_active` flag on DynamoDB ExamTable.
CUET_PG (g4mzja) -> is_active = False
MPhil (t8ZB83)   -> is_active = False
UGC NET (qjPZtz) -> is_active = True
"""
import sys
import os

# Ensure current dir is on python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

import controller

def backfill():
    updates = {
        'g4mzja': False,  # CUET_PG
        't8ZB83': False,  # MPhil
        'qjPZtz': True,   # UGC NET
    }

    for exam_id, is_active in updates.items():
        print(f"Updating exam {exam_id} to is_active={is_active}...")
        try:
            res = controller.ExamTable.update_item(
                Key={'exam_id': exam_id},
                UpdateExpression="SET is_active = :status",
                ExpressionAttributeValues={':status': is_active},
                ReturnValues="ALL_NEW"
            )
            print(f"Successfully updated {exam_id}: {res.get('Attributes', {})}")
        except Exception as e:
            print(f"Error updating {exam_id}: {e}")

    print("\nCurrent ExamTable status:")
    scan_res = controller.ExamTable.scan(ProjectionExpression="exam_id, exam_name, is_active")
    for item in scan_res.get('Items', []):
        print(f"  {item.get('exam_id')} - {item.get('exam_name')}: is_active = {item.get('is_active')}")

if __name__ == '__main__':
    backfill()
