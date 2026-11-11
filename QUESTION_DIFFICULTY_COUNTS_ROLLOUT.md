# Practice question difficulty counts

1. Deploy the backend to Render with `USE_STORED_QUESTION_DIFFICULTY_COUNTS` unset. Repeat submissions immediately skip the count lookups once their graph totals exist. First-time exam submissions still use the existing scan. Vercel needs no deployment for this change.
2. Once the updated backend is serving traffic, run these commands from the backend directory with credentials for the DynamoDB tables used by that deployment.

   ```sh
   python backfill_question_difficulty_counts.py --apply
   python backfill_question_difficulty_counts.py --verify
   ```

   The first command scans the question bank and writes counts and a revision to each Module record. The second is read-only and compares every module's Easy, Medium, and Hard counts with the legacy scan. If an import changed a module during either command, rerun the affected command. Both commands must exit successfully before enabling the reader.
3. Set `USE_STORED_QUESTION_DIFFICULTY_COUNTS=1` on Render. A first-time exam submission can now read the module counts in one batch for exams with up to 100 modules. Missing or invalid counts use the scan. To switch back to scans, remove the environment variable.

The backfill writes only to the Module table. Existing graph totals, attempts, and answer history require no migration. CSV imports update the question rows and counts in the same DynamoDB transaction.

For direct DynamoDB question edits or deletions, disable the stored-count reader before the edits. Run both commands again before re-enabling it. The same rebuild applies after running an older question importer that lacks count maintenance.
