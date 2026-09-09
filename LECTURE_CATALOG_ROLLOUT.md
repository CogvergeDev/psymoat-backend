# Lecture catalog rollout

The new catalog uses a separate `LectureCatalog` table. The initial import does not write to `Lecture`, `Module`, notes, video storage, or annotations. Existing lecture URLs and IDs continue to work. Changes made later through God Mode deliberately update the selected lecture and its catalog placement together.

## Configuration and deployment order

1. Review the proposed workbook and resolve the mapping decisions. The JSON proposal is deliberately unapproved. Run `python catalog_workbook_to_manifest.py APPROVED.xlsx catalog-proposal.json approved-catalog.json` to transfer corrections and approvals into a manifest. This refuses unresolved approvals in Proposed, Units or Decisions, validates relationships, and rejects added/removed lecture IDs. A separate manifest remains useful as the exact versioned input to the migration.
2. Deploy the backend with `lecture_catalog.py`, the blueprint registration, and the scripts. Set `CATALOG_ADMIN_EMAILS` to a comma-separated allowlist of actual signed-in admin account emails. New administration routes require a verified existing JWT and this allowlist. The legacy God Mode browser login does not grant server permissions.
3. Set `LECTURE_CATALOG_TABLE` if a table name other than `LectureCatalog` is wanted. Grant the backend IAM role access to that new table. Runtime needs GetItem, Query, UpdateItem, PutItem, DeleteItem, and TransactWriteItems; existing Lecture/Exam/Module access remains necessary. Provisioning additionally needs CreateTable, DescribeTable, and UpdateContinuousBackups.
4. Run `python provision_lecture_catalog.py`. This creates only the new table, with `pk`/`sk` keys and point-in-time recovery. It does not alter an existing table or create a public provisioning endpoint.
5. Run `python import_lecture_catalog.py --manifest approved-catalog.json --report catalog-dry-run.json`. Review missing IDs, exam mismatches, missing videos, and database-only recordings. Explicitly resolve the latter or list deliberately excluded IDs in `acknowledged_database_only_ids`; do not silently omit newly added recordings.
6. Apply the approved input with `python import_lecture_catalog.py --manifest approved-catalog.json --report catalog-import.json --apply --backup catalog-before-import.json`. The backup filename must be new. Each placement and its folder counter are transactional. An interrupted import can be rerun with a new backup filename; matching records are skipped and conflicts are rejected.
7. Verify counts and sample recordings in staging, including a custom exam and custom section names in God Mode. Enable `NEXT_PUBLIC_LECTURE_CATALOG_ENABLED=true` for the frontend build only after its catalog is ready. This is a build-time Next.js flag, so changing it requires a new build.

The default frontend flag is off. With it off, the old folder UI remains available and lecture Back links still receive a return destination. The new admin catalog screen can be used to prepare metadata before enabling the student view.

## Query and write behavior

- `GET /catalog/exams` reads the existing exam catalog, including exams created through God Mode.
- `GET /catalog/:exam/folders` returns folder metadata and counters. No lecture records or video URLs are fetched for this screen.
- `GET /catalog/:exam/folders/:folder` reads only that folder's placement partition, then batch-fetches lightweight summaries for its lecture IDs. An optional `section` restricts the query by sort-key prefix. Database pagination and unprocessed batch keys are handled. At current folder sizes the response includes the whole chosen folder, allowing complete section searches without another network request.
- `GET /catalog/lectures/:id/placement` provides the parent location and cleaned display title for old/direct lecture links.
- `/catalog/admin/...` manages exams, folders, configurable sections, units, and lecture placements. New exams use the existing Exam table so the rest of the app can discover them. Units have distinct stable IDs even when they share a syllabus number.
- God Mode's add/edit forms save the recording, placement pointer, folder entry, folder counts and changed legacy module list in one DynamoDB transaction. A learning module is optional for a lecture-only exam. Existing learning modules remain separate from lecture units.
- Moving a recording decrements its old folder and increments its new folder. Re-saving a recording in the same folder does not increment the count. Deleting through the new God Mode endpoint removes its placement and decrements the count. Referenced units/sections/folders cannot be deleted through the catalog UI. Folders can instead be hidden.
- The student view uses the server's order. It only groups already assigned records for display and filters the currently loaded folder for search; it does not classify by date.

## Rollback

Set `NEXT_PUBLIC_LECTURE_CATALOG_ENABLED=false` and rebuild/redeploy the frontend to restore the original folder UI. The source lecture records and their original titles are preserved by the import, so this rollback does not require restoring the old table. Keep the catalog and import backup for diagnosis. Review any subsequent intentional God Mode lecture edits separately before restoring data; do not overwrite newer edits with an old snapshot.

## Validation

Backend: install `moto[dynamodb]` into an isolated test environment alongside the existing requirements, then run `python -m unittest test_lecture_catalog -v`. Tests create only emulated tables and cover assignments, moves, numeric ordering, counts, conflicts, preservation of notes, module-list updates, deletion, scope validation, and server admin authorization.

Frontend: `npx tsc --noEmit --incremental false`, the standard Next build, and `node tests/catalog-browser.mjs` against a local server with the catalog flag enabled. The browser script needs Playwright and an installed Chromium; `CATALOG_TEST_BROWSER` can specify its executable. Every API request is mocked and nonlocal requests are blocked. It exercises state restoration, mobile layout, and God Mode creation/options.

No pricing, checkout, entitlements, or bundle discounts are introduced. Future bundles can reference canonical unit IDs across series after the workbook's cross-series equivalence decisions are approved.
