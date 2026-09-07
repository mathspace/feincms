# feincms threat model

## Overview

A composable Django CMS embeds page-tree models, content types, rendering, editor/admin interfaces and optional media library into a caller Django project. Public Handler resolves pages through the configured page model; optional preview, embedded applications, contact forms and media ZIP import/export introduce distinct boundaries (feincms/views/__init__.py:16; feincms/content/application/models.py:304; feincms/module/medialibrary/modeladmins.py:128).

FeinCMS supplies components rather than a complete site policy. Which URLs, content types, editors and storage backends are enabled is a caller choice. Publication visibility, staff preview, object editing, upload permission and eventual media access are independently enforced interfaces; authority over one must not be silently treated as authority over all.

| Component | Source |
| --- | --- |
| Page selection and optional preview | feincms/views/__init__.py:16; feincms/contrib/preview/views.py:18 |
| Content rendering and embedded applications | feincms/content/raw/models.py:23; feincms/content/application/models.py:304 |
| Admin permissions and media workflows | feincms/admin/tree_editor.py:444; feincms/module/medialibrary/modeladmins.py:128 |
| Contact forms and packaging | feincms/content/contactform/models.py:51; setup.py:21 |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Library embedded in Django | Media file save | Django setting FEINCMS_MEDIALIBRARY_UPLOAD_TO or medialibrary/%Y/%m/ → field; reconfigure may replace storage/upload_to | Default storage name medialibrary/&lt;year&gt;/&lt;month&gt;/&lt;generated filename&gt;; reconfigure can override storage/upload_to | Storage backend/readers | Django field storage and admin upload permission | feincms/default_settings.py:23; feincms/module/medialibrary/models.py:105; feincms/module/medialibrary/models.py:131 |
| Privileged ZIP import | ZIP overwrite | Admin POST overwrite + ZIP member dirname/basename → normalized name → field.upload_to override → storage save | Archive dirname + slugified basename + lowercased extension, passed through MediaFile storage | Media storage and database | Admin/CSRF/add permission plus storage path handling | feincms/module/medialibrary/zip.py:75; feincms/module/medialibrary/zip.py:97 |
| Privileged ZIP export | ZIP export | Admin selected queryset + current site/domain/date → fixed basename → os.path.join(MEDIA_ROOT, basename); redirect MEDIA_URL join | MEDIA_ROOT/export_&lt;slugified site.domain&gt;_&lt;YYYYMMDD&gt;.zip; download redirect MEDIA_URL plus that basename | Local filesystem then media-serving audience | Admin action authorization; subsequent media access host-owned | feincms/module/medialibrary/zip.py:137; feincms/module/medialibrary/modeladmins.py:107 |
| Optional public contact-form content | Contact email | Contact POST → configured form validation → cleaned email/body → content.email recipient → host mail backend | Recipient [ContactFormContent.email]; sender from validated submitted email | Configured mail backend and content recipient | Django form validation; host mail/rate/CSRF policy | feincms/content/contactform/models.py:55 |
| Operator medialibrary_to_filer | Media migration | Required content types + first auth.User by pk → all MediaFile rows → filer model/file creation and content replacement | Host django-filer DB/storage; new file owner is first auth.User; matching old page-media content deleted | Host storage/database; selected first user receives ownership | Operator authority; required content-type assertion; caller must assess target ownership/rollback | feincms/management/commands/medialibrary_to_filer.py:20; feincms/management/commands/medialibrary_to_filer.py:28 |
| Operator rebuild_mptt | Tree rebuild | Command → Page._tree_manager.rebuild() | Host Page tree database pointers | Host database | Operator management/database authority | feincms/management/commands/rebuild_mptt.py:27 |
| Operator medialibrary_orphans | Orphan report | os.walk of literal relative path; compare names to MediaFile file values | &lt;command working directory&gt;/media/medialibrary; unmatched paths printed to stdout, no deletion | Local file reader and operator console | Host file-read permissions; report only; MEDIA_ROOT not consulted | feincms/management/commands/medialibrary_orphans.py:14 |

## Threat Model, Trust Boundaries, and Assumptions

**Protected assets.** Published/draft page content and tree state, media files, archive metadata, contact-form personal data and editor authority (feincms/module/page/models.py:148; feincms/module/medialibrary/zip.py:149; feincms/content/contactform/models.py:20). Trusted HTML/template/application configuration and host storage/database integrity (feincms/content/raw/models.py:23; feincms/content/application/models.py:317).

**Actors and starting authority.** Public visitors control paths, query strings and exposed form input; staff editors and uploaders possess separate explicitly granted content/media authority. Archive uploaders can influence bytes, entry paths and comments but are not inherently filesystem administrators. A developer defining templates, URLconfs, wrappers or storage backends already provides executable application configuration.

**Trust boundaries and owned controls.**

- Anonymous/request callers resolve best-match active pages with active-ancestor checks. This is publication visibility, not a complete site-specific ownership policy. Preview reads page by ID and requires staff, setting private/no-store response headers (feincms/module/page/models.py:85; feincms/contrib/preview/views.py:18).
- Editors use Django admin permissions. TreeEditor optionally invokes object-aware has_perm; default is model-level checks. Caller must install an actual object-permission backend when enabling that setting (feincms/admin/tree_editor.py:444; feincms/default_settings.py:62).
- Content editors can supply HTML: RawContent marks text safe; RichTextContent passes an optional cleanser to RichTextField, whose form cleaning calls that function. Trust in editors and chosen cleanser is material; rich text is not uniformly escaped plain text (feincms/content/raw/models.py:23; feincms/content/richtext/models.py:43; feincms/contrib/richtext.py:17).
- ApplicationContent resolves configured URLconf and directly calls the resolved view or trusted wrapper with the request. Embedded application authentication/authorization belongs to that view/integration; CMS page selection does not independently grant its capabilities (feincms/content/application/models.py:317).
- Media bulk upload is admin_view wrapped, CSRF protected and requires medialibrary.add_mediafile. ZIP bytes and JSON comments produce files, metadata and categories; overwrite uses archive directory plus normalized basename. Django storage owns final name/path enforcement (feincms/module/medialibrary/modeladmins.py:128; feincms/module/medialibrary/modeladmins.py:222; feincms/module/medialibrary/zip.py:43).
- Export reads selected media local paths, writes a deterministic site/date archive under MEDIA_ROOT and redirects to MEDIA_URL. Access to served archive content is a separate hosting boundary from permission to run the admin action (feincms/module/medialibrary/zip.py:137; feincms/module/medialibrary/modeladmins.py:96).
- Contact-form POST validates Django form data then mails from submitted email to the content-configured recipient. Host mail backend, CSRF middleware and abuse/rate policy remain caller configuration (feincms/content/contactform/models.py:51).
- Local management commands retain operator authority: medialibrary_to_filer copies media into django-filer owned by the first auth.User ordered by primary key, creates replacement content and deletes old content; rebuild_mptt calls the Page tree manager. medialibrary_orphans only reports paths from a fixed working-directory-relative media/medialibrary walk, rather than resolving MEDIA_ROOT (feincms/management/commands/medialibrary_to_filer.py:28; feincms/management/commands/rebuild_mptt.py:27; feincms/management/commands/medialibrary_orphans.py:14).

**Security objectives.** Separate public publication, staff preview, page editing, media mutation and archive reading permissions. Match HTML trust to editor permissions and cleanse policy; preserve embedded-view access controls. Keep archive import/export within intended storage and audience; protect form data and apply host resource limits.

**Assumptions and unresolved controls.**

- Concrete MEDIA_ROOT, MEDIA_URL, storage backend, authentication backend and public site URL are caller-owned and absent.
- Object-level permission default is false; this is an explicit configurable model, not evidence of tenant isolation.
- Library setup builds FeinCMS; no CI publishing workflow appears in inventory (setup.py:21).
- Caller URL wiring, storage path checks, editor roles, cleansing policy, media-server access and resource limits require deployment evidence. Normal page publication rules do not demonstrate tenant isolation or private media protection.

## Attack Surface, Mitigations, and Attacker Stories

These are prioritized hypotheses, not validated vulnerabilities. Each requires its stated caller, data and exposure prerequisites; ordinary use of authority already granted is not a new capability.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | An editor or media uploader crosses the authority intended for their role, exposing draft/private content or executing active content in a more-privileged reader’s browser. | A real installation grants lower-trust content authorship and renders that content with insufficient policy for its audience. | Content confidentiality or browser-session compromise. | Django admin permissions, optional object permissions, staff preview; optional rich-text cleanser. | Match author trust to allowed content types and sanitization; define object/preview scope. | feincms/admin/tree_editor.py:444; feincms/contrib/preview/views.py:30; feincms/content/raw/models.py:23 |
| 1 | A privileged archive export becomes readable by an unauthorized media-serving audience. | MEDIA_URL serves the generated archive without the intended equivalent authorization. | Bulk disclosure of selected files and metadata. | Admin action controls export initiation; actual download controls belong to media hosting. | Bind export retrieval to its intended audience and define cleanup/retention. | feincms/module/medialibrary/zip.py:137; feincms/module/medialibrary/modeladmins.py:107 |
| 2 | A permitted ZIP uploader supplies paths, comments or compressed content that cause unintended overwrite or excessive import work. | Upload permission plus relevant storage/path/resource behavior; direct filesystem traversal is not assumed. | Media integrity loss or bounded/shared resource exhaustion. | Admin wrapper, CSRF, add permission, normalized basename and Django storage enforcement. | Constrain overwrite authority and archive work; verify final paths with the configured storage. | feincms/module/medialibrary/modeladmins.py:222; feincms/module/medialibrary/zip.py:75 |
| 2 | A public request reaches an embedded application capability whose caller assumes the CMS already authorized it. | ApplicationContent is enabled and its resolved view lacks required independent access checks. | Unauthorized application action/data access. | Configured URLconf/view wrapper and host view-level controls. | Preserve embedded-view authentication/authorization across CMS mounting. | feincms/content/application/models.py:317 |
| 3 | Public contact-form traffic sends unwanted volume or discloses submitted data to a misconfigured recipient. | Enabled content type, reachable form and insufficient host abuse/recipient policy. | Mail resource use or personal-data disclosure. | Django form validation; recipient comes from configured content rather than submitted recipient data. | Constrain configured recipients and apply host rate/CSRF/mail policy. | feincms/content/contactform/models.py:51 |
| 3 | An operator migrates media assuming ownership and rollback are preserved automatically. | The optional django-filer migration is usable and its first-user ownership or partial content replacement differs from the approved target policy. | Unintended file ownership/content changes; scope depends on host filer permissions. | Required content-type assertion; migration runs with local operator authority. | Verify target owner, storage and recovery plan before authorizing migration. | feincms/management/commands/medialibrary_to_filer.py:20; feincms/management/commands/medialibrary_to_filer.py:28 |

## Severity Calibration (Critical, High, Medium, Low)

| Level | Repository-specific example | Counterexample or limiting prerequisite |
| --- | --- | --- |
| Critical | A demonstrated CMS boundary grants broad privileged server execution or mass access to highly sensitive hosted data. | Neither raw HTML authoring nor archive-upload permission alone establishes server execution or that data scale. |
| High | A lower-trust author compromises a privileged browser session, or an archive download exposes confidential bulk media. | Requires actual author/viewer trust separation or private files and reachable unauthorized downloads. |
| Medium | A permitted uploader damages a bounded media set or reachable inputs cause a material limited outage. | Storage controls, size limits and privilege already granted to the uploader can reduce or remove new impact. |
| Low | A local editor preview or best-effort contact notification fails without protected data or state impact. | Intentionally public content/media and trusted raw-HTML authoring are not defects by themselves. |

This model uses an independent source-backed architecture pass. Repository citations were checked against the supplied inventory and source lines; application code and external services were not executed. Source-established behavior is distinct from unverified deployment exposure. Revisit the model when the described input, storage, authorization or publication boundaries change.

Repository: github.com/mathspace/feincms
Version: 8a4d46e31b2ca21ea426a3cd834b29e885d54335
