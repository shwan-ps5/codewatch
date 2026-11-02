# Python front-end CVE pairs, second batch (2026-11-02): every advisory read

Source: GitHub-reviewed advisories in the PyPI ecosystem (OSV export, all years) with CWE 22, 78, 79, 89, 94, 502,
601, 611, 918 or 1336 and a referenced fix commit. 1,050 name exactly one fix commit (59 already in a suite); the
991 others were fetched (`git fetch --depth 2 --filter=blob:none`, two at a time) and kept when the fix changes a
template or a front-end script (.html, Jinja, .js/.ts/.tsx/.vue) outside tests and vendored bundles: 44 within
step 22's limits (three non-test source files, 150 lines), 21 more up to six files or 400 lines, and 37 larger
ones, of which those with a small total change were read. Advisories naming two or three commits in one repository
(67 with CWE-79) were read too for Django/Flask/FastAPI apps; one was accepted only when the extra commits are
backports of the same change, and the main-branch commit is used.

Rules, as in PLAN.md step 22: an application built on Django, Flask or FastAPI (reusable Django apps and Flask
modules count; frameworks, libraries, Tornado/CherryPy/Bottle/Falcon/Twisted apps and tools don't); the fix
changes a template or shipped script and is one change for one weakness; the flow is in the changed files. Split
before any scan: blind when `int(sha256(id), 16) % 3 == 0`. Blind cases are described here only by app and file
kind, so this record can't guide rule work.

`.svelte` isn't a scored extension (`SOURCE_EXTENSIONS["python-web"]`), so fixes made only in Svelte components
(Open WebUI, Fava) were rejected; Fava GHSA-6hcj-qrw3-m66q is scored on its .ts files only.

## Accepted (30: 21 in cve-pairs-python-frontend, 9 blind)

- `GHSA-3c5x-4hvx-qrrr` accepted (`cve-pairs-python-frontend`): graphite-web dashboard.js (+ views.py): relative-time fields stored unencoded and rendered into the dashboard; fix HTML-encodes them, anchors the number regex, and checks the dashboard name parameter.
- `GHSA-3m3h-v9hv-9j4h` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): django-wiki (Django), notification plugin JS.
- `GHSA-52gm-qmg3-r4qp` accepted (`cve-pairs-python-frontend`): airflow ti_log.js/utils.ts: log text through AnsiUp linkified any URL scheme into HTML; fix sets url_allowlist = {}.
- `GHSA-5jc6-h9w7-jm3p` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): MobSF (Django), a template script plus upload views.
- `GHSA-6g7x-4c7m-g63m` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): Review Board (Django), reviews JS.
- `GHSA-6hcj-qrw3-m66q` accepted (`cve-pairs-python-frontend`): Fava (Flask) frontend charts (bar.ts, line.ts, tooltip.ts...): ledger account names and descriptions concatenated into tooltip HTML; fix builds DOM nodes. Its two .svelte files aren't a scored extension, so only the .ts part is scored.
- `GHSA-6wxc-8mgq-w26m` accepted (`cve-pairs-python-frontend`): Weblate full.js/search.js: unit search results and machine-translation origins (stored strings) built into the preview with jQuery HTML/template strings; fix builds DOM nodes and allows only http(s) origin links. 222 changed lines (a rewrite of one widget), over step 22's 120-line limit but one focused fix.
- `GHSA-8vwv-2v7v-jmgr` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): Horizon (Django), static JS plus table code; backport pair, master commit c844bd6 used.
- `GHSA-9wj3-cfq8-wpvj` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): modoboa (Django), a form template and nav JS. GHSA-pqgm-9g82-wcm7 shares its commit.
- `GHSA-c467-5c2g-jp86` accepted (`cve-pairs-python-frontend`): modoboa admin.js: domain name input and title attribute into $.html / confirm question; fix adds htmlEncode.
- `GHSA-crvm-xjhm-9h29` accepted (`cve-pairs-python-frontend`): OctoPrint action_command_*.js: printer-sent messages passed as PNotify/dialog HTML; fix wraps them in _.escape.
- `GHSA-fh64-r2vc-xvhr` accepted (`cve-pairs-python-frontend`): MLflow UI (.tsx/.ts): MLmodel artifact parsed with js-yaml load() (custom JS types execute); fix uses safeLoad.
- `GHSA-fmqq-25x9-c6hm` accepted (`cve-pairs-python-frontend`): Indico (Flask) misc.js + templates: confirmation prompts built with jQuery {html: message} from titles users submit; fix uses {text: message} and drops HTML from the messages. Eleven files, 35 lines, one weakness.
- `GHSA-h8pc-j334-jjhm` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): OctoPrint (Flask), settings JS and a Jinja2 snippet.
- `GHSA-j772-hpmw-32rm` accepted (`cve-pairs-python-frontend`): (backport pair; 7f8c788 used) Horizon horizon.js: instance console log response put into $('pre.logs').html; fix uses .text.
- `GHSA-jxgr-gcj5-cqqg` accepted (`cve-pairs-python-frontend`): (LTS backport pair; 42440eb on develop used) Nautobot object_list.html + forms.js: filter field names/values from the query string printed into unquoted data- attributes and rebuilt into the URL by string splicing; fix quotes the attributes and uses URLSearchParams.
- `GHSA-mfv8-q39f-mgfg` accepted (`cve-pairs-python-frontend`): invenio-communities (Flask module) about.html/portalbox_main.html: community page, description and curation policy (user-written HTML) printed with |safe; fix adds a bleach sanitize_html filter.
- `GHSA-mgmm-cmhj-2h5f` accepted (`cve-pairs-python-frontend`): modoboa listing.js: filter tag text passed as jQuery "html"; fix adds htmlEncode.
- `GHSA-mqwh-r366-4224` accepted (`cve-pairs-python-frontend`): cabot statuscheck_detail.html: check result error (from the polled endpoint) under autoescape off; fix removes it.
- `GHSA-pjx4-3f3p-29v3` accepted (`cve-pairs-python-frontend`): django-ucamlookup templates: select2 configured with escapeMarkup identity, so directory names/titles render as HTML; fix escapes them.
- `GHSA-pwgc-w4x9-gw67` accepted (`cve-pairs-python-frontend`): changedetection.io templates: macros and pages in .jinja files, which Flask doesn't autoescape, printed watch and tag fields; fix renames them to .html (autoescape on) and updates imports. Seven files, 20 changed lines plus the renamed files.
- `GHSA-rffm-9q57-q649` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): Open WebUI (FastAPI), a front-end TS utility.
- `GHSA-vx6v-xg64-pmr8` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): django-helpdesk (Django), a list template; fix 2c7065e used, the other commit is its backport.
- `GHSA-wcm6-wv95-7jw6` accepted (`cve-pairs-python-frontend`): pyLoad packages.js (both themes): link URL and name concatenated into HTML; fix adds onclick='return false' to the link (partial: name stays unescaped, so a still-flagged finding would be real).
- `GHSA-wpvx-26f7-65q3` accepted, **blind** (`cve-pairs-blind-python-frontend-2`): Mayan EDMS (Django), common templates.
- `GHSA-wrp6-9w7f-3wxg` accepted (`cve-pairs-python-frontend`): calibre-web edit_books.js: chosen upload file name put into the page with $.html; fix uses .text.
- `GHSA-x7mf-wrh9-r76c` accepted (`cve-pairs-python-frontend`): OctoPrint classicwebcam_settings.js: snapshot content type from a fetched URL concatenated into $("<p>...<img src=...>"); fix builds elements with .text/.attr.
- `GHSA-xrf4-39fm-j5f2` accepted (`cve-pairs-python-frontend`): Fava (Flask) errors.html/_layout.html/help.html: error messages that echo the time/filter query parameters printed with |safe; fix drops |safe and marks only trusted HTML as Markup.
- `GHSA-xv64-8p4r-94gq` accepted (`cve-pairs-python-frontend`): pgAdmin browser/templates/browser/js/utils.js: a stored layout setting printed into a JS string in a Jinja-rendered script ('{{ layout }}', no HTML autoescape for .js); fix uses |tojson. The other two files are small refactors.
- `GHSA-xvxq-g8hw-fx4g` accepted (`cve-pairs-python-frontend`): OctoPrint .jinja2 templates (autoescape off): request headers, host, user and plugin fields printed raw (reverse_proxy_test reflects request headers); fix adds |e and an autoescape block. Eight files, 54 lines, one weakness.

## Rejected (93)

- `GHSA-246w-56m2-5899` rejected: Synapse: Twisted server; ten files.
- `GHSA-2g59-m95p-pgfq` rejected: Chainlit: SSRF fixed in Python only (server.py); the one JS file is a Cypress test helper. Not a front-end case.
- `GHSA-2r4h-8jxv-w2j8` rejected: CKAN: fix in a Python helper only.
- `GHSA-3p4q-x8f3-p7vq` rejected: Jupyter Notebook: Tornado app.
- `GHSA-3v79-q7ph-j75h` rejected: MLflow: two different commits in Python.
- `GHSA-3xpf-xq7r-v8c5` rejected: open-webui: fix only in .svelte files, not a scored extension.
- `GHSA-3xxv-p78r-4fc6` rejected: airflow: the referenced commit only adds a CodeMirror JSON editor to trigger.html; the XSS fix itself is not in it.
- `GHSA-4952-p58q-6crx` rejected: JupyterLab: library sanitizer allowlist (apputils), Tornado app.
- `GHSA-4h72-34j6-j8x7` rejected: Maloja: Bottle app, not Django/Flask/FastAPI.
- `GHSA-4m3g-6r7g-jv4f` rejected: gradio-pdf: a Gradio component; the fix is a dependency upgrade in build config.
- `GHSA-4w8f-hjm9-xwgf` rejected: django-s3file: path traversal fixed in the Python middleware; the JS change is incidental. Not a front-end case.
- `GHSA-4wcc-jv3p-prqw` rejected: CherryMusic: CherryPy app.
- `GHSA-547x-748v-vp6p` rejected: Dash: framework.
- `GHSA-56v6-2fhr-wxgq` rejected: Nautobot: fix in Python forms only.
- `GHSA-5qrq-9645-g5g2` rejected: Fides: fides.js consent library, eleven TS files.
- `GHSA-6jp6-9rf9-gc66` rejected: Weblate: three different commits in unrelated places.
- `GHSA-72qc-wxch-74mg` rejected: NiceGUI: UI framework; the fix is in the framework's add_css (Python), not an app.
- `GHSA-785h-76cm-cpmf` rejected: django-tomselect: a widget library; nine templates.
- `GHSA-78qv-3mpx-9cqq` rejected: NiceGUI: UI framework; the fix is in Element.run_method (Python).
- `GHSA-7hfx-h3j3-rwq4` rejected: D-Tale: thirteen files, SSRF setting.
- `GHSA-7pq5-qcp6-mcww` rejected: CKAN: upload type checks in Python only.
- `GHSA-824w-x939-6cmc` rejected: TensorZero: Rust gateway with a TypeScript UI server; not a Python web app.
- `GHSA-8g68-2hcj-h8vg` rejected: Horizon: fix in a Python template filter only.
- `GHSA-8hf7-h89p-3pqj` rejected: MobSF: 203 lines, mostly Python manifest descriptions; templates change only the filter.
- `GHSA-8p7v-2jvj-v54r` rejected: Airflow: fix in Python (www/utils.py) only.
- `GHSA-8w3f-4r8f-pf53` rejected: pyLoad: a rewrite (mostly re-indentation) of a userscript that runs inside third-party captcha pages, not the app's own pages; 186 lines.
- `GHSA-927p-xrc2-x2gj` rejected: ansibleguy-webui: mixes Python model validators in five files with JS escaping.
- `GHSA-947x-pv47-pp3q` rejected: pywb: its own WSGI framework.
- `GHSA-99cv-8cvv-666c` rejected: Airflow: fix in Python views only.
- `GHSA-9cg4-9hv5-3376` rejected: WebSSH: Tornado app.
- `GHSA-9f4f-jv96-8766` rejected: open-webui: fix only in .svelte files, not a scored extension.
- `GHSA-9q4r-x2hj-jmvr` rejected: copyparty: its own HTTP server, not Django/Flask/FastAPI.
- `GHSA-c3qv-mf8h-434r` rejected: Roundup: its own web framework.
- `GHSA-c5f8-35qr-q4fm` rejected: Synapse: Twisted server; ten files.
- `GHSA-cf72-vg59-4j4h` rejected: Khoj: two different commits (sanitizing, then a 345-line DOM rewrite).
- `GHSA-cf9f-wmhp-v4pr` rejected: Nautobot: 21-22 Python files per commit.
- `GHSA-ch57-39q2-4crm` rejected: malla: 23 files.
- `GHSA-cj5w-8mjf-r5f8` rejected: jupyterlab-git: JupyterLab extension (Tornado); command injection into a terminal session.
- `GHSA-cjjf-27cc-pvmv` rejected: pyLoad: the fix mixes a Python path-traversal change (cnl_blueprint.py) with a postMessage origin check in a userscript; unrelated changes in one commit.
- `GHSA-cxqq-w3x5-7ph3` rejected: MobSF: eight source files, mixing a loosened URL regex, Python validation moves and template changes.
- `GHSA-f962-v9hr-pfg5` rejected: jupyterlab-git: a JupyterLab extension (Jupyter server, Tornado), not a Django/Flask/FastAPI app.
- `GHSA-fj2m-qvh9-jq4q` rejected: local-deep-research: two different commits, both Python (PDF pipeline).
- `GHSA-fqxj-46wg-9v84` rejected: Flask-AppBuilder: framework code (its stock OAuth login template).
- `GHSA-g4rf-pc26-6hmr` rejected: OMERO.web: twelve files mixing Python redirect checks and templates.
- `GHSA-g4rw-82hq-8jpr` rejected: MapProxy: its own WSGI service, fix in Python.
- `GHSA-g67g-hvc3-xmvf` rejected: OMERO.web: 25 files.
- `GHSA-grm6-x6mr-q3cv` rejected: Horizon: fix in Python only (escaping Angular templating in safe HTML).
- `GHSA-gw2q-cgvq-9g3v` rejected: Roundup: its own web framework; two different commits.
- `GHSA-h5wp-jrqc-cwwx` rejected: rdiffweb: CherryPy app.
- `GHSA-hm45-mgqm-gjm4` rejected: Red-Dashboard: two different commits.
- `GHSA-hwvq-6gjx-j797` rejected: Jupyter Notebook: Tornado app; the fix swaps the whole sanitizer library.
- `GHSA-j4gv-6x9v-v23g` rejected: OMERO.web: a jquery-form library update across ten files.
- `GHSA-j57p-g33w-95c5` rejected: Horizon: lists the same fix commits as GHSA-8vwv-2v7v-jmgr.
- `GHSA-jmc6-2wr8-h3wj` rejected: open-webui: the fix is in .svelte components (iframe sandbox); the only counted file (stores/index.ts) holds a setting default. .svelte isn't a scored extension.
- `GHSA-jpgw-2r9m-8qfw` rejected: Kiwi TCMS: two different commits (upload MIME types; a Python sanitizer).
- `GHSA-jq6c-r9xf-qxjm` rejected: D-Tale: fifteen files, RCE through custom filters (Python).
- `GHSA-m2jw-cj8v-937r` rejected: copyparty: its own HTTP server, not Django/Flask/FastAPI.
- `GHSA-m3v4-v5gx-7wf5` rejected: OpenMed: a library; code injection in model loading (Python).
- `GHSA-m65p-9j7q-6w33` rejected: MLflow: path traversal fixed in Python handlers; the .ts change only passes a field. Not a front-end case.
- `GHSA-m973-4vpc-x43c` rejected: graphite-web: same fix commit (2f178f4) as GHSA-3c5x-4hvx-qrrr.
- `GHSA-p4g9-c9qr-wmg5` rejected: django-ajax-utilities pagination.js: a URL-prefix check bypass ("/\"); a validator bypass no rule can see.
- `GHSA-p6rw-44q7-3fw4` rejected: nbdime: Jupyter/Tornado tool.
- `GHSA-pqgm-9g82-wcm7` rejected: modoboa: same fix commit (d33d3cd) as GHSA-9wj3-cfq8-wpvj; one pair per commit.
- `GHSA-pwxh-7358-jq2x` rejected: open-webui: fix only in .svelte files, not a scored extension.
- `GHSA-q624-9634-77gh` rejected: CherryMusic: CherryPy app; same commit as GHSA-4wcc-jv3p-prqw.
- `GHSA-q68h-xwq5-mm7x` rejected: label-studio: a rebuilt minified bundle plus error-page templates; the avatar-upload flow isn't visible in the change.
- `GHSA-q8hg-3vqv-f8v3` rejected: Fava: fix only in .svelte files, not a scored extension.
- `GHSA-q99p-78hp-xg5c` rejected: graphite-web: same fix commit (2f178f4) as GHSA-3c5x-4hvx-qrrr.
- `GHSA-qxh9-qmf2-rhwc` rejected: Roundup: its own web framework, not Django/Flask/FastAPI; 23 files.
- `GHSA-r2hr-4v48-fjv3` rejected: Nautobot: BANNER_* configuration rendered as HTML; settings, two different commits.
- `GHSA-r3jc-vhf4-6v32` rejected: CKAN: fix in Python (datatables blueprint) only.
- `GHSA-r5pr-887v-m2w9` rejected: Memray: a profiler writing static HTML reports from command-line metadata; no web app.
- `GHSA-r735-9gc6-2hvq` rejected: calibre-web: same fix commit (7ad419d) as GHSA-wrp6-9w7f-3wxg, a later duplicate advisory.
- `GHSA-rfw2-x9f8-2f6m` rejected: LinkedIn Oncall: Falcon app.
- `GHSA-rhjj-f6gq-6gx2` rejected: Horizon: fix in Python only.
- `GHSA-rmjr-87wv-gf87` rejected: mammoth.js: a JS library (docx conversion), not an app.
- `GHSA-v4xv-795h-rv4h` rejected: Nautobot: Markdown sanitizing added in Python only.
- `GHSA-v82v-c5x8-w282` rejected: NiceGUI: framework, vendored DOMPurify.
- `GHSA-vcf6-3wv2-5vcr` rejected: Airflow: two different commits (template literals, then URL detection), not one fix.
- `GHSA-vfj8-5pj7-2f9g` rejected: OpenC3 COSMOS: Ruby/Vue app; the pip package is a client.
- `GHSA-vq76-5ghr-9p4v` rejected: manila-ui: fix in Python only.
- `GHSA-vqxw-9pg7-v7v9` rejected: Locust: fix in Python (web.py) only.
- `GHSA-vv2x-vrpj-qqpq` rejected: Bleach: sanitizer library.
- `GHSA-w7xj-8fx7-wfch` rejected: open-webui: fix only in .svelte files, not a scored extension.
- `GHSA-w8vc-cwv9-wx67` rejected: Roundup: its own web framework.
- `GHSA-wxhm-2mq7-7697` rejected: Prompty: a library (prompt loader), not a web app.
- `GHSA-x2mh-8fmc-rqgh` rejected: Airflow: connection testing put behind a settings flag (Python and a form script); a settings flag, not a code flow.
- `GHSA-x37x-qf4v-f54f` rejected: Roundup: its own web framework.
- `GHSA-xgfm-fjx6-62mj` rejected: readthedocs-sphinx-search: a Sphinx extension's JS (library), not an app.
- `GHSA-xjgw-ghrx-wfff` rejected: Roundup: its own web framework.
- `GHSA-xqcf-hj92-967m` rejected: Django REST framework: framework code (the browsable API's base.html), like Django's own templates.
- `GHSA-xvg9-69gf-fjrf` rejected: Material for MkDocs: a static-site theme, not a Python web app.
- `GHSA-xx6g-jj35-pxjv` rejected: WsgiDAV: a WebDAV library/server, not a Django/Flask/FastAPI app.
