# Cloud-Based Image Storage Application - S. Younish (5325128021)
Flask app: authentication, upload with validation (5 MB, PNG/JPG/JPEG/GIF/WEBP), categories/tags/folder-style keys,
thumbnails, search + filter (name, category, date), controlled share links, storage usage, owner-only view/delete.

## Run locally (demo mode, no OCI needed)
    py -m venv .venv
    .venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    python app.py          ->  http://127.0.0.1:5000

## Cloud mode (what the hackathon asks for)
1. Object storage: create private bucket `younish-image-store-5325128021`; set up `~/.oci/config` (OCI SDK).
2. Set env vars: OCI_ENABLED=true, OCI_NAMESPACE, OCI_BUCKET, OCI_REGION.
3. Cloud database for metadata: create an OCI Autonomous Database (Always Free), download its wallet,
   then set DATABASE_URL=oracle+oracledb://USER:PASSWORD@TNS_ALIAS  (tables are created automatically).
4. Run `python app.py`, upload an image, then verify it in OCI Console (bucket Objects + database table).
Never commit keys, wallet files or passwords.
