# LaboratorySystem Web

## Run
1. Open Command Prompt in this folder.
2. Run `py -m pip install -r requirements.txt`
3. Run `py app.py`
4. Open http://127.0.0.1:5000

Default admin: `admin` / `Admin@123`

The app creates `hardware_inventory.db` automatically. Do not delete the database if you want to preserve users, inventory, requests, and history.

## Database architecture and reset

The web application uses one SQLite database file only:

`hardware_inventory.db`

It contains the `users`, `hardware`, `hardware_requests`, `password_resets`, and `audit_log` tables. The application no longer auto-seeds hardware every time it starts, so deleting the database will not silently restore an old hardware catalog. Admin can use **Dashboard -> Reset Database** to clear all application data and recreate only the default administrator account.

After a reset, add the required hardware again through the Admin Hardware Catalog.
