#!/bin/bash
# One-shot Odoo 18 pre-auth lab (own deployment). Test ONLY against this — that is
# what Odoo's policy permits ("test exclusively on your own deployments").
#   usage: bash odoo-lab-docker.sh [dbname] [master_pwd]
set -e
DB="${1:-labdb}"
MP="${2:-zoya-lab-2026}"
B="http://127.0.0.1:8069"

echo "== images =="
sudo docker pull -q postgres:16 && sudo docker pull -q odoo:18

echo "== postgres (POSTGRES_USER is created as SUPERUSER -> RCE leg representable) =="
sudo docker rm -f zoya_pg >/dev/null 2>&1 || true
sudo docker run -d --name zoya_pg -e POSTGRES_USER=odoo -e POSTGRES_PASSWORD=odoo \
  -e POSTGRES_DB=postgres postgres:16 >/dev/null
sleep 8

echo "== odoo =="
sudo docker rm -f zoya_odoo >/dev/null 2>&1 || true
sudo docker run -d --name zoya_odoo --link zoya_pg:db -p 127.0.0.1:8069:8069 \
  -e HOST=db -e USER=odoo -e PASSWORD=odoo odoo:18 >/dev/null
sleep 20

echo "== pin dbfilter (without this, auth='public' routes 404 on a multi-DB host) =="
sudo docker exec zoya_odoo bash -c \
  "grep -q '^dbfilter' /etc/odoo/odoo.conf || printf 'dbfilter = ^${DB}\$\n' >> /etc/odoo/odoo.conf"
sudo docker restart zoya_odoo >/dev/null; sleep 18

echo "== init a DB (installs 'website' so its public routes exist) =="
sudo docker exec zoya_odoo odoo -d "$DB" -i website --without-demo=all --stop-after-init \
  --db_host=db --db_user=odoo --db_password=odoo 2>&1 | tail -2
sudo docker restart zoya_odoo >/dev/null; sleep 15

echo "== smoke test =="
curl -s -o /dev/null -w "  /web/database/manager      -> HTTP %{http_code}\n" "$B/web/database/manager"
curl -s -X POST "$B/jsonrpc" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"call","params":{"service":"db","method":"list","args":[]},"id":1}'; echo
echo "  shipped conf: $(sudo docker exec zoya_odoo grep -E '^; *admin_passwd' /etc/odoo/odoo.conf)"
echo "  role: $(sudo docker exec zoya_pg psql -U odoo -d postgres -tAc "select rolname,rolsuper from pg_roles where rolname='odoo'")"
echo
echo "Lab up. Master password default is 'admin'; adopt your own via:"
echo "  curl -s -o /dev/null -w '%{http_code}\n' -X POST $B/web/database/create \\"
echo "    --data-urlencode master_pwd=$MP --data-urlencode name=$DB --data-urlencode lang=en_US \\"
echo "    --data-urlencode password=admin --data-urlencode login=admin --data-urlencode phone= --data-urlencode demo=False"
