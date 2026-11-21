#!/usr/bin/env bash
# Applies the fixes shieldcheck prints to a real web server and scans again.
# The site must go from F to A with nothing but the generated snippets.
#
# For CI runners only: it overwrites system web server config and /var/www/html
# with sudo. Usage: live-fixes.sh nginx|apache|caddy  (needs ./shieldcheck and jq)
set -euo pipefail

server=$1
url=http://127.0.0.1/
work=$(mktemp -d)

case $server in
  nginx) service=nginx ;;
  apache) service=apache2 ;;
  caddy) service=caddy ;;
  *) echo "unknown server $server" >&2; exit 2 ;;
esac
sudo apt-get install -y -qq "$service" >/dev/null

# A site with no security headers that also leaks /.git and /.env.
sudo rm -rf /var/www/html
sudo mkdir -p /var/www/html/.well-known /var/www/html/.git
echo '<!doctype html><title>fixture</title><p>fixture</p>' | sudo tee /var/www/html/index.html >/dev/null
printf 'Contact: mailto:security@fixture.test\nExpires: %s\n' "$(date -u -d '+6 months' +%Y-%m-%dT%H:%M:%SZ)" |
  sudo tee /var/www/html/.well-known/security.txt >/dev/null
echo 'ref: refs/heads/main' | sudo tee /var/www/html/.git/HEAD >/dev/null
echo 'FIXTURE_KEY=not-a-secret' | sudo tee /var/www/html/.env >/dev/null

# configure writes the server's config with the given snippet files pasted
# where each snippet's caption says it belongs, then restarts the server.
configure() {
  local fixes
  fixes=$(cat "$@" /dev/null)
  case $server in
    nginx)
      printf 'server {\n    listen 80 default_server;\n    root /var/www/html;\n%s\n}\n' "$fixes" |
        sudo tee /etc/nginx/sites-enabled/default >/dev/null
      sudo nginx -t
      ;;
    apache)
      echo "$fixes" | sudo tee /etc/apache2/conf-available/zz-shieldcheck.conf >/dev/null
      sudo a2enmod -q headers
      sudo a2enconf -q zz-shieldcheck
      sudo apache2ctl configtest
      ;;
    caddy)
      printf ':80 {\n    root * /var/www/html\n    file_server\n%s\n}\n' "$fixes" |
        sudo tee /etc/caddy/Caddyfile >/dev/null
      ;;
  esac
  sudo systemctl restart "$service"
  curl --silent --retry 10 --retry-connrefused --retry-delay 1 --output /dev/null "$url"
}

fix() { # fix <jq filter selecting the []Fix list>: prints this server's snippet
  jq -r --arg p "$server" "$1 | .[]? | select(.platform == \$p) | .snippet" "$work/before.json"
}

configure
./shieldcheck scan "$url" --allow-private --probe --format json >"$work/before.json"
jq -e '.grade == "F" and ([.findings[].id] | contains(["csp.missing", "frame.missing", "exposed.git", "exposed.env"]))' "$work/before.json" >/dev/null ||
  { echo "the unfixed fixture should be an F with missing headers and exposed files:"; jq -c '[.grade, [.findings[].id]]' "$work/before.json"; exit 1; }

fix '.headerFixes' >"$work/headers"
fix '.findings[] | select(.id == "exposed.git") | .fixes' >"$work/exposed"
fix '.findings[] | select(.id == "disclosure.version") | .fixes' >"$work/disclosure" # empty when no version is disclosed
test -s "$work/headers" && test -s "$work/exposed"
echo "--- fixes applied to $server ---"
cat "$work/headers" "$work/exposed" "$work/disclosure"

configure "$work/headers" "$work/exposed" "$work/disclosure"
./shieldcheck scan "$url" --allow-private --probe --format json >"$work/after.json"
./shieldcheck scan "$url" --allow-private --probe --no-color
jq -e '.grade == "A"
  and ([.findings[] | select(.severity != "pass" and .severity != "info")] | length == 0)
  and ([.findings[].id] | contains(["csp.ok", "frame.ok", "exposed.none", "securitytxt.ok"]))' "$work/after.json" >/dev/null ||
  { echo "the generated $server fixes did not fix the site"; exit 1; }
echo "$server: F before, A after applying the generated fixes"
