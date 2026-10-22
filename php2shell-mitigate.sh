#!/usr/bin/env bash
# php2shell-mitigate.sh - temporary mitigation for php2shell
# (CVE-2026-109618 / CVE-2026-109619) on Ubuntu and AlmaLinux 8, including
# FastPanel 2 hosts whose PHP builds under /opt are never updated by apt/dnf.
#
# What it does in every PHP it finds (distro, Remi SCL, FastPanel /opt/*):
#   - drop-in ini: session.upload_progress.enabled = 0 (the confirmed
#     unauthenticated path of CVE-2026-109619);
#   - PHP-FPM pools: php_admin_flag so .user.ini / ini_set / php_value cannot
#     turn it back on;
#   - Apache mod_php: php_admin_flag at server level (beats .htaccess);
#   - FastPanel panel PHP (/opt/fphp): cap post_max_size (CVE-2026-109618).
# It is a stopgap. Install the vendor fix as soon as one exists.
#
# Full guide: HUONG-DAN.md next to this file.
set -euo pipefail
shopt -s nullglob
# Never 'cmd | grep -q' here: grep -q exits early, cmd gets SIGPIPE and
# pipefail reports the match as a failure. Use 'grep ... >/dev/null'.

SCRIPT_VERSION=1.0.0
MODE=status
RELOAD=1
POST_MAX_MB=32
CAP_ALL=0
FORCE_OS=0
TS=$(date +%Y%m%d-%H%M%S)

MARK='; php2shell CVE-2026-109618/109619 temporary mitigation - remove after vendor fix'
DROPIN_NAME=99-php2shell.ini
POOL_MARK='; php2shell-mitigation (CVE-2026-109618/109619)'
POOL_PIN='php_admin_flag[session.upload_progress.enabled] = off'
BLOCK_BEGIN='; >>> php2shell-mitigation'
BLOCK_END='; <<< php2shell-mitigation'
APACHE_MARK='# php2shell CVE-2026-109618/109619 temporary mitigation - remove after vendor fix'
FPM_UNIT_RE='^(fastpanel2-apps|fp2-php[0-9]+-fpm|php[0-9.]*-fpm|php-fpm|php[0-9]+-php-fpm)\.service$'
APACHE_UNIT_RE='^(apache2|httpd)\.service$'

usage() {
  cat <<'EOF'
Usage: php2shell-mitigate.sh [MODE] [OPTIONS]

Modes (pick one, default --status):
  --status        report PHP installs, patch state and current setting; writes nothing
  --dry-run       --status plus the list of files --apply would change; writes nothing
  --apply         write the mitigation, test configs, reload running PHP/web services
  --revert        remove everything --apply added, test configs, reload services

Options:
  --no-reload     write/revert files but do not reload any service
  --post-max MB   body-size cap for the FastPanel panel PHP /opt/fphp (default 32, 0 = no cap)
  --cap-all       apply the --post-max cap to every PHP found, not only /opt/fphp
  --force-os      run on an OS other than Ubuntu / AlmaLinux 8 (untested)
  -h, --help      show this help

Exit codes: 0 ok, 1 error (nothing reloaded after a failed config test),
            2 --apply finished but some PHP still reads upload_progress On,
              or running services were not reloaded (--no-reload, no systemd).
EOF
}

say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n== %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case $1 in
    --status) MODE=status ;;
    --dry-run) MODE=dry-run ;;
    --apply) MODE=apply ;;
    --revert) MODE=revert ;;
    --no-reload) RELOAD=0 ;;
    --post-max)
      [[ ${2:-} =~ ^[0-9]+$ ]] || die "--post-max needs a size in MB (integer)"
      POST_MAX_MB=$2; shift ;;
    --cap-all) CAP_ALL=1 ;;
    --force-os) FORCE_OS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done
((POST_MAX_MB == 0 || POST_MAX_MB >= 4)) || die "--post-max must be 0 or >= 4"

WRITE=0
[[ $MODE == apply || $MODE == revert ]] && WRITE=1
if [[ $EUID -ne 0 ]]; then
  ((WRITE)) && die "--$MODE must run as root"
  warn "not root: some checks may be incomplete"
fi

# ---------------------------------------------------------------- OS
[[ -r /etc/os-release ]] || die "/etc/os-release not found"
OS_ID=$(. /etc/os-release; echo "${ID:-}")
OS_LIKE=$(. /etc/os-release; echo "${ID_LIKE:-}")
OS_VER=$(. /etc/os-release; echo "${VERSION_ID:-}")
OS_NAME=$(. /etc/os-release; echo "${PRETTY_NAME:-$OS_ID}")
case " $OS_ID $OS_LIKE " in
  *" ubuntu "*|*" debian "*) FAMILY=deb ;;
  *" rhel "*|*" fedora "*|*" almalinux "*) FAMILY=rhel ;;
  *) FAMILY=unknown ;;
esac
SUPPORTED=0
[[ $OS_ID == ubuntu ]] && SUPPORTED=1
[[ $OS_ID == almalinux && ${OS_VER%%.*} == 8 ]] && SUPPORTED=1
if ((!SUPPORTED)); then
  ((FORCE_OS)) || die "unsupported OS '$OS_NAME' (supported: Ubuntu, AlmaLinux 8); --force-os to try anyway"
  [[ $FAMILY == unknown ]] && die "cannot tell package family of '$OS_NAME'"
  warn "running on untested OS '$OS_NAME' (family $FAMILY)"
fi

# ---------------------------------------------------------------- discovery
declare -a DROPIN_DIRS=() INLINE_FILES=() POOL_FILES=() CLI_BINS=() FPM_BINS=()
declare -A SEEN=() CAPSET=() BIN_LABEL=() MISSING_DIR=()

add_uniq() { # array-name value
  local -n _arr=$1
  [[ -n ${SEEN["$1|$2"]:-} ]] && return 0
  SEEN["$1|$2"]=1
  _arr+=("$2")
}

add_ini_dir() { # dir cap
  [[ -d $1 ]] || return 0
  add_uniq DROPIN_DIRS "$1"
  (($2)) && CAPSET[$1]=1
  return 0
}

add_php() { # php-bin fpm-bin fpm-conf pool-dir label cap
  local php=$1 fpm=$2 fconf=$3 pooldir=$4 label=$5 cap=$6 scan ini d p
  [[ -x $php ]] || return 0
  # FastPanel may point /usr/bin/php at /opt/phpNN/bin/php: list each real binary once,
  # under the label of whoever ships it (FastPanel roots are discovered first).
  local real
  real=$(readlink -f "$php")
  if [[ -z ${SEEN["real|$real"]:-} ]]; then
    SEEN["real|$real"]=1
    add_uniq CLI_BINS "$php"
    BIN_LABEL[$php]=$label
  fi
  scan=$("$php" --ini 2>/dev/null | sed -n 's/^Scan for additional \.ini files in: *//p' || true)
  if [[ -x $fpm ]]; then
    add_uniq FPM_BINS "$fpm|$fconf"
    BIN_LABEL[$fpm]=$label
    scan+=":$("$fpm" -i 2>/dev/null | sed -n 's/^Scan this dir for additional \.ini files => *//p' || true)"
  fi
  local found=0
  IFS=: read -ra dirs <<<"$scan"
  for d in "${dirs[@]}"; do
    [[ $d == /* ]] || continue # skips "", "(none)", "no value"
    # A compiled-in scan dir that does not exist yet (seen on FastPanel /opt/fphp)
    # is still read once created: create it rather than edit a package-owned php.ini.
    [[ -d $d ]] || MISSING_DIR[$d]=1
    add_uniq DROPIN_DIRS "$d"
    ((cap)) && CAPSET[$d]=1
    found=1
  done
  if ((!found)); then # built without a scan dir: edit the loaded php.ini itself
    ini=$("$php" --ini 2>/dev/null | sed -n 's/^Loaded Configuration File: *//p' || true)
    [[ -f $ini ]] && { add_uniq INLINE_FILES "$ini"; ((cap)) && CAPSET[$ini]=1; }
    if [[ -x $fpm ]]; then
      ini=$("$fpm" -i 2>/dev/null | sed -n 's/^Loaded Configuration File => *//p' || true)
      [[ -f $ini ]] && { add_uniq INLINE_FILES "$ini"; ((cap)) && CAPSET[$ini]=1; }
    fi
  fi
  for p in "$pooldir"/*.conf; do [[ -f $p ]] && add_uniq POOL_FILES "$p"; done
  return 0
}

cap_for() { # root -> 1 when the body cap applies
  ((POST_MAX_MB > 0)) || { echo 0; return; }
  [[ $1 == /opt/fphp ]] && { echo 1; return; }
  echo "$CAP_ALL"
}

# FastPanel 2 (same /opt layout on Ubuntu and AlmaLinux)
for r in /opt/fphp /opt/php[5-8][0-9]; do
  add_php "$r/bin/php" "$r/sbin/php-fpm" "$r/etc/php-fpm.conf" "$r/etc/php-fpm.d" fastpanel "$(cap_for "$r")"
done
if [[ $FAMILY == deb ]]; then
  # Ubuntu/Debian and ondrej PPA: one conf.d per SAPI
  for b in /usr/bin/php[0-9]*.[0-9]*; do
    v=${b#/usr/bin/php}
    add_php "$b" "/usr/sbin/php-fpm$v" "/etc/php/$v/fpm/php-fpm.conf" "/etc/php/$v/fpm/pool.d" distro "$CAP_ALL"
  done
  for d in /etc/php/*/*/conf.d; do add_ini_dir "$d" "$CAP_ALL"; done
else
  # AlmaLinux AppStream: /etc/php.d shared by every SAPI (cli, fpm, mod_php)
  add_php /usr/bin/php /usr/sbin/php-fpm /etc/php-fpm.conf /etc/php-fpm.d distro "$CAP_ALL"
  add_ini_dir /etc/php.d "$CAP_ALL"
  # Remi SCL packages (php74, php81, php82 ... under /opt/remi)
  for r in /opt/remi/php[0-9]*; do
    n=${r##*/}
    add_php "$r/root/usr/bin/php" "$r/root/usr/sbin/php-fpm" "/etc/opt/remi/$n/php-fpm.conf" "/etc/opt/remi/$n/php-fpm.d" remi "$CAP_ALL"
  done
fi

APACHE_CTL="" APACHE_CONF="" MODPHP=0
if [[ $FAMILY == deb ]] && command -v apache2ctl >/dev/null; then
  APACHE_CTL=apache2ctl
  APACHE_CONF=/etc/apache2/conf-available/php2shell-mitigation.conf
elif [[ $FAMILY == rhel ]] && command -v httpd >/dev/null; then
  APACHE_CTL=httpd
  APACHE_CONF=/etc/httpd/conf.d/zz-php2shell-mitigation.conf
fi
if [[ -n $APACHE_CTL ]] && "$APACHE_CTL" -M 2>/dev/null | grep -E '^ *php[0-9]*_module' >/dev/null; then
  MODPHP=1
fi

HAVE_SYSTEMD=0
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] && HAVE_SYSTEMD=1

# ---------------------------------------------------------------- content
dropin_body() { # cap
  printf '%s\nsession.upload_progress.enabled = 0\n' "$MARK"
  (($1)) && printf 'post_max_size = %sM\nupload_max_filesize = %sM\n' "$POST_MAX_MB" "$((POST_MAX_MB - 2))"
  return 0
}

inline_strip() { # file -> stdout without our block
  awk -v s="$BLOCK_BEGIN" -v e="$BLOCK_END" '$0==s{skip=1;next} $0==e{skip=0;next} !skip{print}' "$1"
}

inline_apply() { # file cap -> stdout with our block at the end
  inline_strip "$1"
  printf '%s\n%s\n[PHP]\n' "$BLOCK_BEGIN" "$MARK"
  dropin_body "$2" | tail -n +2
  printf '%s\n' "$BLOCK_END"
}

pool_apply() { # pool.conf -> stdout: drop any upload_progress directive, pin after every pool header
  awk -v m="$POOL_MARK" -v pin="$POOL_PIN" '
    $0 == m { skip = 1; next }
    skip && /upload_progress\.enabled/ { skip = 0; next }
    { skip = 0 }
    /^[ \t]*php_(admin_)?(value|flag)\[session\.upload_progress\.enabled\]/ { next }
    { print }
    /^[ \t]*\[[^]]+\][ \t]*$/ && !/^[ \t]*\[global\]/ { print m; print pin }
  ' "$1"
}

pool_revert() { # pool.conf -> stdout without our marker+pin pairs
  awk -v m="$POOL_MARK" '
    $0 == m { skip = 1; next }
    skip && /upload_progress\.enabled/ { skip = 0; next }
    { skip = 0; print }
  ' "$1"
}

apache_body() {
  cat <<EOF
$APACHE_MARK
<IfModule php_module>
    php_admin_flag session.upload_progress.enabled off
</IfModule>
<IfModule php7_module>
    php_admin_flag session.upload_progress.enabled off
</IfModule>
<IfModule php5_module>
    php_admin_flag session.upload_progress.enabled off
</IfModule>
EOF
}

same_file() { # a b: identical bytes (coreutils only; minimal AlmaLinux has no cmp)
  [[ $(sha256sum <"$1") == $(sha256sum <"$2") ]]
}

CHANGED=0 RELOADED=0 RELOAD_FAILED=0
put() { # path backup(0/1) < content
  local path=$1 backup=$2 tmp
  tmp=$(mktemp)
  cat >"$tmp"
  if [[ -f $path ]] && same_file "$tmp" "$path"; then
    say "  ok      $path"
  elif ((WRITE)); then
    [[ -f $path && $backup == 1 ]] && cp -a "$path" "$path.bak-php2shell-$TS"
    if [[ -f $path ]]; then cat "$tmp" >"$path"; else install -m 0644 "$tmp" "$path"; fi
    say "  write   $path"; CHANGED=1
  else
    say "  would   $path"
  fi
  rm -f "$tmp"
}

drop() { # path: remove a file only if it starts with our marker
  local path=$1
  [[ -f $path ]] || return 0
  if ! head -n 1 "$path" | grep -F 'php2shell' >/dev/null; then
    warn "$path exists but was not written by this script; left alone"
    return 0
  fi
  if ((WRITE)); then rm -f "$path"; say "  remove  $path"; CHANGED=1; else say "  would remove $path"; fi
}

# ---------------------------------------------------------------- report
php_setting() { # php-bin
  "$1" -r 'echo ini_get("session.upload_progress.enabled") === false ? "n/a" : (ini_get("session.upload_progress.enabled") ? "On" : "Off");' 2>/dev/null || echo "?"
}

upstream_state() { # php-bin: compare with upstream fixed releases
  "$1" -r '
    $fix = array("8.2" => "8.2.35", "8.3" => "8.3.36", "8.4" => "8.4.27", "8.5" => "8.5.12");
    $b = PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;
    if (isset($fix[$b])) echo version_compare(PHP_VERSION, $fix[$b], ">=") ? "fixed upstream" : "VULNERABLE (fix: " . $fix[$b] . ")";
    elseif (version_compare(PHP_VERSION, "8.2", "<")) echo "VULNERABLE (EOL, no upstream fix)";
    else echo "unknown branch";
  ' 2>/dev/null || echo "?"
}

rpm_cmp() { # a b -> -1/0/1 or empty when rpm lua lacks vercmp
  rpm --eval "%{lua: print(rpm.vercmp('$1', '$2'))}" 2>/dev/null | grep -E '^-?[01]$' || true
}

report_packages() {
  hdr "OS packages (vendor backports keep the old version number)"
  local any=0 pkg ver
  if [[ $FAMILY == deb ]]; then
    while read -r pkg ver; do
      [[ $pkg == php-common ]] && continue
      any=1
      if zgrep -qE 'CVE-2026-10961[89]' "/usr/share/doc/$pkg/changelog.Debian.gz" 2>/dev/null; then
        say "  PATCHED     $pkg $ver"
      else
        say "  NOT PATCHED $pkg $ver -> apt update && apt install --only-upgrade '${pkg%-common}*'"
      fi
    done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php*-common' 2>/dev/null | awk '$1=="ii"{print $2, $3}' || true)
  else
    local -A el8_fix=(
      [7.2]=7.2.24-1.module_el8.10.0+4315+7b734bf3.alma.1
      [7.3]=7.3.20-1.module_el8.10.0+4316+90ea5fe5.alma.1
      [7.4]=7.4.33-8.module_el8.10.0+4321+cf5fd4bb
      [8.0]=8.0.30-1.module_el8.10.0+4319+26f10322.alma.1
      [8.2]=8.2.33-1.module_el8.10.0+4320+c30d6dbb.alma.1
    )
    while read -r pkg ver; do
      any=1
      if rpm -q --changelog "$pkg" 2>/dev/null | grep -E 'CVE-2026-10961[89]' >/dev/null; then
        say "  PATCHED     $pkg $ver"; continue
      fi
      local stream min=""
      stream=$(echo "$ver" | cut -d. -f1,2)
      [[ $pkg == php-common && $OS_ID == almalinux && ${OS_VER%%.*} == 8 ]] && min=${el8_fix[$stream]:-}
      if [[ -n $min ]]; then
        case $(rpm_cmp "$ver" "$min") in
          -1) say "  NOT PATCHED $pkg $ver (need >= $min) -> dnf clean metadata && dnf upgrade 'php*'" ;;
          0|1) say "  PATCHED     $pkg $ver (>= $min)" ;;
          *) say "  CHECK       $pkg $ver: compare with $min by hand" ;;
        esac
      else
        say "  CHECK       $pkg $ver: no CVE entry in changelog; see vendor advisory"
      fi
    done < <(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'php*-common' 2>/dev/null | sort || true)
  fi
  ((any)) || say "  (no OS PHP package installed)"
}

report_bins() {
  hdr "PHP binaries (setting = what a fresh process reads from ini files)"
  local b label
  for b in "${CLI_BINS[@]}"; do
    label=${BIN_LABEL[$b]}
    local state="see OS packages above"
    [[ $label != distro ]] && state=$(upstream_state "$b")
    printf '  %-36s %-10s %-9s upload_progress=%-4s %s\n' "$b" "$label" \
      "$("$b" -r 'echo PHP_VERSION;' 2>/dev/null || echo ?)" "$(php_setting "$b")" "$state"
  done
  local entry f
  for entry in "${FPM_BINS[@]}"; do
    f=${entry%%|*}
    printf '  %-36s %-10s fpm       upload_progress=%s\n' "$f" "${BIN_LABEL[$f]}" \
      "$("$f" -i 2>/dev/null | sed -n 's/^session\.upload_progress\.enabled => \([^ ]*\) .*/\1/p' | head -n 1)"
  done
  ((${#CLI_BINS[@]})) || say "  (no PHP found)"
}

report_pools_apache() {
  hdr "PHP-FPM pools"
  local p sections pins
  for p in "${POOL_FILES[@]}"; do
    sections=$(grep -cE '^[[:space:]]*\[[^]]+\][[:space:]]*$' "$p" || true)
    sections=$((sections - $(grep -cE '^[[:space:]]*\[global\]' "$p" || true)))
    pins=$(grep -cF "$POOL_PIN" "$p" || true)
    printf '  %-56s pools=%s pinned=%s\n' "$p" "$sections" "$pins"
  done
  ((${#POOL_FILES[@]})) || say "  (no pool file)"
  hdr "Apache mod_php"
  if ((MODPHP)); then
    if "$APACHE_CTL" -t -D DUMP_INCLUDES 2>/dev/null | grep -F "${APACHE_CONF##*/}" >/dev/null; then
      say "  mod_php loaded; server-level pin active: $APACHE_CONF"
    else
      say "  mod_php loaded; NO server-level pin yet ($APACHE_CONF)"
    fi
  else
    say "  mod_php not loaded"
  fi
}

report_hints() {
  hdr "Web-server settings worth a manual look (PHP_VALUE / upload_progress overrides)"
  local hits
  hits=$(grep -rlsE 'PHP_(ADMIN_)?VALUE|upload_progress' /etc/nginx /usr/local/fastpanel2-nginx /etc/apache2 /etc/httpd 2>/dev/null \
    | grep -vF "${APACHE_CONF:-/nonexistent}" | head -n 20 || true)
  if [[ -n $hits ]]; then printf '  %s\n' $hits; else say "  none found"; fi
}

# ---------------------------------------------------------------- change
plan_apply() {
  hdr "Changes (${MODE})"
  local d f p
  for d in "${DROPIN_DIRS[@]}"; do
    if [[ -n ${MISSING_DIR[$d]:-} && ! -d $d ]]; then
      if ((WRITE)); then mkdir -p -m 0755 "$d"; say "  mkdir   $d"; CHANGED=1; else say "  would mkdir $d"; fi
    fi
    put "$d/$DROPIN_NAME" 0 < <(dropin_body "${CAPSET[$d]:-0}")
  done
  for f in "${INLINE_FILES[@]}"; do put "$f" 1 < <(inline_apply "$f" "${CAPSET[$f]:-0}"); done
  for p in "${POOL_FILES[@]}"; do put "$p" 1 < <(pool_apply "$p"); done
  if ((MODPHP)); then
    put "$APACHE_CONF" 0 < <(apache_body)
    if [[ $FAMILY == deb && ! -e /etc/apache2/conf-enabled/${APACHE_CONF##*/} ]]; then
      if ((WRITE)); then a2enconf -q "$(basename "$APACHE_CONF" .conf)" >/dev/null; say "  enable  ${APACHE_CONF##*/}"; CHANGED=1
      else say "  would enable ${APACHE_CONF##*/} (a2enconf)"; fi
    fi
  fi
}

plan_revert() {
  hdr "Changes (revert)"
  local d f p
  for d in "${DROPIN_DIRS[@]}"; do drop "$d/$DROPIN_NAME"; done
  for f in "${INLINE_FILES[@]}"; do put "$f" 1 < <(inline_strip "$f"); done
  for p in "${POOL_FILES[@]}"; do put "$p" 1 < <(pool_revert "$p"); done
  if [[ -n $APACHE_CONF && -f $APACHE_CONF ]]; then
    if [[ $FAMILY == deb && -e /etc/apache2/conf-enabled/${APACHE_CONF##*/} ]]; then
      if ((WRITE)); then a2disconf -q "$(basename "$APACHE_CONF" .conf)" >/dev/null; say "  disable ${APACHE_CONF##*/}"; CHANGED=1
      else say "  would disable ${APACHE_CONF##*/}"; fi
    fi
    drop "$APACHE_CONF"
  fi
}

fpm_test_cmd() { # unit -> prints the unit's php-fpm command with -t, or nothing
  local argv a out=()
  argv=$(systemctl show -p ExecStart --value "$1" 2>/dev/null | sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p' | head -n 1)
  [[ -n $argv ]] || return 0
  for a in $argv; do
    case $a in --nodaemonize|-F|--daemonize|-D) ;; *) out+=("$a") ;; esac
  done
  printf '%s ' "${out[@]}" -t
}

reload_services() {
  hdr "Test and reload"
  # Reload even when no file changed: an earlier run may have written the files
  # and stopped before reloading, leaving running workers on the old setting.
  ((CHANGED)) || say "  no file changed; reloading anyway so running workers use the current files"
  if ((!RELOAD)); then say "  --no-reload: reload the PHP-FPM and web services yourself"; return 0; fi
  if ((!HAVE_SYSTEMD)); then warn "systemd not running: reload PHP-FPM / Apache yourself"; return 0; fi
  local units u cmd out failed=0 ok_units=()
  units=$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' \
    | grep -E "$FPM_UNIT_RE|$APACHE_UNIT_RE" || true)
  for u in $units; do
    if [[ $u =~ $APACHE_UNIT_RE ]]; then
      if out=$("$APACHE_CTL" -t 2>&1); then ok_units+=("$u"); else say "  FAIL test $u:"; say "$out"; failed=1; fi
      continue
    fi
    cmd=$(fpm_test_cmd "$u")
    if [[ -z $cmd ]]; then warn "cannot read ExecStart of $u; not reloaded"; failed=1; continue; fi
    # shellcheck disable=SC2086
    if out=$($cmd 2>&1); then ok_units+=("$u"); else say "  FAIL test $u ($cmd):"; say "$out"; failed=1; fi
  done
  if ((failed)); then
    say "  a config test failed: NO service was reloaded."
    say "  fix the error above, or run --revert, then reload yourself."
    exit 1
  fi
  for u in "${ok_units[@]}"; do
    if systemctl reload-or-restart "$u"; then say "  reloaded $u"; RELOADED=1
    else warn "reload of $u failed: check 'systemctl status $u'"; RELOAD_FAILED=1; fi
  done
  ((${#ok_units[@]})) || say "  no running PHP-FPM / Apache unit found"
  return 0
}

final_check() {
  local b entry f bad=0
  for b in "${CLI_BINS[@]}"; do [[ $(php_setting "$b") == On ]] && bad=1; done
  for entry in "${FPM_BINS[@]}"; do
    f=${entry%%|*}
    "$f" -i 2>/dev/null | grep -E '^session\.upload_progress\.enabled => On' >/dev/null && bad=1
  done
  hdr "Result"
  if ((bad)); then
    say "  some PHP still reads upload_progress On (see list above)"
  else
    say "  every PHP found reads upload_progress Off in its ini files"
  fi
  if ((!RELOADED || RELOAD_FAILED)); then
    say "  running PHP-FPM / mod_php workers keep the OLD setting until their service is reloaded"
    bad=1
  fi
  ((bad)) && exit 2
  return 0
}

# ---------------------------------------------------------------- main
say "php2shell-mitigate $SCRIPT_VERSION | $OS_NAME | mode=$MODE | $(hostname)"
case $MODE in
  status)
    report_packages; report_bins; report_pools_apache; report_hints ;;
  dry-run)
    report_packages; report_bins; plan_apply ;;
  apply)
    plan_apply; reload_services; report_bins; report_pools_apache; final_check ;;
  revert)
    plan_revert; reload_services; report_bins; report_pools_apache ;;
esac
