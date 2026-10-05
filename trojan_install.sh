#!/usr/bin/env bash
# Based on xyz690/Trojan. Maintained certificate workflow for Debian/Ubuntu.
# Installation and repair are explicit operations; sourcing this file is inert.

TROJAN_CONFIG=${TROJAN_CONFIG:-/usr/src/trojan/server.conf}
TROJAN_CERT_DIR=${TROJAN_CERT_DIR:-/usr/src/trojan-cert}
TROJAN_WEBROOT=${TROJAN_WEBROOT:-/usr/share/nginx/html}
TROJAN_ACME_HOME=${TROJAN_ACME_HOME:-${HOME}/.acme.sh}
TROJAN_ACME_BIN=${TROJAN_ACME_BIN:-${TROJAN_ACME_HOME}/acme.sh}

fail() { printf '错误：%s\n' "$*" >&2; return 1; }

validate_domain() {
    local domain=$1 label
    [[ ${#domain} -le 253 && $domain == *.* ]] || return 1
    local -a labels
    IFS=. read -r -a labels <<< "$domain"
    [[ $domain != *. ]] || return 1
    for label in "${labels[@]}"; do
        [[ ${#label} -ge 1 && ${#label} -le 63 &&
           $label =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || return 1
    done
}

require_root() { [[ $EUID -eq 0 ]] || fail '请用 sudo 或 root 执行。'; }

ensure_dependencies() {
    [[ -r /etc/os-release ]] || { fail '无法识别操作系统。'; return 1; }
    # shellcheck source=/dev/null
    . /etc/os-release
    case "$ID" in
        ubuntu|debian) ;;
        *) fail '维护版仅支持 Debian/Ubuntu；不会修改其他发行版。'; return 1 ;;
    esac
    apt-get update || return 1
    apt-get install -y ca-certificates curl nginx openssl socat cron python3 xz-utils || return 1
    # Keep UFW, firewalld and SELinux policy intact.
    systemctl enable --now cron || return 1
}

ensure_acme() {
    [[ -x $TROJAN_ACME_BIN ]] && return 0
    local installer rc
    installer=$(mktemp) || return 1
    if curl --fail --show-error --location --proto '=https' --tlsv1.2 \
        https://get.acme.sh -o "$installer"; then
        sh "$installer" --home "$TROJAN_ACME_HOME"
        rc=$?
    else
        rc=1
    fi
    rm -f -- "$installer"
    [[ $rc -eq 0 && -x $TROJAN_ACME_BIN ]] || { fail 'acme.sh 安装失败。'; return 1; }
}

ensure_renewal_cron() {
    local jobs new_jobs quoted_bin quoted_home
    jobs=$(crontab -l 2>/dev/null || true)
    if printf '%s\n' "$jobs" | grep -F -- "$TROJAN_ACME_BIN" | grep -q -- '--cron'; then
        return 0
    fi
    printf -v quoted_bin '%q' "$TROJAN_ACME_BIN"
    printf -v quoted_home '%q' "$TROJAN_ACME_HOME"
    new_jobs=$(printf '%s\n17 3 * * * %s --cron --home %s >/dev/null 2>&1 # grandlulu-trojan-acme\n' \
        "$jobs" "$quoted_bin" "$quoted_home")
    printf '%s\n' "$new_jobs" | crontab - || { fail '无法配置证书续签 cron。'; return 1; }
}

write_reload_hook() {
    mkdir -p -- "$TROJAN_CERT_DIR" || return 1
    chmod 700 "$TROJAN_CERT_DIR" || return 1
    cat > "$TROJAN_CERT_DIR/reload-certificate.sh" <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail
cert=$1
key=$2
domain=$3
openssl x509 -in "$cert" -noout -checkend 0 >/dev/null
openssl x509 -in "$cert" -noout -checkhost "$domain" >/dev/null
cert_public=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -pubout)
key_public=$(openssl pkey -in "$key" -pubout)
[[ $cert_public == "$key_public" ]] || { echo 'Certificate/key mismatch' >&2; exit 1; }
if [[ ${4:-} != --check-only ]] && systemctl cat trojan.service >/dev/null 2>&1; then
    systemctl restart trojan.service
fi
HOOK
    chmod 700 "$TROJAN_CERT_DIR/reload-certificate.sh"
}

certificate_key_type() {
    local domain=$1
    if [[ -f $TROJAN_ACME_HOME/$domain/$domain.conf &&
          ! -f $TROJAN_ACME_HOME/${domain}_ecc/$domain.conf ]]; then
        printf 'rsa\n'
    elif [[ -f $TROJAN_ACME_HOME/$domain/$domain.conf &&
            -s $TROJAN_CERT_DIR/fullchain.cer ]] && \
         openssl x509 -in "$TROJAN_CERT_DIR/fullchain.cer" -text -noout | grep -q rsaEncryption; then
        printf 'rsa\n'
    else
        printf 'ecc\n'
    fi
}

restore_certificates() {
    local backup=$1 file
    for file in fullchain.cer private.key; do
        if [[ -f $backup/$file ]]; then
            cp -p -- "$backup/$file" "$TROJAN_CERT_DIR/$file" || return 1
        else
            rm -f -- "$TROJAN_CERT_DIR/$file" || return 1
        fi
    done
}

clear_certificate_backup() {
    local backup=$1
    rm -f -- "$backup/fullchain.cer" "$backup/private.key"
    rmdir -- "$backup"
}

issue_and_install_certificate() {
    local domain=$1 key_type issue_status backup file reload_command install_status lineage_config
    local was_active=0
    local -a key_args install_args force_args
    validate_domain "$domain" || { fail '请输入有效的完整域名。'; return 1; }
    [[ -x $TROJAN_ACME_BIN ]] || { fail 'acme.sh 不存在。'; return 1; }
    mkdir -p -- "$TROJAN_WEBROOT" || return 1
    nginx -t || return 1
    if ! systemctl is-active --quiet nginx.service; then
        systemctl start nginx.service || return 1
    fi
    # HTTP-01 uses the running Nginx webroot; never stop it for renewal.
    key_type=$(certificate_key_type "$domain") || return 1
    install_args=()
    if [[ $key_type == rsa ]]; then
        key_args=(--keylength 2048)
    else
        key_args=(--keylength ec-256)
        install_args=(--ecc)
    fi
    lineage_config="$TROJAN_ACME_HOME/$domain/$domain.conf"
    [[ $key_type == ecc ]] && lineage_config="$TROJAN_ACME_HOME/${domain}_ecc/$domain.conf"
    force_args=()
    if [[ -f $lineage_config ]] && grep -q '^Le_Webroot=' "$lineage_config" &&
       ! grep -Fxq "Le_Webroot='$TROJAN_WEBROOT'" "$lineage_config"; then
        # A not-due --issue exits before saving webroot. Force the migration once.
        force_args=(--force)
    fi
    if "$TROJAN_ACME_BIN" --issue --server letsencrypt --home "$TROJAN_ACME_HOME" \
        -d "$domain" --webroot "$TROJAN_WEBROOT" "${key_args[@]}" "${force_args[@]}"; then
        issue_status=0
    else
        issue_status=$?
    fi
    [[ $issue_status -eq 0 || $issue_status -eq 2 ]] || {
        fail "证书签发失败（退出码 $issue_status）；未替换服务证书。"; return 1;
    }
    [[ $issue_status -ne 2 || ${#force_args[@]} -eq 0 ]] || {
        fail '旧续签方式尚未迁移到 webroot；未替换服务证书。'; return 1;
    }
    write_reload_hook || return 1
    backup=$(mktemp -d) || return 1
    chmod 700 "$backup" || return 1
    for file in fullchain.cer private.key; do
        if [[ -f $TROJAN_CERT_DIR/$file ]]; then
            cp -p -- "$TROJAN_CERT_DIR/$file" "$backup/$file" || return 1
        fi
    done
    systemctl is-active --quiet trojan.service && was_active=1
    printf -v reload_command '%q %q %q %q' "$TROJAN_CERT_DIR/reload-certificate.sh" \
        "$TROJAN_CERT_DIR/fullchain.cer" "$TROJAN_CERT_DIR/private.key" "$domain"
    if "$TROJAN_ACME_BIN" --install-cert --home "$TROJAN_ACME_HOME" -d "$domain" \
        "${install_args[@]}" --key-file "$TROJAN_CERT_DIR/private.key" \
        --fullchain-file "$TROJAN_CERT_DIR/fullchain.cer" --reloadcmd "$reload_command"; then
        install_status=0
    else
        install_status=$?
    fi
    if [[ $install_status -ne 0 ]] || ! "$TROJAN_CERT_DIR/reload-certificate.sh" \
        "$TROJAN_CERT_DIR/fullchain.cer" "$TROJAN_CERT_DIR/private.key" "$domain" --check-only; then
        restore_certificates "$backup" || { fail "证书回退失败，备份保留在 $backup"; return 1; }
        if [[ $was_active -eq 1 ]]; then
            systemctl restart trojan.service || printf '服务重启失败，请检查 journalctl -u trojan。\n' >&2
        fi
        clear_certificate_backup "$backup"
        fail '新证书安装或校验失败，已回退原证书。'
        return 1
    fi
    chmod 600 "$TROJAN_CERT_DIR/private.key" || return 1
    clear_certificate_backup "$backup"
    ensure_renewal_cron || return 1
    printf '证书已校验并安装；续签使用 Nginx webroot，并自动重新加载 Trojan。\n'
}

configure_webroot() {
    local domain=$1 config=/etc/nginx/conf.d/trojan-webroot.conf
    [[ ! -e $config ]] || { fail 'Nginx 专用配置已存在，请使用修复证书操作。'; return 1; }
    mkdir -p -- "$TROJAN_WEBROOT" || return 1
    cat > "$config" <<EOF
server {
    listen 80;
    server_name $domain;
    root "$TROJAN_WEBROOT";
    location /.well-known/acme-challenge/ { try_files \$uri =404; }
    location / { try_files \$uri \$uri/ =404; }
}
EOF
    nginx -t || { rm -f -- "$config"; return 1; }
    if systemctl is-active --quiet nginx.service; then
        systemctl reload nginx.service || return 1
    else
        systemctl enable --now nginx.service || return 1
    fi
}

install_trojan() {
    local domain=$1 download_dir release_json version password
    validate_domain "$domain" || { fail '请输入有效域名。'; return 1; }
    [[ ! -e $TROJAN_CONFIG && ! -e /usr/src/trojan/trojan ]] || {
        fail '检测到现有 Trojan；请使用 repair-cert，避免重置密码或覆盖配置。'; return 1;
    }
    [[ $(uname -m) == x86_64 ]] || { fail '本安装入口仅支持 x86_64。'; return 1; }
    ensure_dependencies || return 1
    configure_webroot "$domain" || return 1
    ensure_acme || return 1
    issue_and_install_certificate "$domain" || return 1
    download_dir=$(mktemp -d) || return 1
    if ! curl --fail --show-error --location --proto '=https' --tlsv1.2 \
        https://api.github.com/repos/trojan-gfw/trojan/releases/latest -o "$download_dir/release.json"; then
        rmdir "$download_dir" 2>/dev/null || true
        return 1
    fi
    release_json=$download_dir/release.json
    version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"].lstrip("v"))' "$release_json") || return 1
    [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { fail '上游版本信息无效。'; return 1; }
    curl --fail --show-error --location --proto '=https' --tlsv1.2 \
        "https://github.com/trojan-gfw/trojan/releases/download/v${version}/trojan-${version}-linux-amd64.tar.xz" \
        -o "$download_dir/trojan.tar.xz" || return 1
    tar -xJf "$download_dir/trojan.tar.xz" -C /usr/src || return 1
    /usr/src/trojan/trojan --version || { fail 'Trojan 二进制无法运行，请检查系统库依赖。'; return 1; }
    rm -f -- "$download_dir/release.json" "$download_dir/trojan.tar.xz"
    rmdir -- "$download_dir"
    password=$(openssl rand -hex 24) || return 1
    umask 077
    mkdir -p -- "$(dirname "$TROJAN_CONFIG")" || return 1
    python3 - "$TROJAN_CONFIG" "$TROJAN_CERT_DIR" "$password" <<'CONFIG'
import json, pathlib, sys
config, cert_dir, password = sys.argv[1:]
pathlib.Path(config).write_text(json.dumps({
    "run_type": "server", "local_addr": "0.0.0.0", "local_port": 443,
    "remote_addr": "127.0.0.1", "remote_port": 80, "password": [password],
    "log_level": 2, "ssl": {"cert": cert_dir + "/fullchain.cer", "key": cert_dir + "/private.key"},
    "tcp": {"no_delay": True, "keep_alive": True}
}, indent=2) + "\n")
CONFIG
    cat > /etc/systemd/system/trojan.service <<EOF
[Unit]
Description=Trojan proxy
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/src/trojan/trojan -c "$TROJAN_CONFIG"
Restart=on-failure
RestartSec=5
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || return 1
    systemctl enable --now trojan.service || return 1
    printf 'Trojan 已安装：服务器 %s，端口 443。\n密码保存在 %s；没有生成含密码的公开下载包。\n' "$domain" "$TROJAN_CONFIG"
}

repair_cert() {
    local domain=$1
    validate_domain "$domain" || { fail '请输入有效域名。'; return 1; }
    [[ -s $TROJAN_CONFIG ]] || { fail '找不到现有 Trojan 配置，请检查安装路径。'; return 1; }
    ensure_dependencies || return 1
    ensure_acme || return 1
    issue_and_install_certificate "$domain"
}

main() {
    local action=${1:-} domain=${2:-} choice
    if [[ -z $action ]]; then
        printf 'Grandlulu Trojan 维护版\n1. 新安装\n3. 修复证书（保留现有密码）\n0. 退出\n'
        read -r -p '请选择：' choice
        case "$choice" in 1) action=install ;; 3) action=repair-cert ;; 0) return 0 ;; *) fail '无效选项。'; return 1 ;; esac
    fi
    case "$action" in
        install|repair-cert)
            require_root || return 1
            [[ -n $domain ]] || read -r -p '请输入 Trojan 域名：' domain
            printf '请确认域名仍指向 VPS，并允许 HTTP-01 的 TCP 80 与 Trojan 的 TCP 443。\n'
            if [[ $action == install ]]; then install_trojan "$domain"; else repair_cert "$domain"; fi
            ;;
        check-cert)
            validate_domain "$domain" || return 1
            openssl x509 -in "$TROJAN_CERT_DIR/fullchain.cer" -noout -dates -checkend 0 -checkhost "$domain"
            ;;
        *) fail '用法：bash trojan_install.sh [install|repair-cert|check-cert] 域名'; return 1 ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    main "$@"
fi
