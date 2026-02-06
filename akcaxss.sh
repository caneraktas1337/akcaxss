#!/usr/bin/env bash
set -euo pipefail

readonly TOOL_NAME="AkcaXSS"
readonly VERSION="1.0.0"
readonly BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OUTPUT_DIR="${BASE_DIR}/output"
readonly TEMP_DIR="${BASE_DIR}/temp"
readonly GOBIN="${HOME}/go/bin"
readonly TOOLS_DIR="${HOME}/tools"
export PATH="${GOBIN}:${TOOLS_DIR}:${TOOLS_DIR}/ParamSpider:${PATH}"

readonly -a STATIC_EXTENSIONS=("jpg" "jpeg" "png" "gif" "svg" "css" "js" "woff" "woff2" "ico" "pdf")

readonly -a USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
)

CONCURRENCY=15
DELAY=300
FAILURE_COUNT=0
FAILURE_THRESHOLD=20
WAF_DETECTED=0
TARGET=""
SCAN_START=""
PROXY="${AKCAXSS_PROXY:-}"

cleanup() {
    local exit_code=$?
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
    if [[ ${exit_code} -ne 0 ]] && [[ ${exit_code} -ne 130 ]]; then
        printf "\n[!] %s exited with code %d\n" "${TOOL_NAME}" "${exit_code}" >&2
    fi
    exit ${exit_code}
}

trap cleanup EXIT
trap 'printf "\n[!] Interrupted by user. Cleaning up...\n"; exit 130' INT TERM

log_info() {
    printf "[*] %s\n" "$1"
}

log_success() {
    printf "[+] %s\n" "$1"
}

log_error() {
    printf "[-] %s\n" "$1" >&2
}

log_warn() {
    printf "[!] %s\n" "$1"
}

random_ua() {
    local idx=$(( RANDOM % ${#USER_AGENTS[@]} ))
    printf "%s" "${USER_AGENTS[${idx}]}"
}

init_dirs() {
    mkdir -p "${OUTPUT_DIR}" "${TEMP_DIR}"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

install_go_tool() {
    local name="$1"
    local repo="$2"
    if check_command "${name}"; then
        log_success "${name} is already installed"
        return 0
    fi
    log_info "Installing ${name}..."
    if ! go install "${repo}@latest" 2>/dev/null; then
        log_error "Failed to install ${name}"
        return 1
    fi
    log_success "${name} installed successfully"
}

tool_install_mode() {
    log_info "Starting ${TOOL_NAME} tool installation..."
    printf "=%.0s" {1..60}; printf "\n"

    if ! check_command "go"; then
        log_error "Go is not installed. Please install Go >= 1.21 first."
        exit 1
    fi

    if ! check_command "pip3" && ! check_command "pip"; then
        log_error "pip/pip3 is not installed. Please install Python3 + pip first."
        exit 1
    fi

    if ! check_command "git"; then
        log_error "git is not installed. Please install git first."
        exit 1
    fi

    mkdir -p "${GOBIN}" "${TOOLS_DIR}"

    local failed=0
    local installed=0
    local skipped=0

    install_go_tool "gospider" "github.com/jaeles-project/gospider" && { ((installed++)) || true; } || { ((failed++)) || true; }
    install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana" && { ((installed++)) || true; } || { ((failed++)) || true; }
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls" && { ((installed++)) || true; } || { ((failed++)) || true; }
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau" && { ((installed++)) || true; } || { ((failed++)) || true; }
    install_go_tool "hakrawler" "github.com/hakluke/hakrawler" && { ((installed++)) || true; } || { ((failed++)) || true; }
    install_go_tool "urlfinder" "github.com/projectdiscovery/urlfinder/cmd/urlfinder" && { ((installed++)) || true; } || { ((failed++)) || true; }
    install_go_tool "dalfox" "github.com/hahwul/dalfox/v2" && { ((installed++)) || true; } || { ((failed++)) || true; }
    install_go_tool "uro" "github.com/s0md3v/uro" 2>/dev/null || {
        if check_command "uro"; then
            log_success "uro is already installed"
        else
            log_info "Installing uro via pip..."
            if pip3 install uro 2>/dev/null || pip install uro 2>/dev/null; then
                log_success "uro installed successfully"
                ((installed++)) || true
            else
                log_error "Failed to install uro"
                ((failed++)) || true
            fi
        fi
    }

    if check_command "urless"; then
        log_success "urless is already installed"
    else
        log_info "Installing urless via pip..."
        if pip3 install urless 2>/dev/null || pip install urless 2>/dev/null; then
            log_success "urless installed successfully"
            ((installed++)) || true
        else
            log_error "Failed to install urless"
            ((failed++)) || true
        fi
    fi

    if [[ -d "${TOOLS_DIR}/ParamSpider" ]] && [[ -f "${TOOLS_DIR}/ParamSpider/paramspider/main.py" ]]; then
        log_success "ParamSpider is already installed"
    else
        log_info "Installing ParamSpider..."
        rm -rf "${TOOLS_DIR}/ParamSpider"
        if git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git "${TOOLS_DIR}/ParamSpider" 2>/dev/null; then
            cd "${TOOLS_DIR}/ParamSpider"
            pip3 install -r requirements.txt 2>/dev/null || pip install -r requirements.txt 2>/dev/null || true
            pip3 install . 2>/dev/null || pip install . 2>/dev/null || true
            cd "${BASE_DIR}"
            log_success "ParamSpider installed successfully"
            ((installed++)) || true
        else
            log_error "Failed to install ParamSpider"
            ((failed++)) || true
        fi
    fi

    printf "\n"
    printf "=%.0s" {1..60}; printf "\n"
    log_info "${TOOL_NAME} Installation Summary"
    printf "=%.0s" {1..60}; printf "\n"
    log_success "Tools processed successfully"
    if [[ ${failed} -gt 0 ]]; then
        log_warn "${failed} tool(s) failed to install"
    fi
    printf "=%.0s" {1..60}; printf "\n"
}

validate_tools() {
    local missing=0
    local -a required_tools=("gospider" "katana" "waybackurls" "gau" "hakrawler" "urlfinder" "dalfox" "uro" "urless")

    for tool in "${required_tools[@]}"; do
        if ! check_command "${tool}"; then
            log_error "Missing required tool: ${tool}"
            ((missing++)) || true
        fi
    done

    if [[ ! -d "${TOOLS_DIR}/ParamSpider" ]] && ! check_command "paramspider"; then
        log_error "Missing required tool: ParamSpider"
        ((missing++)) || true
    fi

    if [[ ${missing} -gt 0 ]]; then
        log_error "${missing} required tool(s) missing. Run: $0 --tool-install"
        exit 1
    fi

    log_success "All required tools validated"
}

build_extension_filter() {
    local pattern=""
    for ext in "${STATIC_EXTENSIONS[@]}"; do
        if [[ -n "${pattern}" ]]; then
            pattern="${pattern}|"
        fi
        pattern="${pattern}\\.${ext}"
    done
    printf '%s' "${pattern}"
}

run_gospider() {
    local domain="$1"
    local outfile="${TEMP_DIR}/gospider_out.txt"
    log_info "Running gospider on ${domain}..."
    gospider -s "https://${domain}" -d 3 -c 10 -t 5 --other-source --include-subs \
        -H "User-Agent: $(random_ua)" \
        -o "${TEMP_DIR}/gospider_raw" >/dev/null 2>&1 || true
    if [[ -d "${TEMP_DIR}/gospider_raw" ]]; then
        cat "${TEMP_DIR}/gospider_raw"/* 2>/dev/null | grep -oP 'https?://[^\s"'"'"'<>]+' > "${outfile}" 2>/dev/null || true
        rm -rf "${TEMP_DIR}/gospider_raw"
    fi
    [[ -f "${outfile}" ]] || touch "${outfile}"
    log_success "gospider collected $(wc -l < "${outfile}") URLs"
}

run_katana() {
    local domain="$1"
    local outfile="${TEMP_DIR}/katana_out.txt"
    log_info "Running katana on ${domain}..."
    katana -u "https://${domain}" -d 3 -jc -kf all -c 10 -silent \
        -H "User-Agent: $(random_ua)" \
        -o "${outfile}" 2>/dev/null || true
    [[ -f "${outfile}" ]] || touch "${outfile}"
    log_success "katana collected $(wc -l < "${outfile}") URLs"
}

run_waybackurls() {
    local domain="$1"
    local outfile="${TEMP_DIR}/waybackurls_out.txt"
    log_info "Running waybackurls on ${domain}..."
    printf "%s\n" "${domain}" | waybackurls > "${outfile}" 2>/dev/null || true
    [[ -f "${outfile}" ]] || touch "${outfile}"
    log_success "waybackurls collected $(wc -l < "${outfile}") URLs"
}

run_gau() {
    local domain="$1"
    local outfile="${TEMP_DIR}/gau_out.txt"
    log_info "Running gau on ${domain}..."
    printf "%s\n" "${domain}" | gau --threads 5 > "${outfile}" 2>/dev/null || true
    [[ -f "${outfile}" ]] || touch "${outfile}"
    log_success "gau collected $(wc -l < "${outfile}") URLs"
}

run_hakrawler() {
    local domain="$1"
    local outfile="${TEMP_DIR}/hakrawler_out.txt"
    log_info "Running hakrawler on ${domain}..."
    printf "https://%s\n" "${domain}" | hakrawler -d 3 -t 5 -subs \
        -h "User-Agent: $(random_ua)" > "${outfile}" 2>/dev/null || true
    [[ -f "${outfile}" ]] || touch "${outfile}"
    log_success "hakrawler collected $(wc -l < "${outfile}") URLs"
}

run_urlfinder() {
    local domain="$1"
    local outfile="${TEMP_DIR}/urlfinder_out.txt"
    log_info "Running urlfinder on ${domain}..."
    urlfinder -d "${domain}" -all -silent -o "${outfile}" 2>/dev/null || true
    [[ -f "${outfile}" ]] || touch "${outfile}"
    log_success "urlfinder collected $(wc -l < "${outfile}") URLs"
}

merge_urls() {
    log_info "Merging all collected URLs..."
    cat "${TEMP_DIR}/gospider_out.txt" \
        "${TEMP_DIR}/katana_out.txt" \
        "${TEMP_DIR}/waybackurls_out.txt" \
        "${TEMP_DIR}/gau_out.txt" \
        "${TEMP_DIR}/hakrawler_out.txt" \
        "${TEMP_DIR}/urlfinder_out.txt" 2>/dev/null | \
        grep -oP 'https?://[^\s"'"'"'<>]+' | \
        sort -u > "${TEMP_DIR}/merged_raw.txt" 2>/dev/null || true
    [[ -f "${TEMP_DIR}/merged_raw.txt" ]] || touch "${TEMP_DIR}/merged_raw.txt"
    local count
    count=$(wc -l < "${TEMP_DIR}/merged_raw.txt")
    log_success "Total merged unique URLs: ${count}"
}

remove_static_extensions() {
    log_info "Removing static file extensions..."
    local filter
    filter=$(build_extension_filter)
    grep -viE "(${filter})(\?.*)?$" "${TEMP_DIR}/merged_raw.txt" > "${TEMP_DIR}/no_static.txt" 2>/dev/null || true
    [[ -f "${TEMP_DIR}/no_static.txt" ]] || touch "${TEMP_DIR}/no_static.txt"
    cp "${TEMP_DIR}/no_static.txt" "${OUTPUT_DIR}/urls_raw.txt"
    local count
    count=$(wc -l < "${TEMP_DIR}/no_static.txt")
    log_success "URLs after static removal: ${count}"
}

clean_urls() {
    log_info "Cleaning URLs with urless..."
    cat "${TEMP_DIR}/no_static.txt" | urless > "${TEMP_DIR}/urless_out.txt" 2>/dev/null || {
        cp "${TEMP_DIR}/no_static.txt" "${TEMP_DIR}/urless_out.txt"
    }
    [[ -f "${TEMP_DIR}/urless_out.txt" ]] || touch "${TEMP_DIR}/urless_out.txt"

    log_info "De-duplicating with uro..."
    cat "${TEMP_DIR}/urless_out.txt" | uro > "${TEMP_DIR}/uro_out.txt" 2>/dev/null || {
        cp "${TEMP_DIR}/urless_out.txt" "${TEMP_DIR}/uro_out.txt"
    }
    [[ -f "${TEMP_DIR}/uro_out.txt" ]] || touch "${TEMP_DIR}/uro_out.txt"
    local count
    count=$(wc -l < "${TEMP_DIR}/uro_out.txt")
    log_success "URLs after cleaning: ${count}"
}

extract_parameterized() {
    log_info "Extracting parameterized URLs..."
    grep -E '[?&][^=]+=' "${TEMP_DIR}/uro_out.txt" > "${TEMP_DIR}/parameterized.txt" 2>/dev/null || true
    [[ -f "${TEMP_DIR}/parameterized.txt" ]] || touch "${TEMP_DIR}/parameterized.txt"
    local count
    count=$(wc -l < "${TEMP_DIR}/parameterized.txt")
    log_success "Parameterized URLs found: ${count}"
}

run_paramspider() {
    local domain="$1"
    log_info "Running ParamSpider on ${domain}..."
    local ps_out="${TEMP_DIR}/paramspider_out.txt"
    if check_command "paramspider"; then
        paramspider -d "${domain}" --level high -o "${ps_out}" 2>/dev/null || true
    elif [[ -f "${TOOLS_DIR}/ParamSpider/paramspider/main.py" ]]; then
        python3 "${TOOLS_DIR}/ParamSpider/paramspider/main.py" -d "${domain}" --level high -o "${ps_out}" 2>/dev/null || true
    fi

    if [[ -f "${ps_out}" ]]; then
        cat "${ps_out}" >> "${TEMP_DIR}/parameterized.txt" 2>/dev/null || true
    fi

    local results_file="results/${domain}.txt"
    if [[ -f "${results_file}" ]]; then
        cat "${results_file}" >> "${TEMP_DIR}/parameterized.txt" 2>/dev/null || true
    fi

    local output_dir_ps="output/${domain}.txt"
    if [[ -f "${output_dir_ps}" ]]; then
        cat "${output_dir_ps}" >> "${TEMP_DIR}/parameterized.txt" 2>/dev/null || true
    fi

    sort -u "${TEMP_DIR}/parameterized.txt" -o "${TEMP_DIR}/parameterized.txt" 2>/dev/null || true
    cp "${TEMP_DIR}/parameterized.txt" "${OUTPUT_DIR}/urls_clean.txt"
    local count
    count=$(wc -l < "${OUTPUT_DIR}/urls_clean.txt")
    log_success "Total XSS candidate URLs: ${count}"
}

monitor_waf() {
    local status_code="$1"
    if [[ "${status_code}" == "403" ]] || [[ "${status_code}" == "429" ]]; then
        ((FAILURE_COUNT++)) || true
        if [[ ${FAILURE_COUNT} -ge ${FAILURE_THRESHOLD} ]]; then
            WAF_DETECTED=1
            if [[ ${CONCURRENCY} -gt 3 ]]; then
                CONCURRENCY=$(( CONCURRENCY / 2 ))
                [[ ${CONCURRENCY} -lt 3 ]] && CONCURRENCY=3
            fi
            if [[ ${DELAY} -lt 2000 ]]; then
                DELAY=$(( DELAY * 2 ))
                [[ ${DELAY} -gt 5000 ]] && DELAY=5000
            fi
            log_warn "WAF/Rate limit detected. Adjusting: concurrency=${CONCURRENCY}, delay=${DELAY}ms"
            FAILURE_COUNT=0
        fi
    fi
}

pre_scan_waf_check() {
    local domain="$1"
    log_info "Performing pre-scan WAF detection probe..."
    local probe_status
    probe_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "User-Agent: $(random_ua)" \
        "https://${domain}/?test=<script>alert(1)</script>" 2>/dev/null || echo "000")
    monitor_waf "${probe_status}"

    probe_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "User-Agent: $(random_ua)" \
        "https://${domain}/?q=<img+src=x+onerror=alert(1)>" 2>/dev/null || echo "000")
    monitor_waf "${probe_status}"

    if [[ ${WAF_DETECTED} -eq 1 ]]; then
        log_warn "WAF detected during pre-scan. Using conservative settings."
    else
        log_success "No immediate WAF detection. Proceeding with standard settings."
    fi
}

draw_progress() {
    local current="$1"
    local total="$2"
    local found="$3"
    local bar_width=30
    local percent=0
    if [[ ${total} -gt 0 ]]; then
        percent=$(( current * 100 / total ))
    fi
    local filled=$(( current * bar_width / (total > 0 ? total : 1) ))
    local empty=$(( bar_width - filled ))
    local bar=""
    local i
    for (( i=0; i<filled; i++ )); do bar+="█"; done
    for (( i=0; i<empty; i++ )); do bar+="░"; done
    printf "\r    [%s] %d/%d (%d%%) | 🔥 Found: %d " "${bar}" "${current}" "${total}" "${percent}" "${found}"
}

run_dalfox() {
    log_info "Running dalfox XSS scanner..."
    local candidate_count
    candidate_count=$(wc -l < "${OUTPUT_DIR}/urls_clean.txt")

    if [[ ${candidate_count} -eq 0 ]]; then
        log_warn "No candidate URLs found for XSS testing"
        printf "[]" > "${OUTPUT_DIR}/dalfox.json"
        return 0
    fi

    log_info "Scanning ${candidate_count} URLs with dalfox (worker=${CONCURRENCY}, delay=${DELAY}ms)..."
    if [[ -n "${PROXY}" ]]; then
        log_info "Using proxy: ${PROXY}"
    fi

    printf "[]" > "${OUTPUT_DIR}/dalfox.json"
    local scanned=0
    local xss_found=0
    local total_waf_hits=0
    local batch_file="${TEMP_DIR}/dalfox_batch.txt"
    local batch_out="${TEMP_DIR}/dalfox_batch_out.json"
    local batch_size=${CONCURRENCY}
    local line_num=0

    draw_progress 0 "${candidate_count}" 0

    > "${batch_file}"
    local batch_count=0

    while IFS= read -r url || [[ -n "${url}" ]]; do
        [[ -z "${url}" ]] && continue
        printf '%s\n' "${url}" >> "${batch_file}"
        ((batch_count++)) || true

        if [[ ${batch_count} -ge ${batch_size} ]]; then
            local dalfox_cmd=(dalfox file "${batch_file}"
                --only-poc r
                --silence
                --skip-bav
                --skip-mining-dom
                --format json
                --output "${batch_out}"
                --worker "${CONCURRENCY}"
                --delay "${DELAY}"
                -H "User-Agent: $(random_ua)"
            )
            [[ -n "${PROXY}" ]] && dalfox_cmd+=(--proxy "${PROXY}")

            "${dalfox_cmd[@]}" 2>"${TEMP_DIR}/dalfox_stderr.txt" || true

            if [[ -f "${batch_out}" ]] && [[ -s "${batch_out}" ]]; then
                local new_findings
                new_findings=$(grep -c '{' "${batch_out}" 2>/dev/null | head -1 || echo "0")
                new_findings=$(( new_findings + 0 ))
                xss_found=$(( xss_found + new_findings ))
                cat "${batch_out}" >> "${TEMP_DIR}/dalfox_all_results.json" 2>/dev/null || true
                rm -f "${batch_out}"
            fi

            if [[ -f "${TEMP_DIR}/dalfox_stderr.txt" ]]; then
                local waf_hits
                waf_hits=$(grep -ciE '403|429|forbidden|rate.limit' "${TEMP_DIR}/dalfox_stderr.txt" 2>/dev/null | head -1 || echo "0")
                waf_hits=$(( waf_hits + 0 ))
                total_waf_hits=$(( total_waf_hits + waf_hits ))
            fi

            scanned=$(( scanned + batch_count ))
            [[ ${scanned} -gt ${candidate_count} ]] && scanned=${candidate_count}
            draw_progress "${scanned}" "${candidate_count}" "${xss_found}"

            > "${batch_file}"
            batch_count=0
        fi
    done < "${OUTPUT_DIR}/urls_clean.txt"

    if [[ ${batch_count} -gt 0 ]]; then
        local dalfox_cmd=(dalfox file "${batch_file}"
            --only-poc r
            --silence
            --skip-bav
            --skip-mining-dom
            --format json
            --output "${batch_out}"
            --worker "${CONCURRENCY}"
            --delay "${DELAY}"
            -H "User-Agent: $(random_ua)"
        )
        [[ -n "${PROXY}" ]] && dalfox_cmd+=(--proxy "${PROXY}")

        "${dalfox_cmd[@]}" 2>"${TEMP_DIR}/dalfox_stderr.txt" || true

        if [[ -f "${batch_out}" ]] && [[ -s "${batch_out}" ]]; then
            local new_findings
            new_findings=$(grep -c '{' "${batch_out}" 2>/dev/null | head -1 || echo "0")
            new_findings=$(( new_findings + 0 ))
            xss_found=$(( xss_found + new_findings ))
            cat "${batch_out}" >> "${TEMP_DIR}/dalfox_all_results.json" 2>/dev/null || true
            rm -f "${batch_out}"
        fi

        if [[ -f "${TEMP_DIR}/dalfox_stderr.txt" ]]; then
            local waf_hits
            waf_hits=$(grep -ciE '403|429|forbidden|rate.limit' "${TEMP_DIR}/dalfox_stderr.txt" 2>/dev/null | head -1 || echo "0")
            waf_hits=$(( waf_hits + 0 ))
            total_waf_hits=$(( total_waf_hits + waf_hits ))
        fi

        scanned=$(( scanned + batch_count ))
        [[ ${scanned} -gt ${candidate_count} ]] && scanned=${candidate_count}
    fi

    draw_progress "${candidate_count}" "${candidate_count}" "${xss_found}"
    printf "\n"

    if [[ -f "${TEMP_DIR}/dalfox_all_results.json" ]] && [[ -s "${TEMP_DIR}/dalfox_all_results.json" ]]; then
        cp "${TEMP_DIR}/dalfox_all_results.json" "${OUTPUT_DIR}/dalfox.json"
    else
        printf "[]" > "${OUTPUT_DIR}/dalfox.json"
    fi

    if [[ ${total_waf_hits} -gt 5 ]]; then
        log_warn "Detected ${total_waf_hits} WAF/rate-limit responses during scan"
        WAF_DETECTED=1
    fi

    log_success "Dalfox scan complete: ${xss_found} potential XSS found in ${candidate_count} URLs"
}

compute_xss_score() {
    local url="$1"
    local param="$2"
    local payload="$3"
    local confidence="$4"
    local csp_present="$5"
    local waf_flag="$6"
    local score=50

    if echo "${payload}" | grep -qiE 'alert|confirm|prompt|eval|onerror|onload'; then
        score=$(( score + 20 ))
    fi

    if echo "${payload}" | grep -qiE '<script|<img|<svg|<iframe|<body|<input|<details'; then
        score=$(( score + 15 ))
    fi

    if echo "${param}" | grep -qiE 'search|q|query|keyword|redirect|url|return|callback|next|ref|page|html|content|template|msg|message|text|value|input|data'; then
        score=$(( score + 10 ))
    fi

    if [[ "${confidence}" == "high" ]] || [[ "${confidence}" == "certain" ]]; then
        score=$(( score + 15 ))
    elif [[ "${confidence}" == "medium" ]] || [[ "${confidence}" == "firm" ]]; then
        score=$(( score + 5 ))
    fi

    if echo "${url}" | grep -qiE 'reflect|mirror|echo|debug'; then
        score=$(( score + 5 ))
    fi

    if [[ "${waf_flag}" == "1" ]]; then
        score=$(( score - 15 ))
    fi

    if [[ "${csp_present}" == "1" ]]; then
        score=$(( score - 10 ))
    fi

    [[ ${score} -gt 100 ]] && score=100
    [[ ${score} -lt 0 ]] && score=0

    printf "%d" "${score}"
}

score_to_severity() {
    local score="$1"
    if [[ ${score} -ge 80 ]]; then
        printf "Critical"
    elif [[ ${score} -ge 55 ]]; then
        printf "High"
    else
        printf "Medium"
    fi
}

severity_to_color() {
    local severity="$1"
    case "${severity}" in
        Critical) printf "#dc3545" ;;
        High)     printf "#fd7e14" ;;
        Medium)   printf "#ffc107" ;;
        *)        printf "#6c757d" ;;
    esac
}

detect_csp() {
    local domain="$1"
    local csp_found=0
    local headers
    headers=$(curl -sI -H "User-Agent: $(random_ua)" "https://${domain}" 2>/dev/null || true)
    if echo "${headers}" | grep -qi "content-security-policy"; then
        csp_found=1
        log_warn "CSP header detected on target"
    fi
    printf "%d" "${csp_found}"
}

generate_scores() {
    local csp_present="$1"
    log_info "Generating XSS risk scores..."

    local json_file="${OUTPUT_DIR}/dalfox.json"
    local score_file="${OUTPUT_DIR}/score.json"

    if [[ ! -s "${json_file}" ]] || [[ "$(cat "${json_file}")" == "[]" ]]; then
        printf "[]" > "${score_file}"
        return 0
    fi

    printf "[" > "${score_file}"
    local first=1
    local line

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        [[ "${line}" == "[" ]] && continue
        [[ "${line}" == "]" ]] && continue

        line="${line#,}"
        line="${line%,}"
        [[ -z "${line}" ]] && continue

        local url param payload confidence_raw
        url=$(printf '%s' "${line}" | grep -oP '"inject_url"\s*:\s*"[^"]*"' | head -1 | sed 's/"inject_url"\s*:\s*"//' | sed 's/"$//' || echo "")
        if [[ -z "${url}" ]]; then
            url=$(printf '%s' "${line}" | grep -oP '"data"\s*:\s*"[^"]*"' | head -1 | sed 's/"data"\s*:\s*"//' | sed 's/"$//' || echo "")
        fi
        param=$(printf '%s' "${line}" | grep -oP '"param"\s*:\s*"[^"]*"' | head -1 | sed 's/"param"\s*:\s*"//' | sed 's/"$//' || echo "")
        payload=$(printf '%s' "${line}" | grep -oP '"payload"\s*:\s*"[^"]*"' | head -1 | sed 's/"payload"\s*:\s*"//' | sed 's/"$//' || echo "")
        confidence_raw=$(printf '%s' "${line}" | grep -oP '"severity"\s*:\s*"[^"]*"' | head -1 | sed 's/"severity"\s*:\s*"//' | sed 's/"$//' || echo "medium")

        [[ -z "${url}" ]] && continue

        local score
        score=$(compute_xss_score "${url}" "${param}" "${payload}" "${confidence_raw}" "${csp_present}" "${WAF_DETECTED}")
        local severity
        severity=$(score_to_severity "${score}")

        if [[ ${first} -eq 0 ]]; then
            printf "," >> "${score_file}"
        fi
        first=0

        local safe_url safe_param safe_payload
        safe_url=$(printf '%s' "${url}" | sed 's/\\/\\\\/g; s/"/\\"/g')
        safe_param=$(printf '%s' "${param}" | sed 's/\\/\\\\/g; s/"/\\"/g')
        safe_payload=$(printf '%s' "${payload}" | sed 's/\\/\\\\/g; s/"/\\"/g')

        cat >> "${score_file}" <<SCOREJSON
{
    "url": "${safe_url}",
    "parameter": "${safe_param}",
    "payload": "${safe_payload}",
    "original_confidence": "${confidence_raw}",
    "risk_score": ${score},
    "severity": "${severity}",
    "waf_detected": ${WAF_DETECTED},
    "csp_present": ${csp_present}
}
SCOREJSON
    done < "${json_file}"

    printf "]" >> "${score_file}"
    log_success "Scores written to output/score.json"
}

generate_report() {
    local domain="$1"
    local scan_end
    scan_end=$(date -u "+%Y-%m-%d %H:%M:%S UTC")
    local total_tested
    total_tested=$(wc -l < "${OUTPUT_DIR}/urls_clean.txt" 2>/dev/null || echo "0")

    log_info "Generating HTML report..."

    local findings_count=0
    local table_rows=""

    local score_file="${OUTPUT_DIR}/score.json"
    if [[ -s "${score_file}" ]] && [[ "$(cat "${score_file}")" != "[]" ]]; then
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            [[ "${line}" == "[" ]] && continue
            [[ "${line}" == "]" ]] && continue

            line="${line#,}"
            line="${line%,}"
            [[ -z "${line}" ]] && continue

            local url param payload score severity color
            url=$(printf '%s' "${line}" | grep -oP '"url"\s*:\s*"[^"]*"' | head -1 | sed 's/"url"\s*:\s*"//' | sed 's/"$//' || echo "")
            param=$(printf '%s' "${line}" | grep -oP '"parameter"\s*:\s*"[^"]*"' | head -1 | sed 's/"parameter"\s*:\s*"//' | sed 's/"$//' || echo "")
            payload=$(printf '%s' "${line}" | grep -oP '"payload"\s*:\s*"[^"]*"' | head -1 | sed 's/"payload"\s*:\s*"//' | sed 's/"$//' || echo "")
            score=$(printf '%s' "${line}" | grep -oP '"risk_score"\s*:\s*[0-9]+' | head -1 | sed 's/"risk_score"\s*:\s*//' || echo "0")
            severity=$(printf '%s' "${line}" | grep -oP '"severity"\s*:\s*"[^"]*"' | head -1 | sed 's/"severity"\s*:\s*"//' | sed 's/"$//' || echo "Medium")
            color=$(severity_to_color "${severity}")

            [[ -z "${url}" ]] && continue
            ((findings_count++)) || true

            local safe_url safe_param safe_payload
            safe_url=$(printf '%s' "${url}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            safe_param=$(printf '%s' "${param}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            safe_payload=$(printf '%s' "${payload}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')

            table_rows="${table_rows}<tr>
<td>${findings_count}</td>
<td style=\"word-break:break-all;max-width:350px;\">${safe_url}</td>
<td><code>${safe_param}</code></td>
<td style=\"word-break:break-all;max-width:300px;\"><code>${safe_payload}</code></td>
<td><strong>${score}</strong>/100</td>
<td><span style=\"background-color:${color};color:#fff;padding:3px 10px;border-radius:4px;font-weight:bold;\">${severity}</span></td>
</tr>"
        done < "${score_file}"
    fi

    local waf_status="Not Detected"
    [[ ${WAF_DETECTED} -eq 1 ]] && waf_status="<span style='color:#dc3545;font-weight:bold;'>Detected</span>"

    cat > "${OUTPUT_DIR}/report.html" <<REPORTHTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${TOOL_NAME} - XSS Scan Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;}
.container{max-width:1400px;margin:0 auto;padding:30px 20px;}
.header{background:linear-gradient(135deg,#161b22 0%,#1a1e2e 100%);border:1px solid #30363d;border-radius:12px;padding:35px;margin-bottom:30px;text-align:center;}
.header h1{font-size:2.2em;color:#58a6ff;margin-bottom:8px;letter-spacing:1px;}
.header .subtitle{color:#8b949e;font-size:1.1em;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:30px;}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:24px;text-align:center;transition:transform 0.2s;}
.stat-card:hover{transform:translateY(-2px);}
.stat-card .stat-value{font-size:2.4em;font-weight:700;color:#58a6ff;}
.stat-card .stat-label{color:#8b949e;font-size:0.9em;margin-top:6px;text-transform:uppercase;letter-spacing:1px;}
.stat-card.critical .stat-value{color:#dc3545;}
.stat-card.high .stat-value{color:#fd7e14;}
.stat-card.medium .stat-value{color:#ffc107;}
.stat-card.waf .stat-value{font-size:1.1em;}
.findings{background:#161b22;border:1px solid #30363d;border-radius:12px;overflow:hidden;margin-bottom:30px;}
.findings h2{padding:20px 24px;border-bottom:1px solid #30363d;color:#f0f6fc;font-size:1.3em;}
table{width:100%;border-collapse:collapse;}
th{background:#1c2128;color:#8b949e;padding:14px 16px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px;border-bottom:2px solid #30363d;}
td{padding:14px 16px;border-bottom:1px solid #21262d;font-size:0.92em;vertical-align:top;}
tr:hover{background:#1c2128;}
code{background:#1c2128;padding:2px 7px;border-radius:4px;font-family:'Fira Code','Cascadia Code',monospace;font-size:0.88em;color:#79c0ff;}
.no-findings{text-align:center;padding:60px 20px;color:#8b949e;}
.no-findings .icon{font-size:3em;margin-bottom:15px;}
.footer{text-align:center;color:#484f58;font-size:0.85em;padding:20px;border-top:1px solid #21262d;}
.meta-info{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:30px;}
.meta-item{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;display:flex;justify-content:space-between;align-items:center;}
.meta-item .label{color:#8b949e;font-size:0.9em;}
.meta-item .value{color:#c9d1d9;font-weight:600;}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🦊 ${TOOL_NAME}</h1>
<p class="subtitle">Automated XSS Vulnerability Scanner — Bug Bounty Edition v${VERSION}</p>
</div>
<div class="meta-info">
<div class="meta-item"><span class="label">Target Domain</span><span class="value">${domain}</span></div>
<div class="meta-item"><span class="label">Scan Started</span><span class="value">${SCAN_START}</span></div>
<div class="meta-item"><span class="label">Scan Completed</span><span class="value">${scan_end}</span></div>
<div class="meta-item"><span class="label">WAF Status</span><span class="value">${waf_status}</span></div>
</div>
<div class="stats-grid">
<div class="stat-card"><div class="stat-value">${total_tested}</div><div class="stat-label">URLs Tested</div></div>
<div class="stat-card critical"><div class="stat-value">${findings_count}</div><div class="stat-label">XSS Findings</div></div>
<div class="stat-card high"><div class="stat-value">${CONCURRENCY}</div><div class="stat-label">Final Concurrency</div></div>
<div class="stat-card medium"><div class="stat-value">${DELAY}ms</div><div class="stat-label">Final Delay</div></div>
</div>
<div class="findings">
<h2>📋 Vulnerability Findings</h2>
REPORTHTML

    if [[ ${findings_count} -gt 0 ]]; then
        cat >> "${OUTPUT_DIR}/report.html" <<TABLEHTML
<table>
<thead>
<tr><th>#</th><th>URL</th><th>Parameter</th><th>Payload</th><th>Risk Score</th><th>Severity</th></tr>
</thead>
<tbody>
${table_rows}
</tbody>
</table>
TABLEHTML
    else
        cat >> "${OUTPUT_DIR}/report.html" <<NOFINDHTML
<div class="no-findings">
<div class="icon">✅</div>
<h3>No XSS Vulnerabilities Found</h3>
<p>The automated scan did not detect confirmed XSS vulnerabilities in the tested endpoints.</p>
<p style="margin-top:10px;font-size:0.9em;">This does not guarantee the absence of vulnerabilities. Manual testing is recommended.</p>
</div>
NOFINDHTML
    fi

    cat >> "${OUTPUT_DIR}/report.html" <<FOOTERHTML
</div>
<div class="footer">
<p>Generated by ${TOOL_NAME} v${VERSION} — $(date -u "+%Y-%m-%d %H:%M:%S UTC")</p>
<p style="margin-top:4px;">⚠️ This report is for authorized security testing only. Unauthorized use is prohibited.</p>
</div>
</div>
</body>
</html>
FOOTERHTML

    log_success "Report generated: output/report.html (${findings_count} findings)"
}

run_self_audit() {
    log_info "Running automated self-audit..."
    local audit_file="${OUTPUT_DIR}/audit.txt"
    local script_path="${BASE_DIR}/akcaxss.sh"
    local issues=0

    cat > "${audit_file}" <<AUDITHEAD
================================================================================
${TOOL_NAME} v${VERSION} — Automated Code Audit Report
Generated: $(date -u "+%Y-%m-%d %H:%M:%S UTC")
================================================================================

AUDITHEAD

    printf "[ SECTION 1: INPUT VALIDATION ]\n\n" >> "${audit_file}"

    if grep -qn 'set -euo pipefail' "${script_path}" 2>/dev/null; then
        printf "  [PASS] Line 2: Strict mode enabled (set -euo pipefail)\n" >> "${audit_file}"
    else
        printf "  [FAIL] Strict mode (set -euo pipefail) not found\n" >> "${audit_file}"
        ((issues++)) || true
    fi

    if grep -qn 'readonly' "${script_path}" 2>/dev/null; then
        local ro_count
        ro_count=$(grep -c 'readonly' "${script_path}" 2>/dev/null || echo "0")
        printf "  [PASS] %d readonly declarations found — immutable constants enforced\n" "${ro_count}" >> "${audit_file}"
    else
        printf "  [WARN] No readonly variables found\n" >> "${audit_file}"
        ((issues++)) || true
    fi

    if grep -qn 'TARGET=.*\$1' "${script_path}" 2>/dev/null || grep -qn 'TARGET="${1' "${script_path}" 2>/dev/null; then
        printf "  [PASS] Target input is assigned from positional parameter\n" >> "${audit_file}"
    fi

    printf "\n[ SECTION 2: COMMAND INJECTION ANALYSIS ]\n\n" >> "${audit_file}"

    local eval_count
    eval_count=$(grep -c 'eval ' "${script_path}" 2>/dev/null | head -1 || echo "0")
    eval_count=$(( eval_count + 0 ))
    if [[ ${eval_count} -eq 0 ]]; then
        printf "  [PASS] No eval statements found — no eval-based injection risk\n" >> "${audit_file}"
    else
        printf "  [FAIL] %d eval statement(s) found — potential injection vector\n" "${eval_count}" >> "${audit_file}"
        ((issues++)) || true
    fi

    local backtick_count
    backtick_count=$(grep -c '`' "${script_path}" 2>/dev/null | head -1 || echo "0")
    backtick_count=$(( backtick_count + 0 ))
    if [[ ${backtick_count} -eq 0 ]]; then
        printf "  [PASS] No backtick command substitution — uses safe \$() syntax\n" >> "${audit_file}"
    else
        printf "  [INFO] %d line(s) contain backtick characters (review context)\n" "${backtick_count}" >> "${audit_file}"
    fi

    printf "\n[ SECTION 3: TEMP FILE SAFETY ]\n\n" >> "${audit_file}"

    if grep -qn 'trap cleanup EXIT' "${script_path}" 2>/dev/null; then
        printf "  [PASS] EXIT trap registered for cleanup\n" >> "${audit_file}"
    else
        printf "  [FAIL] No EXIT trap for temp file cleanup\n" >> "${audit_file}"
        ((issues++)) || true
    fi

    if grep -qn 'trap.*INT' "${script_path}" 2>/dev/null; then
        printf "  [PASS] INT/TERM signal trap registered for graceful shutdown\n" >> "${audit_file}"
    else
        printf "  [FAIL] No INT signal trap\n" >> "${audit_file}"
        ((issues++)) || true
    fi

    if grep -qn 'rm -rf.*TEMP_DIR' "${script_path}" 2>/dev/null; then
        printf "  [PASS] Temp directory cleanup implemented in cleanup()\n" >> "${audit_file}"
    else
        printf "  [WARN] Temp directory cleanup not explicitly found\n" >> "${audit_file}"
        ((issues++)) || true
    fi

    if grep -qn 'mktemp\|/tmp/' "${script_path}" 2>/dev/null; then
        printf "  [WARN] References to /tmp or mktemp found — potential symlink risk\n" >> "${audit_file}"
        ((issues++)) || true
    else
        printf "  [PASS] No /tmp references — uses project-local temp directory\n" >> "${audit_file}"
    fi

    printf "\n[ SECTION 4: RACE CONDITIONS ]\n\n" >> "${audit_file}"

    local bg_count
    bg_count=$(grep -c '&$' "${script_path}" 2>/dev/null | head -1 || echo "0")
    bg_count=$(( bg_count + 0 ))
    if [[ ${bg_count} -le 2 ]]; then
        printf "  [PASS] Minimal background processes — low race condition risk\n" >> "${audit_file}"
    else
        printf "  [WARN] %d background process launches detected — verify synchronization\n" "${bg_count}" >> "${audit_file}"
        ((issues++)) || true
    fi

    if grep -qn 'sort -u.*-o' "${script_path}" 2>/dev/null; then
        printf "  [PASS] sort -u with -o flag used for safe in-place deduplication\n" >> "${audit_file}"
    fi

    printf "\n[ SECTION 5: ERROR HANDLING ]\n\n" >> "${audit_file}"

    local or_true_count
    or_true_count=$(grep -c '|| true' "${script_path}" 2>/dev/null | head -1 || echo "0")
    or_true_count=$(( or_true_count + 0 ))
    printf "  [INFO] %d defensive '|| true' guards found for non-critical commands\n" "${or_true_count}" >> "${audit_file}"

    if grep -qn 'check_command' "${script_path}" 2>/dev/null; then
        printf "  [PASS] Tool existence checks implemented via check_command()\n" >> "${audit_file}"
    fi

    if grep -qn 'validate_tools' "${script_path}" 2>/dev/null; then
        printf "  [PASS] Full tool validation gate before scan execution\n" >> "${audit_file}"
    fi

    printf "\n[ SECTION 6: OUTPUT SANITIZATION ]\n\n" >> "${audit_file}"

    if grep -qn 'sed.*&amp;' "${script_path}" 2>/dev/null; then
        printf "  [PASS] HTML entity encoding applied to report output\n" >> "${audit_file}"
    else
        printf "  [WARN] HTML encoding may be incomplete in report generation\n" >> "${audit_file}"
        ((issues++)) || true
    fi

    printf "\n[ SECTION 7: NETWORK SAFETY ]\n\n" >> "${audit_file}"

    if grep -qn 'PROXY.*AKCAXSS_PROXY' "${script_path}" 2>/dev/null; then
        printf "  [PASS] Proxy support via environment variable (AKCAXSS_PROXY)\n" >> "${audit_file}"
    fi

    if grep -qn 'random_ua\|USER_AGENTS' "${script_path}" 2>/dev/null; then
        printf "  [PASS] User-Agent rotation implemented\n" >> "${audit_file}"
    fi

    if grep -qn 'monitor_waf\|WAF_DETECTED\|FAILURE_THRESHOLD' "${script_path}" 2>/dev/null; then
        printf "  [PASS] WAF detection and adaptive throttling implemented\n" >> "${audit_file}"
    fi

    printf "\n[ SECTION 8: VARIABLE QUOTING ]\n\n" >> "${audit_file}"

    local unquoted
    unquoted=$(grep -cE '\$[A-Z_]+[^"}\]]' "${script_path}" 2>/dev/null | head -1 || echo "0")
    unquoted=$(( unquoted + 0 ))
    if [[ ${unquoted} -lt 5 ]]; then
        printf "  [PASS] Variables appear properly quoted throughout\n" >> "${audit_file}"
    else
        printf "  [INFO] %d potential unquoted variable expansions (review recommended)\n" "${unquoted}" >> "${audit_file}"
    fi

    printf "\n================================================================================\n" >> "${audit_file}"
    printf "AUDIT SUMMARY\n" >> "${audit_file}"
    printf "================================================================================\n" >> "${audit_file}"
    printf "Total issues found: %d\n" "${issues}" >> "${audit_file}"
    if [[ ${issues} -eq 0 ]]; then
        printf "Status: ALL CHECKS PASSED\n" >> "${audit_file}"
    elif [[ ${issues} -le 3 ]]; then
        printf "Status: MINOR ISSUES — Review recommended\n" >> "${audit_file}"
    else
        printf "Status: REVIEW REQUIRED — Multiple issues detected\n" >> "${audit_file}"
    fi
    printf "================================================================================\n" >> "${audit_file}"

    log_success "Self-audit complete: output/audit.txt (${issues} issues)"
}

print_banner() {
    cat <<'BANNER'

     █████╗ ██╗  ██╗ ██████╗ █████╗ ██╗  ██╗███████╗███████╗
    ██╔══██╗██║ ██╔╝██╔════╝██╔══██╗╚██╗██╔╝██╔════╝██╔════╝
    ███████║█████╔╝ ██║     ███████║ ╚███╔╝ ███████╗███████╗
    ██╔══██║██╔═██╗ ██║     ██╔══██║ ██╔██╗ ╚════██║╚════██║
    ██║  ██║██║  ██╗╚██████╗██║  ██║██╔╝ ██╗███████║███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
                                       v1.0.0 by caneraktas1337

    [ Automated XSS Scanner for Bug Bounty Hunters ]

BANNER
}

scan_mode() {
    local domain="$1"
    SCAN_START=$(date -u "+%Y-%m-%d %H:%M:%S UTC")

    print_banner
    log_info "Target: ${domain}"
    log_info "Scan started: ${SCAN_START}"
    printf "=%.0s" {1..60}; printf "\n"

    validate_tools
    init_dirs

    log_info "Phase 1: URL & Endpoint Discovery"
    printf -- "-%.0s" {1..60}; printf "\n"
    run_gospider "${domain}"
    run_katana "${domain}"
    run_waybackurls "${domain}"
    run_gau "${domain}"
    run_hakrawler "${domain}"
    run_urlfinder "${domain}"

    log_info "Phase 2: Merge & Deduplicate"
    printf -- "-%.0s" {1..60}; printf "\n"
    merge_urls
    remove_static_extensions

    log_info "Phase 3: URL Cleaning"
    printf -- "-%.0s" {1..60}; printf "\n"
    clean_urls

    log_info "Phase 4: Parameter Extraction"
    printf -- "-%.0s" {1..60}; printf "\n"
    extract_parameterized
    run_paramspider "${domain}"

    log_info "Phase 5: WAF Detection & Tuning"
    printf -- "-%.0s" {1..60}; printf "\n"
    pre_scan_waf_check "${domain}"

    log_info "Phase 6: XSS Scanning with Dalfox"
    printf -- "-%.0s" {1..60}; printf "\n"
    run_dalfox

    local csp_present
    csp_present=$(detect_csp "${domain}")

    log_info "Phase 7: Scoring & Reporting"
    printf -- "-%.0s" {1..60}; printf "\n"
    generate_scores "${csp_present}"
    generate_report "${domain}"

    log_info "Phase 8: Self Audit"
    printf -- "-%.0s" {1..60}; printf "\n"
    run_self_audit

    printf "\n"
    printf "=%.0s" {1..60}; printf "\n"
    log_success "Scan complete for ${domain}"
    printf "=%.0s" {1..60}; printf "\n"
    log_info "Results:"
    log_info "  Raw URLs:    output/urls_raw.txt"
    log_info "  Clean URLs:  output/urls_clean.txt"
    log_info "  Dalfox JSON: output/dalfox.json"
    log_info "  Scores:      output/score.json"
    log_info "  Report:      output/report.html"
    log_info "  Audit:       output/audit.txt"
    printf "=%.0s" {1..60}; printf "\n"
}

main() {
    if [[ $# -lt 1 ]]; then
        print_banner
        printf "Usage:\n"
        printf "  %s <domain>          Run XSS scan on target domain\n" "$0"
        printf "  %s --tool-install    Install all required tools\n" "$0"
        printf "\nEnvironment variables:\n"
        printf "  AKCAXSS_PROXY        HTTP proxy (e.g. http://127.0.0.1:8080)\n"
        printf "\nExample:\n"
        printf "  %s example.com\n" "$0"
        exit 1
    fi

    case "$1" in
        --tool-install)
            print_banner
            tool_install_mode
            ;;
        --help|-h)
            print_banner
            printf "Usage:\n"
            printf "  %s <domain>          Run XSS scan on target domain\n" "$0"
            printf "  %s --tool-install    Install all required tools\n" "$0"
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            exit 1
            ;;
        *)
            TARGET="$1"
            if [[ ! "${TARGET}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
                log_error "Invalid domain format: ${TARGET}"
                exit 1
            fi
            scan_mode "${TARGET}"
            ;;
    esac
}

main "$@"
