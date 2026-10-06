#!/usr/bin/env bash
# Download the tested release, not an untested branch. Never request GitHub tokens.
set -Eeuo pipefail

RXS3_VERSION='0.1.0-rc2'
ARCHIVE="rx-pro-s3-manager-${RXS3_VERSION}.tar.gz"
SHA256='8b6a9aadbc17c21d8b651918785b91df0284b54ead2b0728cc06a9fdf1b167cb'
URL="https://github.com/cwash797-cmd/RX-PRO-S3-Manager/releases/download/v${RXS3_VERSION}/${ARCHIVE}"
mode='fresh'
destination=''
case "${1:-}" in
    '') ;;
    --existing-panel) mode='existing'; shift ;;
    --download-only)
        mode='download'
        destination="${2:?Укажите новый каталог для скачивания}"
        shift 2 ;;
    --help|-h)
        printf '%s\n' 'Использование: sudo bash get.sh [--existing-panel]' \
            'По умолчанию: чистая установка 3x-ui 3.9.0, затем мастер и меню.' \
            'Только скачать/проверить: bash get.sh --download-only НОВЫЙ_КАТАЛОГ'
        exit 0 ;;
    *) echo 'Неизвестный параметр. Используйте --help.' >&2; exit 2 ;;
esac
[[ $# -eq 0 ]] || { echo 'Лишние параметры.' >&2; exit 2; }
if [[ "$mode" != download ]]; then
    [[ $EUID -eq 0 ]] || { echo 'Запустите команду через sudo.' >&2; exit 1; }
    [[ -t 0 ]] || { echo 'Нужен терминал: не запускайте через curl | bash.' >&2; exit 1; }
    [[ $(uname -m) == x86_64 ]] || { echo 'Нужна архитектура x86_64.' >&2; exit 1; }
    # Standard root-owned OS metadata, not downloaded code.
    . /etc/os-release
    case "${ID}:${VERSION_ID}" in
        ubuntu:22.04|ubuntu:24.04|debian:12) ;;
        *) echo 'Нужны Ubuntu 22.04/24.04 или Debian 12.' >&2; exit 1 ;;
    esac
    [[ -d /run/systemd/system ]] || { echo 'Нужен systemd, не Docker.' >&2; exit 1; }
    if [[ "$mode" == fresh ]]; then
        if [[ -f /opt/rxs3/.rxs3-managed && ! -L /opt/rxs3/.rxs3-managed ]] && \
            { [[ -e /usr/local/x-ui ]] || [[ -e /var/lib/rxs3/config.json ]] || [[ -e /var/lib/rxs3/setup.json ]]; }; then
            mode='existing'
            if [[ -f /var/lib/rxs3/config.json ]]; then
                echo 'Найден установленный менеджер. Обновим его файлы; панель и данные сохраняются.'
            else
                echo 'Найдена незавершённая установка менеджера. Обновим его файлы и продолжим мастер.'
            fi
        elif [[ -e /usr/local/x-ui || -e /etc/x-ui ]]; then
            echo 'Найдена существующая панель, не установленная этим менеджером. Переустанавливать её не будем.'
            read -r -p 'Подключить её к менеджеру? [да/нет; Enter = нет]: ' answer
            case "$answer" in
                да|Да|yes|y) mode='existing' ;;
                *) echo 'Ничего не изменено.'; exit 0 ;;
            esac
        fi
    fi
    apt-get update
    apt-get install -y python3 python3-cryptography python3-qrcode iproute2 ca-certificates curl
else
    [[ ! -e "$destination" && ! -L "$destination" ]] || { echo 'Каталог назначения уже существует.' >&2; exit 1; }
fi
command -v curl >/dev/null || { echo 'Сначала установите curl и ca-certificates.' >&2; exit 1; }
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/rxs3-download.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
printf 'Скачивание проверенного тестового релиза %s...\n' "$RXS3_VERSION"
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 300 --max-filesize 10000000 "$URL" -o "$work/$ARCHIVE"
printf '%s  %s\n' "$SHA256" "$work/$ARCHIVE" | sha256sum -c -
tar --no-same-owner --no-same-permissions -xzf "$work/$ARCHIVE" -C "$work"
release="$work/rx-pro-s3-manager-${RXS3_VERSION}"
(cd "$release" && sha256sum -c SHA256SUMS)
if [[ "$mode" == download ]]; then
    mkdir -- "$destination"
    cp -a -- "$release/." "$destination/"
    printf 'Релиз проверен и распакован: %s. Ничего не установлено.\n' "$destination"
    exit 0
fi
python3 "$release/install.py" --check
if [[ "$mode" == fresh ]]; then
    python3 "$release/install.py" --fresh-panel
else
    python3 "$release/install.py"
fi
if ! rxs3 setup; then
    printf '%s\n' 'Настройка не завершена. Сервер переустанавливать не нужно.' \
        'Продолжить: sudo rxs3 setup' \
        'Исправить ключи/бакет VK: sudo rxs3 setup --edit-vk' \
        'Показать состояние: sudo rxs3 status'
    exit 1
fi
if [[ ! -f /var/lib/rxs3/config.json ]]; then
    echo 'Мастер отложен. Продолжить позже: sudo rxs3 setup'
    exit 0
fi
rxs3
