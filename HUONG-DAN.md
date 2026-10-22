# Vá tạm php2shell (CVE-2026-109618 / CVE-2026-109619) — Ubuntu & AlmaLinux 8

Bộ này gồm 2 file:

| File | Vai trò |
|---|---|
| `php2shell-mitigate.sh` | Script vá tạm: dò mọi bản PHP trên máy, tắt đường khai thác, kiểm tra cấu hình, reload dịch vụ, có chế độ gỡ |
| `HUONG-DAN.md` | File này |

> **Đây là vá tạm, không phải bản vá.** Cách sửa triệt để duy nhất là cài bản PHP
> đã vá của nhà cung cấp. Dùng script khi bản vá chưa có (ví dụ PHP của FastPanel)
> hoặc chưa cài kịp.

Repo: <https://github.com/tiendungdev/php2shell-mitigation>

---

## 0. Chạy nhanh ngay sau khi SSH vào server

Đăng nhập bằng root rồi dán:

```bash
wget -qO /root/php2shell-mitigate.sh https://raw.githubusercontent.com/tiendungdev/php2shell-mitigation/main/php2shell-mitigate.sh
bash /root/php2shell-mitigate.sh --status      # xem hiện trạng, không ghi gì
bash /root/php2shell-mitigate.sh --dry-run     # xem file sẽ đổi, không ghi gì
bash /root/php2shell-mitigate.sh --apply       # áp dụng
```

Hoặc gộp thành một dòng, tải xong là áp dụng luôn:

```bash
wget -qO /root/php2shell-mitigate.sh https://raw.githubusercontent.com/tiendungdev/php2shell-mitigation/main/php2shell-mitigate.sh && bash /root/php2shell-mitigate.sh --apply
```

Phải dùng `&&`, **không** dùng `&`. `&` đẩy `wget` chạy nền nên `bash` chạy ngay khi file
chưa tải xong, có thể là file rỗng, tải dở hoặc bản cũ. `&&` chỉ chạy script khi tải thành công.
Tương tự, đừng dùng `wget -qO- … | bash`: mất mạng giữa chừng thì bash vẫn chạy phần đã tải về.

Máy chưa có `wget` (AlmaLinux 8 bản tối giản) thì cài bằng `dnf -y install wget`, hoặc thay
dòng đầu bằng `curl`:

```bash
curl -fsSLo /root/php2shell-mitigate.sh https://raw.githubusercontent.com/tiendungdev/php2shell-mitigation/main/php2shell-mitigate.sh
```

Kiểm tra nhanh file vừa tải: `head -1 /root/php2shell-mitigate.sh` phải là
`#!/usr/bin/env bash`.

**Muốn mọi server chạy đúng một phiên bản**: thay `main` trong link bằng mã commit
(xem trong tab *Commits* của repo), ví dụ `…/php2shell-mitigation/<commit-sha>/php2shell-mitigate.sh`.
Link `main` có thể được GitHub cache vài phút sau khi sửa script.

---

## 1. Lỗi là gì

Công bố ngày 2026-10-21, CVSS v4 9.2. Kẻ tấn công **không cần đăng nhập**, chỉ cần
gửi một request HTTP upload (`multipart/form-data`) là có thể chạy lệnh dưới quyền
user của PHP worker.

| CVE | Cơ chế | Đường bị khai thác đã xác nhận |
|---|---|---|
| CVE-2026-109619 | Request kết thúc bằng lỗi fatal (gồm hết bộ nhớ) để lại trạng thái cũ; request kế tiếp trên cùng worker dùng vùng nhớ đã giải phóng (use-after-free) | **Session upload progress** (bật mặc định, kể cả khi ứng dụng không dùng session); cảnh báo khi nạp `PHP_VALUE` / `.htaccess` |
| CVE-2026-109618 | Upload multipart làm cạn `memory_limit`, PHP huỷ giữa chừng để lại bộ nhớ dở dang | mod_php (đã xác nhận); PHP-FPM được coi là có thể bị, chưa có exploit hoàn chỉnh |

Bị ảnh hưởng: PHP-FPM, Apache mod_php (rủi ro cao nhất), php-cgi.

Bản sửa upstream: **8.2.35, 8.3.36, 8.4.27, 8.5.12**. Mọi bản ≤ 8.1 (EOL) không
có bản sửa chính thức.

Bản phân phối backport bản vá nên **`php -v` vẫn hiện số cũ**. Phải kiểm tra
phiên bản gói, đừng nhìn `php -v`.

## 2. Script làm gì

Với **mọi** bản PHP tìm thấy (PHP của hệ điều hành, Remi SCL, FastPanel `/opt/fphp`
và `/opt/phpNN`):

1. **Tạo file `99-php2shell.ini`** trong thư mục `conf.d` mà bản PHP đó thực sự đọc (lấy từ
   `php --ini` và `php-fpm -i`, không đoán đường dẫn), với nội dung
   `session.upload_progress.enabled = 0`. Thao tác này chặn đường khai thác đã
   xác nhận của CVE-2026-109619.
2. **Pool PHP-FPM**: chèn `php_admin_flag[session.upload_progress.enabled] = off`
   ngay dưới **từng** `[pool]`, đồng thời bỏ mọi dòng `php_value` /
   `php_flag` / `php_admin_*` đang bật lại setting này. Nhờ đó `.user.ini`,
   `ini_set()` hay thiết lập của panel không bật lại được.
3. **Apache mod_php**: thêm `php_admin_flag session.upload_progress.enabled off`
   ở cấp server. Nếu thiếu bước này, một `.htaccess` có `php_flag ... on` sẽ bật
   lại được (đã kiểm chứng bằng test đối chứng).
4. **PHP của panel FastPanel (`/opt/fphp`)**: giới hạn `post_max_size = 32M`,
   `upload_max_filesize = 30M` (mặc định của FastPanel là 512M) để giảm rủi ro
   CVE-2026-109618. Đổi bằng `--post-max`.
5. **Kiểm tra cấu hình trước khi reload**: chạy `php-fpm -t` theo đúng lệnh khởi động
   (`ExecStart`) của từng unit đang chạy, và `apachectl -t`. Chỉ cần **một** bài
   kiểm tra hỏng là **không reload gì cả** và dừng với mã 1.
6. **Reload** các unit PHP-FPM / Apache đang chạy, kể cả khi không file nào đổi
   (phòng trường hợp lần chạy trước đã ghi file nhưng chưa reload).
7. **Báo cáo**: tình trạng gói (đã vá hay chưa), phiên bản và setting của từng bản PHP,
   số pool đã chặn, chặn Apache có được nạp không, và các file cấu hình
   web có `PHP_VALUE` cần xem tay.

Mỗi file có sẵn bị sửa đều được sao lưu thành `<file>.bak-php2shell-<thời-gian>`.
File do script tạo mang dòng đánh dấu `php2shell` nên `--revert` gỡ được chính xác.

## 3. Hệ điều hành hỗ trợ

| Hệ điều hành | PHP được xử lý | Unit được reload |
|---|---|---|
| **Ubuntu** (đã test 24.04) | `/etc/php/X.Y/{cli,fpm,apache2,cgi}/conf.d`, pool `/etc/php/X.Y/fpm/pool.d/*.conf` (gói Ubuntu và PPA ondrej) | `phpX.Y-fpm`, `apache2` |
| **AlmaLinux 8** | `/etc/php.d` (dùng chung cho cli/fpm/mod_php), pool `/etc/php-fpm.d/*.conf`; Remi SCL `/etc/opt/remi/phpNN/` | `php-fpm`, `phpNN-php-fpm`, `httpd` |
| **FastPanel 2** (cả hai hệ) | `/opt/fphp` (PHP của panel, chạy phpMyAdmin), `/opt/phpNN` (PHP của site) | `fastpanel2-apps`, `fp2-phpNN-fpm` |

Hệ điều hành khác (Debian, Rocky, AlmaLinux 9…) bị từ chối, trừ khi thêm
`--force-os` (chưa được test).

Yêu cầu: `bash` ≥ 4.4, `systemd`, quyền root cho `--apply` / `--revert`. Chỉ
dùng coreutils, `awk`, `sed`, `grep`. Không cần `diff` hay `cmp`.

## 4. Cách dùng nhanh

```bash
# 0) Chép script lên máy (hoặc chạy từ xa, xem mục 5)
scp php2shell-mitigate.sh root@SERVER:/root/

# 1) Xem hiện trạng — không ghi gì
sudo bash php2shell-mitigate.sh --status

# 2) Xem trước những file sẽ đổi — không ghi gì
sudo bash php2shell-mitigate.sh --dry-run

# 3) Áp dụng
sudo bash php2shell-mitigate.sh --apply
echo $?      # 0 = xong; 1 = lỗi, không reload; 2 = còn chỗ On hoặc chưa reload
```

Kết quả `--apply` đúng sẽ trông như sau:

```
== Test and reload
  reloaded fastpanel2-apps.service
  reloaded php8.3-fpm.service
  reloaded apache2.service
...
== PHP-FPM pools
  /opt/fphp/etc/php-fpm.d/app.conf      pools=1 pinned=1
== Apache mod_php
  mod_php loaded; server-level pin active: /etc/apache2/conf-available/php2shell-mitigation.conf
== Result
  every PHP found reads upload_progress Off in its ini files
```

Cần thấy đủ ba điều: mọi dòng `upload_progress=Off`, `pinned` bằng `pools`, và
Apache báo `server-level pin active` (nếu có mod_php).

## 5. Chạy từ xa qua SSH (không cần chép file)

```bash
ssh root@SERVER 'bash -s -- --status' < php2shell-mitigate.sh
ssh root@SERVER 'bash -s -- --dry-run' < php2shell-mitigate.sh
ssh root@SERVER 'bash -s -- --apply'   < php2shell-mitigate.sh
```

SSH chạy ở cổng khác thì thêm `-p 2223`. Nếu máy có fail2ban, đừng dò cổng
liên tục kẻo bị khoá IP.

## 6. Tuỳ chọn

| Tuỳ chọn | Ý nghĩa |
|---|---|
| `--status` | (mặc định) Chỉ báo cáo |
| `--dry-run` | Báo cáo + danh sách file sẽ đổi |
| `--apply` | Ghi + kiểm tra cấu hình + reload |
| `--revert` | Gỡ mọi thứ `--apply` đã thêm + kiểm tra + reload |
| `--no-reload` | Ghi/gỡ file nhưng không reload; tự reload sau (mã thoát 2 để nhắc) |
| `--post-max MB` | Giới hạn kích thước request của `/opt/fphp` (mặc định 32, `0` = không giới hạn) |
| `--cap-all` | Áp giới hạn `--post-max` cho **mọi** bản PHP (cẩn thận với site cần upload lớn) |
| `--force-os` | Chạy trên hệ điều hành chưa hỗ trợ |

## 7. Cài bản vá thật — theo hệ điều hành

### Ubuntu

```bash
sudo apt update
sudo apt install --only-upgrade 'php8.3*'      # đổi theo phiên bản đang dùng
sudo systemctl restart php8.3-fpm apache2
```

Kiểm tra (script `--status` cũng tự kiểm tra):

```bash
zgrep -E 'CVE-2026-10961[89]' /usr/share/doc/php8.3-common/changelog.Debian.gz
```

Ví dụ thực tế: Ubuntu 24.04 có bản vá trong `php8.3 8.3.6-0ubuntu0.24.04.13`.

### AlmaLinux 8

```bash
sudo dnf clean metadata && sudo dnf upgrade 'php*'
sudo systemctl restart php-fpm        # mod_php: sudo systemctl restart httpd
rpm -q php-common
```

Phiên bản tối thiểu đã vá (theo AlmaLinux). Script tự so sánh khi rpm hỗ trợ:

| Module stream | Gói tối thiểu |
|---|---|
| php:7.2 | `php-7.2.24-1.module_el8.10.0+4315+7b734bf3.alma.1` |
| php:7.3 | `php-7.3.20-1.module_el8.10.0+4316+90ea5fe5.alma.1` |
| php:7.4 | `php-7.4.33-8.module_el8.10.0+4321+cf5fd4bb` |
| php:8.0 | `php-8.0.30-1.module_el8.10.0+4319+26f10322.alma.1` |
| php:8.2 | `php-8.2.33-1.module_el8.10.0+4320+c30d6dbb.alma.1` |

Stream 7.2 / 7.3 / 8.0 đã ngừng hỗ trợ: lần này có vá, lần sau không chắc.
Nếu đã từng bật repo testing: `sudo dnf config-manager --disable almalinux-testing`.

**mod_php trên AlmaLinux 8** (`httpd -M | grep -E 'mpm_|php'` thấy `mpm_prefork_module`
và `php_module`/`php7_module`) là cấu hình rủi ro cao nhất. Nên chuyển về MPM event +
PHP-FPM.

### FastPanel (cả hai hệ)

PHP của FastPanel (`fastpanel2-fphp`, `fastpanel2-phpNN`) nằm trong repo riêng
`repo.fastpanel.direct`, **`apt upgrade` / `dnf upgrade` của hệ điều hành không vá**.
Theo dõi bản mới:

```bash
# Ubuntu
apt update && apt-cache policy fastpanel2-fphp fastpanel2-php82 fastpanel2-php84
# AlmaLinux
dnf --refresh list --upgrades 'fastpanel2-php*' 'fastpanel2-fphp'
```

`/opt/fphp` hiện là **PHP 7.4.33 (EOL)**. Bản này không bao giờ có bản vá
upstream, chỉ FastPanel mới thay được nó.

## 8. Lưu ý riêng cho FastPanel

- **phpMyAdmin công khai.** Panel nginx (cổng `7777`/`8888`) chuyển
  `/phpmyadmin` thẳng vào `/opt/fphp` mà không qua đăng nhập panel. Đây là điểm
  tấn công không cần xác thực rõ nhất. Nên giới hạn IP, ví dụ thêm vào
  `/usr/local/fastpanel2-nginx/apps/secure/auth.conf`:
  ```nginx
  allow 1.2.3.4;     # IP quản trị
  deny all;
  ```
  rồi `systemctl reload fastpanel2-nginx`. Hoặc chặn cổng 7777/8888 bằng firewall chỉ
  cho IP quản trị.
- **Đổi thiết lập PHP của site trên giao diện FastPanel** có thể làm FastPanel
  ghi lại file pool và mất dòng `php_admin_flag`. File `conf.d/99-php2shell.ini`
  vẫn còn, nhưng **hãy chạy lại `--apply` sau mỗi lần đổi** (không sao nếu chạy
  lặp lại).
- **Tạo site mới / đổi phiên bản PHP của site**: chạy lại `--apply`.
- **Cập nhật gói FastPanel** không xoá `99-php2shell.ini` (file không thuộc gói),
  nhưng có thể ghi đè `app.conf`. Chạy `--status` sau mỗi lần cập nhật.

## 9. Gỡ bỏ (khi đã có bản vá chính thức)

```bash
sudo bash php2shell-mitigate.sh --revert
```

`--revert` xoá các file `99-php2shell.ini`, file chặn của Apache (Ubuntu: `a2disconf`),
các dòng chặn có đánh dấu trong pool, khối đánh dấu trong `php.ini` (nếu có), rồi
kiểm tra cấu hình và reload.

Giới hạn: `--apply` **xoá** các dòng `php_value`/`php_flag` gốc đang bật
`session.upload_progress` trong pool, và `--revert` **không** khôi phục chúng. Nếu
cần, lấy lại từ `<file>.bak-php2shell-<thời-gian>` đầu tiên.

Giữ lại sau khi đã vá cũng không hại gì: chỉ ứng dụng **hiển thị thanh tiến trình
upload bằng session** mới bị ảnh hưởng. Upload file thông thường vẫn chạy.

## 10. Những gì script KHÔNG làm

- **Không phải bản vá.** CVE-2026-109618 chỉ được giảm rủi ro (giới hạn kích thước
  request của panel), chưa được chặn.
- **Không đặt `memory_limit = -1`.** AlmaLinux có gợi ý cách này để tránh đường
  hết bộ nhớ, nhưng khi đó một request lớn có thể ăn hết RAM của cả máy. Nếu vẫn muốn, thêm
  `php_admin_value[memory_limit] = -1` vào pool, **kèm** giới hạn bộ nhớ bằng
  cgroup/systemd (`MemoryMax=` cho unit PHP-FPM). **Không** dùng `RLIMIT_AS` /
  `RLIMIT_DATA` vì chúng có thể kích hoạt đúng đường lỗi.
- **Không xử lý** LiteSpeed/`lsphp`, PHP trong Docker/container, bản PHP tự biên dịch ở
  đường dẫn lạ (không phải `/opt/fphp`, `/opt/phpNN`, `/opt/remi/phpNN`, PHP của hệ điều hành).
  Với các bản đó, đặt `session.upload_progress.enabled = 0` bằng tay
  trong `php.ini` hoặc pool.
- **Không sửa** `PHP_VALUE` trong nginx/Apache. Mục "Web-server settings worth a
  manual look" liệt kê các file có `PHP_VALUE`/`upload_progress` để xem tay.
  Setting sai trong đó gây cảnh báo là một đường kích hoạt CVE-2026-109619.
- **Không gửi request khai thác** để "thử". Hãy kiểm tra bằng `--status` và so sánh
  phiên bản. Trường `PHP_SESSION_UPLOAD_PROGRESS` nằm trong **body** của POST, mà
  access log nginx/Apache thường không ghi body. Chỉ log audit của WAF/ModSecurity mới
  thấy được. Dấu hiệu dễ kiểm hơn là process lạ sinh ra từ PHP worker:
  ```bash
  ps -eo pid,ppid,user,args --forest | grep -B2 -E '\b(sh|bash|curl|wget|nc)\b' | grep -A2 -E 'php-fpm|apache2|httpd'
  ```

## 11. Xử lý sự cố

| Triệu chứng | Nguyên nhân / cách xử lý |
|---|---|
| `FAIL test <unit>` + `NO service was reloaded` (mã 1) | Cấu hình của unit đó đang lỗi (có thể lỗi sẵn từ trước). Sửa lỗi in ra, hoặc chạy `--revert`. Không dịch vụ nào bị reload nên dịch vụ đang chạy không bị ảnh hưởng |
| Mã thoát 2, báo `keep the OLD setting` | Đã dùng `--no-reload` hoặc máy không có systemd: tự reload PHP-FPM/Apache |
| Mã thoát 2, còn `upload_progress=On` | Có file `.ini` khác nạp **sau** `99-` (tên bắt đầu bằng chữ thường hoặc `99z…`), hoặc bản PHP lạ. Tìm bằng `php --ini` và `grep -r upload_progress <conf.d>` |
| `pinned` < `pools` | File pool viết theo kiểu lạ (header `[pool]` có ký tự đặc biệt). Thêm tay dòng `php_admin_flag[session.upload_progress.enabled] = off` dưới header đó |
| Apache báo `NO server-level pin` sau `--apply` | Apache không nạp `conf-enabled/` (Ubuntu) hoặc `conf.d/` (AlmaLinux). Thêm `Include` cho file đó vào cấu hình chính |
| `cannot read ExecStart of <unit>` | Unit dùng script bọc ngoài; kiểm tra cấu hình bằng tay rồi `systemctl reload <unit>` |
| `unsupported OS` | Chỉ hỗ trợ Ubuntu và AlmaLinux 8; thêm `--force-os` nếu chấp nhận rủi ro |

## 12. Đã kiểm thử những gì (2026-10-22)

| Môi trường | Nội dung test | Kết quả |
|---|---|---|
| Container **AlmaLinux 8.10** + systemd, AppStream `php:8.2` (FPM + mod_php trên prefork), FastPanel giả lập `/opt/fphp` với 2 pool | `--status`, `--dry-run`, `--apply`, chạy `--apply` lần 2, `--revert`; **hỏi trực tiếp worker đang chạy** qua socket FastCGI và mod_php qua HTTP | Trước: `On` → sau `--apply`: `Off` (fphp `post_max=32M`) → sau `--revert`: `On`; pool sau revert trùng hash với bản gốc |
| Container **Ubuntu 24.04** + systemd, `php8.3-fpm` + `libapache2-mod-php8.3`, FastPanel giả lập `/opt/php84` (pool đang chạy) và `/opt/php82` (không pool, unit tắt) | Như trên + thử bật lại bằng `.user.ini` (FPM) và `.htaccess` (mod_php); `--no-reload`; chạy không phải root; tham số sai | `.user.ini` và `.htaccess` **không** bật lại được; đối chứng âm: bỏ file chặn Apache thì `.htaccess` bật lại được `On`; mã thoát đúng |
| **FastPanel thật** trên Ubuntu 24.04 | `--status`, `--dry-run` | Nhận đúng `/opt/fphp` 7.4.33, `/opt/php82`, `/opt/php84`, php8.3 đã vá |
| **FastPanel thật** trên AlmaLinux 8.10 (3 site đang chạy) | `--status`, `--dry-run`, `--apply` | 5 bản PHP FastPanel (`fphp` 7.3.33, 7.4, 8.1, 8.2, 8.3) + php-fpm/mod_php 7.2 của hệ điều hành: tất cả `Off`; 5 pool `pinned=1`; chặn Apache được nạp; worker khởi động lại, không có lỗi trong log; 3 site trả HTTP 200 |
| shellcheck 0.10.0 (`-S warning`) | — | Sạch |

Hai đặc điểm của FastPanel trên AlmaLinux 8, script đã xử lý:

- `/usr/bin/php` là symlink sang `/opt/php83/bin/php` (gói `fastpanel2-php83`), nên
  **không** phải PHP của hệ điều hành. Script so đường dẫn thật nên không báo nhầm là
  "đã vá theo gói hệ điều hành".
- `/opt/fphp` khai báo thư mục quét `/opt/fphp/conf.d` nhưng thư mục chưa tồn tại.
  Script tạo thư mục đó thay vì sửa `php.ini` của gói.

**Chưa test**: gói Remi SCL, PHP biên dịch hoàn toàn không có thư mục quét `conf.d`
(khi đó script chuyển sang ghi một khối có đánh dấu vào `php.ini`).

## Nguồn

- AlmaLinux: <https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/>
- Ubuntu: <https://ubuntu.com/blog/php2shell-vulnerability-fixes-available>
- Script tham khảo: <https://github.com/revonnet/php-fix>, <https://gist.github.com/egorleet/b20af845ee313fe600a51e6054d45991>
- PoC (chỉ đọc để hiểu cơ chế, không chạy): <https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC>
