/*
Copyright © 2026 Ulas SAYGIN

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// FreeBSD pw komutu
	pwCmd = "/usr/sbin/pw"

	// Sistem grupları - mailbox kullanıcısı bu gruplara eklenecek
	mailGroup   = "mail"
	dovecotGroup = "dovecot"

	// Otomatik ID başlangıç değeri
	autoIDStart = 2000

	// Domain sistem kullanıcısı prefix'leri
	domainUserPrefix  = "ed_"
	domainGroupPrefix = "edg_"

	// Mailbox sistem kullanıcısı prefix'leri
	mailboxUserPrefix  = "eu_"
	mailboxGroupPrefix = "eug_"
)

// -----------------------------------------------------------------
// doveconf yardımcı fonksiyonları
// -----------------------------------------------------------------

// checkDoveconfInstalled - doveconf'un sistemde kurulu olup olmadığını kontrol eder
func checkDoveconfInstalled() error {
	_, err := exec.LookPath("doveconf")
	if err != nil {
		return fmt.Errorf("doveconf bulunamadı: dovecot kurulu değil ya da PATH'te yok. " +
			"Lütfen dovecot'u kurun veya --mail-home flag'ini kullanın")
	}
	return nil
}

// getDoveconfValue - doveconf komutundan belirtilen key'in değerini okur
func getDoveconfValue(key string) (string, error) {
	if err := checkDoveconfInstalled(); err != nil {
		return "", err
	}
	out, err := exec.Command("doveconf", "-h", key).Output()
	if err != nil {
		return "", fmt.Errorf("doveconf %s komutu başarısız: %w", key, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// -----------------------------------------------------------------
// Güvenlik validasyon fonksiyonları
// -----------------------------------------------------------------

// validateDomainName - domain adının güvenli olduğunu doğrular
// Yalnızca harf, rakam, nokta ve tire karakterlerine izin verilir (RFC 1123)
func validateDomainName(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain adı boş olamaz")
	}
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return fmt.Errorf("domain adında geçersiz karakter: %q (yalnızca harf, rakam, nokta ve tire kabul edilir)", c)
		}
	}
	// Path traversal denemeleri için ek kontrol
	if strings.Contains(domain, "..") {
		return fmt.Errorf("domain adı '..' içeremez")
	}
	return nil
}

// validateLocalPart - e-posta adresinin kullanıcı kısmının güvenli olduğunu doğrular
// RFC 5321'e göre izin verilen karakterler (basitleştirilmiş)
func validateLocalPart(localpart string) error {
	if localpart == "" {
		return fmt.Errorf("e-posta kullanıcı adı boş olamaz")
	}
	for _, c := range localpart {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '+') {
			return fmt.Errorf("e-posta kullanıcı adında geçersiz karakter: %q", c)
		}
	}
	if strings.Contains(localpart, "..") {
		return fmt.Errorf("e-posta kullanıcı adı '..' içeremez")
	}
	return nil
}

// validateMailHomePath - --mail-home parametresinin güvenli olduğunu doğrular
// Mutlak path olmalı ve path traversal içermemeli
func validateMailHomePath(path string) error {
	if path == "" {
		return nil // boş geçerli, doveconf'dan alınacak
	}
	// Mutlak path zorunlu
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("mail-home mutlak path olmalıdır (/ ile başlamalı): %s", path)
	}
	// filepath.Clean ile normalize et ve tekrar karşılaştır
	cleaned := filepath.Clean(path)
	if cleaned != path && cleaned+"/" != path {
		return fmt.Errorf("mail-home geçersiz path içeriyor (normalize sonucu farklı): %s → %s", path, cleaned)
	}
	// Path traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("mail-home '..' içeremez: %s", path)
	}
	// Null byte injection
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("mail-home null byte içeremez")
	}
	return nil
}

// validateDoveconfPath - doveconf'dan gelen path'in güvenli olduğunu doğrular
func validateDoveconfPath(path string) error {
	if path == "" {
		return fmt.Errorf("doveconf'dan alınan mail dizini boş")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("doveconf'dan alınan path mutlak olmalı: %s", path)
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("doveconf'dan alınan path '..' içeriyor: %s", path)
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("doveconf'dan alınan path null byte içeriyor")
	}
	return nil
}

// parseMailHomePath - doveconf'dan gelen mail_home değerini parse eder
// Örnek: /server_data/mail/%d/%n  → domain ve username ile tam path üretir
func parseMailHomePath(mailHome, domain, username string) string {
	path := mailHome
	path = strings.ReplaceAll(path, "%d", domain)
	path = strings.ReplaceAll(path, "%n", username)
	path = strings.ReplaceAll(path, "%u", username+"@"+domain)
	return path
}

// getMailBaseDir - doveconf'dan mail dizin tabanını alır
// mail_home varsa onu kullanır, yoksa mail_location'dan çıkarır
// Dönen değer %d/%n içeren ham template'tir
func getMailBaseDir() (string, error) {
	// Önce mail_home'u dene
	mailHome, err := getDoveconfValue("mail_home")
	if err == nil && mailHome != "" {
		return mailHome, nil
	}

	// mail_home yoksa mail_location'dan parse et
	// Örnek: maildir:~/Maildir:LAYOUT=fs
	mailLocation, err := getDoveconfValue("mail_location")
	if err != nil {
		return "", fmt.Errorf("doveconf'dan mail dizini alınamadı: %w", err)
	}

	// "maildir:~/Maildir:..." → "~/Maildir" kısmını al
	parts := strings.Split(mailLocation, ":")
	if len(parts) < 2 {
		return "", fmt.Errorf("geçersiz mail_location formatı: %s", mailLocation)
	}
	path := parts[1]

	// "~/" prefix'ini kaldır, mail_home ile birleştirilecek
	path = strings.TrimPrefix(path, "~/")

	// mail_home olmadan salt mail_location ile temel dizin belirlenemez
	// Bu durumda varsayılan bir yapı döndür
	return "/var/mail/virtual/%d/%n/" + path, nil
}

// buildMailDir - domain ve username için tam mail dizinini oluşturur
func buildMailDir(domain, username string) (string, error) {
	template, err := getMailBaseDir()
	if err != nil {
		return "", err
	}
	result := parseMailHomePath(template, domain, username)
	if err := validateDoveconfPath(result); err != nil {
		return "", err
	}
	return result, nil
}

// buildDomainMailDir - domain için üst mail dizinini oluşturur (%n olmadan)
func buildDomainMailDir(domain string) (string, error) {
	template, err := getMailBaseDir()
	if err != nil {
		return "", err
	}
	// %n kısmını kaldır, sadece domain dizinini al
	path := parseMailHomePath(template, domain, "")
	// Sondaki fazla slash'ları temizle
	path = filepath.Clean(path)
	if err := validateDoveconfPath(path); err != nil {
		return "", err
	}
	return path, nil
}

// -----------------------------------------------------------------
// FreeBSD pw yardımcı fonksiyonları
// -----------------------------------------------------------------

// pwIDExists - FreeBSD'de verilen uid veya gid'in kullanımda olup olmadığını kontrol eder
func pwUIDExists(uid int64) bool {
	err := exec.Command(pwCmd, "usershow", "-u", strconv.FormatInt(uid, 10)).Run()
	return err == nil
}

func pwGIDExists(gid int64) bool {
	err := exec.Command(pwCmd, "groupshow", "-g", strconv.FormatInt(gid, 10)).Run()
	return err == nil
}

func pwUsernameExists(username string) bool {
	err := exec.Command(pwCmd, "usershow", username).Run()
	return err == nil
}

func pwGroupnameExists(groupname string) bool {
	err := exec.Command(pwCmd, "groupshow", groupname).Run()
	return err == nil
}

// -----------------------------------------------------------------
// Otomatik ID yönetimi
// -----------------------------------------------------------------

// isUIDUsedInDB - veritabanında uid kullanılıyor mu kontrol eder
func isUIDUsedInDB(uid int64) bool {
	return mdb.IsUIDUsed(uid)
}

// isGIDUsedInDB - veritabanında gid kullanılıyor mu kontrol eder
func isGIDUsedInDB(gid int64) bool {
	return mdb.IsGIDUsed(gid)
}

// findNextFreeUID - autoIDStart'tan başlayarak hem FreeBSD'de hem DB'de
// kullanılmayan ilk uid'i döndürür
func findNextFreeUID(startFrom int64) int64 {
	if startFrom < autoIDStart {
		startFrom = autoIDStart
	}
	for id := startFrom; id < 65000; id++ {
		if !pwUIDExists(id) && !isUIDUsedInDB(id) {
			return id
		}
	}
	return -1 // bulunamadı
}

// findNextFreeGID - autoIDStart'tan başlayarak hem FreeBSD'de hem DB'de
// kullanılmayan ilk gid'i döndürür
func findNextFreeGID(startFrom int64) int64 {
	if startFrom < autoIDStart {
		startFrom = autoIDStart
	}
	for id := startFrom; id < 65000; id++ {
		if !pwGIDExists(id) && !isGIDUsedInDB(id) {
			return id
		}
	}
	return -1 // bulunamadı
}

// resolveUID - verilen uid'i doğrular veya otomatik seçer
// uid <= 0 ise otomatik seçilir
func resolveUID(requestedUID int64) (int64, error) {
	if requestedUID <= 0 {
		// Otomatik seç
		uid := findNextFreeUID(autoIDStart)
		if uid < 0 {
			return 0, fmt.Errorf("kullanılabilir uid bulunamadı (2000-65000 aralığı dolu)")
		}
		return uid, nil
	}
	// Verilen uid çakışıyor mu?
	if pwUIDExists(requestedUID) || isUIDUsedInDB(requestedUID) {
		// Çakışıyor, bir sonrakini bul
		uid := findNextFreeUID(requestedUID + 1)
		if uid < 0 {
			return 0, fmt.Errorf("uid %d kullanımda ve uygun alternatif bulunamadı", requestedUID)
		}
		fmt.Printf("UYARI: uid %d kullanımda, %d kullanılacak\n", requestedUID, uid)
		return uid, nil
	}
	return requestedUID, nil
}

// resolveGID - verilen gid'i doğrular veya otomatik seçer
func resolveGID(requestedGID int64) (int64, error) {
	if requestedGID <= 0 {
		gid := findNextFreeGID(autoIDStart)
		if gid < 0 {
			return 0, fmt.Errorf("kullanılabilir gid bulunamadı (2000-65000 aralığı dolu)")
		}
		return gid, nil
	}
	if pwGIDExists(requestedGID) || isGIDUsedInDB(requestedGID) {
		gid := findNextFreeGID(requestedGID + 1)
		if gid < 0 {
			return 0, fmt.Errorf("gid %d kullanımda ve uygun alternatif bulunamadı", requestedGID)
		}
		fmt.Printf("UYARI: gid %d kullanımda, %d kullanılacak\n", requestedGID, gid)
		return gid, nil
	}
	return requestedGID, nil
}

// -----------------------------------------------------------------
// FreeBSD sistem kullanıcısı oluşturma / silme
// -----------------------------------------------------------------

// createSystemGroup - FreeBSD'de sistem grubu oluşturur
func createSystemGroup(groupname string, gid int64) error {
	if pwGroupnameExists(groupname) {
		return fmt.Errorf("grup %s zaten mevcut", groupname)
	}
	args := []string{"groupadd", groupname, "-g", strconv.FormatInt(gid, 10)}
	out, err := exec.Command(pwCmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("grup oluşturulamadı (%s): %s", groupname, string(out))
	}
	return nil
}

// deleteSystemGroup - FreeBSD'de sistem grubunu siler (rollback için)
func deleteSystemGroup(groupname string) {
	exec.Command(pwCmd, "groupdel", groupname).Run()
}

// createSystemUser - FreeBSD'de sistem kullanıcısı oluşturur
func createSystemUser(username string, uid int64, groupname string) error {
	if pwUsernameExists(username) {
		return fmt.Errorf("kullanıcı %s zaten mevcut", username)
	}
	args := []string{
		"useradd", username,
		"-u", strconv.FormatInt(uid, 10),
		"-g", groupname,
		"-d", "/nonexistent",
		"-s", "/usr/sbin/nologin",
		"-c", "Mail System User",
	}
	out, err := exec.Command(pwCmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("kullanıcı oluşturulamadı (%s): %s", username, string(out))
	}
	return nil
}

// deleteSystemUser - FreeBSD'de sistem kullanıcısını siler (rollback için)
func deleteSystemUser(username string) {
	exec.Command(pwCmd, "userdel", username).Run()
}

// addUserToGroup - FreeBSD'de kullanıcıyı bir gruba ekler
func addUserToGroup(username, groupname string) error {
	out, err := exec.Command(pwCmd, "groupmod", groupname, "-m", username).CombinedOutput()
	if err != nil {
		return fmt.Errorf("kullanıcı %s, %s grubuna eklenemedi: %s", username, groupname, string(out))
	}
	return nil
}

// removeUserFromGroup - FreeBSD'de kullanıcıyı gruptan çıkarır (rollback için)
func removeUserFromGroup(username, groupname string) {
	// Mevcut üyeleri al, bu kullanıcıyı çıkar, güncelle
	out, err := exec.Command(pwCmd, "groupshow", groupname).Output()
	if err != nil {
		return
	}
	// pw groupshow çıktısı: groupname:*:gid:member1,member2
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 4 {
		return
	}
	members := strings.Split(fields[3], ",")
	var newMembers []string
	for _, m := range members {
		if m != username {
			newMembers = append(newMembers, m)
		}
	}
	exec.Command(pwCmd, "groupmod", groupname, "-M", strings.Join(newMembers, ",")).Run()
}

// ensureDirectory - dizin yoksa oluşturur ve sahipliğini ayarlar
func ensureDirectory(path string, uid, gid int64) error {
	if err := os.MkdirAll(path, 0750); err != nil {
		return fmt.Errorf("dizin oluşturulamadı (%s): %w", path, err)
	}
	if err := os.Chown(path, int(uid), int(gid)); err != nil {
		return fmt.Errorf("dizin sahipliği ayarlanamadı (%s): %w", path, err)
	}
	return nil
}

// -----------------------------------------------------------------
// Domain sistem kurulumu
// -----------------------------------------------------------------

// SetupDomainSysUser - vmailbox domain eklenirken FreeBSD sistem kullanıcısı ve
// dizin yapısını oluşturur. Başarı durumunda kullanılan gerçek uid/gid döner.
//
// Akış:
//  1. uid/gid çakışma kontrolü ve gerekirse otomatik seçim
//  2. edg_{gid} grubu oluştur
//  3. ed_{uid} kullanıcısı oluştur
//  4. mail ve dovecot gruplarına ekle
//  5. doveconf'dan domain mail dizinini al ve oluştur
//  6. Hata durumunda rollback
func SetupDomainSysUser(domainName string, requestedUID, requestedGID int64) (int64, int64, error) {
	// 0. doveconf kurulu mu kontrol et — kurulu değilse hiçbir şey yapma
	if err := checkDoveconfInstalled(); err != nil {
		return 0, 0, err
	}

	// 0b. Parametre güvenlik validasyonu
	if err := validateDomainName(domainName); err != nil {
		return 0, 0, err
	}

	// 1. uid/gid çözümle
	uid, err := resolveUID(requestedUID)
	if err != nil {
		return 0, 0, err
	}
	gid, err := resolveGID(requestedGID)
	if err != nil {
		return 0, 0, err
	}

	groupname := fmt.Sprintf("%s%d", domainGroupPrefix, gid)
	username := fmt.Sprintf("%s%d", domainUserPrefix, uid)

	// 2. Grup oluştur
	if err := createSystemGroup(groupname, gid); err != nil {
		return 0, 0, err
	}

	// 3. Kullanıcı oluştur — hata durumunda grubu geri al
	if err := createSystemUser(username, uid, groupname); err != nil {
		deleteSystemGroup(groupname)
		return 0, 0, err
	}

	// 4. mail ve dovecot gruplarına ekle — hata durumunda user+group geri al
	if err := addUserToGroup(username, mailGroup); err != nil {
		deleteSystemUser(username)
		deleteSystemGroup(groupname)
		return 0, 0, err
	}
	if err := addUserToGroup(username, dovecotGroup); err != nil {
		removeUserFromGroup(username, mailGroup)
		deleteSystemUser(username)
		deleteSystemGroup(groupname)
		return 0, 0, err
	}

	// 5. Domain mail dizinini oluştur
	mailDir, err := buildDomainMailDir(domainName)
	if err != nil {
		// Sistem kullanıcısı oluşturuldu, geri al
		removeUserFromGroup(username, dovecotGroup)
		removeUserFromGroup(username, mailGroup)
		deleteSystemUser(username)
		deleteSystemGroup(groupname)
		return 0, 0, fmt.Errorf("mail dizini belirlenemedi: %w", err)
	}
	if err := ensureDirectory(mailDir, uid, gid); err != nil {
		removeUserFromGroup(username, dovecotGroup)
		removeUserFromGroup(username, mailGroup)
		deleteSystemUser(username)
		deleteSystemGroup(groupname)
		return 0, 0, fmt.Errorf("mail dizini oluşturulamadı (%s): %w", mailDir, err)
	}
	fmt.Printf("Mail dizini oluşturuldu: %s\n", mailDir)

	fmt.Printf("Domain sistem kullanıcısı oluşturuldu: %s (uid=%d), grup: %s (gid=%d)\n",
		username, uid, groupname, gid)
	return uid, gid, nil
}

// -----------------------------------------------------------------
// Mailbox sistem kurulumu
// -----------------------------------------------------------------

// SetupMailboxSysUser - vmailbox eklenirken FreeBSD sistem kullanıcısı ve
// mail dizinini oluşturur. Başarı durumunda kullanılan gerçek uid/gid döner.
//
// mailHomeDir: --mail-home değeri (boşsa doveconf'dan alınır)
// localpart:   e-posta adresinin kullanıcı kısmı (örn. "ulas")
// domainName:  e-posta domain'i (örn. "siteadresi.com.tr")
//
// Akış:
//  1. uid/gid çakışma kontrolü ve gerekirse otomatik seçim
//  2. eug_{gid} grubu oluştur
//  3. eu_{uid} kullanıcısı oluştur
//  4. mail ve dovecot gruplarına ekle
//  5. mail dizini belirle (--mail-home veya doveconf) ve oluştur
//  6. Hata durumunda rollback
func SetupMailboxSysUser(localpart, domainName, mailHomeDir string, requestedUID, requestedGID int64) (int64, int64, string, error) {
	// 0. --mail-home verilmemişse doveconf gerekli, önce kontrol et
	if mailHomeDir == "" {
		if err := checkDoveconfInstalled(); err != nil {
			return 0, 0, "", err
		}
	}

	// 0b. Parametre güvenlik validasyonu
	if err := validateLocalPart(localpart); err != nil {
		return 0, 0, "", err
	}
	if err := validateDomainName(domainName); err != nil {
		return 0, 0, "", err
	}
	if err := validateMailHomePath(mailHomeDir); err != nil {
		return 0, 0, "", err
	}

	// 1. uid/gid çözümle
	uid, err := resolveUID(requestedUID)
	if err != nil {
		return 0, 0, "", err
	}
	gid, err := resolveGID(requestedGID)
	if err != nil {
		return 0, 0, "", err
	}

	groupname := fmt.Sprintf("%s%d", mailboxGroupPrefix, gid)
	username := fmt.Sprintf("%s%d", mailboxUserPrefix, uid)

	// 2. Grup oluştur
	if err := createSystemGroup(groupname, gid); err != nil {
		return 0, 0, "", err
	}

	// 3. Kullanıcı oluştur
	if err := createSystemUser(username, uid, groupname); err != nil {
		deleteSystemGroup(groupname)
		return 0, 0, "", err
	}

	// 4. mail ve dovecot gruplarına ekle
	if err := addUserToGroup(username, mailGroup); err != nil {
		deleteSystemUser(username)
		deleteSystemGroup(groupname)
		return 0, 0, "", err
	}
	if err := addUserToGroup(username, dovecotGroup); err != nil {
		removeUserFromGroup(username, mailGroup)
		deleteSystemUser(username)
		deleteSystemGroup(groupname)
		return 0, 0, "", err
	}

	// 5. Mail dizini belirle
	var finalMailDir string
	if mailHomeDir != "" {
		// --mail-home verilmiş, direkt kullan
		finalMailDir = mailHomeDir
	} else {
		// doveconf'dan üret
		finalMailDir, err = buildMailDir(domainName, localpart)
		if err != nil {
			removeUserFromGroup(username, dovecotGroup)
			removeUserFromGroup(username, mailGroup)
			deleteSystemUser(username)
			deleteSystemGroup(groupname)
			return 0, 0, "", fmt.Errorf("mail dizini belirlenemedi: %w", err)
		}
	}

	// Dizini oluştur
	if finalMailDir != "" {
		if err := ensureDirectory(finalMailDir, uid, gid); err != nil {
			removeUserFromGroup(username, dovecotGroup)
			removeUserFromGroup(username, mailGroup)
			deleteSystemUser(username)
			deleteSystemGroup(groupname)
			return 0, 0, "", fmt.Errorf("mail dizini oluşturulamadı (%s): %w", finalMailDir, err)
		}
		fmt.Printf("Mail dizini oluşturuldu: %s\n", finalMailDir)
	}

	fmt.Printf("Mailbox sistem kullanıcısı oluşturuldu: %s (uid=%d), grup: %s (gid=%d)\n",
		username, uid, groupname, gid)
	return uid, gid, finalMailDir, nil
}
