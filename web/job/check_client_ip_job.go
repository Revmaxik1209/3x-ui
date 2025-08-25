package job

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"time"

	"x-ui/database"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/xray"
)

type CheckClientIpJob struct {
	lastClear int64
}

var job *CheckClientIpJob

func NewCheckClientIpJob() *CheckClientIpJob {
	job = new(CheckClientIpJob)
	return job
}

func (j *CheckClientIpJob) Run() {
	if j.lastClear == 0 {
		j.lastClear = time.Now().Unix()
	}

	shouldClearAccessLog := false
	iplimitActive := j.hasLimitIp()
	f2bInstalled := j.checkFail2BanInstalled()
	isAccessLogAvailable := j.checkAccessLogAvailable(iplimitActive)

	if iplimitActive {
		if f2bInstalled && isAccessLogAvailable {
			shouldClearAccessLog = j.processLogFile()
		} else {
			if !f2bInstalled {
				logger.Warning("[LimitIP] Fail2Ban is not installed, Please install Fail2Ban from the x-ui bash menu.")
			}
		}
	}

	if shouldClearAccessLog || (isAccessLogAvailable && time.Now().Unix()-j.lastClear > 3600) {
		j.clearAccessLog()
	}
}

func (j *CheckClientIpJob) clearAccessLog() {
	logAccessP, err := os.OpenFile(xray.GetAccessPersistentLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		logger.Warning("client ip job: failed to open persistent access log:", err)
		return
	}
	defer logAccessP.Close()

	accessLogPath, err := xray.GetAccessLogPath()
	if err != nil {
		logger.Warning("client ip job: failed to get access log path:", err)
		return
	}

	file, err := os.Open(accessLogPath)
	if err != nil {
		logger.Warning("client ip job: failed to open access log:", err)
		return
	}
	defer file.Close()

	_, err = io.Copy(logAccessP, file)
	j.checkError(err)

	err = os.Truncate(accessLogPath, 0)
	j.checkError(err)
	j.lastClear = time.Now().Unix()
}

func (j *CheckClientIpJob) hasLimitIp() bool {
	db := database.GetDB()
	var inbounds []*model.Inbound

	err := db.Model(model.Inbound{}).Find(&inbounds).Error
	if err != nil {
		return false
	}

	for _, inbound := range inbounds {
		if inbound.Settings == "" {
			continue
		}

		settings := map[string][]model.Client{}
		json.Unmarshal([]byte(inbound.Settings), &settings)
		clients := settings["clients"]

		for _, client := range clients {
			limitIp := client.LimitIP
			if limitIp > 0 {
				return true
			}
		}
	}

	return false
}

func (j *CheckClientIpJob) processLogFile() bool {

	ipRegex := regexp.MustCompile(`from (?:tcp:|udp:)?\[?([0-9a-fA-F\.:]+)\]?:\d+ accepted`)
	emailRegex := regexp.MustCompile(`email: (.+)$`)

	accessLogPath, _ := xray.GetAccessLogPath()
	file, _ := os.Open(accessLogPath)
	defer file.Close()

	// Use a map to a slice to preserve the order of first appearance of IPs
	inboundClientIps := make(map[string][]string)
	ipIsSeenForEmail := make(map[string]map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Extract IP
		ipMatches := ipRegex.FindStringSubmatch(line)
		if len(ipMatches) < 2 {
			continue
		}

		ip := ipMatches[1]

		if ip == "127.0.0.1" || ip == "::1" {
			continue
		}

		// Extract Email
		emailMatches := emailRegex.FindStringSubmatch(line)
		if len(emailMatches) < 2 {
			continue
		}
		email := emailMatches[1]

		// Store IPs in chronological order of first appearance
		if _, ok := ipIsSeenForEmail[email]; !ok {
			ipIsSeenForEmail[email] = make(map[string]bool)
		}
		if !ipIsSeenForEmail[email][ip] {
			inboundClientIps[email] = append(inboundClientIps[email], ip)
			ipIsSeenForEmail[email][ip] = true
		}
	}

	shouldCleanLog := false
	for email, chronologicallyAppearedIps := range inboundClientIps {
		clientIpsRecord, err := j.getInboundClientIps(email)
		if err != nil {
			shouldCleanLog = j.addInboundClientIps(email, chronologicallyAppearedIps) || shouldCleanLog
			continue
		}

		shouldCleanLog = j.updateInboundClientIps(clientIpsRecord, email, chronologicallyAppearedIps) || shouldCleanLog
	}

	return shouldCleanLog
}

func (j *CheckClientIpJob) checkFail2BanInstalled() bool {
	cmd := "fail2ban-client"
	args := []string{"-h"}
	err := exec.Command(cmd, args...).Run()
	return err == nil
}

func (j *CheckClientIpJob) checkAccessLogAvailable(iplimitActive bool) bool {
	accessLogPath, err := xray.GetAccessLogPath()
	if err != nil {
		return false
	}

	if accessLogPath == "none" || accessLogPath == "" {
		if iplimitActive {
			logger.Warning("[LimitIP] Access log path is not set, Please configure the access log path in Xray configs.")
		}
		return false
	}

	return true
}

func (j *CheckClientIpJob) checkError(e error) {
	if e != nil {
		logger.Warning("client ip job err:", e)
	}
}

func (j *CheckClientIpJob) getInboundClientIps(clientEmail string) (*model.InboundClientIps, error) {
	db := database.GetDB()
	InboundClientIps := &model.InboundClientIps{}
	err := db.Model(model.InboundClientIps{}).Where("client_email = ?", clientEmail).First(InboundClientIps).Error
	if err != nil {
		return nil, err
	}
	return InboundClientIps, nil
}

// addInboundClientIps is called when a client is seen for the first time.
// It establishes the initial set of allowed IPs based on the chronological order from the log.
func (j *CheckClientIpJob) addInboundClientIps(clientEmail string, chronologicallyAppearedIps []string) bool {
	inbound, err := j.getInboundByEmail(clientEmail)
	if err != nil {
		logger.Errorf("failed to fetch inbound settings for email %s: %s", clientEmail, err)
		return false
	}

	if inbound.Settings == "" {
		logger.Debug("inbound settings are empty for email:", clientEmail)
		return false
	}

	settings := map[string][]model.Client{}
	json.Unmarshal([]byte(inbound.Settings), &settings)
	clients := settings["clients"]
	var limitIp int
	var clientFound bool
	for _, client := range clients {
		if client.Email == clientEmail {
			limitIp = client.LimitIP
			clientFound = true
			break
		}
	}

	if !clientFound || limitIp <= 0 || !inbound.Enable {
		return false // No limit for this user, or user not found
	}

	// The first `limitIp` IPs from the log become the initial allowed set.
	// The rest are banned.
	ipsToAllow := chronologicallyAppearedIps
	var ipsToBan []string

	if len(chronologicallyAppearedIps) > limitIp {
		ipsToAllow = chronologicallyAppearedIps[:limitIp]
		ipsToBan = chronologicallyAppearedIps[limitIp:]
	}

	// Log IPs to ban
	if len(ipsToBan) > 0 {
		logIpFile, err := os.OpenFile(xray.GetIPLimitLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logger.Errorf("failed to open IP limit log file: %s", err)
			return true // We tried to ban, so log should be cleaned
		}
		defer logIpFile.Close()
		ipLogger := log.New(logIpFile, "", log.LstdFlags)
		for _, ipToBan := range ipsToBan {
			ipLogger.Printf("[LIMIT_IP] Email = %s || SRC = %s", clientEmail, ipToBan)
		}
	}

	// Save the allowed IPs to a new DB record
	newRecord := &model.InboundClientIps{}
	jsonIps, err := json.Marshal(ipsToAllow)
	if err != nil {
		logger.Error("failed to marshal IPs to JSON:", err)
		return true
	}

	newRecord.ClientEmail = clientEmail
	newRecord.Ips = string(jsonIps)

	db := database.GetDB()
	if err := db.Save(newRecord).Error; err != nil {
		logger.Error("failed to create inboundClientIps record:", err)
	}

	return true
}

func isRelated(newIpStr string, existingIps []string) bool {
	newIp := net.ParseIP(newIpStr)
	if newIp == nil {
		return false
	}

	var mask net.IPMask
	if newIp.To4() != nil {
		// IPv4, use /16 subnet
		mask = net.CIDRMask(16, 32)
	} else {
		// IPv6, use /64 subnet
		mask = net.CIDRMask(64, 128)
	}

	for _, existingIpStr := range existingIps {
		existingIp := net.ParseIP(existingIpStr)
		if existingIp == nil {
			continue
		}
		if newIp.Mask(mask).Equal(existingIp.Mask(mask)) {
			return true
		}
	}
	return false
}

// updateInboundClientIps is called when a client already has a record of allowed IPs.
// It checks new IPs against the existing set.
func (j *CheckClientIpJob) updateInboundClientIps(inboundClientIps *model.InboundClientIps, clientEmail string, currentIpsFromLog []string) bool {
	inbound, err := j.getInboundByEmail(clientEmail)
	if err != nil {
		logger.Errorf("failed to fetch inbound settings for email %s: %s", clientEmail, err)
		return false
	}

	if inbound.Settings == "" {
		logger.Debug("inbound settings are empty for email:", clientEmail)
		return false
	}

	settings := map[string][]model.Client{}
	json.Unmarshal([]byte(inbound.Settings), &settings)
	clients := settings["clients"]
	var limitIp int
	var clientFound bool
	for _, client := range clients {
		if client.Email == clientEmail {
			limitIp = client.LimitIP
			clientFound = true
			break
		}
	}

	if !clientFound || limitIp <= 0 || !inbound.Enable {
		return false // No limit for this user
	}

	// Load stored IPs
	var storedIps []string
	if inboundClientIps.Ips != "" {
		if err := json.Unmarshal([]byte(inboundClientIps.Ips), &storedIps); err != nil {
			logger.Warningf("failed to unmarshal stored IPs for %s, starting fresh: %v", clientEmail, err)
			storedIps = []string{}
		}
	}

	allowedIpsMap := make(map[string]struct{})
	for _, ip := range storedIps {
		allowedIpsMap[ip] = struct{}{}
	}

	var ipsToBan []string
	var newIpAdded bool

	// Collect unique new IPs from the log
	uniqueNewIps := make(map[string]bool)
	for _, currentIp := range currentIpsFromLog {
		if _, isAllowed := allowedIpsMap[currentIp]; isAllowed {
			continue
		}
		uniqueNewIps[currentIp] = true
	}

	for newIp := range uniqueNewIps {
		if len(storedIps) < limitIp {
			storedIps = append(storedIps, newIp)
			newIpAdded = true
		} else {
			if isRelated(newIp, storedIps) {
				// FIFO rotation: remove the oldest, add the newest
				if len(storedIps) > 0 {
					storedIps = storedIps[1:]
					storedIps = append(storedIps, newIp)
					newIpAdded = true
				}
			} else {
				ipsToBan = append(ipsToBan, newIp)
			}
		}
	}

	// Log IPs to ban
	if len(ipsToBan) > 0 {
		logIpFile, err := os.OpenFile(xray.GetIPLimitLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logger.Errorf("failed to open IP limit log file: %s", err)
			return true
		}
		defer logIpFile.Close()
		ipLogger := log.New(logIpFile, "", log.LstdFlags)
		for _, ipToBan := range ipsToBan {
			ipLogger.Printf("[LIMIT_IP] Email = %s || SRC = %s", clientEmail, ipToBan)
		}
	}

	// If we added/rotated IPs in the allowed list, update the database
	if newIpAdded {
		jsonIps, err := json.Marshal(storedIps) // IPs are now in FIFO order
		if err != nil {
			logger.Error("failed to marshal new allowed IPs to JSON:", err)
			return true
		}
		inboundClientIps.Ips = string(jsonIps)
		db := database.GetDB()
		if err := db.Save(inboundClientIps).Error; err != nil {
			logger.Error("failed to save updated inboundClientIps:", err)
		}
	}

	return len(ipsToBan) > 0 || newIpAdded
}

func (j *CheckClientIpJob) getInboundByEmail(clientEmail string) (*model.Inbound, error) {
	db := database.GetDB()
	inbound := &model.Inbound{}

	err := db.Model(&model.Inbound{}).Where("settings LIKE ?", "%"+clientEmail+"%").First(inbound).Error
	if err != nil {
		return nil, err
	}

	return inbound, nil
}


