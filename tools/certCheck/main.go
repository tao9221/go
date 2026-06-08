package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// 配置结构（JSON 格式）

type Config struct {
	Domains []string    `json:"domains"`
	Alert   AlertConfig `json:"alert"`
	Email   EmailConfig `json:"email"`
}

type AlertConfig struct {
	DaysBeforeExpiry int `json:"days_before_expiry"`
}

type EmailConfig struct {
	SMTPHost string   `json:"smtp_host"`
	SMTPPort int      `json:"smtp_port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	UseSSL   bool     `json:"use_ssl"`
}

// 证书检测结果

type CertResult struct {
	Domain    string
	ExpiresAt time.Time
	DaysLeft  int
	Error     error
}

func main() {
	configFile := flag.String("config", "config.json", "配置文件路径 (JSON格式)")
	flag.Parse()

	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	if cfg.Alert.DaysBeforeExpiry <= 0 {
		cfg.Alert.DaysBeforeExpiry = 15
	}

	log.Printf("开始检测 %d 个域名，提前 %d 天告警\n",
		len(cfg.Domains), cfg.Alert.DaysBeforeExpiry)

	var results []CertResult
	for _, domain := range cfg.Domains {
		r := checkCert(domain)
		results = append(results, r)
		if r.Error != nil {
			log.Printf("[ERROR] %-30s => %v", domain, r.Error)
		} else {
			log.Printf("[OK]    %-30s => 到期: %s (剩余 %d 天)",
				domain, r.ExpiresAt.Format("2006-01-02"), r.DaysLeft)
		}
	}

	var needAlert []CertResult
	for _, r := range results {
		if r.Error != nil || r.DaysLeft <= cfg.Alert.DaysBeforeExpiry {
			needAlert = append(needAlert, r)
		}
	}

	if len(needAlert) == 0 {
		log.Println("所有域名证书均正常，无需发送告警。")
		return
	}

	log.Printf("发现 %d 个域名需要告警，准备发送邮件...", len(needAlert))

	body := buildEmailBody(needAlert, cfg.Alert.DaysBeforeExpiry)
	subject := fmt.Sprintf("【证书告警】%d 个域名证书即将到期或检测异常", len(needAlert))

	if err := sendEmail(cfg.Email, subject, body); err != nil {
		log.Fatalf("邮件发送失败: %v", err)
	}
	log.Println("告警邮件发送成功！")
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func checkCert(domain string) CertResult {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimRight(domain, "/")

	host := domain
	port := "443"
	if h, p, err := net.SplitHostPort(domain); err == nil {
		host = h
		port = p
	}

	address := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		return CertResult{Domain: domain, Error: fmt.Errorf("TLS 连接失败: %w", err)}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertResult{Domain: domain, Error: fmt.Errorf("未获取到证书")}
	}

	leaf := certs[0]
	expiry := leaf.NotAfter
	daysLeft := int(time.Until(expiry).Hours() / 24)

	return CertResult{
		Domain:    domain,
		ExpiresAt: expiry,
		DaysLeft:  daysLeft,
	}
}

func buildEmailBody(results []CertResult, threshold int) string {
	var sb strings.Builder
	sb.WriteString(`<html><body style="font-family:Arial,sans-serif;font-size:14px;color:#333;padding:20px">`)
	sb.WriteString(`<h2 style="color:#d9534f;margin-bottom:8px">SSL 证书告警通知</h2>`)
	sb.WriteString(fmt.Sprintf(
		`<p>以下域名证书距到期不足 <b>%d 天</b>或检测异常，请及时续签处理：</p>`,
		threshold,
	))

	sb.WriteString(`<table border="1" cellpadding="10" cellspacing="0"
		style="border-collapse:collapse;width:100%;max-width:700px;margin-top:10px">`)
	sb.WriteString(`<tr style="background:#f0f0f0;font-weight:bold">
		<td>域名</td><td>到期时间</td><td>剩余天数</td><td>状态</td>
	</tr>`)

	for _, r := range results {
		var expStr, daysStr, status, bg string
		if r.Error != nil {
			expStr = "—"
			daysStr = "—"
			status = r.Error.Error()
			bg = "#fff0f0"
		} else {
			expStr = r.ExpiresAt.Format("2006-01-02 15:04:05")
			daysStr = fmt.Sprintf("%d 天", r.DaysLeft)
			switch {
			case r.DaysLeft <= 7:
				status, bg = "紧急（7天内）", "#fff0f0"
			case r.DaysLeft <= threshold:
				status, bg = "即将到期", "#fffbe6"
			default:
				status, bg = "正常", "#f0fff4"
			}
		}
		sb.WriteString(fmt.Sprintf(
			`<tr style="background:%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			bg, r.Domain, expStr, daysStr, status,
		))
	}

	sb.WriteString(`</table>`)
	sb.WriteString(fmt.Sprintf(
		`<p style="color:#999;font-size:12px;margin-top:20px">检测时间：%s</p>`,
		time.Now().Format("2006-01-02 15:04:05"),
	))
	sb.WriteString(`</body></html>`)
	return sb.String()
}

func sendEmail(cfg EmailConfig, subject, htmlBody string) error {
	to := strings.Join(cfg.To, ", ")
	header := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n\r\n",
		cfg.From, to, subject,
	)
	msg := []byte(header + htmlBody)
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)

	if cfg.UseSSL {
		tlsCfg := &tls.Config{ServerName: cfg.SMTPHost}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("SSL 连接 %s 失败: %w", addr, err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, cfg.SMTPHost)
		if err != nil {
			return fmt.Errorf("SMTP 客户端创建失败: %w", err)
		}
		defer client.Quit()

		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP 认证失败（请检查授权码）: %w", err)
		}
		if err = client.Mail(cfg.Username); err != nil {
			return fmt.Errorf("设置发件人失败: %w", err)
		}
		for _, r := range cfg.To {
			if err = client.Rcpt(strings.TrimSpace(r)); err != nil {
				return fmt.Errorf("设置收件人 %s 失败: %w", r, err)
			}
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		if _, err = w.Write(msg); err != nil {
			return err
		}
		return w.Close()
	}

	return smtp.SendMail(addr, auth, cfg.Username, cfg.To, msg)
}