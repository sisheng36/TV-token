package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ============ data types ============

type QRCodeResp struct {
	Data struct {
		QRCodeURL string `json:"qrCodeUrl"`
		SID       string `json:"sid"`
	} `json:"data"`
}

type StatusResp struct {
	Status   string `json:"status"`
	AuthCode string `json:"authCode"`
}

type TokenEncryptedResp struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
	} `json:"data"`
}

type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type CheckResult struct {
	Status       string `json:"status"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	Error        string `json:"error,omitempty"`
}

// ============ crypto helpers ============

func getParams(t int64) map[string]string {
	return map[string]string{
		"akv":     "2.8.1496",
		"apv":     "1.3.6",
		"b":       "XiaoMi",
		"d":       "e87a4d5f4f28d7a17d73c524eaa8ac37",
		"m":       "23046RP50C",
		"mac":     "",
		"n":       "23046RP50C",
		"t":       strconv.FormatInt(t, 10),
		"wifiMac": "020000000000",
	}
}

func h(chars []rune, modifier int64) string {
	modifierStr := strconv.FormatInt(modifier, 10)
	numericModifier := 0
	if len(modifierStr) > 7 {
		numericModifier, _ = strconv.Atoi(modifierStr[7:])
	}

	var sb strings.Builder
	for _, c := range chars {
		charCode := int(c)
		newCharCode := int(math.Abs(float64(charCode-(numericModifier%127)-1)))
		if newCharCode < 33 {
			newCharCode += 33
		}
		sb.WriteRune(rune(newCharCode))
	}
	return sb.String()
}

func generateKey(t int64) string {
	params := getParams(t)
	keys := make([]string, 0, len(params))
	for k := range params {
		if k != "t" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(params[k])
	}
	concatenated := sb.String()

	chars := []rune(concatenated)
	seen := make(map[rune]bool)
	unique := make([]rune, 0, len(chars))
	for _, c := range chars {
		if !seen[c] {
			seen[c] = true
			unique = append(unique, c)
		}
	}

	transformed := h(unique, t)
	hash := md5.Sum([]byte(transformed))
	return hex.EncodeToString(hash[:])
}

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			uconn := utls.UClient(conn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
			if err := uconn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("utls handshake: %w", err)
			}
			return uconn, nil
		},
	},
}

func doPost(url string, bodyJSON []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	return httpClient.Do(req)
}

func doGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	return httpClient.Do(req)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	padLen := int(data[len(data)-1])
	if padLen > len(data) || padLen > aes.BlockSize || padLen == 0 {
		return nil, fmt.Errorf("invalid padding length")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

func decrypt(ciphertextB64 string, ivHex string, t int64) (string, error) {
	keyHex := generateKey(t)
	key := []byte(keyHex) // 32-byte UTF-8 hex string -> AES-256

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", fmt.Errorf("decode iv: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plain := make([]byte, len(ciphertext))
	mode.CryptBlocks(plain, ciphertext)

	plain, err = pkcs7Unpad(plain)
	if err != nil {
		return "", fmt.Errorf("unpad: %w", err)
	}

	return string(plain), nil
}

// ============ handlers ============

func handleGenerateQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body := map[string]interface{}{
		"scopes": "user:base,file:all:read,file:all:write",
		"width":  500,
		"height": 500,
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := doPost(
		"https://api.extscreen.com/aliyundrive/qrcode",
		bodyJSON,
	)
	if err != nil {
		log.Printf("QR API request failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "生成二维码失败"})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("QR API returned %d", resp.StatusCode)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "上游服务异常"})
		return
	}

	var result QRCodeResp
	if err := json.Unmarshal(respBody, &result); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "解析响应失败"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"sid":     result.Data.SID,
		"qr_link": result.Data.QRCodeURL,
	})
}

// exchangeToken sends params to the token API, decrypts, returns TokenInfo.
func exchangeToken(params map[string]string) (*TokenInfo, error) {
	params["Content-Type"] = "application/json"
	bodyJSON, _ := json.Marshal(params)

	req, _ := http.NewRequest("POST", "https://api.extscreen.com/aliyundrive/v3/token", bytes.NewReader(bodyJSON))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	for k, v := range params {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	tokenResp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer tokenResp.Body.Close()

	tokenBody, _ := io.ReadAll(tokenResp.Body)
	var tokenEnc TokenEncryptedResp
	if err := json.Unmarshal(tokenBody, &tokenEnc); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	ts, _ := strconv.ParseInt(params["t"], 10, 64)
	plainData, err := decrypt(tokenEnc.Data.Ciphertext, tokenEnc.Data.IV, ts)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	var tokenInfo TokenInfo
	if err := json.Unmarshal([]byte(plainData), &tokenInfo); err != nil {
		return nil, fmt.Errorf("parse token json: %w", err)
	}
	return &tokenInfo, nil
}

func handleCheckStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sid := strings.TrimRight(strings.TrimPrefix(r.URL.Path, "/api/check/"), "/")
	if sid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing sid"})
		return
	}

	resp, err := doGet("https://openapi.alipan.com/oauth/qrcode/" + sid + "/status")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "查询状态失败"})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var statusData StatusResp
	if err := json.Unmarshal(respBody, &statusData); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "解析状态失败"})
		return
	}

	if statusData.Status == "LoginSuccess" && statusData.AuthCode != "" {
		t := time.Now().Unix()
		params := getParams(t)
		params["code"] = statusData.AuthCode

		tokenInfo, err := exchangeToken(params)
		if err != nil {
			log.Printf("token exchange error: %v", err)
			writeJSON(w, http.StatusOK, CheckResult{Status: "LoginFailed"})
			return
		}

		writeJSON(w, http.StatusOK, CheckResult{
			Status:       "LoginSuccess",
			RefreshToken: tokenInfo.RefreshToken,
			AccessToken:  tokenInfo.AccessToken,
		})
		return
	}

	writeJSON(w, http.StatusOK, CheckResult{Status: statusData.Status})
}

func handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RefreshToken == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"code": 400, "message": "refresh_token is required", "data": nil,
			})
			return
		}

		t := time.Now().Unix()
		params := getParams(t)
		params["refresh_token"] = body.RefreshToken

		tokenInfo, err := exchangeToken(params)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"code": 500, "message": err.Error(), "data": nil,
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"token_type":    "Bearer",
			"access_token":  tokenInfo.AccessToken,
			"refresh_token": tokenInfo.RefreshToken,
			"expires_in":    tokenInfo.ExpiresIn,
		})

	case http.MethodGet:
		refreshUI := r.URL.Query().Get("refresh_ui")
		if refreshUI == "" {
			writeJSON(w, http.StatusOK, map[string]string{
				"refresh_token": "",
				"access_token":  "",
				"text":          "refresh_ui parameter is required",
			})
			return
		}

		t := time.Now().Unix()
		params := getParams(t)
		params["refresh_token"] = refreshUI

		tokenInfo, err := exchangeToken(params)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]string{
				"refresh_token": "",
				"access_token":  "",
				"text":          err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"refresh_token": tokenInfo.RefreshToken,
			"access_token":  tokenInfo.AccessToken,
			"text":          "",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ============ main ============

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/generate", handleGenerateQR)
	mux.HandleFunc("/api/check/", handleCheckStatus)
	mux.HandleFunc("/api/oauth/alipan/token", handleTokenRefresh)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Printf("阿里云盘TV Token 服务启动: http://0.0.0.0:%s\n", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

// ============ embedded HTML ============

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>阿里云盘TV Token</title>
<link rel="icon" type="image/x-icon" href="data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAABMLAAATCwAAAAAAAAAAAAD+bmoB/nFpS/5yaMb+dGjz/ndo/f55aP/+fWn//oBq//6Da//+hm3//Yhv//2Kcv39jHXz/Y14xv2Ne0v9kIMB/3FpTP5yaOL+c2j//nZo//54aP/+emf//nxn//6Aaf/+hGz//oZt//2Gbf/9iXH//Yt1//2MeP/9jXzi/Y1+TP9xaMX+c2j//nVo//53aP/+eGb//oNx//6omf//yL7//9XM///Pxf/+t6j//paC//6JdP/9i3j//Yx8//2Mf8X/c2jy/nRo//52aP/+d2b//pSF///b1v///Pz///////////////////7+///q5//+r6L//op4//6Ke//9i3/y/3Ro/f92aP/+dmb//o+A///n4/////////Du///Mwv//uqz//8a7///p5f////////b0//6uo//+iHr//ol//P92aP//d2j//3tr///Nxv///////+Tg//6Zh//+gWn//oFo//6DbP/+k4D//9XO////////6eb//pWK//6Hfv//d2j//3dm//+Qgf//8/H///n4//6ikv/+fWb//oFq//6DbP/+hW7//oNu//6UhP//6+n///Du//6jnP/+hX7//3lo//94Zf//ppn////////k3//+hnH//oBp//6Cav/+g2z//oRu//6Oe///wbj//+Dc//6dk//+iID//oeB//96aP//eWX//6yg////////3df//4Nt//6Aaf/+gmv//oNt//6Dbv/+m4v///f2///s6//+kIb//oV+//6Hgv//e2j//3pm//+hkv///Pz//+7q//+Pe//+gGj//oJr//6Ebf/+gm3//qyg///+/v//5OL//oyE//6GgP/+h4P//3xo//98Z///i3f//+jk////////yL7//4hy//+Bav/+gm3//paG///i3v///////8bB//6Gfv/+hoL//oeF//99aP3/fmj//35n//+zpf//+/r///38///e2P//wbX//8e9///r5////////+ro//+Yj//+hn///oeD//6Hh/z/fmjy/39o//9/aP//g2z//7qt///08v///////////////////v7//+Xi//+imf//hn3//4eB//+Hhf//iIjy/39nxf9/aP//gGj//4Bo//+Bav//mof//76z///Ryf//zcX//7Sq//+RhP//hXr//4d///+Hgv//iIb//4mJxf9/Z0z/f2ji/4Bo//+Aaf//gGn//39p//+Aav//g27//4Nw//+Dcv//hXf//4d8//+Hf///iIP//4mH4v+JiUz/fmcB/4BoS/+AaMb/gGnz/4Fq/f+Bav//gWz//4Ju//+Ecf//hXX//4Z4//+HfP3/iIDz/4mDxv+Jhkv/io8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    min-height: 100vh;
    display: flex;
    justify-content: center;
    padding: 2rem 1rem;
  }
  .container { max-width: 900px; width: 100%; }
  .header {
    display: flex; align-items: center; gap: 1rem;
    padding-bottom: 1.5rem; border-bottom: 1px solid #1e293b; margin-bottom: 2rem;
  }
  .icon {
    width: 48px; height: 48px; border-radius: 12px;
    background: linear-gradient(135deg, #14b8a6, #0d9488);
    display: flex; align-items: center; justify-content: center; font-size: 1.5rem;
  }
  .header h1 { font-size: 1.5rem; font-weight: 700; }
  .header p { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .grid { display: grid; gap: 1.5rem; }
  @media (min-width: 768px) { .grid { grid-template-columns: 1fr 1fr; } }
  .card {
    background: #1e293b; border: 1px solid #334155;
    border-radius: 12px; padding: 1.5rem;
  }
  .card-title { font-size: 0.9rem; font-weight: 600; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
  .token-box {
    width: 100%; min-height: 80px; padding: 0.75rem;
    background: #0f172a; border: 1px solid #334155; border-radius: 8px;
    font-family: "SF Mono", "Fira Code", monospace; font-size: 0.75rem;
    color: #94a3b8; word-break: break-all; resize: none;
    margin-bottom: 0.75rem; line-height: 1.5;
  }
  .btn {
    display: inline-flex; align-items: center; gap: 0.5rem;
    padding: 0.5rem 1rem; border-radius: 8px; border: none;
    font-size: 0.875rem; font-weight: 500; cursor: pointer;
    transition: all 0.2s;
  }
  .btn-primary {
    background: linear-gradient(135deg, #14b8a6, #0d9488);
    color: #fff; width: 100%; justify-content: center;
    padding: 0.875rem 1rem; font-size: 1rem;
  }
  .btn-primary:hover { opacity: 0.9; }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-ghost { background: transparent; color: #94a3b8; }
  .btn-ghost:hover { background: #334155; }
  .btn-copy { background: transparent; color: #14b8a6; font-size: 0.8rem; padding: 0.25rem 0.5rem; }
  .btn-copy:hover { background: #0f2a2a; }
  .flex-row { display: flex; align-items: center; justify-content: space-between; }
  .loading { display: flex; flex-direction: column; align-items: center; gap: 1rem; padding: 2rem 0; color: #64748b; }
  .spinner { width: 2rem; height: 2rem; border: 3px solid #334155; border-top-color: #14b8a6; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .success { display: flex; flex-direction: column; align-items: center; gap: 0.75rem; padding: 2rem 0; color: #34d399; }
  .success-icon { width: 64px; height: 64px; border-radius: 50%; background: #022c22; display: flex; align-items: center; justify-content: center; font-size: 2rem; }
  .api-route { padding: 0.75rem; background: #0f172a; border-radius: 8px; font-family: monospace; font-size: 0.75rem; color: #94a3b8; word-break: break-all; }
  .info-card { margin-top: 1.5rem; }
  .info-grid { display: grid; gap: 1rem; }
  @media (min-width: 768px) { .info-grid { grid-template-columns: 1fr 1fr; } }
  .info-list { list-style: disc; padding-left: 1.25rem; font-size: 0.85rem; color: #94a3b8; line-height: 1.8; }
  .alert {
    background: #422006; border: 1px solid #78350f; border-radius: 8px;
    padding: 1rem; margin-top: 1rem; display: flex; align-items: flex-start; gap: 0.75rem;
    font-size: 0.85rem; color: #fbbf24;
  }
  .modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.6);
    display: flex; align-items: center; justify-content: center; z-index: 100;
  }
  .modal {
    background: #1e293b; border: 1px solid #334155; border-radius: 12px;
    padding: 1.5rem; max-width: 420px; width: 90%;
  }
  .modal h3 { margin-bottom: 0.75rem; }
  .modal p { color: #94a3b8; font-size: 0.875rem; line-height: 1.6; margin-bottom: 1.5rem; }
  .modal strong { color: #e2e8f0; }
  .modal-footer { display: flex; gap: 0.75rem; justify-content: flex-end; flex-wrap: wrap; }
  .btn-outline { background: transparent; border: 1px solid #ef4444; color: #ef4444; }
  .btn-outline:hover { background: #450a0a; }
  .btn-normal { background: #334155; color: #e2e8f0; }
  .btn-normal:hover { background: #475569; }
  .hidden { display: none !important; }
  .qr-box { text-align: center; margin: 1rem 0; }
  .qr-box img { border-radius: 8px; border: 2px solid #334155; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="icon"><svg viewBox="0 0 24 24" width="24" height="24" fill="none"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4S5.33 6.59 4.65 10.04C2.35 10.28.5 12.28.5 14.5c0 2.48 2.02 4.5 4.5 4.5h13c2.48 0 4.5-2.02 4.5-4.5 0-2.22-1.85-4.22-4.15-4.46z" fill="url(#cloud-grad)"/><defs><linearGradient id="cloud-grad" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#FF6A00"/><stop offset="100%" stop-color="#FF9500"/></linearGradient></defs></svg></div>
    <div>
      <h1>阿里云盘TV Token</h1>
      <p>获取阿里云盘TV端的授权令牌，解锁高速下载</p>
    </div>
  </div>

  <div class="grid">
    <!-- Left: Tokens -->
    <div>
      <div class="card">
        <div class="flex-row" style="margin-bottom:0.5rem">
          <span class="card-title" style="margin-bottom:0">访问令牌</span>
          <button class="btn btn-copy" id="copyAccessBtn" disabled onclick="copyToken('access')">复制</button>
        </div>
        <textarea class="token-box" id="accessToken" readonly placeholder="授权成功后，访问令牌将显示在这里..."></textarea>
      </div>
      <div class="card" style="margin-top:1.5rem">
        <div class="flex-row" style="margin-bottom:0.5rem">
          <span class="card-title" style="margin-bottom:0">刷新令牌</span>
          <button class="btn btn-copy" id="copyRefreshBtn" disabled onclick="copyToken('refresh')">复制</button>
        </div>
        <textarea class="token-box" id="refreshToken" readonly placeholder="刷新令牌将显示在这里..." style="min-height:60px"></textarea>
      </div>
    </div>

    <!-- Right: Auth -->
    <div>
      <div class="card">
        <div class="card-title">🔑 授权操作</div>
        <div id="authArea">
          <div class="loading" id="loadingArea">
            <div class="spinner"></div>
            <span>正在获取授权链接...</span>
          </div>
          <div id="authBtnArea" class="hidden">
            <div class="qr-box" id="qrBox"></div>
            <button class="btn btn-primary" id="authBtn" onclick="handleAuth()">
              开始授权登录
            </button>
            <p style="color:#64748b;font-size:0.75rem;text-align:center;margin-top:0.75rem">点击按钮后，在新窗口扫码授权</p>
          </div>
          <div class="success hidden" id="successArea">
            <div class="success-icon">✅</div>
            <p>已成功获取令牌</p>
          </div>
        </div>
      </div>

      <div class="card" style="margin-top:1.5rem">
        <div class="card-title">API 路由</div>
        <p style="font-size:0.8rem;margin-bottom:0.5rem;color:#94a3b8">OAuth 令牌链接：</p>
        <div class="api-route" id="apiRoute"></div>
      </div>
    </div>
  </div>

  <!-- Info Card -->
  <div class="card info-card">
    <div class="card-title">💡 使用说明</div>
    <div class="info-grid">
      <div>
        <h4 style="font-size:0.85rem;margin-bottom:0.5rem">功能说明</h4>
        <ul class="info-list">
          <li>本工具帮助获取阿里云盘TV版的刷新令牌</li>
          <li>TV接口可绕过三方应用权益包的速率限制</li>
          <li>需要SVIP会员才能享受高速下载</li>
        </ul>
      </div>
      <div>
        <h4 style="font-size:0.85rem;margin-bottom:0.5rem">使用步骤</h4>
        <ul class="info-list">
          <li>点击"开始授权登录"按钮</li>
          <li>在弹出的页面中使用阿里云盘APP扫码</li>
          <li>授权成功后令牌会自动显示</li>
          <li>复制令牌到对应的播放软件中使用</li>
        </ul>
      </div>
    </div>
    <div class="alert">
      <span>⚠️</span>
      <div>
        <strong>温馨提示</strong>
        <p style="margin-top:0.25rem">TV接口能绕过三方应用权益包的速率限制，但需要SVIP会员才能享受高速下载。</p>
      </div>
    </div>
  </div>
</div>

<!-- Notice Modal -->
<div class="modal-overlay" id="noticeModal">
  <div class="modal">
    <h3>使用说明</h3>
    <p>
      本工具能帮助你一键获取「阿里云盘TV版」的刷新令牌，完全免费。<br><br>
      <strong>注意：</strong> TV接口能绕过三方应用权益包的速率限制，但前提你得是SVIP。
    </p>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="window.open('https://www.alipan.com/cpx/member?userCode=MjAyNTk2','_blank')">
        开通会员
      </button>
      <button class="btn btn-normal" onclick="closeNotice()">我知道了</button>
    </div>
  </div>
</div>

<script>
let currentSid = "";
let checkTimer = null;
let accessToken = "";
let refreshToken = "";

document.getElementById("apiRoute").textContent = location.protocol + "//" + location.host + "/api/oauth/alipan/token";

function closeNotice() {
  document.getElementById("noticeModal").style.display = "none";
}

async function generateQR() {
  try {
    const resp = await fetch("/api/generate", { method: "POST" });
    const data = await resp.json();
    if (data.error) {
      alert("初始化失败: " + data.error);
      return;
    }
    currentSid = data.sid;
    document.getElementById("qrBox").innerHTML =
      '<img src="https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=' +
      encodeURIComponent("https://www.alipan.com/o/oauth/authorize?sid=" + data.sid) +
      '" alt="QR Code" width="280" height="280">';
    document.getElementById("loadingArea").classList.add("hidden");
    document.getElementById("authBtnArea").classList.remove("hidden");
  } catch(e) {
    alert("初始化失败，请检查网络");
  }
}

function handleAuth() {
  const authUrl = "https://www.alipan.com/o/oauth/authorize?sid=" + currentSid;
  window.open(authUrl, "_blank");
  document.getElementById("authBtn").disabled = true;
  document.getElementById("authBtn").textContent = "授权中...";
  checkTimer = setTimeout(() => checkStatus(currentSid), 1000);
}

async function checkStatus(sid) {
  try {
    const resp = await fetch("/api/check/" + sid);
    const data = await resp.json();

    if (data.status === "LoginSuccess") {
      accessToken = data.access_token || "";
      refreshToken = data.refresh_token || "";
      document.getElementById("accessToken").value = accessToken;
      document.getElementById("refreshToken").value = refreshToken;
      document.getElementById("copyAccessBtn").disabled = !accessToken;
      document.getElementById("copyRefreshBtn").disabled = !refreshToken;
      document.getElementById("authBtnArea").classList.add("hidden");
      document.getElementById("successArea").classList.remove("hidden");
    } else if (data.status === "ScanSuccess") {
      document.getElementById("authBtn").textContent = "已扫码，等待确认...";
      checkTimer = setTimeout(() => checkStatus(sid), 2000);
    } else if (data.status === "LoginFailed") {
      document.getElementById("authBtn").disabled = false;
      document.getElementById("authBtn").textContent = "开始授权登录";
      alert("登录失败，请刷新页面重试");
    } else if (data.status === "QRCodeExpired") {
      document.getElementById("authBtn").disabled = false;
      document.getElementById("authBtn").textContent = "开始授权登录";
      alert("链接过期，请刷新页面重试");
    } else {
      // WaitLogin
      checkTimer = setTimeout(() => checkStatus(sid), 2000);
    }
  } catch(e) {
    console.error("检查状态出错:", e);
  }
}

function copyToken(type) {
  const text = type === "access" ? accessToken : refreshToken;
  navigator.clipboard.writeText(text).then(() => {
    alert((type === "access" ? "访问令牌" : "刷新令牌") + " 已复制");
  }).catch(() => {
    alert("复制失败");
  });
}

// init
generateQR();
</script>
</body>
</html>`
