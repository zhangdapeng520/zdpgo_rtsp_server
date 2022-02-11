package conf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/aler9/gortsplib"
	"github.com/aler9/gortsplib/pkg/headers"
	"golang.org/x/crypto/nacl/secretbox"
	"gopkg.in/yaml.v2"

	"github.com/zhangdapeng520/zdpgo_rtsp_server/internal/logger"
)

func decrypt(key string, byts []byte) ([]byte, error) {
	enc, err := base64.StdEncoding.DecodeString(string(byts))
	if err != nil {
		return nil, err
	}

	var secretKey [32]byte
	copy(secretKey[:], key)

	var decryptNonce [24]byte
	copy(decryptNonce[:], enc[:24])
	decrypted, ok := secretbox.Open(nil, enc[24:], &decryptNonce, &secretKey)
	if !ok {
		return nil, fmt.Errorf("decryption error")
	}

	return decrypted, nil
}

// 从文件加载配置
func loadFromFile(fpath string, conf *Conf) (bool, error) {
	// 创建配置文件
	if fpath == "config.yml" {
		if _, err := os.Stat(fpath); err != nil {
			return false, nil
		}
	}

	// 读取配置文件
	byts, err := ioutil.ReadFile(fpath)
	if err != nil {
		return true, err
	}

	// 寻找环境变量
	if key, ok := os.LookupEnv("RTSP_CONFKEY"); ok {
		byts, err = decrypt(key, byts)
		if err != nil {
			return true, err
		}
	}

	// 加载yaml配置，生成map对象
	var temp interface{}
	err = yaml.Unmarshal(byts, &temp)
	if err != nil {
		return true, err
	}

	// 转换interface{}为空字符串，避免json解析错误
	var convert func(i interface{}) interface{}
	convert = func(i interface{}) interface{} {
		switch x := i.(type) {
		case map[interface{}]interface{}:
			m2 := map[string]interface{}{}
			for k, v := range x {
				m2[k.(string)] = convert(v)
			}
			return m2

		case []interface{}:
			a2 := make([]interface{}, len(x))
			for i, v := range x {
				a2[i] = convert(v)
			}
			return a2
		}

		return i
	}
	temp = convert(temp)

	// 检查不存在的参数
	var checkNonExistentFields func(what interface{}, ref interface{}) error
	checkNonExistentFields = func(what interface{}, ref interface{}) error {
		if what == nil {
			return nil
		}

		ma, ok := what.(map[string]interface{})
		if !ok {
			return fmt.Errorf("不是map类型")
		}

		// 遍历map对象
		for k, v := range ma {
			fi := func() reflect.Type {
				rr := reflect.TypeOf(ref)
				for i := 0; i < rr.NumField(); i++ {
					f := rr.Field(i)
					if f.Tag.Get("json") == k {
						return f.Type
					}
				}
				return nil
			}()
			if fi == nil {
				return fmt.Errorf("不存在的参数: '%s'", k)
			}

			if fi == reflect.TypeOf(map[string]*PathConf{}) && v != nil {
				ma2, ok := v.(map[string]interface{})
				if !ok {
					return fmt.Errorf("参数 %s 不是map类型", k)
				}

				for k2, v2 := range ma2 {
					err := checkNonExistentFields(v2, reflect.Zero(fi.Elem().Elem()).Interface())
					if err != nil {
						return fmt.Errorf("参数 %s, 键 %s: %s", k, k2, err)
					}
				}
			}
		}
		return nil
	}
	err = checkNonExistentFields(temp, Conf{})
	if err != nil {
		return true, err
	}

	// 转换生成的map为json字符串
	byts, err = json.Marshal(temp)
	if err != nil {
		return true, err
	}

	// 从json加载配置
	err = json.Unmarshal(byts, conf)
	if err != nil {
		return true, err
	}

	return true, nil
}

// Conf 配置对象
type Conf struct {
	// general
	LogLevel                  LogLevel        `json:"logLevel"`
	LogDestinations           LogDestinations `json:"logDestinations"`
	LogFile                   string          `json:"logFile"`
	ReadTimeout               StringDuration  `json:"readTimeout"`
	WriteTimeout              StringDuration  `json:"writeTimeout"`
	ReadBufferCount           int             `json:"readBufferCount"`
	ExternalAuthenticationURL string          `json:"externalAuthenticationURL"`
	API                       bool            `json:"api"`
	APIAddress                string          `json:"apiAddress"`
	Metrics                   bool            `json:"metrics"`
	MetricsAddress            string          `json:"metricsAddress"`
	PPROF                     bool            `json:"pprof"`
	PPROFAddress              string          `json:"pprofAddress"`
	RunOnConnect              string          `json:"runOnConnect"`
	RunOnConnectRestart       bool            `json:"runOnConnectRestart"`

	// RTSP
	RTSPDisable       bool        `json:"rtspDisable"`
	Protocols         Protocols   `json:"protocols"`
	Encryption        Encryption  `json:"encryption"`
	RTSPAddress       string      `json:"rtspAddress"`
	RTSPSAddress      string      `json:"rtspsAddress"`
	RTPAddress        string      `json:"rtpAddress"`
	RTCPAddress       string      `json:"rtcpAddress"`
	MulticastIPRange  string      `json:"multicastIPRange"`
	MulticastRTPPort  int         `json:"multicastRTPPort"`
	MulticastRTCPPort int         `json:"multicastRTCPPort"`
	ServerKey         string      `json:"serverKey"`
	ServerCert        string      `json:"serverCert"`
	AuthMethods       AuthMethods `json:"authMethods"`
	ReadBufferSize    int         `json:"readBufferSize"`

	// RTMP
	RTMPDisable bool   `json:"rtmpDisable"`
	RTMPAddress string `json:"rtmpAddress"`

	// HLS
	HLSDisable         bool           `json:"hlsDisable"`
	HLSAddress         string         `json:"hlsAddress"`
	HLSAlwaysRemux     bool           `json:"hlsAlwaysRemux"`
	HLSSegmentCount    int            `json:"hlsSegmentCount"`
	HLSSegmentDuration StringDuration `json:"hlsSegmentDuration"`
	HLSSegmentMaxSize  StringSize     `json:"hlsSegmentMaxSize"`
	HLSAllowOrigin     string         `json:"hlsAllowOrigin"`

	// paths
	Paths map[string]*PathConf `json:"paths"`
}

// Load 加载配置
func Load(fpath string) (*Conf, bool, error) {
	conf := &Conf{} // 创建配置对象

	found, err := loadFromFile(fpath, conf) // 加载文件
	if err != nil {
		return nil, false, err
	}

	err = loadFromEnvironment("RTSP", conf) // 从环境加载RTSP流
	if err != nil {
		return nil, false, err
	}

	err = conf.CheckAndFillMissing() // 检查并填充缺失值
	if err != nil {
		return nil, false, err
	}

	return conf, found, nil
}

// CheckAndFillMissing 检查并填充缺失值
func (conf *Conf) CheckAndFillMissing() error {
	// 日志等级
	if conf.LogLevel == 0 {
		conf.LogLevel = LogLevel(logger.Info)
	}

	// 日志输出
	if len(conf.LogDestinations) == 0 {
		conf.LogDestinations = LogDestinations{logger.DestinationStdout: {}}
	}

	// 日志文件
	if conf.LogFile == "" {
		conf.LogFile = "logs/zdpgo/zdpgo_rtsp_server.log"
	}

	// 读超时
	if conf.ReadTimeout == 0 {
		conf.ReadTimeout = 10 * StringDuration(time.Second)
	}

	// 写超时
	if conf.WriteTimeout == 0 {
		conf.WriteTimeout = 10 * StringDuration(time.Second)
	}

	// 读缓冲
	if conf.ReadBufferCount == 0 {
		conf.ReadBufferCount = 512
	}

	// 权限校验路由
	if conf.ExternalAuthenticationURL != "" {
		if !strings.HasPrefix(conf.ExternalAuthenticationURL, "http://") &&
			!strings.HasPrefix(conf.ExternalAuthenticationURL, "https://") {
			return fmt.Errorf("'externalAuthenticationURL' 必须是 HTTP URL")
		}
	}

	// api地址
	if conf.APIAddress == "" {
		conf.APIAddress = "127.0.0.1:9997"
	}

	// 普罗米修斯地址
	if conf.MetricsAddress == "" {
		conf.MetricsAddress = "127.0.0.1:9998"
	}

	// pprof地址
	if conf.PPROFAddress == "" {
		conf.PPROFAddress = "127.0.0.1:9999"
	}

	// 协议
	if len(conf.Protocols) == 0 {
		conf.Protocols = Protocols{
			Protocol(gortsplib.TransportUDP):          {},
			Protocol(gortsplib.TransportUDPMulticast): {},
			Protocol(gortsplib.TransportTCP):          {},
		}
	}

	// 加密协议
	if conf.Encryption == EncryptionStrict {
		if _, ok := conf.Protocols[Protocol(gortsplib.TransportUDP)]; ok {
			return fmt.Errorf("strict模式不能使用UDP传输协议")
		}

		if _, ok := conf.Protocols[Protocol(gortsplib.TransportUDPMulticast)]; ok {
			return fmt.Errorf("strict模式不能使用UDP-multicast传输协议")
		}
	}

	// rtsp地址
	if conf.RTSPAddress == "" {
		conf.RTSPAddress = ":8554"
	}

	// rtsps地址
	if conf.RTSPSAddress == "" {
		conf.RTSPSAddress = ":8555"
	}

	// rtp地址
	if conf.RTPAddress == "" {
		conf.RTPAddress = ":8000"
	}

	// rtc地址
	if conf.RTCPAddress == "" {
		conf.RTCPAddress = ":8001"
	}

	if conf.MulticastIPRange == "" {
		conf.MulticastIPRange = "224.1.0.0/16"
	}

	if conf.MulticastRTPPort == 0 {
		conf.MulticastRTPPort = 8002
	}

	if conf.MulticastRTCPPort == 0 {
		conf.MulticastRTCPPort = 8003
	}

	// https cert配置
	if conf.ServerKey == "" {
		conf.ServerKey = "server.key"
	}

	if conf.ServerCert == "" {
		conf.ServerCert = "server.crt"
	}

	// 权限配置
	if len(conf.AuthMethods) == 0 {
		conf.AuthMethods = AuthMethods{headers.AuthBasic, headers.AuthDigest}
	}

	if conf.RTMPAddress == "" {
		conf.RTMPAddress = ":1935"
	}

	if conf.HLSAddress == "" {
		conf.HLSAddress = ":8888"
	}

	if conf.HLSSegmentCount == 0 {
		conf.HLSSegmentCount = 3
	}

	if conf.HLSSegmentDuration == 0 {
		conf.HLSSegmentDuration = 1 * StringDuration(time.Second)
	}

	if conf.HLSSegmentMaxSize == 0 {
		conf.HLSSegmentMaxSize = 50 * 1024 * 1024
	}

	if conf.HLSAllowOrigin == "" {
		conf.HLSAllowOrigin = "*"
	}

	// 路径
	if conf.Paths == nil {
		conf.Paths = make(map[string]*PathConf)
	}

	// "~^.*$"是"all"的别名
	if _, ok := conf.Paths["all"]; ok {
		conf.Paths["~^.*$"] = conf.Paths["all"]
		delete(conf.Paths, "all")
	}

	// 遍历路径
	for name, pconf := range conf.Paths {
		if pconf == nil { // 配置路径
			conf.Paths[name] = &PathConf{}
			pconf = conf.Paths[name]
		}

		err := pconf.checkAndFillMissing(conf, name) // 检查缺失
		if err != nil {
			return err
		}
	}

	return nil
}
