package Configs

import (
	"log"
	"strings"
)

var ExpJsonMap ExpJson       // define ExpJson file object
var ConfigJsonMap ConfigJson // define base config file object
var UserObject UserOption    // define user flag output object
var RespObject HttpResult    // define http response result object

var ColorMistake *log.Logger // define error log output
var ColorInfo *log.Logger    // define standard log output
var ColorSend *log.Logger    // define message sending output
var ColorSuccess *log.Logger // define success log output
var FindResltAll []string    // store all poc return results
var FindReslt []string
var ReqData *strings.Reader
var JudgeStatus = map[string]bool{`contains`: false, `code`: false}
var FlageStatus = false
