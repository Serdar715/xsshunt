package banner

import "github.com/fatih/color"

func GetBanner() string {
	cyan := color.New(color.FgCyan).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	banner := `
` + cyan(`
▐▄• ▄ .▄▄ · .▄▄ ·     ▄ .▄▄• ▄▌ ▐ ▄ ▄▄▄▄▄
 █▌█▌▪▐█ ▀. ▐█ ▀.    ██▪▐█▐█▪██▌•█▌▐█•██  
 ·██·  ▄▀▀▀█▄▄▀▀▀█▄   ██▀▀█▐█▌▐█▪▐█▐▐▌ ▐█.▪
▪▐█·█▌▐█▄▪▐█▐█▄▪▐█   ██▌▐▀ ▐█▀·.██▐█▌ ▐█▌·
•▀▀ ▀▀ ▀▀▀▀  ▀▀▀▀    ▀▀▀ ·  ▀ • ▀▀ █▪ ▀▀▀ 
`) + `
          ` + red(`XSSHunt - Advanced XSS Scanner v2.0`) + `
                   ` + yellow(`by @Serdar715`) + `

` + cyan(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`) + `
  ` + yellow(`Features:`) + `
    • DOM-based XSS detection
    • Reflected XSS detection  
    • WAF bypass techniques
    • Smart payload generation
    • Context-aware payloads
    • Comprehensive reporting
` + cyan(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`) + `
`
	return banner
}
