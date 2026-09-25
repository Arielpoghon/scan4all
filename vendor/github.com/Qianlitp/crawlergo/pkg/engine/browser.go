package engine

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/Qianlitp/crawlergo/pkg/logger"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/chromedp"
)

type Browser struct {
	Ctx          *context.Context
	Cancel       *context.CancelFunc
	tabs         []*context.Context
	tabCancels   []context.CancelFunc
	ExtraHeaders map[string]interface{}
	lock         sync.Mutex
}

func InitBrowser(chromiumPath string, extraHeaders map[string]interface{}, proxy string, noHeadless bool) *Browser {
	var bro Browser
	opts := append(chromedp.DefaultExecAllocatorOptions[:],

		// Executable path
		chromedp.ExecPath(chromiumPath),
		// Headless mode
		chromedp.Flag("headless", !noHeadless),
		// https://github.com/chromedp/chromedp/issues/997#issuecomment-1030596050
		// incognito mode not used
		// Disable the GPU and GUI
		chromedp.Flag("disable-gpu", true),
		// Disable the sandbox
		chromedp.Flag("no-sandbox", true),
		// Ignore certificate errors
		chromedp.Flag("ignore-certificate-errors", true),

		chromedp.Flag("disable-images", true),
		//
		chromedp.Flag("disable-web-security", true),
		//
		chromedp.Flag("disable-xss-auditor", true),
		//
		chromedp.Flag("disable-setuid-sandbox", true),

		chromedp.Flag("allow-running-insecure-content", true),

		chromedp.Flag("disable-webgl", true),

		chromedp.Flag("disable-popup-blocking", true),

		chromedp.WindowSize(1920, 1080),
	)
	// Configure the browser proxy
	if proxy != "" {
		opts = append(opts, chromedp.ProxyServer(proxy))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	bctx, _ := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(log.Printf),
	)
	// https://github.com/chromedp/chromedp/issues/824#issuecomment-845664441
	// To create multiple tabs in one browser, first create the browser context by running the following statement
	err := chromedp.Run(bctx)
	if err != nil {
		// not found chrome process need exit
		logger.Logger.Fatal("chromedp run error: ", err.Error())
	}
	bro.Cancel = &cancel
	bro.Ctx = &bctx
	bro.ExtraHeaders = extraHeaders
	return &bro
}

func (bro *Browser) NewTab(timeout time.Duration) (*context.Context, context.CancelFunc) {
	bro.lock.Lock()
	ctx, cancel := chromedp.NewContext(*bro.Ctx)
	//defer cancel()
	tCtx, _ := context.WithTimeout(ctx, timeout)
	bro.tabs = append(bro.tabs, &tCtx)
	bro.tabCancels = append(bro.tabCancels, cancel)
	//defer cancel2()
	bro.lock.Unlock()

	//return bro.Ctx, &cancel
	return &tCtx, cancel
}

func (bro *Browser) Close() {
	logger.Logger.Info("closing browser.")
	for _, cancel := range bro.tabCancels {
		cancel()
	}

	for _, ctx := range bro.tabs {
		err := browser.Close().Do(*ctx)
		if err != nil {
			logger.Logger.Debug(err)
		}
	}

	err := browser.Close().Do(*bro.Ctx)
	if err != nil {
		logger.Logger.Debug(err)
	}
	(*bro.Cancel)()
}
