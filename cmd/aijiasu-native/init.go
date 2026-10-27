package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"aijiasu-native/internal/native/bootstrap"
)

func runInit(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies cliDependencies) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options bootstrap.Options
	var asJSON bool
	flags.StringVar(&options.Directory, "config-dir", "", "私密配置目录")
	flags.StringVar(&options.Reference, "reference", "", "离线参考 ELF 文件")
	flags.StringVar(&options.TLSPin, "tls-pin", "", "已独立确认的登录服务公钥 SHA-256")
	flags.BoolVar(&asJSON, "json", false, "输出 JSON")
	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		printInitHelp(stdout)
		return 0
	}
	if err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "初始化参数无效，请运行 aijiasu-native init --help。")
		return exitUsage
	}
	if options.TLSPin != "" {
		pin, err := hex.DecodeString(options.TLSPin)
		if err != nil || len(pin) != 32 {
			fmt.Fprintln(stderr, "TLS 公钥指纹必须为 64 位十六进制。")
			return exitUsage
		}
	}
	if ctx.Err() != nil {
		return cancelled(stderr)
	}
	if options.Directory == "" {
		options.Directory, err = dependencies.defaultDirectory()
		if err != nil {
			fmt.Fprintln(stderr, "无法确定用户配置目录，请使用 --config-dir 指定。")
			return exitFailure
		}
	}
	if dependencies.initialize == nil {
		fmt.Fprintln(stderr, "初始化功能不可用。")
		return exitFailure
	}
	result, err := dependencies.initialize(ctx, options)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return cancelled(stderr)
		}
		message := "初始化失败，请检查网络、参考版本及私密配置。"
		switch {
		case errors.Is(err, bootstrap.ErrDownload):
			message = "参考文件下载失败，请检查网络；只接受固定官方 HTTPS 地址，不跟随重定向。"
		case errors.Is(err, bootstrap.ErrReference):
			message = "参考文件校验失败，只支持完整 SHA-256 匹配的官方 Linux amd64 4.3.0.1 文件。"
		case errors.Is(err, bootstrap.ErrTLSConflict):
			message = "已有登录公钥指纹与 --tls-pin 不同，已保留原配置；请先独立核实信任设置。"
		case errors.Is(err, bootstrap.ErrConfiguration):
			message = "私密配置无法读取或发布，请检查目录权限、文件格式和占用；已有配置未被覆盖。"
		}
		fmt.Fprintln(stderr, message)
		return exitFailure
	}
	if asJSON {
		if json.NewEncoder(stdout).Encode(result) != nil {
			return exitFailure
		}
		return 0
	}
	fmt.Fprintf(stdout, "私密配置已就绪：新建 %d 个，保留 %d 个。\n", len(result.Created), len(result.Preserved))
	return 0
}

func printInitHelp(writer io.Writer) {
	fmt.Fprintln(writer, `用法: aijiasu-native init [选项]

--config-dir <目录>   私密配置目录，默认使用 aijiasu-native 用户目录
--reference <文件>   离线使用官方 Linux amd64 4.3.0.1 的 ajiasu ELF 文件
--tls-pin <指纹>     在新建配置中保存已独立确认的登录服务公钥 SHA-256
--json               输出 initialized、created、preserved

默认通过固定官方 HTTPS 地址下载参考归档，不跟随重定向。
提取前校验参考 ELF 的完整 SHA-256；只读取，不执行参考客户端。
有效已有配置保持原样；只补齐缺失文件，不登录账号。
现有 TLS 公钥指纹与显式选项不同时拒绝覆盖；不会自动观察或接受证书。`)
}
