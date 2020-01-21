module go.bog.dev/scep2acme

go 1.13

require (
	github.com/go-acme/lego/v3 v3.3.0
	github.com/go-kit/kit v0.9.0
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/micromdm/scep v1.0.1-0.20181219164221-1e0c4b782f3f
	go.bog.dev/errpool v0.0.0-20191129185448-a143b125d7bb
	gopkg.in/yaml.v2 v2.2.2
)

replace github.com/fullsailor/pkcs7 => github.com/groob/pkcs7 v0.0.0-20180824154052-36585635cb64

replace github.com/micromdm/scep => go.bog.dev/micromdm-scep v1.0.1-0.20200121202423-f5052c70aa47
