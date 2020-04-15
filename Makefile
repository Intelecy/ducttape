default:
	@mkdir -p ./dist
	go generate
	GOOS=windows go build -ldflags="-X 'main.binName=ducttape.exe'" -o dist/ducttape.exe
	GOOS=linux   go build -ldflags="-X 'main.binName=ducttape'"     -o dist/ducttape

clean:
	-rm -rf ./dist
	-rm -f resource.syso
