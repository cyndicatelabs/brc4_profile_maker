.PHONY: all clean

FILENAME := brc4_profile_maker

all: brc4_profile_maker

brc4_profile_maker: main.go
	go build -o ./brc4_profile_maker .

clean:
	rm -f brc4_profile_maker
