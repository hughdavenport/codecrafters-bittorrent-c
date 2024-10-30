[![progress-banner](https://backend.codecrafters.io/progress/bittorrent/99a7daf0-ad72-4c80-beb1-9748261c96bd)](https://app.codecrafters.io/users/codecrafters-bot?r=2qF)
[![patreon](https://img.shields.io/badge/patreon-FF5441?style=for-the-badge&logo=Patreon)](https://www.patreon.com/hughdavenport)
[![youtube](https://img.shields.io/badge/youtube-FF0000?style=for-the-badge&logo=youtube)](https://www.youtube.com/watch?v=dqw7B6eR9P8&list=PL5r5Q39GjMDfetFdGmnhjw1svsALW1HIY)

This is a repository for my solutions to the
["Build Your Own BitTorrent" Challenge](https://app.codecrafters.io/courses/bittorrent/overview) in C. You can see my progress above.
You can also watch a [YouTube series](https://www.youtube.com/watch?v=dqw7B6eR9P8&list=PL5r5Q39GjMDfetFdGmnhjw1svsALW1HIY) where I discuss and code the solutions.

**Note**: If you're viewing this repo on GitHub, head over to
[codecrafters.io](https://codecrafters.io) to try the challenge.

# Running the program

The entry point for your BitTorrent implementation is in `app/main.c`, but you can compile and run it with `your_bittorrent.sh`, or `debug.sh` if you want to go step by step.

```sh
$ ./your_bittorrent.sh
Available subcommands:
    decode
    info
    peers
    parse
    hash

$ ./your_bittorrent.sh decode "24:some bencoded string"
"some bencoded string"

$ ./your_bittorrent.sh info sample.torrent
Tracker URL: http://bittorrent-test-tracker.codecrafters.io/announce
Length: 92063
Info Hash: d69f91e6b2ae4c542468d1073a71d4ea13879a7f
Piece Length: 32768
Piece Hashes:
e876f67a2a8886e8f36b136726c30fa29703022d
6e2275e604a0766656736e81ff10b55204ad8d35
f00d937a0213df1982bc8d097227ad9e909acc17

$ ./your_bittorrent.sh peers sample.torrent
165.232.41.73:51556
165.232.38.164:51532
165.232.35.114:51437

$ ./your_bittorrent.sh parse http://example.com
scheme = http
user = (null)
pass = (null)
host = example.com
port = 80 (80)
path = (null)
query = (null)
fragment = (null)

$ ./your_bittorrent.sh hash sample.torrent
32682077130437f19fb388813bca3355378b7621
```
