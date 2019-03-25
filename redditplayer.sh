#!/bin/bash -x

# authentication settings
TOKENFILE=token.sh
source cred.sh

# API settings
USER_AGENT="cli-player/0.1 by pinusb"
URL="https://oauth.reddit.com"

read -r -d '' HELP <<'EOF'
reddit-cli-player - A reddit-sourced music player for your command line

Usage:  reddit-cli-player [options]

Options:
EOF
read -r -d '' OPTIONS <<'EOF'
    -p, --player <string>	command to run as player. Default "mpv --no-video"
    -s, --subreddits <string>	comma-separated list of subreddits to source
    -f, --files <string>	comma-separated list of filenames from which to read a list of subreddits
    --hot	sort by hot posts (default)
    --new	sort by new posts
    --top	sort by top posts
    --top-time <string>	one of "all", "week", "month", "year". Use with "--top"
    --order <string>`	order of generated playlist: either "random" or "upvotes"
    -c, --categories <string>	comma-separated list of categories to source
    --list-categories	print a list of available categories and exit
    --list-subreddits	print a list of available subreddits and exit
    --no-skip-regex	try playing all urls, even the ones not recognized by youtube-dl
    --fast-inexact-load	don't wait until all subreddits are scraped to start playing
EOF
read -r -d '' MAN <<'EOF'
EOF

# ============ PARAMETER PARSING =============
# default parameters
PLAYER="mpv"

PARAMS=""
while (( "$#" )); do
    case "$1" in
      -h|--help)
          echo "$HELP"
          hash column &>/dev/null && 
	      echo "$OPTIONS" | column -W 2 -s $'\t' -t || 
	      echo "$OPTIONS"
	  echo "$MAN"
          exit 0
          ;;
      -f|--files)
          READ_FILES=$2
          shift 2
          ;;
      -s|--subreddits)
          SUBREDDITS=$2
          shift 2
          ;;
      --order)
          ORDER=$2
          shift 2
          ;;
      -p|--player)
          PLAYER=$2
          shift 2
          ;;
      -c|--categories)
          CATEGORIES=$2
          shift 2
          ;;
      --list-categories)
          A_LIST_CATEGORIES=1
          shift 
          ;;
      --list-subreddits)
          A_LIST_SUBREDDITS=1
          shift 
          ;;
      --no-skip-regex)
          A_SKIP_REGEX=0
          shift
          ;;
      --fast-inexact-load)
          A_FAST_LOAD=1
          shift
          ;;
      -*) # unsupported flags
          echo "Error: Unsupported flag $1" >&2
          exit 1
          ;;
      *) # preserve positional arguments
          PARAMS="$PARAMS $1"
          shift
          ;;
    esac
done
# set positional arguments in their proper place
eval set -- "$PARAMS"


# ============ VARIABLE SETUP =============

declare -a subreddits
subreddits=()
if [ -n "$READ_FILES" ]; then
    IFS=',' read -r -a files <<<"$READ_FILES"
    for f in "${files[@]}"; do
        IFS=$'\n' read -r -a arr < "$f"
        subreddits+=( "${arr[@]}" )
    done
    unset files
    unset arr
fi
if [ -n "$SUBREDDITS" ]; then
    echo "parsing subreddits"
    IFS=',' read -r -a arr <<<"$SUBREDDITS"
    subreddits+=( "${arr[@]}" )
    unset arr
fi
if [ -n "$CATEGORIES" ]; then
    names=$(< subreddits.json jq -r '.[] | 
        select(.category | inside("'"$CATEGORIES"'")) | .name')
    IFS=$'\n' arr=($names)
    IFS=' '
    subreddits+=( "${arr[@]}" )
    unset arr
    unset names
fi
[ -z "$A_SKIP_REGEX" ] && A_SKIP_REGEX=1

PLAYLIST_FILE=$(mktemp /tmp/reddit-music-XXXX.m3u)
IPC_FILE="/tmp/mpv.fifo"
[ -e "$IPC_FILE" ] && rm -f "$IPC_FILE"
mkfifo "$IPC_FILE"

# ============= QUERY COMMANDS ============

# commands such as --list-categories or --list-subreddits do not play anything. We implement them here

if [ -n "$A_LIST_CATEGORIES" ]; then
    echo -e "Here's a list of categories we have:\n"
    < subreddits.json jq -r '.[] | .category' | sort -u
    exit 0
fi
if [ -n "$A_LIST_SUBREDDITS" ]; then
    echo -e "Here's a list of subreddits we have:\n"
    L_FORMAT_STRING='\(.name)\t\(.title)\t\(.subscribers)\t\(.category)'
    if [ -z "$CATEGORIES" ]; then
        echo -e "Try using -c to narrow this to fewer categories!"
        list_json=$(< subreddits.json jq -r '.[] | "'"$L_FORMAT_STRING"'"')
    else
        list_json=$(< subreddits.json jq -r '.[] | 
            select(.category | inside("'"$CATEGORIES"'")) | 
                "'"$L_FORMAT_STRING"'"')
        unset CATEGORIES_LIST
        # 
    fi
        echo "$list_json" \
        | sort -t $'\t' -k 4,4 -k 3,3rn \
        | column -s $'\t' -t
    unset L_FORMAT_STRING
    unset list_json
    exit 0
fi

# ============ UTILITY FUNCTIONS ==========

req() {
    curl -s -H "$auth_string" -A "$USER_AGENT" "$URL$1" 
}

auth() {
    if [ -e token.sh ]; then
        token=$(cat token.sh)
    else

        # first we get auth token
	local tokenres
        tokenres=$(curl -A "$USER_AGENT" \
            -X POST -d "grant_type=password&username=$USERNAME&password=$PASSWORD" \
            --user "$CLIENT_ID:$CLIENT_SECRET" \
            "$URL/api/v1/access_token")

        token=$(echo "$tokenres" | jq -r ".access_token")

        echo "$token" > "$TOKENFILE"
    fi 
    auth_string="Authorization: bearer $token"
}
auth

get_res() {
    # $1 is name of var where to store result
    # $2 is subreddit, 
    # $3 is sort type {new, top, hot}
    # $4 is query arguments appended to url 
    # stores raw urls in $got_urls and a more complete result in $got_res
    local subreddit="$1"
    local sort_by="$2"
    local args="$3"
    local res
    res=$(req "/r/$subreddit/${sort_by}.json?$args")
    echo "$res" | jq '.data.children[]'
}
export -f req # for xargs
export auth_string USER_AGENT URL # needed by req
export -f get_res  # for xargs

parse_urls() {
    local res="$1"
    local urls
    urls=$(echo "$res" | jq -r '.[] | select(.kind == "t3" 
        and .data.is_self != true) | 
            .data.url')
    echo "$urls"
}

# ========= GET POST LIST FROM SUBREDDITS ===========
get_post_list() {
    lockfile=$(mktemp -t lock.XXXXXX)
    trap 'rm -f "$lockfile"' 0
    xargs_command="
    echo Scraping \"{}\" >&2
    {
        flock -x 99
        "'get_res "{}" "top" "t=all"'"
    } 99>$lockfile
    "
    local res
    PAR="-P20"
    # PAR=''
    res=$(echo "$1" | xargs "$PAR" -d ' ' -I{} bash -c "$xargs_command")

    # ============= PROCESS LIST ==========================
    # order by score
    res=$(echo "$res" | jq '[.] | sort_by(.data.score)')

    echo "$res"
}

# ============== SKIP URLS BASED ON REGEX =============
# for clean_urls and better indent consitency
read -r -d '' PY_SOURCE <<'EOF'
import youtube_dl
import sys
import re
res = [getattr(ie.__class__, '__dict__').get('_VALID_URL', None) \
    for ie in youtube_dl.extractor.gen_extractors()]
res = [re.compile(r) for r in res if r is not None and r is not '.*']
res.pop()
for url in sys.stdin:
    for pattern in res:
        if re.match(pattern, url):
            print(url)
            break
EOF
clean_urls() {
    local urls
    if [ "$A_SKIP_REGEX" = 1 ]; then
        echo "" | python -c "$PY_SOURCE"
        urls=$(echo "$1" | python -c  "$PY_SOURCE")
        echo "$urls"
    fi
}

get_all() {
    local got_posts
    local got_urls
    local got_urls
    got_posts=$(get_post_list "$1 ")
    got_urls=$(parse_urls "$got_posts")
    got_urls=$(clean_urls "$got_urls")
    echo "$got_urls"
}

start_player() {
    case "$PLAYER" in
        mpv*)
            # args="--no-video"
            [ -n "$A_FAST_LOAD" ] && args="--input-file=$IPC_FILE"
            ;;
        vlc*)
            # TODO Add fast load for vlc
            ;;
        mplayer*)
            # TODO Add fast load for mplayer
            ;;
        cmus*)
            # TODO Add fast load for cmus
            ;;
        *)
            ;;
    esac
    $PLAYER $args "$1" >/dev/null 2>&1 &
} 

# got_posts=$(get_post_list "${subreddits[2]} ${subreddits[3]} ")

echo "PLAYLIST FILE: $PLAYLIST_FILE"
if [ -n "$A_FAST_LOAD" ]; then
    # first pass so we play something immediately
    got_urls=$(get_all "${subreddits[1]} ")
    echo "$got_urls" > "$PLAYLIST_FILE"
    start_player "$PLAYLIST_FILE"
fi
#now everything else
got_urls=$(get_all "${subreddits[*]}")
echo "$got_urls" > "$PLAYLIST_FILE"
echo "Done scraping"
[ -z "$A_FAST_LOAD" ] && start_player "$PLAYLIST_FILE"

[ -n "$A_FAST_LOAD" ] && {
    echo "playlist_clear" > "$IPC_FILE"
    echo "loadlist $PLAYLIST_FILE append" > "$IPC_FILE"
}