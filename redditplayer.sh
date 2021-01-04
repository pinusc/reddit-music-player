#!/bin/bash

set -Eeuo pipefail

# authentication settings
TOKENFILE=token.sh
source cred.sh

# API settings
USER_AGENT="cli-player/0.1 by pinusb"
URL="https://oauth.reddit.com"
TOKEN_URL="https://www.reddit.com"

read -r -d '' HELP <<EOF || true
reddit-cli-player - A reddit-sourced music player for your command line

Usage:  reddit-cli-player [options]

Options:
EOF
read -r -d '' OPTIONS <<EOF || true
-p, --player <string>	command to run as player. Default "mpv --no-video"
-s, --subreddits <string>	comma-separated list of subreddits to source
-f, --files <string>	comma-separated list of filenames from which to read a list of subreddits
--hot	sort by hot posts (default)
--new	sort by new posts
--top	sort by top posts
--top-time <string>	one of "all", "week", "month", "year". Use with "--top"
--order <string>	order of generated playlist: one of "random", "upvotes", "normalized", "time"
-c, --categories <string>	comma-separated list of categories to source
--list-categories	print a list of available categories and exit
--list-subreddits	print a list of available subreddits and exit
--no-skip-regex	try playing all urls, even the ones not recognized by youtube-dl
--fast-inexact-load	don't wait until all subreddits are scraped to start playing
EOF

read -r -d '' MAN <<EOF || true
EOF

#============================== PARSE PARAMETERS ===============================
# default parameters
PLAYER="mpv"
A_LIST_TYPE="top"
A_ORDER="upvotes"
A_TOP_TIME="upvotes"


PARAMS=""
READ_FILES=""
SUBREDDITS=""
CATEGORIES=""
A_SKIP_REGEX=""
A_LIST_CATEGORIES=""
A_LIST_SUBREDDITS=""
A_FAST_LOAD=""
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
			A_ORDER=$2
			shift 2
			;;
		--top|--new|--hot)
			A_LIST_TYPE="${1#--*}"
			shift
			;;
		--top-*)
			A_LIST_TYPE=top
			A_TOP_TIME="${1#--top-}"
			[ "$A_TOP_TIME" != "hour" ] &&
			  [ "$A_TOP_TIME" != "day" ]  &&
			  [ "$A_TOP_TIME" != "week" ]  &&
			  [ "$A_TOP_TIME" != "month" ]  &&
			  [ "$A_TOP_TIME" != "year" ]  &&
			  [ "$A_TOP_TIME" != "all" ] &&
			  { echo "Invalid option: $1" >&2; exit 1; }
			shift
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

#============================= CHECK_DEPENDENCIES =============================
hash python &>/dev/null || { echo "'python' and 'youtube-dl' not found"; exit 1; }
hash youtube-dl &>/dev/null || { echo "'youtube-dl' not found"; exit 1; }
hash curl &>/dev/null || { echo "'curl' not found"; exit 1; }
player_exec="${PLAYER% *}"
hash "$player_exec" &>/dev/null || { echo "'$player_exec' not found"; exit 1; }

#============================== SETUP VARIABLES ================================

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
	echo "@jq1" >&2
	names=$(< subreddits.json jq -r '.[] | 
		select(.category | inside("'"$CATEGORIES"'")) | .name')
	IFS=',' read -r -a arr <<<"$names"
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

#=========================== HANDLE QUERY COMMANDS =============================

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


#============================= UTILITY FUNCTIONS ===============================

req() {
	curl -s -H "$auth_string" -A "$USER_AGENT" "$URL$1" 
}

auth() {
	if [ -e "$TOKENFILE" ] && [ -n "$(cat "$TOKENFILE")" ]; then
		token=$(cat "$TOKENFILE")
	else

		# first we get auth token
		local tokenres
		tokenres=$(curl -A "$USER_AGENT" \
			-X POST -d "grant_type=password&username=$USERNAME&password=$PASSWORD" \
			--user "$CLIENT_ID:$CLIENT_SECRET" \
			"$TOKEN_URL/api/v1/access_token/")

		echo "@jq2 - token" >&2
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
	[ -z "$1" ] && exit 1
	local subreddit="$1"
	local sort_by="$2"
	local args="$3"
	local res
	res=$(req "/r/$subreddit/${sort_by}.json?$args")
	echo  "@jq3 - get-res" >&2
	echo "$res" | jq '.data.children[]'
}
export -f req # for xargs
export auth_string USER_AGENT URL # needed by req
export -f get_res  # for xargs

parse_urls() {
	local res="$1"
	local urls
	echo "@jq4 - parse-urls" >&2
	urls=$(echo "$res" | jq -r '.[] | select(.kind == "t3" 
		and .data.is_self != true) | 
			.data.url')
	echo "$urls"
}

#======================= GET POST LIST FROM SUBREDDITS =========================

get_post_list() {
	lockfile=$(mktemp -t lock.XXXXXX)
	trap 'rm -f "$lockfile"' 0
	local args=""
	[ "$A_LIST_TYPE" = "top" ] && args="\"t=$A_TOP_TIME\""
	xargs_command="
	echo Scraping \"{}\" >&2
	{
		flock -x 99
		n=\$(echo \"{}\" | tr -d '\\n' ) 
		get_res \"\$n\" $A_LIST_TYPE $args
	} 99>$lockfile
	"
	local res
	PAR="-P20"
	# PAR=''
	res=$(echo "$1" | xargs "$PAR" -d ' ' -I{} bash -c "$xargs_command")
	res=$(echo "$res" | jq --slurp)

	#============================== PROCESS LIST ===============================
	# echo "$res" > out.json

	# order by score
	echo "@jq5 - parse-post-list" >&2
	sort_key=""
	case "$A_ORDER" in
		score)
			sort_key=".data.score"
			;;
		normalized)
			# very naive implementation
			# normalized score is upvotes/subscrivers
			sort_key=".data.score / .data.subreddit_subscribers"
			;;
		random|shuffle)
			# .data.name is a pseudo-random hash
			# it's not quite "true" shuffle for some definitions of true
			# but it's idempotent, so that's nice
			sort_key=".data.name"
			;;
		time)
			sort_key=".data.created"
			;;
	esac
	if [ -n "$sort_key" ]; then
		res=$(echo "$res" | jq "sort_by($sort_key)")
	fi
	
	echo "$res"
}

pre_filter_posts() {
	local res="$1"
	local urls
	echo "@jq4 - parse-urls" >&2
	posts=$(echo "$res" | \
		jq -r '[.[] | select(.kind == "t3" and .data.is_self != true)]')
	echo "$posts"
}

# for clean_urls and better indent consitency
read -r -d '' PY_SOURCE <<'EOF' || true
import youtube_dl
import sys
import re
res = [getattr(ie.__class__, '__dict__').get('_VALID_URL', None) \
	for ie in youtube_dl.extractor.gen_extractors()]
res = [re.compile(r) for r in res if r is not None and r != '.*']
for url in sys.stdin:
	for pattern in res:
		if re.match(pattern, url):
			print(1,end='')
			break
	else:
		print(0,end='')
EOF

filter_posts() {
	# remove all urls that do not conform to youtube-dl regexes
	local urls
	local urlv
	local posts="$1"
	if [ "$A_SKIP_REGEX" = 1 ]; then
		# small amount of magic here
		# the python program reads urls and prints "1" if good, "0" otherwise
		# then with jq we get the indices of all the "1"s and use them
		# as indices of the "posts" array to construct an array of "good" posts
		urls=$(parse_urls "$posts")
		urlv=$(echo "$urls" | python -c  "$PY_SOURCE")
		posts=$(echo "$posts" | jq --arg urlv "$urlv" \
			'. as $p | [$urlv | indices("1")[] | $p[.]]')
	fi
	echo "$posts"
}

get_posts() {
	# wrapper around get_post_list, parse_urls, and clean_urls
	local got_posts
	local got_urls
	got_posts=$(get_post_list "$1")
	got_posts=$(pre_filter_posts "$got_posts")
	got_posts=$(filter_posts "$got_posts")

	echo "$got_posts"
}

make_playlist() {
	echo '#EXTM3U'
	echo "$1" | jq -r '.[] | "#EXTINF:,\(.data.title)
		\(.data.url)"'
}

start_player() {
	args=""
	case "$PLAYER" in
		mpv*)
			args="--no-video"
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
	# $PLAYER $args "$1" >/dev/null 2>&1 &
	$PLAYER $args "$1" &
} 

echo "PLAYLIST FILE: $PLAYLIST_FILE"
if [ -n "$A_FAST_LOAD" ]; then
	# first pass so we play something immediately
	got_posts=$(get_posts "${subreddits[1]}")
	make_playlist "$got_posts" > "$PLAYLIST_FILE"
	start_player "$PLAYLIST_FILE"
fi
#now everything else
got_posts=$(get_posts "${subreddits[*]}")
make_playlist "$got_posts" > "$PLAYLIST_FILE"
echo "Done scraping"
[ -z "$A_FAST_LOAD" ] && start_player "$PLAYLIST_FILE"

[ -n "$A_FAST_LOAD" ] && {
	echo "playlist_clear" > "$IPC_FILE"
	echo "loadlist $PLAYLIST_FILE append" > "$IPC_FILE"
}
