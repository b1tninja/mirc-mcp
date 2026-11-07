; mcp-bridge.mrc - the mIRC half of mirc-mcp.
;
; It opens no socket, listens on no port and starts no DCC. The MCP server reaches
; it only through mIRC's SendMessage interface (a window message plus shared memory
; on this PC), and it keeps recent messages in an in-memory hash table that is never
; written to disk.
;
; Load once:  /load -rs "%APPDATA%\mIRC\mcp-bridge.mrc"
;
; Everything the MCP server sends that carries user text arrives base64-encoded, so
; the editbox line itself is only [A-Za-z0-9+/=.] and mIRC never parses that text
; for |, $ or %. The script re-checks the policy the server enforces: a fixed set of
; verbs, no CTCP byte, no "=nick" (DCC chat) target, no channel list or "join 0".

alias mcp.version { mcp.init | return 1 }
alias -l mcp.max { return 500 }

on *:LOAD: { mcp.init }
on *:START: { mcp.init }
on *:UNLOAD: { if ($hget(mcp.log)) hfree mcp.log }

alias -l mcp.init {
  if (!$hget(mcp.log)) {
    hmake mcp.log 100
    hadd mcp.log seq 0
  }
}

; ---- message buffer ---------------------------------------------------------
; Each entry: seq -> cid TAB ctime TAB type TAB window TAB nick TAB text

alias -l mcp.rec {
  if (!$hget(mcp.log)) mcp.init
  var %s = $calc($hget(mcp.log, seq) + 1), %t = $chr(9)
  hadd mcp.log seq %s
  hadd mcp.log %s $+($cid, %t, $ctime, %t, $1, %t, $2, %t, $3, %t, $4-)
  var %old = $calc(%s - $mcp.max)
  if ($hget(mcp.log, %old) != $null) hdel mcp.log %old
}

on *:TEXT:*:*: { mcp.rec TEXT $iif($chan, $chan, $nick) $nick $1- }
on *:ACTION:*:*: { mcp.rec ACTION $iif($chan, $chan, $nick) $nick $1- }
on *:NOTICE:*:*: { mcp.rec NOTICE $iif($chan, $chan, $nick) $nick $1- }
on *:INPUT:*: {
  if ($left($1, 1) == /) || ($ctrlenter) return
  if ($target ischan) || ($query($target)) mcp.rec SELF $target $me $1-
}

; ---- identifiers the MCP server evaluates -----------------------------------

alias mcp.seq { return $iif($hget(mcp.log), $hget(mcp.log, seq), 0) }
alias mcp.msg { return $hget(mcp.log, $1) }

; $mcp.conn(N) -> cid TAB status TAB server TAB network TAB me   ($mcp.conn(0) = count)
alias mcp.conn {
  if ($1 == 0) return $scon(0)
  var %t = $chr(9)
  return $+($scon($1).cid, %t, $scon($1).status, %t, $scon($1).server, %t, $scon($1).network, %t, $scon($1).me)
}

; $mcp.chan(cid, N) -> channel TAB users TAB topic   (N = 0: count)
alias mcp.chan {
  if (!$mcp.hascid($1)) return
  scid $1
  var %r
  if ($2 == 0) %r = $chan(0)
  elseif ($chan($2)) %r = $+($v1, $chr(9), $nick($v1, 0), $chr(9), $chan($v1).topic)
  scid -r
  return %r
}

; $mcp.query(cid, N) -> nick   (N = 0: count)
alias mcp.query {
  if (!$mcp.hascid($1)) return
  scid $1
  var %r = $query($2)
  scid -r
  return %r
}

; $mcp.ev(cid, base64-expression) evaluates in that connection's context.
; The server builds the expression from an allowlisted identifier and checked args.
alias mcp.ev {
  if (!$isid) || (!$mcp.hascid($1)) return
  scid $1
  var %r = $eval($mcp.b64d($2), 2)
  scid -r
  return %r
}

alias -l mcp.hascid {
  var %i = $scon(0)
  while (%i) {
    if ($scon(%i).cid == $1) return $true
    dec %i
  }
  return $false
}

alias -l mcp.b64d {
  bunset &mcpb
  bset -t &mcpb 1 $1
  noop $decode(&mcpb, bm)
  return $bvar(&mcpb, 1-).text
}

; ---- the only command the MCP server runs -------------------------------------
; /mcp.do <cid> <verb> <b64 target> [b64 text]

alias mcp.do {
  if ($isid) return
  if (!$mcp.hascid($1)) { echo -s [mcp] refused: no connection $1 | return }
  var %v = $2, %t = $mcp.b64d($3), %x = $iif($4 != $null, $mcp.b64d($4))
  if (!$istok(msg notice action join part whois names topic, %v, 32)) { echo -s [mcp] refused verb %v | return }
  if ($chr(1) isin %t) || ($chr(1) isin %x) { echo -s [mcp] refused: CTCP byte | return }
  if (%t == $null) || ($left(%t, 1) == =) || ($chr(44) isin %t) || ($chr(32) isin %t) || (%t == 0) { echo -s [mcp] refused target | return }
  scid $1
  if (%v == msg) msg %t %x
  elseif (%v == notice) notice %t %x
  elseif (%v == action) describe %t %x
  elseif (%v == join) join %t
  elseif (%v == part) part %t %x
  elseif (%v == whois) whois %t
  elseif (%v == names) names %t
  elseif (%v == topic) {
    if (%x == $null) topic %t
    else topic %t %x
  }
  if ($istok(msg notice action, %v, 32)) mcp.rec $iif(%v == msg, SELF, SELF- $+ $upper(%v)) %t $me %x
  scid -r
}
