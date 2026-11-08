; phosphor-nicks.mrc - give every nick its own colour, apart from the message text.
;
; Each nick gets a colour picked by an MD5 hash of its (lower-cased) name, so the same nick always
; has the same colour, in every channel and after restarts, and you can follow who is talking.
; The colours come from pn.palette below. Brackets use the theme's "nick" colour.
;
; Display only: it reformats incoming channel and private messages and actions, and stops
; mIRC's default line (haltdef). It sends nothing, opens nothing, and does not touch CTCP, so
; CTCP filters in other scripts keep working. Message text is echoed as received; mIRC does
; not evaluate $ or % inside it.
;
; Load:   /load -rs phosphor-nicks.mrc        Unload: /unload -rs phosphor-nicks.mrc

; Nick colours: mIRC's fixed extended colours (16-98), chosen for spread on black: grey,
; lavender, olive, teal, orange, mint, pink, peach, magenta. Each is 7.9:1 to 17.7:1 on black
; and far from the message green, red (kicks), yellow (highlights), link blue and dim green.
; Edit to taste; colour codes are 0-98.
alias -l pn.palette { return 95 85 43 46 53 81 87 77 74 }

alias -l pn.c { return $+($chr(3), $color($1).dd) }
alias -l pn.cnum { return $+($chr(3), $base($1, 10, 10, 2)) }

; stable colour for a nick: MD5 of the lower-cased nick, modulo the palette size
; (MD5 spreads short nicks far more evenly than mIRC's $hash)
alias -l pn.nickcolour {
  var %p = $pn.palette
  return $gettok(%p, $calc($base($left($md5($lower($1)), 7), 16, 10) % $numtok(%p, 32) + 1), 32)
}

alias -l pn.nick {
  ; nick with its channel mode prefix (@, +, ...) when it is in the nicklist, else as sent
  var %n = $iif($1 ischan, $nick($1, $2).pnick)
  if (%n == $null) %n = $2
  return $+($pn.cnum($pn.nickcolour($2)), %n)
}

on ^*:TEXT:*:#: {
  echo -tlbfmr $chan $+($pn.c(nick), <, $pn.nick($chan, $nick), $pn.c(nick), >) $+($pn.c(normal), $1-)
  haltdef
}
on ^*:TEXT:*:?: {
  echo -tlbfmr $nick $+($pn.c(nick), <, $pn.nick($nick, $nick), $pn.c(nick), >) $+($pn.c(normal), $1-)
  haltdef
}
on ^*:ACTION:*:#: {
  echo -tlbfmr $chan $+($pn.c(action), *) $pn.nick($chan, $nick) $+($pn.c(action), $1-)
  haltdef
}
on ^*:ACTION:*:?: {
  echo -tlbfmr $nick $+($pn.c(action), *) $pn.nick($nick, $nick) $+($pn.c(action), $1-)
  haltdef
}
