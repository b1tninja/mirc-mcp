; phosphor-nicks.mrc - draw the nick in a different colour from the message text.
;
; Display only: it reformats incoming channel and private messages and actions, using the
; colour items the theme sets ("nick" for the nick, "normal"/"action" for the text), and
; stops mIRC's default line (haltdef). It sends nothing, opens nothing, and does not touch
; CTCP, so CTCP filters in other scripts keep working. Message text is echoed as received;
; mIRC does not evaluate $ or % inside it.
;
; Load:   /load -rs phosphor-nicks.mrc        Unload: /unload -rs phosphor-nicks.mrc

alias -l pn.c { return $+($chr(3), $color($1).dd) }
alias -l pn.nick {
  ; nick with its channel mode prefix (@, +, ...) when it is in the nicklist, else as sent
  var %n = $iif($1 ischan, $nick($1, $2).pnick)
  if (%n == $null) %n = $2
  return $+($pn.c(nick), %n)
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
