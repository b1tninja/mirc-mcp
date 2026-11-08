# make_rain.ps1 - render an original "digital rain" background for the Phosphor theme.
#
# Columns of half-width katakana, digits and symbols fall down a black field; each stream
# fades from a brighter head to a dim tail, and CRT scanlines are baked in every third row.
# No pixel is brighter than (0,54,19): the brightest green at which every Phosphor palette
# colour keeps at least 4.5:1 contrast, so chat text stays readable over every part of it.
#
#   powershell -NoProfile -File tools\make_rain.ps1 -Out themes\phosphor-rain.png -Tile [-Seed 7]
#
# -Tile makes a seamless tile (streams wrap top to bottom, width and height are whole cells and
# whole scanline periods), for mIRC's tiled background mode: it then covers a window of any size
# at 1:1, with no stretching. Without -Tile, -Width/-Height give a single full-screen picture.

param(
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$Width = 2560,
    [int]$Height = 1440,
    [int]$Seed = 7,
    [switch]$Tile
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

if ($Tile) {
    # 44 columns x 24 rows of 22 px cells = 968 x 528; 528 is a multiple of the 3 px scanline period
    $Width = 44 * 22
    $Height = 24 * 22
}
$rand = New-Object System.Random($Seed)
$bmp = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.Clear([System.Drawing.Color]::Black)
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit

$cell = 22
$font = New-Object System.Drawing.Font('MS Gothic', 16, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
# half-width katakana U+FF66..U+FF9D, digits, a few symbols
$glyphs = @()
foreach ($c in 0xFF66..0xFF9D) { $glyphs += [string][char]$c }
$glyphs += '0123456789:=*+-<>|'.ToCharArray() | ForEach-Object { [string]$_ }

$maxG = 54.0
$cols = [math]::Floor($Width / $cell)
$rows = [math]::Ceiling($Height / $cell)
for ($col = 0; $col -lt $cols; $col++) {
    # 1-3 streams per column at random heights; some columns stay empty
    $streams = $rand.Next(0, 4)
    for ($s = 0; $s -lt $streams; $s++) {
        $len = $rand.Next(6, 28)
        $head = $rand.Next(0, $rows + $len)
        for ($k = 0; $k -lt $len; $k++) {
            $row = $head - $k
            if ($Tile) { $row = (($row % $rows) + $rows) % $rows }  # wrap: seamless top/bottom
            elseif ($row -lt 0 -or $row -ge $rows) { continue }
            # head brightest, tail fades out; the head is at most maxG
            $t = 1.0 - ($k / $len)
            $gv = [int](10 + ($maxG - 10) * [math]::Pow($t, 1.6))
            if ($k -eq 0) { $gv = [int]$maxG }
            $color = [System.Drawing.Color]::FromArgb(255, 0, $gv, [int]($gv * 0.36))
            $brush = New-Object System.Drawing.SolidBrush($color)
            $ch = $glyphs[$rand.Next(0, $glyphs.Count)]
            $g.DrawString($ch, $font, $brush, [single]($col * $cell + 2), [single]($row * $cell))
            $brush.Dispose()
        }
    }
}
$g.Dispose()

# Bake in scanlines and clamp every pixel to (0..0, <=54, <=19) in one pass over the raw bytes.
$rect = New-Object System.Drawing.Rectangle(0, 0, $Width, $Height)
$data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadWrite, $bmp.PixelFormat)
$stride = $data.Stride
$bytes = New-Object byte[] ($stride * $Height)
[System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)
for ($y = 0; $y -lt $Height; $y++) {
    $line = ($y % 3) -eq 2
    $base = $y * $stride
    for ($x = 0; $x -lt $Width; $x++) {
        $i = $base + $x * 3          # B, G, R
        $gch = [int]$bytes[$i + 1]
        if ($line -and $gch -lt 30) { $gch = 30 }
        if ($gch -gt 54) { $gch = 54 }
        $bytes[$i + 2] = 0
        $bytes[$i + 1] = [byte]$gch
        $bytes[$i] = [byte][math]::Min(19, [math]::Round($gch * 0.36))
    }
}
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $data.Scan0, $bytes.Length)
$bmp.UnlockBits($data)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
"{0} {1}x{2} {3} bytes" -f $Out, $Width, $Height, (Get-Item $Out).Length
