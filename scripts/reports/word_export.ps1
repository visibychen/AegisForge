param(
    [Parameter(Mandatory = $true)][string]$InputDocx,
    [Parameter(Mandatory = $true)][string]$OutputPdf,
    [switch]$UpdateFields
)
$ErrorActionPreference = 'Stop'
$inputPath = (Resolve-Path -LiteralPath $InputDocx).Path
$pdfPath = [IO.Path]::GetFullPath($OutputPdf)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($pdfPath)) | Out-Null
$word = $null
$document = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $word.AutomationSecurity = 3
    $readOnly = -not $UpdateFields.IsPresent
    $document = $word.Documents.Open($inputPath, $false, $readOnly, $false)
    if ($UpdateFields) {
        foreach ($styleId in @(-20, -21)) {
            # Built-in IDs select the actual localized Word TOC styles.
            $style = $document.Styles.Item($styleId)
            $style.Font.Name = 'Times New Roman'
            $style.Font.NameFarEast = [string]::Concat([char]0x5B8B, [char]0x4F53)
            $style.Font.Size = 10.5
            $style.Font.Color = 0
            $style.ParagraphFormat.LineSpacingRule = 4
            $style.ParagraphFormat.LineSpacing = 22
            $style.ParagraphFormat.SpaceBefore = 0
            $style.ParagraphFormat.SpaceAfter = 0
            $style.ParagraphFormat.KeepWithNext = 0
            $style.ParagraphFormat.KeepTogether = 0
        }
        $document.Fields.Update() | Out-Null
        foreach ($toc in $document.TablesOfContents) {
            $toc.Update()
            # Word may materialize its localized built-in TOC styles instead of
            # supplied aliases. Format the actual field range before pagination.
            $toc.Range.Font.Name = 'Times New Roman'
            $toc.Range.Font.NameFarEast = [string]::Concat([char]0x5B8B, [char]0x4F53)
            $toc.Range.Font.Size = 10.5
            $toc.Range.Font.Color = 0
            $toc.Range.ParagraphFormat.LineSpacingRule = 4
            $toc.Range.ParagraphFormat.LineSpacing = 22
            $toc.Range.ParagraphFormat.SpaceBefore = 0
            $toc.Range.ParagraphFormat.SpaceAfter = 0
            $toc.Range.ParagraphFormat.KeepWithNext = 0
            $toc.Range.ParagraphFormat.KeepTogether = 0
        }
        $document.Repaginate()
        foreach ($toc in $document.TablesOfContents) { $toc.UpdatePageNumbers() }
        $document.Save()
    }
    $document.ExportAsFixedFormat($pdfPath, 17)
    [pscustomobject]@{ Pages=$document.ComputeStatistics(2); Sections=$document.Sections.Count; Pdf=$pdfPath } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $document) { $document.Close(0); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($document) }
    if ($null -ne $word) { $word.Quit(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($word) }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
