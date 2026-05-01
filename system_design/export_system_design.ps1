$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exports = Join-Path $root "exports"
$docxDir = Join-Path $exports "docx"
$pdfDir = Join-Path $exports "pdf"
$pngDir = Join-Path $exports "png"
$diagramPngDir = Join-Path $pngDir "diagrams"
$htmlDir = Join-Path $exports "html"
$tempDir = Join-Path $exports "_tmp"

$dirs = @($exports, $docxDir, $pdfDir, $pngDir, $diagramPngDir, $htmlDir, $tempDir)
foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$docSources = @(
    (Join-Path $root "README.md"),
    (Join-Path $root "current-state-analysis.md"),
    (Join-Path $root "proposed-langgraph-design.md"),
    (Join-Path $root "high-level-development-guide.md"),
    (Join-Path $root "implementation-backlog.md"),
    (Join-Path $root "ULM diagrams\current-and-target-flow.md"),
    (Join-Path $root "ULM diagrams\langgraph-state-and-nodes.md")
)

$diagramSources = @(
    (Join-Path $root "ULM diagrams\current-and-target-flow.md"),
    (Join-Path $root "ULM diagrams\langgraph-state-and-nodes.md")
)

function Convert-MarkdownToDocx {
    param(
        [string]$InputFile,
        [string]$OutputFile
    )

    & pandoc $InputFile -f gfm -t docx -o $OutputFile
    if ($LASTEXITCODE -ne 0) {
        throw "pandoc DOCX conversion failed for $InputFile"
    }
}

function Get-HeadlessBrowserPath {
    $candidates = @(
        "C:\Program Files\Google\Chrome\Application\chrome.exe",
        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "No supported headless browser was found for PDF generation."
}

function Convert-HtmlToPdf {
    param(
        [string]$InputHtmlFile,
        [string]$OutputFile
    )

    $browser = Get-HeadlessBrowserPath
    $inputUri = "file:///" + (($InputHtmlFile -replace "\\", "/") -replace " ", "%20")
    $profileDir = Join-Path $tempDir ("browser-profile-" + [System.IO.Path]::GetFileNameWithoutExtension($OutputFile))
    New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
    $arguments = @(
        "--headless",
        "--disable-gpu",
        "--user-data-dir=$profileDir",
        "--allow-file-access-from-files",
        "--no-pdf-header-footer",
        "--print-to-pdf=$OutputFile",
        $inputUri
    )

    & $browser @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Headless browser PDF generation failed for $InputHtmlFile"
    }

    $deadline = (Get-Date).AddSeconds(30)
    while ((-not (Test-Path $OutputFile)) -and ((Get-Date) -lt $deadline)) {
        Start-Sleep -Milliseconds 500
    }

    if (-not (Test-Path $OutputFile)) {
        throw "PDF output was not created for $InputHtmlFile"
    }
}

function Convert-MarkdownToHtml {
    param(
        [string]$InputFile,
        [string]$OutputFile
    )

    & pandoc $InputFile -f gfm -t html5 --standalone -o $OutputFile
    if ($LASTEXITCODE -ne 0) {
        throw "pandoc HTML conversion failed for $InputFile"
    }
}

function Render-MermaidMarkdown {
    param(
        [string]$InputFile,
        [string]$ArtefactsDir,
        [string]$OutputMarkdown
    )

    & mmdc -i $InputFile -o $OutputMarkdown -a $ArtefactsDir -e png -t neutral -w 1800 -H 1200 -s 2
    if ($LASTEXITCODE -ne 0) {
        throw "Mermaid PNG render failed for $InputFile"
    }
}

foreach ($source in $docSources) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($source)
    $docxOut = Join-Path $docxDir ($baseName + ".docx")
    $pdfOut = Join-Path $pdfDir ($baseName + ".pdf")
    $htmlOut = Join-Path $htmlDir ($baseName + ".html")

    Convert-MarkdownToDocx -InputFile $source -OutputFile $docxOut
    Convert-MarkdownToHtml -InputFile $source -OutputFile $htmlOut
    Convert-HtmlToPdf -InputHtmlFile $htmlOut -OutputFile $pdfOut
}

foreach ($source in $diagramSources) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($source)
    $artefactDir = Join-Path $tempDir ($baseName + "_png")
    $outputMarkdown = Join-Path $tempDir ($baseName + "_rendered.md")

    New-Item -ItemType Directory -Force -Path $artefactDir | Out-Null
    Render-MermaidMarkdown -InputFile $source -ArtefactsDir $artefactDir -OutputMarkdown $outputMarkdown

    Get-ChildItem $artefactDir -File -Filter *.png | ForEach-Object {
        $targetName = "{0}-{1}" -f $baseName, $_.Name
        Copy-Item $_.FullName (Join-Path $diagramPngDir $targetName) -Force
    }
}

Write-Output "Exports created under $exports"
