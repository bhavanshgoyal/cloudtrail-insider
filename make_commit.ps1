git add -A
git commit -m "Review 2: fix proposed detector, add ablation, threats to validity

- Fix conformal calibration data leak (separate fit/cal splits)
- Fix scoring pipeline to use C4 incident aggregation
- Add ablation study (C1-C4 component contribution)
- Add parameter sweep (suppress_days, contamination)
- Add threats to validity document
- Update README with preliminary metric numbers
- Fix Unicode encoding issues in pipeline output
- Initialise git with proper .gitignore"

Write-Host "========================================================" -ForegroundColor Green
Write-Host "✅ Commit created successfully!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "To push to a new GitHub repository, you can run:"
Write-Host "  gh repo create cloudtrail-insider --private --source=. --push"
Write-Host "Or if you already have a remote configured:"
Write-Host "  git push -u origin main"
