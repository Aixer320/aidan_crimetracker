This GitHub repository was only created on 14/11/25. I have unfortunately taken a long time to figure out how to sync this repository with my PyCharm project meanwhile working on it. This is a Flask web app for reporting and visualising Queensland crime data on an interactive Leaflet map. Supports user submissions, admin moderation, CSV imports, suburb/postcode filtering, heatmap, and basic analytics (weekday/month charts).

Download this entire directory as a zip file. Go to Code -> Download Zip.
Then go to 10DIG-25 > crime_tracker

Then run this line of code in the terminal:
$repo='aidan_crimetracker'; $url='https://github.com/Aixer320/aidan_crimetracker.git'; Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force; if (-not (Test-Path $repo)) { git clone $url $repo }; Set-Location $repo; if (-not (Test-Path '.venv')) { py -3 -m venv .venv }; .\.venv\Scripts\Activate.ps1; python -m pip install --upgrade pip; if (Test-Path 'requirements.txt') { pip install -r requirements.txt } else { pip install Flask requests }

You can now run app.py and enjoy the crime tracker!
