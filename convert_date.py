import sys
from datetime import datetime, timezone

# Récupérer la date passée en argument
date_str = sys.argv[1]  # exemple: "Wed Jan 22 11:57:04 2025 +0100"

# Parser la date du format Git
dt = datetime.strptime(date_str, "%a %b %d %H:%M:%S %Y %z")

# Convertir en UTC et forcer heure/min/sec à 00:00:00
dt_utc = dt.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

# Afficher dans le format désiré
print(dt_utc.strftime("%Y-%m-%d %H:%M:%S%z"))

